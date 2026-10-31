using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>
    /// What an Android probe makes of what it read: pure functions over the raw
    /// reads, with no Android API in them, so the tests can hand them every way a
    /// read fails. The plugin's <c>ProbeReads.kt</c>, translated.
    /// </summary>
    /// <remarks>
    /// The rule: a failed read is never a clean negative. A probe that could
    /// read nothing answers status <c>error</c>; one that read some parts answers
    /// <c>ok</c> with those parts and names the rest in <c>unread</c>, each with
    /// why. A backend takes either as missing evidence, never as a measured "no".
    /// </remarks>
    internal static class AndroidProbeReads
    {
        /// <summary>Split APKs listed, at most: a backend's bound for any list.</summary>
        public const int MaxSplits = 64;

        /// <summary>How a failure and its causes are read for <c>unread</c>: the platform's reader (Android sets Java's).</summary>
        public static Causes.Reader Read { get; set; } = Causes.DotNet;

        public static JsonObject Ok(params (string Key, object? Value)[] pairs)
        {
            var result = new JsonObject { ["status"] = "ok" };
            foreach (var (key, value) in pairs)
            {
                if (value is not null)
                {
                    result[key] = ProbeJson.Node(value);
                }
            }

            return result;
        }

        public static JsonObject Error(string reason) => new JsonObject
        {
            ["status"] = "error",
            ["error"] = Take(reason, 240),
        };

        /// <summary>/proc/mounts: lines, or null when the file could not be read.</summary>
        public static JsonObject Mounts(IReadOnlyList<string>? lines)
        {
            if (lines is null)
            {
                return Error("/proc/mounts is not readable");
            }

            if (lines.Count == 0)
            {
                return Error("/proc/mounts returned no lines");
            }

            var protectedPrefixes = new[] { "/system", "/vendor", "/product", "/odm", "/system_ext" };
            var writable = new List<string>();
            foreach (var line in lines)
            {
                var parts = line.Split(' ');
                if (parts.Length < 4)
                {
                    continue;
                }

                var mountPoint = parts[1];
                var options = parts[3].Split(',');
                if (protectedPrefixes.Any(prefix => mountPoint == prefix || mountPoint.StartsWith(prefix + "/", StringComparison.Ordinal))
                    && options.Contains("rw"))
                {
                    writable.Add(mountPoint + ":" + parts[3]);
                }
            }

            return Ok(("protected_rw_mounts", writable.Distinct().Take(32).ToList()));
        }

        /// <summary>
        /// /proc/self/status: lines, or null when unreadable. TracerPid is the
        /// measurement: missing or unparsable, nothing was measured -- it is never
        /// taken as 0. Seccomp and NoNewPrivs are context, -1 when absent.
        /// </summary>
        public static JsonObject Tracer(IReadOnlyList<string>? lines)
        {
            if (lines is null)
            {
                return Error("/proc/self/status is not readable");
            }

            int? tracerPid = null;
            var tracerSeen = false;
            var seccomp = -1;
            var noNewPrivs = -1;
            foreach (var line in lines)
            {
                if (line.StartsWith("TracerPid:", StringComparison.Ordinal))
                {
                    tracerSeen = true;
                    tracerPid = IntOrNull(After(line));
                }
                else if (line.StartsWith("Seccomp:", StringComparison.Ordinal))
                {
                    seccomp = IntOrNull(After(line)) ?? -1;
                }
                else if (line.StartsWith("NoNewPrivs:", StringComparison.Ordinal))
                {
                    noNewPrivs = IntOrNull(After(line)) ?? -1;
                }
            }

            if (!tracerSeen)
            {
                return Error("TracerPid is missing from /proc/self/status");
            }

            if (tracerPid is not int pid)
            {
                return Error("TracerPid is not a number");
            }

            return Ok(("tracer_pid", pid), ("seccomp", seccomp), ("no_new_privs", noNewPrivs));
        }

        /// <summary>The two developer settings, each read on its own: a read that threw is unread, not "off".</summary>
        public static JsonObject DeveloperSettings(Outcome<bool> adb, Outcome<bool> developer)
        {
            if (adb.IsFailure && developer.IsFailure)
            {
                return Error("neither developer setting could be read: " + Why(adb.Error));
            }

            var unread = new List<KeyValuePair<string, string>>();
            if (adb.Error is not null)
            {
                unread.Add(new KeyValuePair<string, string>("adb_enabled", Why(adb.Error)));
            }

            if (developer.Error is not null)
            {
                unread.Add(new KeyValuePair<string, string>("developer_options_enabled", Why(developer.Error)));
            }

            return WithUnread(
                Ok(("adb_enabled", adb.IsFailure ? null : (object)adb.Value), ("developer_options_enabled", developer.IsFailure ? null : (object)developer.Value)),
                unread);
        }

        /// <summary><c>command -v su</c>: a lookup that could not run, or never finished, is not "no su".</summary>
        public static JsonObject RootShell(CommandResult lookup)
        {
            if (lookup.Problem is string problem)
            {
                return Error("su lookup " + problem);
            }

            var path = lookup.Output.Trim();
            return Ok(("su_path", Take(path, 512)), ("su_found", path.Length > 0));
        }

        /// <summary>One getprop run per property: a property not read is unread, never "".</summary>
        public static JsonObject SystemProperties(IReadOnlyList<KeyValuePair<string, CommandResult>> results)
        {
            var values = new JsonObject();
            var unread = new List<KeyValuePair<string, string>>();
            foreach (var (name, result) in results)
            {
                if (result.Problem is string problem)
                {
                    unread.Add(new KeyValuePair<string, string>(name, "getprop " + problem));
                }
                else
                {
                    values[name] = Take(result.Output.Trim(), 256);
                }
            }

            if (values.Count == 0)
            {
                return Error("no property could be read: " + (unread.Count > 0 ? unread[0].Value : string.Empty));
            }

            return WithUnread(Ok(("properties", values)), unread);
        }

        /// <summary>Whether each root path exists: a check that threw is unread, never "absent".</summary>
        public static JsonObject RootFiles(IReadOnlyList<KeyValuePair<string, Outcome<bool>>> checks, string buildTags)
        {
            if (checks.Count > 0 && checks.All(check => check.Value.IsFailure))
            {
                return Error("no root path could be checked: " + Why(checks[0].Value.Error));
            }

            var found = checks.Where(check => !check.Value.IsFailure && check.Value.Value).Select(check => check.Key).ToList();
            var unread = checks.Where(check => check.Value.IsFailure)
                .Select(check => new KeyValuePair<string, string>(check.Key, Why(check.Value.Error)))
                .ToList();
            return WithUnread(
                Ok(
                    ("found_paths", found),
                    ("build_tags", buildTags),
                    ("test_keys", buildTags.ToLowerInvariant().Contains("test-keys", StringComparison.Ordinal))),
                unread);
        }

        /// <summary>Local ports: refused is a measured "closed"; any other failure is unread.</summary>
        public static JsonObject FridaPorts(IReadOnlyList<KeyValuePair<int, PortResult>> results)
        {
            if (results.Count > 0 && results.All(result => result.Value.Failed is not null))
            {
                return Error("no port could be tested: " + results[0].Value.Failed);
            }

            var open = results.Where(result => result.Value.Open).Select(result => result.Key).ToList();
            var unread = results.Where(result => result.Value.Failed is not null)
                .Select(result => new KeyValuePair<string, string>(result.Key.ToString(CultureInfo.InvariantCulture), result.Value.Failed!))
                .ToList();
            return WithUnread(Ok(("open_ports", open)), unread);
        }

        /// <summary>
        /// This process's thread names. A thread that ended between listing and
        /// reading is gone, not unread; one whose name could not be read is
        /// unread, since a renamed instrumentation thread could be that one.
        /// </summary>
        public static JsonObject Threads(
            IReadOnlyList<string> names,
            int unreadable,
            IReadOnlyList<string> fridaThreads,
            IReadOnlyList<string> glibThreads,
            IReadOnlyList<string> tokens)
        {
            var named = names.Where(name => name.Length > 0).ToList();
            if (named.Count == 0)
            {
                return Error("no thread of this process could be enumerated");
            }

            var fridaHits = new List<string>();
            var glibHits = new List<string>();
            var tokenHits = new List<string>();
            foreach (var name in named)
            {
                var lower = name.ToLowerInvariant();
                foreach (var t in fridaThreads)
                {
                    if ((lower == t || lower.StartsWith(t, StringComparison.Ordinal)) && !fridaHits.Contains(t))
                    {
                        fridaHits.Add(t);
                    }
                }

                foreach (var t in glibThreads)
                {
                    if (lower == t && !glibHits.Contains(t))
                    {
                        glibHits.Add(t);
                    }
                }

                foreach (var t in tokens)
                {
                    if (lower.Contains(t, StringComparison.Ordinal) && !tokenHits.Contains(t))
                    {
                        tokenHits.Add(t);
                    }
                }
            }

            var unread = unreadable > 0
                ? new[]
                {
                    new KeyValuePair<string, string>(
                        "thread_names",
                        unreadable.ToString(CultureInfo.InvariantCulture) + " of "
                        + (named.Count + unreadable).ToString(CultureInfo.InvariantCulture) + " could not be read"),
                }
                : Array.Empty<KeyValuePair<string, string>>();
            return WithUnread(
                Ok(
                    ("frida_threads", fridaHits),
                    ("glib_threads", glibHits),
                    ("token_threads", tokenHits),
                    ("thread_count", named.Count)),
                unread);
        }

        /// <summary>
        /// The installed split APKs, apart from the base APK: <c>apk_sha256</c>
        /// stays the base APK's alone. Each split by file name with its SHA-256,
        /// sorted by name; a split that could not be hashed is unread, never left
        /// out. No splits is an empty list, a measurement of its own.
        /// </summary>
        public static (JsonArray Listed, List<KeyValuePair<string, string>> Unread) SplitApks(
            IReadOnlyList<KeyValuePair<string, Outcome<string>>> hashes)
        {
            var sorted = hashes.OrderBy(entry => entry.Key, StringComparer.Ordinal).ToList();
            var listed = new JsonArray();
            foreach (var entry in sorted.Where(entry => !entry.Value.IsFailure).Take(MaxSplits))
            {
                listed.Add(new JsonObject { ["name"] = Take(entry.Key, 128), ["sha256"] = entry.Value.Value });
            }

            var unread = sorted.Where(entry => entry.Value.IsFailure)
                .Select(entry => new KeyValuePair<string, string>("split_apks:" + Take(entry.Key, 116), Why(entry.Value.Error)))
                .ToList();
            return (listed, unread);
        }

        /// <summary>
        /// The newest fix the providers gave, each read once: a provider that
        /// threw is unread, never "no fix"; when none could be read, the read
        /// failed.
        /// </summary>
        public static FixRead NewestFix(string permission, IReadOnlyList<KeyValuePair<string, Outcome<Fix?>>> providers)
        {
            if (permission == "none")
            {
                return new FixRead(permission);
            }

            var unread = providers.Where(provider => provider.Value.IsFailure)
                .Select(provider => new KeyValuePair<string, string>(provider.Key, Why(provider.Value.Error)))
                .ToList();
            if (providers.Count > 0 && unread.Count == providers.Count)
            {
                return new FixRead(permission, failure: "no location provider could be read: " + unread[0].Value);
            }

            var fixes = providers.Where(provider => !provider.Value.IsFailure && provider.Value.Value is not null)
                .Select(provider => provider.Value.Value!)
                .ToList();
            var fix = fixes.Count == 0 ? null : fixes.MaxBy(f => f.ElapsedNanos);
            return new FixRead(permission, fix, unread);
        }

        /// <summary>The last known location: the coordinates of the captured fix.</summary>
        public static JsonObject Location(FixRead read)
        {
            if (read.Failure is string failure)
            {
                return Error(failure);
            }

            var result = Ok(("permission", read.Permission));
            if (read.Fix is Fix fix)
            {
                result["latitude"] = fix.Latitude;
                result["longitude"] = fix.Longitude;
                if (fix.AccuracyM is double accuracy)
                {
                    result["accuracy_m"] = accuracy;
                }

                result["age_seconds"] = fix.AgeSeconds;
                result["provider"] = Take(fix.Provider, 32);
                result["fix_time"] = fix.TimeMillis / 1000;
            }

            return WithUnread(result, read.Unread);
        }

        /// <summary>Whether the captured fix came from a mock-location app: never its coordinates.</summary>
        public static JsonObject MockLocation(FixRead read)
        {
            if (read.Failure is string failure)
            {
                return Error(failure);
            }

            var result = Ok(("permission", read.Permission));
            if (read.Fix is Fix fix)
            {
                result["mock"] = fix.Mock;
                result["age_seconds"] = fix.AgeSeconds;
                result["fix_time"] = fix.TimeMillis / 1000;
            }

            return WithUnread(result, read.Unread);
        }

        /// <summary>
        /// Why a read failed, for <c>unread</c> and a probe's <c>error</c>: the
        /// failure and every cause beneath it (<see cref="Causes"/>), within the
        /// contract's 160 characters.
        /// </summary>
        public static string Why(Exception? error)
        {
            var chain = Causes.Chain(error, null, Read);
            return Take(chain.Length == 0 ? "unknown" : chain, 160);
        }

        public static string Take(string value, int count) => value.Length <= count ? value : value.Substring(0, count);

        internal static JsonObject WithUnread(JsonObject result, IEnumerable<KeyValuePair<string, string>> unread)
        {
            var parts = unread.Take(64).ToList();
            if (parts.Count > 0)
            {
                var map = new JsonObject();
                foreach (var (part, why) in parts)
                {
                    map[Take(part, 128)] = Take(why, 160);
                }

                result["unread"] = map;
            }

            return result;
        }

        private static string After(string line)
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            return (colon < 0 ? line : line.Substring(colon + 1)).Trim();
        }

        private static int? IntOrNull(string text) =>
            int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var value) ? value : null;

        /// <summary>One command's run: started at all, finished in time, its exit code and output.</summary>
        internal sealed record CommandResult(bool Started, bool Finished, int? ExitCode, string Output, string? Failure = null)
        {
            /// <summary>Why the command gave no answer, or null when it ran to the end.</summary>
            public string? Problem =>
                !Started ? "could not start" + (Failure is null ? string.Empty : ": " + Failure)
                : !Finished ? "did not finish in time"
                : null;
        }

        /// <summary>How one attempt to reach a local port ended: open, refused (a measured "closed"), or failed with why.</summary>
        internal sealed class PortResult
        {
            private PortResult(bool open, string? failed)
            {
                Open = open;
                Failed = failed;
            }

            public static PortResult Opened { get; } = new PortResult(true, null);

            public static PortResult Refused { get; } = new PortResult(false, null);

            public bool Open { get; }

            /// <summary>Why the test could not be made; null when it was.</summary>
            public string? Failed { get; }

            public static PortResult Failure(string why) => new PortResult(false, why);
        }

        /// <summary>One last-known fix as the collection captured it, with no Android type in it.</summary>
        internal sealed record Fix(
            double Latitude,
            double Longitude,
            double? AccuracyM,
            long AgeSeconds,
            long ElapsedNanos,
            string Provider,
            long TimeMillis,
            bool Mock);

        /// <summary>
        /// The one location read of a collection: the permission the app held,
        /// the newest fix the providers gave (null: none held one), the providers
        /// that could not be read, with why -- or why nothing could be read at
        /// all, when the permission is not reported either.
        /// </summary>
        internal sealed class FixRead
        {
            public FixRead(string? permission, Fix? fix = null, IReadOnlyList<KeyValuePair<string, string>>? unread = null, string? failure = null)
            {
                Permission = permission;
                Fix = fix;
                Unread = unread ?? Array.Empty<KeyValuePair<string, string>>();
                Failure = failure;
            }

            public string? Permission { get; }

            public Fix? Fix { get; }

            public IReadOnlyList<KeyValuePair<string, string>> Unread { get; }

            public string? Failure { get; }
        }

        /// <summary>
        /// The location and mock-location measurements answer from one read, so
        /// the coordinates and the mock flag describe one fix. Read on first use
        /// and never again; a read that threw is a failed read, not retried. Each
        /// collection makes its own.
        /// </summary>
        internal sealed class LocationCapture
        {
            private readonly Lazy<FixRead> value;

            public LocationCapture(Func<FixRead> read)
            {
                value = new Lazy<FixRead>(() =>
                {
                    try
                    {
                        return read();
                    }
#pragma warning disable CA1031 // A read that threw is a failed read, reported as one.
                    catch (Exception error)
#pragma warning restore CA1031
                    {
                        return new FixRead(null, failure: "location read failed: " + Why(error));
                    }
                });
            }

            public FixRead Value => value.Value;
        }
    }

    /// <summary>A read's outcome: its value, or the failure that stopped it.</summary>
    internal readonly struct Outcome<T>
    {
        private Outcome(T value, Exception? error)
        {
            Value = value;
            Error = error;
        }

        public T Value { get; }

        public Exception? Error { get; }

        public bool IsFailure => Error is not null;

        public static Outcome<T> Success(T value) => new Outcome<T>(value, null);

        public static Outcome<T> Failure(Exception error) => new Outcome<T>(default!, error);

        /// <summary>Runs <paramref name="read"/>, keeping a failure as the outcome.</summary>
        public static Outcome<T> Of(Func<T> read)
        {
            try
            {
                return Success(read());
            }
#pragma warning disable CA1031 // The failure is the outcome.
            catch (Exception error)
#pragma warning restore CA1031
            {
                return Failure(error);
            }
        }
    }

    /// <summary>Plain values as JSON nodes, for the collectors' answers.</summary>
    internal static class ProbeJson
    {
        public static JsonNode? Node(object? value)
        {
            switch (value)
            {
                case null:
                    return null;
                case JsonNode node:
                    return node;
                case string s:
                    return JsonValue.Create(s);
                case bool b:
                    return JsonValue.Create(b);
                case int i:
                    return JsonValue.Create(i);
                case long l:
                    return JsonValue.Create(l);
                case double d:
                    return JsonValue.Create(d);
                case float f:
                    return JsonValue.Create((double)f);
                case IEnumerable<KeyValuePair<string, string>> map:
                    var obj = new JsonObject();
                    foreach (var (key, item) in map)
                    {
                        obj[key] = item;
                    }

                    return obj;
                case IEnumerable<string> strings:
                    var texts = new JsonArray();
                    foreach (var item in strings)
                    {
                        texts.Add(item);
                    }

                    return texts;
                case IEnumerable<int> ints:
                    var numbers = new JsonArray();
                    foreach (var item in ints)
                    {
                        numbers.Add(item);
                    }

                    return numbers;
                case IEnumerable<long> longs:
                    var wide = new JsonArray();
                    foreach (var item in longs)
                    {
                        wide.Add(item);
                    }

                    return wide;
                case IEnumerable<JsonNode?> nodes:
                    var array = new JsonArray();
                    foreach (var item in nodes)
                    {
                        array.Add(item);
                    }

                    return array;
                default:
                    throw new NotSupportedException("A probe value of type " + value.GetType().Name + " has no JSON form.");
            }
        }
    }
}
