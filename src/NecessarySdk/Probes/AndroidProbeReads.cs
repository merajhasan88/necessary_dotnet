using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

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

        /// <summary>
        /// The listed names in one line of the memory map, in any case. The app's
        /// own folders and package name are taken out of the line first: Android
        /// names those folders after the package, with random text beside it, and
        /// neither names a tool. Nor does an assembly a release build compiles ahead
        /// of time there: .NET names each libaot-&lt;assembly&gt;.dll.so, after the
        /// app's own assemblies. What else lies inside those folders is still read,
        /// so a library the app was rebuilt with is found by its own name.
        /// </summary>
        public static IReadOnlyList<string> NamesIn(
            string line,
            IReadOnlyList<string> ownFolders,
            string packageName,
            IReadOnlyList<string> tokens)
        {
            var text = line;
            var own = false;
            foreach (var folder in ownFolders)
            {
                own |= text.Contains(folder, StringComparison.Ordinal);
                text = text.Replace(folder, "/", StringComparison.Ordinal);
            }

            var file = text.LastIndexOf('/') + 1;
            if (own
                && string.CompareOrdinal(text, file, "libaot-", 0, "libaot-".Length) == 0
                && text.EndsWith(".dll.so", StringComparison.Ordinal))
            {
                text = text.Substring(0, file);
            }

            if (packageName.Length > 0)
            {
                text = text.Replace(packageName, string.Empty, StringComparison.Ordinal);
            }

            var lower = text.ToLowerInvariant();
            return tokens.Where(token => lower.Contains(token, StringComparison.Ordinal)).ToList();
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

        /// <summary>The shell's lookup of <c>su</c>, its error stream kept out of the answer.</summary>
        public const string RootShellLookup = "command -v su 2>/dev/null || which su 2>/dev/null || true";

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
        /// unread, since a renamed instrumentation thread could be that one. A
        /// thread named for the app itself -- Android gives the main thread part
        /// of the package's name, 15 characters at most -- names no tool.
        /// </summary>
        public static JsonObject Threads(
            IReadOnlyList<string> names,
            int unreadable,
            IReadOnlyList<string> fridaThreads,
            IReadOnlyList<string> glibThreads,
            IReadOnlyList<string> tokens,
            string packageName = "")
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

                if (packageName.Contains(name, StringComparison.Ordinal))
                {
                    continue;
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
                listed.Add((JsonNode)new JsonObject { ["name"] = Take(entry.Key, 128), ["sha256"] = entry.Value.Value });
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
        /// The runtime's debugger thread among this process's thread names
        /// (collector 13): JDWP, through which a debugger attaches to the app's
        /// code. Android starts it only in an app built debuggable, or on a system
        /// that is (ro.debuggable 1): "JDWP" before Android 9, "ADB-JDWP Connection
        /// Control Thread" since (15 characters of it), and "JDWP ..." threads while
        /// a debugger is attached. With a thread name unread, a "no" could be
        /// wrong, so it is unread instead.
        /// </summary>
        public static JsonObject DebugState(bool debuggerConnected, bool waitingForDebugger, IReadOnlyList<string> threadNames, int unreadable)
        {
            var result = Ok(("debugger_connected", debuggerConnected), ("waiting_for_debugger", waitingForDebugger));
            var named = threadNames.Where(name => name.Length > 0).ToList();
            if (named.Any(IsJdwpThread))
            {
                result["jdwp_thread"] = true;
                return result;
            }

            if (named.Count == 0)
            {
                return WithUnread(result, new[] { Part("jdwp_thread", "no thread of this process could be listed") });
            }

            if (unreadable > 0)
            {
                return WithUnread(result, new[]
                {
                    Part("jdwp_thread", unreadable.ToString(CultureInfo.InvariantCulture) + " of "
                        + (named.Count + unreadable).ToString(CultureInfo.InvariantCulture) + " thread names could not be read"),
                });
            }

            result["jdwp_thread"] = false;
            return result;
        }

        public static bool IsJdwpThread(string name) =>
            name.StartsWith("JDWP", StringComparison.Ordinal) || name.StartsWith("ADB-JDWP", StringComparison.Ordinal);

        /// <summary>Where a file lies, and in whose private folder when it is in one.</summary>
        internal sealed record Place(string Kind, string? Owner = null);

        private static readonly Regex[] InstalledApps =
        {
            new Regex("^/data/app/", RegexOptions.CultureInvariant),
            new Regex("^/mnt/expand/[^/]+/app/", RegexOptions.CultureInvariant),
        };

        private static readonly string[] SystemPartitions = { "/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/oem/", "/apex/" };

        private static readonly Regex[] AppData =
        {
            new Regex("^/data/data/([^/]+)/", RegexOptions.CultureInvariant),
            new Regex("^/data/user(?:_de)?/[0-9]+/([^/]+)/", RegexOptions.CultureInvariant),
            new Regex("^/mnt/expand/[^/]+/user(?:_de)?/[0-9]+/([^/]+)/", RegexOptions.CultureInvariant),
        };

        // An installed app's folder is its package name, '-' (which no package name
        // holds) and a random part: /data/app/<package>-<x>/, under /data/app/~~<x>/
        // from Android 11, or on adopted storage.
        private static readonly Regex InstalledOwner = new Regex(
            "^(?:/data/app/|/mnt/expand/[^/]+/app/)(?:~~[^/]+/)?([A-Za-z][A-Za-z0-9_.]*)-[^/]*/",
            RegexOptions.CultureInvariant);

        /// <summary>
        /// installed: where the package manager puts installed apps, Owner naming
        /// the app where its folder does; system: a system partition; app_data: an
        /// app's private folder, Owner naming the app; elsewhere: anywhere else.
        /// </summary>
        public static Place PlaceOf(string path)
        {
            if (InstalledApps.Any(pattern => pattern.IsMatch(path)))
            {
                var owner = InstalledOwner.Match(path);
                return new Place("installed", owner.Success ? owner.Groups[1].Value : null);
            }

            if (SystemPartitions.Any(partition => path.StartsWith(partition, StringComparison.Ordinal)))
            {
                return new Place("system");
            }

            foreach (var pattern in AppData)
            {
                var match = pattern.Match(path);
                if (match.Success)
                {
                    return new Place("app_data", match.Groups[1].Value);
                }
            }

            return new Place("elsewhere");
        }

        // What a process maps to run code: fonts, databases and other data files are not counted.
        private static readonly string[] CodeFiles = { ".apk", ".dex", ".odex", ".vdex", ".oat", ".art", ".so", ".jar" };

        // Apps load Google Play services' code by design (its dynamite modules), from its own folder.
        private const string PlayServices = "com.google.android.gms";

        private static readonly string[] AppHostParts =
        {
            "loaded_from", "data_folder", "uid_matches", "uid_other_apps", "preload_other_apps", "other_app_code",
        };

        private static readonly Regex MapsFields = new Regex(@"\s+", RegexOptions.CultureInvariant);

        // What a started process's linker prints when it cannot load a library it was given.
        private static readonly Regex NotLoaded = new Regex(
            "CANNOT LINK EXECUTABLE \"[^\"]*\": library \"([^\"]+)\"",
            RegexOptions.CultureInvariant);

        // LD_PRELOAD lists libraries split by spaces or colons, as Android's linker reads it.
        private static IEnumerable<string> PreloadList(string? value) =>
            (value ?? string.Empty).Split(new[] { ' ', ':', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);

        private static KeyValuePair<string, string> Part(string name, string why) => new KeyValuePair<string, string>(name, why);

        private static JsonArray Names(IEnumerable<string> names, int max) =>
            new JsonArray(names.Take(max).Select(name => (JsonNode?)Take(name, 128)).ToArray());

        /// <summary>
        /// Whether Android runs the app itself, or another app runs it inside its
        /// own (collector 13). An app that does keeps this one's data, and may keep
        /// its package file, in its own private folder, and runs its own code in
        /// this process. The readings: where Android says the package file and the
        /// data are, the process's user ID against the app's, the other apps Android
        /// names for that user ID, the other apps whose libraries a process the app
        /// starts is made to load first, and the code files mapped in from other
        /// apps' private folders. A host can answer the app's questions to Android
        /// for it, so one part reading clean clears nothing another part shows. A
        /// part not read is unread, never a clean answer.
        /// </summary>
        /// <remarks>
        /// The libraries to load first (LD_PRELOAD) are read twice: in the app's own
        /// environment, which every process it starts inherits, and in one process
        /// it starts -- the list that process was given or, when it could not start,
        /// the library its linker could not load. Libraries outside apps' folders
        /// are not named.
        /// </remarks>
        public static JsonObject AppHost(
            string packageName,
            string? sourceDir,
            string? dataDir,
            int processUid,
            int appUid,
            Outcome<IReadOnlyList<string>?> packagesForUid,
            Outcome<IReadOnlyList<string>> mapsLines,
            Outcome<string?> ownPreload,
            CommandResult startedPreload,
            int maxApps)
        {
            var result = new JsonObject { ["status"] = "ok" };
            var unread = new List<KeyValuePair<string, string>>();
            if (string.IsNullOrEmpty(sourceDir))
            {
                unread.Add(Part("loaded_from", "the app's package file is not named"));
            }
            else
            {
                var where = PlaceOf(sourceDir!);
                result["loaded_from"] =
                    where.Kind == "app_data" && where.Owner != packageName ? "another_app"
                    : where.Kind == "installed" || where.Kind == "system" ? where.Kind
                    : "elsewhere";
            }

            if (string.IsNullOrEmpty(dataDir))
            {
                unread.Add(Part("data_folder", "the app's data folder is not named"));
            }
            else
            {
                var where = PlaceOf(dataDir!.TrimEnd('/') + "/");
                result["data_folder"] =
                    where.Kind != "app_data" ? "elsewhere"
                    : where.Owner == packageName ? "own"
                    : "another_app";
            }

            bool? truncated = null;
            if (packagesForUid.Error is Exception failed)
            {
                unread.Add(Part("uid_matches", Why(failed)));
                unread.Add(Part("uid_other_apps", Why(failed)));
            }
            else
            {
                var packages = packagesForUid.Value;
                result["uid_matches"] = processUid == appUid && packages is not null && packages.Contains(packageName);

                // Android lets only apps signed with this app's own key share its user
                // ID (sharedUserId), so any other name is either such an app or an
                // answer that did not come from Android.
                var others = new SortedSet<string>(
                    (packages ?? (IReadOnlyList<string>)Array.Empty<string>()).Where(name => name != packageName),
                    StringComparer.Ordinal);
                result["uid_other_apps"] = Names(others, maxApps);
                truncated = others.Count > maxApps;
            }

            var preloads = PreloadList(ownPreload.IsFailure ? null : ownPreload.Value).ToList();
            bool startedRead;
            if (startedPreload.Problem is null)
            {
                preloads.AddRange(PreloadList(startedPreload.Output));
                startedRead = true;
            }
            else
            {
                var library = startedPreload.Started && startedPreload.Finished ? NotLoaded.Match(startedPreload.Output) : null;
                startedRead = library is { Success: true };
                if (startedRead)
                {
                    preloads.Add(library!.Groups[1].Value);
                }
            }

            var preloaders = new SortedSet<string>(
                preloads.Select(path => PlaceOf(path).Owner).Where(owner => owner is not null && owner != packageName).Select(owner => owner!),
                StringComparer.Ordinal);
            if (startedRead || preloaders.Count > 0)
            {
                result["preload_other_apps"] = Names(preloaders, maxApps);
                truncated = (truncated ?? false) || preloaders.Count > maxApps;
            }
            else
            {
                unread.Add(Part("preload_other_apps", "a started process " + startedPreload.Problem));
            }

            var lines = mapsLines.IsFailure ? null : mapsLines.Value;
            if (lines is null || lines.Count == 0)
            {
                unread.Add(Part("other_app_code", mapsLines.Error is Exception error ? Why(error) : "/proc/self/maps returned no lines"));
            }
            else
            {
                var owners = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var line in lines)
                {
                    var fields = MapsFields.Split(line.Trim(), 6);
                    if (fields.Length < 6)
                    {
                        continue;
                    }

                    var path = fields[5].EndsWith(" (deleted)", StringComparison.Ordinal)
                        ? fields[5].Substring(0, fields[5].Length - " (deleted)".Length)
                        : fields[5];
                    if (!fields[1].Contains('x', StringComparison.Ordinal) && !CodeFiles.Any(ending => path.EndsWith(ending, StringComparison.Ordinal)))
                    {
                        continue;
                    }

                    var where = PlaceOf(path);
                    if (where.Kind == "app_data" && where.Owner is string owner && owner != packageName && owner != PlayServices)
                    {
                        owners.Add(owner);
                    }
                }

                result["other_app_code"] = Names(owners, maxApps);
                truncated = (truncated ?? false) || owners.Count > maxApps;
            }

            // One flag for the three lists: a list read held more apps than it can.
            if (truncated is bool more)
            {
                result["truncated"] = more;
            }

            if (AppHostParts.All(name => unread.Any(entry => entry.Key == name)))
            {
                return Error("nothing of where the app runs could be read: " + unread[0].Value);
            }

            return WithUnread(result, unread);
        }

        /// <summary>The processor as /proc/cpuinfo names it: an x86 vendor, ARM implementers, a model, a hypervisor.</summary>
        internal sealed record Cpu(string? Vendor, IReadOnlyList<string> Implementers, string? Model, bool? Hypervisor);

        /// <summary>
        /// x86 names its vendor (vendor_id) and lists its flags, hypervisor among
        /// them under a virtual machine; ARM names each core's implementer, 0x41
        /// for Arm's own designs. The model is x86's "model name" or ARM's
        /// "Hardware". Hypervisor is null where there are no x86 flags to read.
        /// </summary>
        public static Cpu CpuOf(IReadOnlyList<string> lines)
        {
            string? vendor = null;
            string? model = null;
            bool? hypervisor = null;
            var implementers = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var line in lines)
            {
                var colon = line.IndexOf(':', StringComparison.Ordinal);
                if (colon < 0)
                {
                    continue;
                }

                var value = line.Substring(colon + 1).Trim();
                switch (line.Substring(0, colon).Trim().ToLowerInvariant())
                {
                    case "vendor_id":
                        if (vendor is null && value.Length > 0)
                        {
                            vendor = value;
                        }

                        break;
                    case "cpu implementer":
                        if (value.Length > 0)
                        {
                            implementers.Add(value.ToLowerInvariant());
                        }

                        break;
                    case "model name":
                    case "hardware":
                        if (model is null && value.Length > 0)
                        {
                            model = value;
                        }

                        break;
                    case "flags":
                        hypervisor = hypervisor == true || value.Split(' ').Contains("hypervisor");
                        break;
                }
            }

            return new Cpu(vendor, implementers.ToList(), model, hypervisor);
        }

        /// <summary>The system features that say what the device is.</summary>
        public static IReadOnlyList<string> FormFactorFeatures { get; } = new[]
        {
            "org.chromium.arc", "org.chromium.arc.device_management", "android.hardware.type.pc",
            "android.hardware.type.automotive", "android.software.leanback", "android.hardware.type.watch",
        };

        /// <summary>
        /// What the device is, by the features its system declares: a Chromebook, a
        /// PC, a car or a TV runs Android apps on hardware no phone has, so its
        /// processor is no sign of an emulator.
        /// </summary>
        public static string FormFactor(ISet<string> features) =>
            features.Contains("org.chromium.arc") || features.Contains("org.chromium.arc.device_management") ? "chromebook"
            : features.Contains("android.hardware.type.pc") ? "pc"
            : features.Contains("android.hardware.type.automotive") ? "car"
            : features.Contains("android.software.leanback") ? "tv"
            : features.Contains("android.hardware.type.watch") ? "watch"
            : "phone_or_tablet";

        /// <summary>The hardware readings of the emulator measurement, and the reasons they give.</summary>
        internal sealed record EmulatorHardware(JsonObject Fields, IReadOnlyList<string> Reasons, IReadOnlyList<KeyValuePair<string, string>> Unread);

        /// <summary>
        /// The processor, the ABIs the system offers and the kernel's machine
        /// (collector 13). Apps that hide an emulator rewrite its build values but
        /// not its processor; no phone running a current Android has an x86 one,
        /// runs under a hypervisor, or has Apple's cores (0x61, an emulator on a
        /// Mac). These count as reasons only on a phone or tablet: a Chromebook, a
        /// PC, a car or a TV may have such hardware, and form_factor says which.
        /// </summary>
        public static EmulatorHardware EmulatorHardwareOf(
            Outcome<IReadOnlyList<string>> cpuLines,
            IReadOnlyList<string> abis,
            string? machine,
            ISet<string> features)
        {
            var fields = new JsonObject();
            var reasons = new List<string>();
            var unread = new List<KeyValuePair<string, string>>();
            var form = FormFactor(features);
            fields["form_factor"] = form;
            fields["abis"] = new JsonArray(abis.Take(8).Select(abi => (JsonNode?)Take(abi, 32)).ToArray());
            if (!string.IsNullOrEmpty(machine))
            {
                fields["machine"] = Take(machine!, 32);
            }

            var lines = cpuLines.IsFailure ? null : cpuLines.Value;
            var cpu = lines is null || lines.Count == 0 ? null : CpuOf(lines);
            if (cpu is null || (cpu.Vendor is null && cpu.Implementers.Count == 0))
            {
                unread.Add(Part("cpu", cpuLines.Error is Exception error ? Why(error) : "/proc/cpuinfo names no processor"));
            }

            if (cpu?.Vendor is string vendor)
            {
                fields["cpu_vendor"] = Take(vendor, 64);
            }

            if (cpu is { Implementers.Count: > 0 })
            {
                fields["cpu_implementers"] = new JsonArray(cpu.Implementers.Take(8).Select(found => (JsonNode?)Take(found, 8)).ToArray());
            }

            if (cpu?.Model is string model)
            {
                fields["cpu_model"] = Take(model, 128);
            }

            if (cpu?.Hypervisor is bool hypervisor)
            {
                fields["hypervisor"] = hypervisor;
            }

            if (form == "phone_or_tablet")
            {
                if (cpu is not null && (cpu.Vendor is not null || cpu.Implementers.Contains("0x61")))
                {
                    reasons.Add("cpu");
                }

                if (cpu?.Hypervisor == true)
                {
                    reasons.Add("hypervisor");
                }

                if (abis.Count == 0 || abis.Any(abi => abi.StartsWith("x86", StringComparison.Ordinal)))
                {
                    reasons.Add("abi");
                }
            }

            return new EmulatorHardware(fields, reasons, unread);
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

        /// <summary>
        /// The apps that handle calls and texts, added to <c>other_access</c>
        /// (<paramref name="result"/>): <c>call_app</c> (collector 13) and
        /// <c>sms_app</c> (collector 15), each the package
        /// <paramref name="entry"/> describes, left out where the phone names
        /// none; each that could not be read is in <c>unread</c> with why, both
        /// kept when both fail.
        /// </summary>
        public static JsonObject WithDefaultApps(
            JsonObject result,
            Outcome<string?> callApp,
            Outcome<string?> smsApp,
            Func<string, JsonObject> entry)
        {
            if (result is null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (entry is null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            var unread = new List<KeyValuePair<string, string>>();
            foreach (var (name, read) in new[] { ("call_app", callApp), ("sms_app", smsApp) })
            {
                if (read.IsFailure)
                {
                    unread.Add(new KeyValuePair<string, string>(name, Why(read.Error)));
                }
                else if (read.Value is { Length: > 0 } package)
                {
                    result[name] = entry(package);
                }
            }

            return WithUnread(result, unread);
        }

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

                // Every command run here exits 0 when it ran, so another exit is a
                // command that did not run as asked -- one the system's linker could
                // not start, say -- and what it printed is why, not an answer.
                : ExitCode is int code && code != 0 ? "exited with " + code.ToString(CultureInfo.InvariantCulture) + FirstLine(Output)
                : null;

            private static string FirstLine(string output)
            {
                var line = output.Trim().Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None)[0];
                return line.Length == 0 ? string.Empty : ": " + line;
            }
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
                        texts.Add((JsonNode?)item);
                    }

                    return texts;
                case IEnumerable<int> ints:
                    var numbers = new JsonArray();
                    foreach (var item in ints)
                    {
                        numbers.Add((JsonNode?)item);
                    }

                    return numbers;
                case IEnumerable<long> longs:
                    var wide = new JsonArray();
                    foreach (var item in longs)
                    {
                        wide.Add((JsonNode?)item);
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
