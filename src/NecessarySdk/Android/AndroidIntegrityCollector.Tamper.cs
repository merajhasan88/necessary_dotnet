using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Android.Content.PM;
using Android.OS;
using Android.Provider;
using Microsoft.Win32.SafeHandles;
using static Necessary.AndroidProbeReads;
using File = System.IO.File;

namespace Necessary
{
    public sealed partial class AndroidIntegrityCollector
    {
        private static readonly Regex Whitespace = new Regex(@"\s+", RegexOptions.CultureInvariant);

        private JsonObject ProbeAppIdentity()
        {
            var pm = context.PackageManager!;
            var packageName = context.PackageName!;
            var flags = OperatingSystem.IsAndroidVersionAtLeast(28)
                ? (long)PackageInfoFlags.SigningCertificates
#pragma warning disable CA1422 // The only flag there is below Android 9.
                : (long)PackageInfoFlags.Signatures;
#pragma warning restore CA1422
            var packageInfo = PackageInfoOf(pm, packageName, flags);
            var appInfo = packageInfo.ApplicationInfo ?? context.ApplicationInfo!;
            var certDigests = new List<string>();

            // Apart from cert_sha256: the certificate(s) signing the APK now, and
            // -- after a key rotation -- the signing lineage, oldest first.
            var currentSigners = new List<string>();
            var lineage = new List<string>();
            if (OperatingSystem.IsAndroidVersionAtLeast(28))
            {
                var signingInfo = packageInfo.SigningInfo;
                var signatures = signingInfo is null
                    ? Array.Empty<Signature>()
                    : (signingInfo.HasMultipleSigners ? signingInfo.GetApkContentsSigners() : signingInfo.GetSigningCertificateHistory())
                        ?? Array.Empty<Signature>();
                foreach (var signature in signatures)
                {
                    certDigests.Add(Sha256Hex(signature.ToByteArray()!));
                }

                foreach (var signature in signingInfo?.GetApkContentsSigners() ?? Array.Empty<Signature>())
                {
                    currentSigners.Add(Sha256Hex(signature.ToByteArray()!));
                }

                if (signingInfo is not null && !signingInfo.HasMultipleSigners)
                {
                    foreach (var signature in signingInfo.GetSigningCertificateHistory() ?? Array.Empty<Signature>())
                    {
                        lineage.Add(Sha256Hex(signature.ToByteArray()!));
                    }
                }
            }
            else
            {
#pragma warning disable CA1422 // The only signatures there are below Android 9.
                foreach (var signature in packageInfo.Signatures ?? new List<Signature>())
#pragma warning restore CA1422
                {
                    certDigests.Add(Sha256Hex(signature.ToByteArray()!));
                }

                currentSigners.AddRange(certDigests);
            }

            certDigests.Sort(StringComparer.Ordinal);
            currentSigners.Sort(StringComparer.Ordinal);

            // A lookup that threw is unread; null from a lookup that worked means
            // no installer named one (adb, or an installer that names nobody).
            string? installerUnread = null;
            string? installer;
            try
            {
                installer = InstallerOf(pm, packageName);
            }
#pragma warning disable CA1031 // Unread, said so below.
            catch (Exception error)
#pragma warning restore CA1031
            {
                installerUnread = AndroidNative.SimpleName(error);
                installer = null;
            }

            // The base APK alone (ApplicationInfo.sourceDir): apk_sha256 never
            // covers the splits, which are listed apart.
            var sourceDir = appInfo.SourceDir!;
            var apkHash = cachedApkSha256 ??= Sha256File(sourceDir);
            var splitsUnread = new List<KeyValuePair<string, string>>();
            var splits = new JsonArray();
            var known = cachedSplits;
            if (known is not null)
            {
                foreach (var (name, sha256) in known)
                {
                    splits.Add(new JsonObject { ["name"] = name, ["sha256"] = sha256 });
                }
            }
            else
            {
                var hashes = new List<KeyValuePair<string, Outcome<string>>>();
                foreach (var path in appInfo.SplitSourceDirs ?? Array.Empty<string>())
                {
                    var name = Path.GetFileName(path);
                    hashes.RemoveAll(entry => entry.Key == name);
                    hashes.Add(new KeyValuePair<string, Outcome<string>>(name, Outcome<string>.Of(() => Sha256File(path))));
                }

                var (listed, unread) = SplitApks(hashes);
                splitsUnread = unread;
                splits = listed;
                if (unread.Count == 0)
                {
                    cachedSplits = listed.Select(item => ((string)item!["name"]!, (string)item["sha256"]!)).ToList();
                }
            }

            long versionCode;
            if (OperatingSystem.IsAndroidVersionAtLeast(28))
            {
                versionCode = packageInfo.LongVersionCode;
            }
            else
            {
#pragma warning disable CA1422 // The only version code there is below Android 9.
                versionCode = packageInfo.VersionCode;
#pragma warning restore CA1422
            }

            var result = Ok(
                ("package_name", packageName),
                ("version_name", packageInfo.VersionName ?? string.Empty),
                ("version_code", versionCode),
                ("debuggable", (appInfo.Flags & ApplicationInfoFlags.Debuggable) != 0),
                ("allow_backup", (appInfo.Flags & ApplicationInfoFlags.AllowBackup) != 0),
                ("cert_sha256", certDigests),
                ("current_signers", currentSigners.Distinct().Take(8).ToList()),
                ("signing_lineage", lineage.Take(8).ToList()),
                ("apk_sha256", apkHash),
                ("split_apks", splits),
                ("installer_package", installer),
                ("source_dir", sourceDir));
            var allUnread = new List<KeyValuePair<string, string>>();
            if (installerUnread is not null)
            {
                allUnread.Add(new KeyValuePair<string, string>("installer_package", installerUnread));
            }

            allUnread.AddRange(splitsUnread);
            if (allUnread.Count > 0)
            {
                var map = new JsonObject();
                foreach (var (part, why) in allUnread)
                {
                    map[part] = why;
                }

                result["unread"] = map;
            }

            return result;
        }

        private static PackageInfo PackageInfoOf(PackageManager pm, string packageName, long flags)
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(33))
            {
                return pm.GetPackageInfo(packageName, PackageManager.PackageInfoFlags.Of(flags))!;
            }

#pragma warning disable CA1422 // The only call there is below Android 13.
            return pm.GetPackageInfo(packageName, (PackageInfoFlags)flags)!;
#pragma warning restore CA1422
        }

        private static JsonObject ProbeDebugState() => Ok(
            ("debugger_connected", Android.OS.Debug.IsDebuggerConnected),
            ("waiting_for_debugger", Android.OS.Debug.WaitingForDebugger()));

        private static JsonObject ProbeRootFiles() => RootFiles(
            RootPaths.Select(path => new KeyValuePair<string, Outcome<bool>>(path, Outcome<bool>.Of(() => new Java.IO.File(path).Exists()))).ToList(),
            Build.Tags ?? string.Empty);

        // A lookup that could not start, or never finished, is not "no su": the
        // probe fails, and the report says it measured nothing.
        private static JsonObject ProbeRootShell() =>
            RootShell(RunCommand("/system/bin/sh", "-c", "command -v su || which su || true"));

        private static JsonObject ProbeSystemProperties()
        {
            var names = new[]
            {
                "ro.secure",
                "ro.debuggable",
                "ro.build.type",
                "ro.build.tags",
                "ro.boot.verifiedbootstate",
                "ro.boot.flash.locked",
                "ro.boot.vbmeta.device_state",
                "ro.boot.veritymode",
            };
            return SystemProperties(names
                .Select(name => new KeyValuePair<string, CommandResult>(name, RunCommand("/system/bin/getprop", name)))
                .ToList());
        }

        private static JsonObject ProbeSelinux()
        {
            // Two independent local views. Some OEMs do not expose
            // /system/bin/getenforce consistently to an application process even
            // though SELinux itself is enforcing; /sys/fs/selinux/enforce is the
            // kernel's own boolean when readable: 1 enforcing, 0 permissive. A
            // command that failed or timed out is unknown, never a verdict.
            var run = RunCommand("/system/bin/sh", "-c", "getenforce 2>/dev/null || true");
            var text = run.Problem is null ? run.Output : string.Empty;
            var mode = Take((text.Trim().Split('\n').FirstOrDefault() ?? string.Empty).TrimEnd('\r'), 64);
            string enforceValue;
            try
            {
                enforceValue = Take(File.ReadAllText("/sys/fs/selinux/enforce").Trim(), 8);
            }
#pragma warning disable CA1031 // Unreadable: no value, and the mode decides alone.
            catch (Exception)
#pragma warning restore CA1031
            {
                enforceValue = string.Empty;
            }

            var normalizedMode =
                string.Equals(mode, "Enforcing", StringComparison.OrdinalIgnoreCase) ? "enforcing"
                : string.Equals(mode, "Permissive", StringComparison.OrdinalIgnoreCase) ? "permissive"
                : string.Equals(mode, "Disabled", StringComparison.OrdinalIgnoreCase) ? "disabled"
                : enforceValue == "1" ? "enforcing"
                : enforceValue == "0" ? "permissive"
                : "unknown";
            return Ok(("mode", normalizedMode), ("getenforce", mode), ("enforce_value", enforceValue));
        }

        // An unreadable /proc/mounts is no measurement, never "no writable mount".
        private static JsonObject ProbeMounts() => Mounts(ReadLines("/proc/mounts"));

        private static JsonObject ProbeRuntimeMaps()
        {
            var lines = ReadLines("/proc/self/maps");
            if (lines is null)
            {
                return Unavailable("/proc/self/maps is not readable");
            }

            var found = new List<string>();
            var suspiciousLines = 0;
            foreach (var original in lines)
            {
                var line = original.ToLowerInvariant();
                var lineMatched = false;
                foreach (var token in SuspiciousRuntimeTokens)
                {
                    if (line.Contains(token, StringComparison.Ordinal))
                    {
                        if (!found.Contains(token))
                        {
                            found.Add(token);
                        }

                        lineMatched = true;
                    }
                }

                if (lineMatched)
                {
                    suspiciousLines++;
                }
            }

            if (lines.Count == 0)
            {
                return Unavailable("/proc/self/maps returned no lines");
            }

            return Ok(("suspicious_tokens", found), ("suspicious_line_count", suspiciousLines), ("maps_lines", lines.Count));
        }

        // An unreadable status file, or a TracerPid missing or not a number, is
        // no measurement -- never a tracer pid of 0.
        private static JsonObject ProbeTracer() => Tracer(ReadLines("/proc/self/status"));

        // A refused connection is a measured "closed"; any other failure means
        // the port could not be tested, and says so.
        private static JsonObject ProbeFridaPorts() => FridaPorts(new[] { 27042, 27043 }
            .Select(port => new KeyValuePair<int, PortResult>(port, TestPort(port)))
            .ToList());

        private static PortResult TestPort(int port)
        {
            try
            {
                using var socket = new Java.Net.Socket();
                socket.Connect(new Java.Net.InetSocketAddress("127.0.0.1", port), 80);
                return PortResult.Opened;
            }
            catch (Java.Net.ConnectException)
            {
                return PortResult.Refused;
            }
#pragma warning disable CA1031 // The port could not be tested: named, never "closed".
            catch (Exception error)
#pragma warning restore CA1031
            {
                return PortResult.Failure(AndroidNative.SimpleName(error));
            }
        }

        private static JsonObject ProbeEmulator()
        {
            var reasons = new List<string>();
            static bool Has(string? value, string token) => value?.ToLowerInvariant().Contains(token, StringComparison.Ordinal) == true;
            var fingerprint = Build.Fingerprint ?? string.Empty;
            if (fingerprint.StartsWith("generic", StringComparison.Ordinal) || Has(fingerprint, "emulator"))
            {
                reasons.Add("fingerprint");
            }

            if (Has(Build.Model, "google_sdk") || Has(Build.Model, "emulator") || Has(Build.Model, "android sdk built for"))
            {
                reasons.Add("model");
            }

            if (Has(Build.Manufacturer, "genymotion"))
            {
                reasons.Add("manufacturer");
            }

            if (Has(Build.Product, "sdk") || Has(Build.Product, "emulator") || Has(Build.Product, "simulator"))
            {
                reasons.Add("product");
            }

            if (Has(Build.Hardware, "goldfish") || Has(Build.Hardware, "ranchu"))
            {
                reasons.Add("hardware");
            }

            if (Has(Build.Board, "goldfish"))
            {
                reasons.Add("board");
            }

            return Ok(
                ("suspected", reasons.Count > 0),
                ("reasons", reasons),
                ("model", Build.Model),
                ("manufacturer", Build.Manufacturer),
                ("product", Build.Product),
                ("hardware", Build.Hardware));
        }

        // A setting that could not be read is unread, never "off".
        private JsonObject ProbeDeveloperSettings()
        {
            var resolver = context.ContentResolver;
            return DeveloperSettings(
                Outcome<bool>.Of(() => Settings.Global.GetInt(resolver, Settings.Global.AdbEnabled, 0) != 0),
                Outcome<bool>.Of(() => Settings.Global.GetInt(resolver, Settings.Global.DevelopmentSettingsEnabled, 0) != 0));
        }

        /// <summary>
        /// Instrumentation-runtime thread names. Structural, not name-of-file
        /// based: Frida's Gum runtime and its GLib dependency spawn threads with
        /// names compiled into the framework (gum-js-loop, pool-frida, gmain,
        /// gdbus). Renaming the injected library -- which defeats the maps
        /// pathname scan -- does not rename these threads. Reads
        /// /proc/self/task/&lt;tid&gt;/comm, which an app can always read for its own
        /// threads.
        /// </summary>
        private static JsonObject ProbeInstrumentationThreads()
        {
            // Unmistakably Frida/Gum: compiled into the framework, so a renamed
            // injected library keeps them.
            var fridaThreads = new[] { "gum-js-loop", "gum-js", "pool-frida" };

            // GLib runtime threads: Frida pulls GLib in, and Android apps almost
            // never link GLib themselves; reported apart, to weigh as
            // corroborating rather than conclusive.
            var glibThreads = new[] { "gmain", "gdbus", "pool-spawner" };

            // A running process always has threads; none enumerated means the
            // probe saw nothing. A thread that ended between listing and reading
            // is gone; one whose name could not be read is unread.
            var names = new List<string>();
            var unreadable = 0;
            string[] tasks;
            try
            {
                tasks = Directory.GetDirectories("/proc/self/task");
            }
#pragma warning disable CA1031 // None listed: the reads below see no thread, and say so.
            catch (Exception)
#pragma warning restore CA1031
            {
                tasks = Array.Empty<string>();
            }

            foreach (var task in tasks)
            {
                try
                {
                    names.Add(File.ReadAllText(Path.Combine(task, "comm")).Trim());
                }
#pragma warning disable CA1031 // Unread, unless the thread is gone.
                catch (Exception)
#pragma warning restore CA1031
                {
                    if (Directory.Exists(task))
                    {
                        unreadable++;
                    }
                }
            }

            return Threads(names, unreadable, fridaThreads, glibThreads, SuspiciousRuntimeTokens);
        }

        /// <summary>
        /// Structurally suspicious executable memory: mappings both writable and
        /// executable, and executable mappings backed by a file marked
        /// "(deleted)". Anonymous executable regions with a recognized
        /// "[anon:...]" label are counted apart as telemetry. A runtime that
        /// compiles code as it runs -- .NET's on Android among them -- maps
        /// writable-and-executable memory in amounts and sizes its release runs
        /// show; every size class is reported, so a backend holds them to the
        /// release's published envelope.
        /// </summary>
        private JsonObject ProbeExecMappings()
        {
            var wx = 0;
            var deletedExec = 0;
            var deletedExecJit = 0;
            var deletedExecOwnCode = 0;

            // The app's own compiled code: Android recompiles an app in the
            // background after an install or update and replaces these files under
            // the running process. Writing here takes installd, system or root, so
            // they are counted apart and are advisory. Nothing outside oat/ is
            // exempt, not even base.apk.
            var sourceDir = context.ApplicationInfo?.SourceDir;
            var parent = sourceDir is null ? null : Path.GetDirectoryName(sourceDir);
            var ownCodeDir = parent is null ? null : parent + "/oat/";
            var anonExecLabeled = 0;
            var anonExecUnlabeled = 0;
            var anonExecUnlabeledBytes = 0L;

            // The size of every writable-executable mapping, largest first.
            var wxSizes = new SortedDictionary<long, int>(Comparer<long>.Create((a, b) => b.CompareTo(a)));
            var samples = new List<string>();
            var lines = ReadLines("/proc/self/maps");
            if (lines is null)
            {
                return Unavailable("/proc/self/maps is not readable");
            }

            foreach (var line in lines)
            {
                var parts = Whitespace.Split(line.Trim(), 6);
                if (parts.Length < 5)
                {
                    continue;
                }

                var perms = parts[1];
                if (perms.Length < 4)
                {
                    continue;
                }

                var writable = perms[1] == 'w';
                var executable = perms[2] == 'x';
                if (!executable)
                {
                    continue;
                }

                var path = parts.Length >= 6 ? parts[5] : string.Empty;
                var size = MappingSize(parts[0]);
                if (writable)
                {
                    wx++;
                    if (size > 0)
                    {
                        wxSizes[size] = wxSizes.TryGetValue(size, out var count) ? count + 1 : 1;
                    }

                    if (samples.Count < 8)
                    {
                        samples.Add(Take(line.Trim(), 160));
                    }
                }

                if (path.Contains("(deleted)", StringComparison.Ordinal))
                {
                    // The ART JIT code cache is a memfd/ashmem region that always
                    // shows as executable and "(deleted)" on a clean device.
                    var lower = path.ToLowerInvariant();
                    var isJit = lower.Contains("jit-cache", StringComparison.Ordinal)
                        || lower.Contains("dalvik-jit-code-cache", StringComparison.Ordinal)
                        || lower.Contains("dalvik-", StringComparison.Ordinal)
                        || lower.Contains("/art", StringComparison.Ordinal)
                        || lower.Contains("jit-zygote", StringComparison.Ordinal);
                    var mapped = (path.EndsWith("(deleted)", StringComparison.Ordinal) ? path.Substring(0, path.Length - "(deleted)".Length) : path).Trim();
                    var isOwnCode = ownCodeDir is not null && mapped.StartsWith(ownCodeDir, StringComparison.Ordinal)
                        && (mapped.EndsWith(".odex", StringComparison.Ordinal) || mapped.EndsWith(".vdex", StringComparison.Ordinal)
                            || mapped.EndsWith(".art", StringComparison.Ordinal) || mapped.EndsWith(".oat", StringComparison.Ordinal));
                    if (isJit)
                    {
                        deletedExecJit++;
                    }
                    else if (isOwnCode)
                    {
                        deletedExecOwnCode++;
                        if (samples.Count < 8)
                        {
                            samples.Add(Take(line.Trim(), 160));
                        }
                    }
                    else
                    {
                        deletedExec++;
                        if (samples.Count < 8)
                        {
                            samples.Add(Take(line.Trim(), 160));
                        }
                    }
                }

                if (path.Length == 0)
                {
                    anonExecUnlabeled++;
                    anonExecUnlabeledBytes += Math.Max(0L, size);
                }
                else if (path.StartsWith("[anon:", StringComparison.Ordinal))
                {
                    anonExecLabeled++;
                }
            }

            if (lines.Count == 0)
            {
                return Unavailable("/proc/self/maps returned no lines");
            }

            var wxBytes = wxSizes.Sum(entry => entry.Key * entry.Value);
            return Ok(
                ("wx_mappings", wx),

                // Every size class, largest first, as "<bytes>:<count>": a list cut
                // short earns no baseline allowance.
                ("wx_bytes", wxBytes),
                ("wx_size_classes", string.Join(",", wxSizes.Select(entry => entry.Key + ":" + entry.Value))),
                ("wx_smallest_bytes", wxSizes.Count == 0 ? 0L : wxSizes.Keys.Last()),
                ("wx_largest_bytes", wxSizes.Count == 0 ? 0L : wxSizes.Keys.First()),
                ("anon_exec_unlabeled_bytes", anonExecUnlabeledBytes),
                ("maps_lines", lines.Count),
                ("deleted_exec_mappings", deletedExec),
                ("deleted_exec_jit", deletedExecJit),
                ("deleted_exec_own_code", deletedExecOwnCode),
                ("anon_exec_labeled", anonExecLabeled),
                ("anon_exec_unlabeled", anonExecUnlabeled),
                ("samples", samples));
        }

        /// <summary>The size of one maps range, "start-end" in hex; 0 if unreadable.</summary>
        private static long MappingSize(string range)
        {
            var dash = range.IndexOf('-', StringComparison.Ordinal);
            if (dash <= 0)
            {
                return 0L;
            }

            if (!long.TryParse(range.AsSpan(0, dash), System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out var start)
                || !long.TryParse(range.AsSpan(dash + 1), System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out var end))
            {
                return 0L;
            }

            return end > start ? end - start : 0L;
        }

        /// <summary>
        /// The app's native code and the system libraries in memory compared with
        /// their files (<see cref="CodeIntegrityComparison"/>): an inline hook
        /// overwrites a prologue and shows up as a byte difference, whatever the
        /// hooking framework is called.
        /// </summary>
        private static JsonObject ProbeCodeIntegrity()
        {
            var started = Stopwatch.StartNew();
            JsonObject native;
            try
            {
                native = CodeIntegrityComparison.Compare(new ProcessMemory());
            }
#pragma warning disable CA1031 // Not compared: said so, never clean.
            catch (Exception error)
#pragma warning restore CA1031
            {
                return Ok(("checked", false), ("reason", "native_error:" + AndroidNative.SimpleName(error)));
            }

            var elapsedMs = started.ElapsedMilliseconds;
            var result = new JsonObject
            {
                ["status"] = "ok",
                ["checked"] = native["checked"]!.DeepClone(),
                ["diff_bytes"] = native["diff_bytes"]!.DeepClone(),
                ["core_compared_bytes"] = native["core_compared_bytes"]!.DeepClone(),
                ["core_diff_bytes"] = native["core_diff_bytes"]!.DeepClone(),
                ["ext_compared_bytes"] = native["ext_compared_bytes"]!.DeepClone(),
                ["ext_diff_bytes"] = native["ext_diff_bytes"]!.DeepClone(),
                ["ext_libs_diff"] = native["ext_libs_diff"]!.DeepClone(),
                ["app_compared_bytes"] = native["app_compared_bytes"]!.DeepClone(),
                ["app_diff_bytes"] = native["app_diff_bytes"]!.DeepClone(),
                ["app_libs_diff"] = native["app_libs_diff"]!.DeepClone(),

                // Visibility into execute-only mappings: a bucket that skipped
                // everything reads as clean unless these are reported.
                ["xom_regions_unlocked"] = native["xom_regions_unlocked"]!.DeepClone(),
                ["xom_regions_unreadable"] = native["xom_regions_unreadable"]!.DeepClone(),
                ["diffed_libs"] = native["diffed_libs"]!.DeepClone(),

                // Wall time of the comparison: what a scan costs.
                ["elapsed_ms"] = elapsedMs,
            };

            // Coverage per bucket: expected = compared + skipped + unreadable, so
            // partial measurement is visible, never read as clean.
            foreach (var bucket in new[] { "core", "ext", "app" })
            {
                foreach (var field in new[] { "expected_bytes", "skipped_bytes", "unreadable_bytes" })
                {
                    result[bucket + "_" + field] = native[bucket + "_" + field]!.DeepClone();
                }

                result[bucket + "_complete"] = native[bucket + "_complete"]!.DeepClone();
            }

            result["protect_restore_failures"] = native["protect_restore_failures"]!.DeepClone();
            return result;
        }

        /// <summary>This process: its maps, its memory read by pointer, mprotect and pread.</summary>
        private sealed class ProcessMemory : ICodeIntegrityMemory
        {
            public IReadOnlyList<string> ReadMaps() => File.ReadAllLines("/proc/self/maps");

            public bool Protect(ulong start, ulong length, int protection) =>
                NativeMethods.Mprotect(unchecked((nint)start), unchecked((nuint)length), protection) == 0;

            public void Read(ulong address, byte[] buffer, int count) =>
                Marshal.Copy(unchecked((nint)address), buffer, 0, count);

            public ICodeIntegrityFile? Open(string path)
            {
                try
                {
                    return new HandleFile(File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
                }
#pragma warning disable CA1031 // Not opened: its bytes are unreadable, counted as such.
                catch (Exception)
#pragma warning restore CA1031
                {
                    return null;
                }
            }
        }

        private sealed class HandleFile : ICodeIntegrityFile
        {
            private readonly SafeFileHandle handle;

            public HandleFile(SafeFileHandle handle)
            {
                this.handle = handle;
            }

            public int ReadAt(long offset, byte[] buffer, int count)
            {
                try
                {
                    return RandomAccess.Read(handle, buffer.AsSpan(0, count), offset);
                }
#pragma warning disable CA1031 // A read that failed ends the comparison of this mapping.
                catch (Exception)
#pragma warning restore CA1031
                {
                    return -1;
                }
            }

            public void Dispose() => handle.Dispose();
        }

        private static class NativeMethods
        {
            [DllImport("libc", EntryPoint = "mprotect", SetLastError = true)]
            public static extern int Mprotect(nint address, nuint length, int protection);
        }
    }
}
