using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;

namespace Necessary
{
    /// <summary>What the comparison needs of the process: its memory map, its memory, protections and files.</summary>
    internal interface ICodeIntegrityMemory
    {
        /// <summary><c>/proc/self/maps</c>, read whole; throws when it cannot be read.</summary>
        string ReadMaps();

        /// <summary>mprotect: true when the protection was set.</summary>
        bool Protect(ulong start, ulong length, int protection);

        /// <summary>Copies <paramref name="count"/> bytes of this process's memory at <paramref name="address"/>.</summary>
        void Read(ulong address, byte[] buffer, int count);

        /// <summary>Opens a file for reading; null when it cannot be opened.</summary>
        ICodeIntegrityFile? Open(string path);
    }

    /// <summary>One opened file.</summary>
    internal interface ICodeIntegrityFile : IDisposable
    {
        /// <summary>pread: the bytes read at <paramref name="offset"/>, 0 at the end, negative on a failure.</summary>
        int ReadAt(long offset, byte[] buffer, int count);
    }

    /// <summary>
    /// What the app owns: the APKs it was installed from, by exact path (base and
    /// splits, as Android names them), and the directories its own files live in
    /// (its install directory, its data directories), each ending in '/'.
    /// </summary>
    internal sealed class AppOwn
    {
        public AppOwn(IReadOnlyList<string> apks, IReadOnlyList<string> dirs)
        {
            Apks = apks;
            Dirs = dirs;
        }

        /// <summary>Nothing owned: only the named libraries are the app's.</summary>
        public static AppOwn None { get; } = new AppOwn(Array.Empty<string>(), Array.Empty<string>());

        public IReadOnlyList<string> Apks { get; }

        public IReadOnlyList<string> Dirs { get; }
    }

    /// <summary>
    /// The app's native code and the system libraries in memory compared with
    /// their files -- an inline hook changes bytes. The plugin's
    /// <c>code_integrity.cpp</c>, translated: for each target every executable
    /// mapping is compared against the same bytes on disk, in three buckets --
    /// the core system libraries, the extended ones, the app's own -- each with
    /// what it was expected to compare, compared, skipped and could not read,
    /// so a bucket that measured less than its targets says so instead of
    /// reading clean.
    /// </summary>
    /// <remarks>
    /// Two rules from the release review of 2026-10-31. One inventory: the
    /// memory map is read once, whole, and every bucket is taken from that
    /// snapshot; a snapshot that cannot be read answers <c>checked</c> false with
    /// a reason, no bucket complete, no byte count made up. Complete means every
    /// target mapping in that snapshot compared. One comparison at a time,
    /// process-wide: a comparison makes execute-only pages readable, reads them
    /// and restores them, and two at once could read a page the other had just
    /// made unreadable again, so every caller -- any DeviceTrust, any thread --
    /// takes the same lock for the whole snapshot, unlock, read and restore. (It
    /// does not make a library the app itself unloads meanwhile safe to read.)
    /// And from the pass over the review's other items: the app region is the
    /// app's own -- the APKs it was installed from, by exact path, and the
    /// libraries named here -- never another package's APK the app loads code
    /// from. For .NET (collector 11, the owner's decision of 2026-10-31, closing
    /// the review's item 5) it is all of the app's own code in files: every
    /// executable file of the app's own that is mapped -- the ahead-of-time
    /// compiled assemblies a release extracts (<c>libaot-*.dll.so</c>), the
    /// runtime's other libraries, the Java and Kotlin Android compiled
    /// (<c>base.odex</c>) -- is compared too, each under its own name. What is
    /// still left out is counted and named (<c>app_outside_count</c>,
    /// <c>app_outside_files</c>): nothing, unless a target is ever narrowed again.
    /// Code the runtime compiles as the app runs has no file, and is in no region.
    /// </remarks>
    internal static class CodeIntegrityComparison
    {
        /// <summary>
        /// Bytes compared per bucket at most: far above any real target set, so
        /// every target mapping is measured in full; anything the budget still
        /// cuts off is reported as skipped, never silently dropped.
        /// </summary>
        public const long BucketBudget = 256L << 20;

        /// <summary>Compared in 256 KiB chunks.</summary>
        public const int Chunk = 256 << 10;

        /// <summary>The page size: the most of a mapping past its file's end that is compared, with zeros.</summary>
        public static readonly int PageSize = Environment.SystemPageSize;

        /// <summary>The app's own executable files outside the region named, at most.</summary>
        public const int OutsideNames = 32;

        public const int ProtRead = 0x1;
        public const int ProtWrite = 0x2;
        public const int ProtExec = 0x4;

        /// <summary>libc and libart.</summary>
        public static readonly string[] Core = { "/libc.so", "/libart.so" };

        /// <summary>Other high-value system hook targets, TLS among them (certificate-pinning bypasses patch libssl and libcrypto).</summary>
        public static readonly string[] Extended =
        {
            "/libc++.so", "/libssl.so", "/libcrypto.so", "/libandroid_runtime.so", "/libbinder.so",
        };

        /// <summary>
        /// The app's own native code by name. The Flutter plugin names the Flutter
        /// engine and the Dart AOT code; a .NET for Android app's own native code
        /// is the .NET runtime and its host instead, so these are their names. A
        /// release APK maps its native libraries straight out of the
        /// (uncompressed) archive unless it extracts them, so <c>/proc/self/maps</c>
        /// shows them backed by <c>base.apk</c>: the app's own APKs are therefore
        /// targets by their exact paths, and these names cover builds that extract.
        /// </summary>
        public static readonly string[] AppNamed =
        {
            "/libmonosgen-2.0.so",
            "/libmonodroid.so",
            "/libxamarin-app.so",
            "/libSystem.Native.so",
            "/libSystem.IO.Compression.Native.so",
            "/libSystem.Security.Cryptography.Native.Android.so",
        };

        // Every comparison, from any thread of the process, one at a time.
        private static readonly object Inspection = new object();

        // The tests' witness that comparisons never overlap, as the native host test's.
        internal static int InFlight;
        internal static int MaxInFlight;

        /// <summary>
        /// Compares the three buckets and answers the native side's figures, in its
        /// order: one snapshot of the memory map, the whole comparison one at a
        /// time in the process.
        /// </summary>
        public static JsonObject Compare(ICodeIntegrityMemory memory, AppOwn own)
        {
            lock (Inspection)
            {
                var now = Interlocked.Increment(ref InFlight);
                if (now > Volatile.Read(ref MaxInFlight))
                {
                    Volatile.Write(ref MaxInFlight, now);
                }

                try
                {
                    return Inspect(memory, own);
                }
                finally
                {
                    Interlocked.Decrement(ref InFlight);
                }
            }
        }

        /// <summary>The protection a maps line's permissions describe.</summary>
        public static int ProtectionOf(string perms)
        {
            var protection = 0;
            if (perms.Length > 0 && perms[0] == 'r')
            {
                protection |= ProtRead;
            }

            if (perms.Length > 1 && perms[1] == 'w')
            {
                protection |= ProtWrite;
            }

            if (perms.Length > 2 && perms[2] == 'x')
            {
                protection |= ProtExec;
            }

            return protection;
        }

        /// <summary>
        /// The executable, file-backed mappings of one snapshot: each line's range,
        /// permissions, offset and path, the path whole (spaces kept, no length
        /// limit), as the native side's parser reads them.
        /// </summary>
        internal static List<Mapping> ExecutableMappings(string snapshot)
        {
            var found = new List<Mapping>();
            foreach (var line in snapshot.Split('\n'))
            {
                if (ParseLine(line) is { } mapping && mapping.Perms.Length > 2 && mapping.Perms[2] == 'x' && mapping.End > mapping.Start)
                {
                    found.Add(mapping);
                }
            }

            return found;
        }

        /// <summary>
        /// One maps line: the range, the permissions, the offset and the path --
        /// everything after the inode and the spaces that follow it; null for a
        /// line without a path.
        /// </summary>
        internal static Mapping? ParseLine(string line)
        {
            var index = 0;
            if (!HexField(line, ref index, '-', out var start) || !HexField(line, ref index, ' ', out var end))
            {
                return null;
            }

            var permsEnd = line.IndexOf(' ', index);
            if (permsEnd < 0 || permsEnd == index)
            {
                return null;
            }

            var perms = line.Substring(index, Math.Min(permsEnd - index, 4));
            index = permsEnd;
            SkipSpaces(line, ref index);
            if (!HexField(line, ref index, ' ', out var offset))
            {
                return null;
            }

            SkipSpaces(line, ref index);

            // The device, "major:minor" in hex, and the inode, in decimal.
            var deviceEnd = line.IndexOf(' ', index);
            if (deviceEnd < 0 || line.IndexOf(':', index, deviceEnd - index) < 0)
            {
                return null;
            }

            index = deviceEnd;
            SkipSpaces(line, ref index);
            var inodeStart = index;
            while (index < line.Length && char.IsDigit(line[index]))
            {
                index++;
            }

            if (index == inodeStart)
            {
                return null;
            }

            SkipSpaces(line, ref index);
            var path = line.Substring(index);
            return path.Length == 0 ? null : new Mapping(start, end, perms, offset, path);
        }

        private static JsonObject Inspect(ICodeIntegrityMemory memory, AppOwn own)
        {
            var core = new Coverage();
            var ext = new Coverage();
            var app = new Coverage();
            var counters = new Counters();
            var names = new StringBuilder();
            var reason = string.Empty;
            var outside = new SortedSet<string>(StringComparer.Ordinal);
            string? snapshot;
            try
            {
                snapshot = memory.ReadMaps();
            }
#pragma warning disable CA1031 // A memory map that cannot be read: nothing compared, and said why.
            catch (Exception)
#pragma warning restore CA1031
            {
                snapshot = null;
            }

            if (snapshot is null)
            {
                reason = "maps_unreadable";
            }
            else if (snapshot.Length == 0)
            {
                reason = "maps_empty";
            }
            else
            {
                var mappings = ExecutableMappings(snapshot);
                var selected = new bool[mappings.Count];
                var buffer = new byte[Chunk];
                var memoryBuffer = new byte[Chunk];
                CompareBucket(memory, NamedTargets(Core), mappings, core, counters, buffer, memoryBuffer, selected, names);
                CompareBucket(memory, NamedTargets(Extended), mappings, ext, counters, buffer, memoryBuffer, selected, names);
                CompareBucket(memory, AppTargets(own, mappings), mappings, app, counters, buffer, memoryBuffer, selected, names);
                outside = OutsideFiles(mappings, selected, own);
                if (core.Found + ext.Found + app.Found == 0)
                {
                    reason = "no_target_mapped";
                }
            }

            var isChecked = core.Found + ext.Found + app.Found > 0;
            var listed = new SortedSet<string>(outside.Select(path => Take(BaseName(path), 128)), StringComparer.Ordinal);
            var files = new JsonArray();
            foreach (var name in listed.Take(OutsideNames))
            {
                files.Add(name);
            }

            return new JsonObject
            {
                ["checked"] = isChecked,
                ["reason"] = isChecked ? string.Empty : reason,
                ["diff_bytes"] = core.Diff,
                ["core_compared_bytes"] = core.Compared,
                ["core_diff_bytes"] = core.Diff,
                ["core_expected_bytes"] = core.Expected,
                ["core_skipped_bytes"] = core.Skipped,
                ["core_unreadable_bytes"] = core.Unreadable,
                ["core_complete"] = core.Complete,
                ["ext_compared_bytes"] = ext.Compared,
                ["ext_diff_bytes"] = ext.Diff,
                ["ext_libs_diff"] = ext.WithDiff,
                ["ext_expected_bytes"] = ext.Expected,
                ["ext_skipped_bytes"] = ext.Skipped,
                ["ext_unreadable_bytes"] = ext.Unreadable,
                ["ext_complete"] = ext.Complete,
                ["app_compared_bytes"] = app.Compared,
                ["app_diff_bytes"] = app.Diff,
                ["app_libs_diff"] = app.WithDiff,
                ["app_expected_bytes"] = app.Expected,
                ["app_skipped_bytes"] = app.Skipped,
                ["app_unreadable_bytes"] = app.Unreadable,
                ["app_complete"] = app.Complete,
                ["xom_regions_unlocked"] = counters.XomUnlocked,
                ["xom_regions_unreadable"] = counters.XomUnreadable,
                ["protect_restore_failures"] = counters.RestoreFailures,
                ["app_outside_count"] = outside.Count,
                ["app_outside_files"] = files,
                ["diffed_libs"] = names.ToString(),
            };
        }

        /// <summary>A target: a path suffix ("/libc.so") or an exact path (one of the app's APKs), and the name a difference is reported under.</summary>
        internal static List<Target> NamedTargets(IEnumerable<string> suffixes) =>
            suffixes.Select(suffix => new Target(suffix, false, suffix.Substring(1))).ToList();

        /// <summary>
        /// The app region: the named libraries, then the app's own APKs by exact
        /// path, then every other executable file of the app's own the snapshot
        /// maps -- under its install or data directories -- each by exact path,
        /// in path order, so a difference is named by its file.
        /// </summary>
        internal static List<Target> AppTargets(AppOwn own, IReadOnlyList<Mapping> mappings)
        {
            var targets = NamedTargets(AppNamed);
            var exact = new HashSet<string>(StringComparer.Ordinal);
            foreach (var apk in own.Apks)
            {
                if (!string.IsNullOrEmpty(apk) && exact.Add(apk))
                {
                    targets.Add(new Target(apk, true, BaseName(apk)));
                }
            }

            var files = mappings
                .Select(mapping => mapping.Path)
                .Where(path => own.Dirs.Any(dir => dir.Length > 0 && path.StartsWith(dir, StringComparison.Ordinal)))
                .Distinct(StringComparer.Ordinal)
                .OrderBy(path => path, StringComparer.Ordinal);
            foreach (var path in files)
            {
                if (exact.Add(path))
                {
                    targets.Add(new Target(path, true, BaseName(path)));
                }
            }

            return targets;
        }

        internal static bool Selects(Target target, string path) =>
            target.Exact ? path == target.Match : path.EndsWith(target.Match, StringComparison.Ordinal);

        /// <summary>
        /// The app's own executable files mapped but in no bucket: their paths,
        /// so the app region never reads as all of the app's code.
        /// </summary>
        internal static SortedSet<string> OutsideFiles(IReadOnlyList<Mapping> mappings, IReadOnlyList<bool> selected, AppOwn own)
        {
            var files = new SortedSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < mappings.Count; index++)
            {
                if (selected[index])
                {
                    continue;
                }

                var path = mappings[index].Path;
                if (own.Dirs.Any(dir => dir.Length > 0 && path.StartsWith(dir, StringComparison.Ordinal)))
                {
                    files.Add(path);
                }
            }

            return files;
        }

        private static string BaseName(string path)
        {
            var slash = path.LastIndexOf('/');
            return slash < 0 ? path : path.Substring(slash + 1);
        }

        private static string Take(string value, int count) => value.Length <= count ? value : value.Substring(0, count);

        private static void SkipSpaces(string line, ref int index)
        {
            while (index < line.Length && (line[index] == ' ' || line[index] == '\t'))
            {
                index++;
            }
        }

        private static bool HexField(string line, ref int index, char terminator, out ulong value)
        {
            value = 0;
            var end = line.IndexOf(terminator, index);
            if (end <= index)
            {
                return false;
            }

            if (!ulong.TryParse(line.AsSpan(index, end - index), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value))
            {
                return false;
            }

            index = end + 1;
            return true;
        }

        /// <summary>Sums a bucket; appends the name of any target that differs.</summary>
        private static void CompareBucket(
            ICodeIntegrityMemory memory,
            IReadOnlyList<Target> targets,
            IReadOnlyList<Mapping> mappings,
            Coverage coverage,
            Counters counters,
            byte[] buffer,
            byte[] memoryBuffer,
            bool[] selected,
            StringBuilder names)
        {
            foreach (var target in targets)
            {
                var before = coverage.Diff;
                if (!CompareOne(memory, target, mappings, coverage, counters, buffer, memoryBuffer, selected))
                {
                    continue;
                }

                if (coverage.Diff > before && names.Length + target.Name.Length + 1 < 480)
                {
                    if (names.Length > 0)
                    {
                        names.Append(',');
                    }

                    names.Append(target.Name);
                }
            }
        }

        /// <summary>
        /// Compares every executable mapping of the snapshot the target selects
        /// against disk, adding what was measured to <paramref name="coverage"/>
        /// and marking each mapping selected; whether any mapping matched.
        /// </summary>
        private static bool CompareOne(
            ICodeIntegrityMemory memory,
            Target target,
            IReadOnlyList<Mapping> mappings,
            Coverage coverage,
            Counters counters,
            byte[] buffer,
            byte[] memoryBuffer,
            bool[] selected)
        {
            var any = false;
            var diffBefore = coverage.Diff;
            for (var index = 0; index < mappings.Count; index++)
            {
                var mapping = mappings[index];

                // Select the target before touching any protection: a mapping
                // that is not measured is never modified. One mapping, one bucket.
                if (!Selects(target, mapping.Path) || selected[index])
                {
                    continue;
                }

                selected[index] = true;
                any = true;
                var span = (long)(mapping.End - mapping.Start);
                coverage.Expected += span;
                var used = coverage.Compared + coverage.Unreadable;
                var room = used < BucketBudget ? BucketBudget - used : 0;
                var limit = Math.Min(span, room);
                coverage.Skipped += span - limit;
                if (limit == 0)
                {
                    continue;
                }

                // Android 10 and later map system libraries execute-only: reading
                // such a page faults. Add PROT_READ for the copy only, and put the
                // original protection back whatever happens next. If adding it is
                // refused, the bytes are unreadable -- counted, never clean.
                var restore = -1;
                if (mapping.Perms[0] != 'r')
                {
                    var original = ProtectionOf(mapping.Perms);
                    if (!memory.Protect(mapping.Start, (ulong)span, original | ProtRead))
                    {
                        counters.XomUnreadable++;
                        coverage.Unreadable += limit;
                        continue;
                    }

                    restore = original;
                    counters.XomUnlocked++;
                }

                try
                {
                    using var file = memory.Open(mapping.Path);
                    if (file is null)
                    {
                        coverage.Unreadable += limit;
                        continue;
                    }

                    var done = CompareMapping(memory, mapping.Start, file, (long)mapping.Offset, limit, buffer, memoryBuffer, coverage);
                    coverage.Compared += done;
                    coverage.Unreadable += limit - done;
                }
                finally
                {
                    if (restore >= 0 && !memory.Protect(mapping.Start, (ulong)span, restore))
                    {
                        counters.RestoreFailures++;
                    }
                }
            }

            if (any)
            {
                coverage.Found++;
                if (coverage.Diff > diffBefore)
                {
                    coverage.WithDiff++;
                }
            }

            return any;
        }

        /// <summary>Compares <paramref name="limit"/> bytes of one mapping with the file at <paramref name="offset"/>; the bytes compared.</summary>
        private static long CompareMapping(
            ICodeIntegrityMemory memory,
            ulong start,
            ICodeIntegrityFile file,
            long offset,
            long limit,
            byte[] buffer,
            byte[] memoryBuffer,
            Coverage coverage)
        {
            long done = 0;
            while (done < limit)
            {
                var want = (int)Math.Min(limit - done, Chunk);
                var got = file.ReadAt(offset + done, buffer, want);
                if (got < 0)
                {
                    // A read that failed: the rest is unreadable.
                    break;
                }

                if (got == 0)
                {
                    // The file ends inside the mapping. The kernel fills the rest
                    // of the file's last page with zeros: an executable segment at
                    // the end of a small library -- many an ahead-of-time compiled
                    // assembly -- is mapped that way. Up to a page of them is
                    // compared with zeros, so code put in that slack is found; more
                    // than a page is no part of the file, faults when touched, and
                    // stays unreadable.
                    var rest = limit - done;
                    if (rest >= PageSize)
                    {
                        break;
                    }

                    memory.Read(start + (ulong)done, memoryBuffer, (int)rest);
                    for (var i = 0; i < rest; i++)
                    {
                        if (memoryBuffer[i] != 0)
                        {
                            coverage.Diff++;
                        }
                    }

                    done += rest;
                    break;
                }

                memory.Read(start + (ulong)done, memoryBuffer, got);
                for (var i = 0; i < got; i++)
                {
                    if (memoryBuffer[i] != buffer[i])
                    {
                        coverage.Diff++;
                    }
                }

                // A short read is no failure: the next read says whether the file
                // ended or goes on.
                done += got;
            }

            return done;
        }

        /// <summary>What one bucket measured. expected = compared + skipped + unreadable.</summary>
        private sealed class Coverage
        {
            public long Expected { get; set; }

            public long Compared { get; set; }

            public long Skipped { get; set; }

            public long Unreadable { get; set; }

            public long Diff { get; set; }

            public int Found { get; set; }

            public int WithDiff { get; set; }

            public bool Complete => Expected > 0 && Compared == Expected;
        }

        /// <summary>One executable mapping of the snapshot.</summary>
        internal sealed record Mapping(ulong Start, ulong End, string Perms, ulong Offset, string Path);

        /// <summary>One target of a bucket.</summary>
        internal sealed record Target(string Match, bool Exact, string Name);

        private sealed class Counters
        {
            public int XomUnlocked { get; set; }

            public int XomUnreadable { get; set; }

            public int RestoreFailures { get; set; }
        }
    }
}
