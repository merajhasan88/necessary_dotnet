using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>What the comparison needs of the process: its memory map, its memory, protections and files.</summary>
    internal interface ICodeIntegrityMemory
    {
        /// <summary><c>/proc/self/maps</c>, line by line; throws when it cannot be read.</summary>
        IReadOnlyList<string> ReadMaps();

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
    /// The app's native code and the system libraries in memory compared with
    /// their files -- an inline hook changes bytes. The plugin's
    /// <c>code_integrity.cpp</c>, translated: for each target library every
    /// executable mapping is compared against the same bytes on disk, in three
    /// buckets -- the core system libraries, the extended ones, the app's own --
    /// each with what it was expected to compare, compared, skipped and could not
    /// read, so a bucket that measured less than its targets says so instead of
    /// reading clean.
    /// </summary>
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
        /// The app's own native code. The Flutter plugin names the Flutter engine
        /// and the Dart AOT code; a .NET for Android app's own native code is the
        /// .NET runtime and its host instead, so these are their names. A release
        /// APK maps its native libraries straight out of the (uncompressed)
        /// archive unless it extracts them, so <c>/proc/self/maps</c> shows them
        /// backed by <c>base.apk</c>: <c>.apk</c> covers the mapped-from-archive
        /// case (base and split APKs), and the names cover builds that extract.
        /// </summary>
        public static readonly string[] App =
        {
            "/libmonosgen-2.0.so",
            "/libmonodroid.so",
            "/libxamarin-app.so",
            "/libSystem.Native.so",
            "/libSystem.IO.Compression.Native.so",
            "/libSystem.Security.Cryptography.Native.Android.so",
            ".apk",
        };

        /// <summary>Compares the three buckets and answers the native side's figures, in its order.</summary>
        public static JsonObject Compare(ICodeIntegrityMemory memory)
        {
            var core = new Coverage();
            var ext = new Coverage();
            var app = new Coverage();
            var counters = new Counters();
            var names = new System.Text.StringBuilder();
            var buffer = new byte[Chunk];
            var memoryBuffer = new byte[Chunk];
            CompareBucket(memory, Core, core, counters, buffer, memoryBuffer, names);
            CompareBucket(memory, Extended, ext, counters, buffer, memoryBuffer, names);
            CompareBucket(memory, App, app, counters, buffer, memoryBuffer, names);
            var isChecked = core.Found + ext.Found + app.Found > 0;
            return new JsonObject
            {
                ["checked"] = isChecked,
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
                ["diffed_libs"] = names.ToString(),
            };
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
        /// One maps line as the native side's <c>sscanf</c> reads it: the range,
        /// the permissions, the offset and the path (at most 511 characters,
        /// leading spaces skipped); null for a line without a path.
        /// </summary>
        internal static (ulong Start, ulong End, string Perms, ulong Offset, string Path)? ParseLine(string line)
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

            var perms = line.Substring(index, Math.Min(permsEnd - index, 7));
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
            var path = line.Substring(index).TrimEnd('\n');
            if (path.Length == 0)
            {
                return null;
            }

            if (path.Length > 511)
            {
                path = path.Substring(0, 511);
            }

            return (start, end, perms, offset, path);
        }

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

        /// <summary>Sums a bucket; appends the name of any library that differs.</summary>
        private static void CompareBucket(
            ICodeIntegrityMemory memory,
            string[] suffixes,
            Coverage coverage,
            Counters counters,
            byte[] buffer,
            byte[] memoryBuffer,
            System.Text.StringBuilder names)
        {
            foreach (var suffix in suffixes)
            {
                var before = coverage.Diff;
                if (!CompareOne(memory, suffix, coverage, counters, buffer, memoryBuffer))
                {
                    continue;
                }

                if (coverage.Diff > before)
                {
                    var name = suffix.Substring(1);
                    var need = name.Length + (names.Length > 0 ? 1 : 0);
                    if (names.Length + need + 1 < 512)
                    {
                        if (names.Length > 0)
                        {
                            names.Append(',');
                        }

                        names.Append(name);
                    }
                }
            }
        }

        /// <summary>
        /// Compares every executable mapping ending with <paramref name="suffix"/>
        /// against disk, adding what was measured to <paramref name="coverage"/>;
        /// whether any mapping matched.
        /// </summary>
        private static bool CompareOne(
            ICodeIntegrityMemory memory,
            string suffix,
            Coverage coverage,
            Counters counters,
            byte[] buffer,
            byte[] memoryBuffer)
        {
            IReadOnlyList<string> lines;
            try
            {
                lines = memory.ReadMaps();
            }
#pragma warning disable CA1031 // As the native side: maps that cannot be opened match nothing.
            catch (Exception)
#pragma warning restore CA1031
            {
                return false;
            }

            var any = false;
            var diffBefore = coverage.Diff;
            foreach (var line in lines)
            {
                var parsed = ParseLine(line);
                if (parsed is not { } mapping || mapping.Perms.Length < 3 || mapping.Perms[2] != 'x')
                {
                    continue;
                }

                // Select the target before touching any protection: a mapping
                // that is not measured is never modified.
                if (!mapping.Path.EndsWith(suffix, StringComparison.Ordinal) || mapping.End <= mapping.Start)
                {
                    continue;
                }

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
                if (got <= 0)
                {
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

                done += got;
                if (got < want)
                {
                    // A short read: the rest is unreadable.
                    break;
                }
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

        private sealed class Counters
        {
            public int XomUnlocked { get; set; }

            public int XomUnreadable { get; set; }

            public int RestoreFailures { get; set; }
        }
    }
}
