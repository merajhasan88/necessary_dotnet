// The code comparison as the plugin's code_integrity.cpp makes it: every
// executable mapping of a target compared with its file, its coverage adding
// up -- expected = compared + skipped + unreadable -- execute-only mappings
// made readable for the copy and put back exactly, and nothing a target's
// mapping could not be read for counted as clean. And the release review of
// 2026-10-31 (items 1, 2 and 5), as the reference repository's native host
// test holds them: one snapshot of the memory map, read whole, its failures
// answering checked false with a reason; the app region the app's own APKs and
// the named libraries, its own files outside it counted and named; a real
// execute-only mapping compared and put back; never two comparisons at once.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Xunit;

namespace Necessary.Tests
{
    public class CodeIntegrityComparisonTests
    {
        private const ulong Page = 0x1000;

        private static long Long(JsonObject result, string field) => (long)result[field]!;

        private static void AddsUp(JsonObject result)
        {
            foreach (var bucket in new[] { "core", "ext", "app" })
            {
                Assert.Equal(
                    Long(result, bucket + "_expected_bytes"),
                    Long(result, bucket + "_compared_bytes") + Long(result, bucket + "_skipped_bytes") + Long(result, bucket + "_unreadable_bytes"));
            }
        }

        [Fact]
        public void A_clean_process_compares_every_target_in_full()
        {
            var memory = new FakeMemory();
            memory.Map(0x10000, 4 * Page, "r-xp", "/apex/com.android.runtime/lib64/bionic/libc.so");
            memory.Map(0x20000, 2 * Page, "r-xp", "/system/lib64/libssl.so");
            memory.Map(0x30000, 3 * Page, "r-xp", "/data/app/~~x/com.example-1/base.apk");
            var result = CodeIntegrityComparison.Compare(memory, new AppOwn(new[] { "/data/app/~~x/com.example-1/base.apk" }, Array.Empty<string>()));
            Assert.True((bool)result["checked"]!);
            Assert.Equal(4 * (long)Page, Long(result, "core_compared_bytes"));
            Assert.True((bool)result["core_complete"]!);
            Assert.True((bool)result["ext_complete"]!);
            Assert.True((bool)result["app_complete"]!);
            Assert.Equal(0, Long(result, "diff_bytes"));
            Assert.Equal(string.Empty, (string?)result["diffed_libs"]);
            AddsUp(result);
        }

        [Fact]
        public void A_changed_byte_is_counted_and_its_library_named()
        {
            var memory = new FakeMemory();
            memory.Map(0x10000, 2 * Page, "r-xp", "/system/lib64/libc.so");
            memory.Map(0x30000, Page, "r-xp", "/data/app/x/lib/arm64/libmonosgen-2.0.so");
            memory.Patch(0x10010, 3);
            memory.Patch(0x30000, 1);
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.Equal(3, Long(result, "core_diff_bytes"));
            Assert.Equal(3, Long(result, "diff_bytes"));
            Assert.Equal(1, Long(result, "app_diff_bytes"));
            Assert.Equal(1, (int)result["app_libs_diff"]!);
            Assert.Equal("libc.so,libmonosgen-2.0.so", (string?)result["diffed_libs"]);
            AddsUp(result);
        }

        [Fact]
        public void A_library_split_by_a_hook_is_compared_mapping_by_mapping()
        {
            var memory = new FakeMemory();
            memory.Map(0x10000, Page, "r-xp", "/system/lib64/libart.so", fileOffset: 0);
            memory.Map(0x11000, Page, "rwxp", "/system/lib64/libart.so", fileOffset: Page);
            memory.Map(0x12000, Page, "r-xp", "/system/lib64/libart.so", fileOffset: 2 * Page);
            memory.Patch(0x11004, 2);
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.Equal(3 * (long)Page, Long(result, "core_compared_bytes"));
            Assert.Equal(2, Long(result, "core_diff_bytes"));
            Assert.Equal("libart.so", (string?)result["diffed_libs"]);
        }

        [Fact]
        public void An_execute_only_mapping_is_made_readable_for_the_copy_and_put_back()
        {
            var memory = new FakeMemory();
            memory.Map(0x10000, 2 * Page, "--xp", "/system/lib64/libc.so");
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.Equal(1, (int)result["xom_regions_unlocked"]!);
            Assert.True((bool)result["core_complete"]!);
            Assert.Equal(CodeIntegrityComparison.ProtExec, memory.ProtectionAt(0x10000));
            Assert.Equal(0, (int)result["protect_restore_failures"]!);
        }

        [Fact]
        public void One_that_cannot_be_made_readable_is_unreadable_never_compared()
        {
            var memory = new FakeMemory { RefuseUnlock = true };
            memory.Map(0x10000, 2 * Page, "--xp", "/system/lib64/libc.so");
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.Equal(1, (int)result["xom_regions_unreadable"]!);
            Assert.Equal(0, Long(result, "core_compared_bytes"));
            Assert.Equal(2 * (long)Page, Long(result, "core_unreadable_bytes"));
            Assert.False((bool)result["core_complete"]!);
            Assert.True((bool)result["checked"]!);
            AddsUp(result);
        }

        [Fact]
        public void A_protection_that_cannot_be_put_back_is_counted()
        {
            var memory = new FakeMemory { RefuseRestore = true };
            memory.Map(0x10000, Page, "--xp", "/system/lib64/libc.so");
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.Equal(1, (int)result["protect_restore_failures"]!);
        }

        [Fact]
        public void A_file_that_cannot_be_opened_or_ends_short_leaves_the_rest_unreadable()
        {
            var memory = new FakeMemory();
            memory.Map(0x10000, 2 * Page, "r-xp", "/system/lib64/libc.so");
            memory.Map(0x20000, 2 * Page, "r-xp", "/system/lib64/libart.so");
            memory.Unopenable.Add("/system/lib64/libc.so");
            memory.ShortFiles["/system/lib64/libart.so"] = (int)Page + 100;
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.Equal(Page + 100, (ulong)Long(result, "core_compared_bytes"));
            Assert.Equal((4 * Page) - (Page + 100), (ulong)Long(result, "core_unreadable_bytes"));
            Assert.False((bool)result["core_complete"]!);
            AddsUp(result);
        }

        [Fact]
        public void What_the_budget_cuts_off_is_skipped_never_dropped()
        {
            var memory = new FakeMemory { Sparse = true };
            var big = (ulong)CodeIntegrityComparison.BucketBudget - Page;
            memory.Map(0x1000_0000, big, "r-xp", "/system/lib64/libc.so");
            memory.Map(0x8000_0000, 4 * Page, "r-xp", "/system/lib64/libart.so");
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.Equal(CodeIntegrityComparison.BucketBudget, Long(result, "core_compared_bytes"));
            Assert.Equal(3 * (long)Page, Long(result, "core_skipped_bytes"));
            Assert.False((bool)result["core_complete"]!);
            AddsUp(result);
        }

        [Fact]
        public void Nothing_found_is_not_checked_and_nothing_is_complete()
        {
            var memory = new FakeMemory();
            memory.Map(0x10000, Page, "r-xp", "/system/lib64/libfoo.so");
            memory.Map(0x20000, Page, "rw-p", "/system/lib64/libc.so");
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.False((bool)result["checked"]!);
            Assert.Equal("no_target_mapped", (string?)result["reason"]);
            Assert.False((bool)result["core_complete"]!);
            Assert.Equal(0, Long(result, "core_expected_bytes"));
        }

        [Fact]
        public void Maps_lines_are_read_as_the_native_side_reads_them()
        {
            var parsed = CodeIntegrityComparison.ParseLine("7f1c2000-7f1c4000 r-xp 00012000 fd:01 1234                       /system/lib64/libc.so");
            Assert.NotNull(parsed);
            Assert.Equal(0x7f1c2000UL, parsed!.Start);
            Assert.Equal(0x7f1c4000UL, parsed.End);
            Assert.Equal("r-xp", parsed.Perms);
            Assert.Equal(0x12000UL, parsed.Offset);
            Assert.Equal("/system/lib64/libc.so", parsed.Path);
            Assert.Null(CodeIntegrityComparison.ParseLine("7f1c2000-7f1c4000 rwxp 00000000 00:00 0 "));
            Assert.Equal("[anon:dalvik-jit] x", CodeIntegrityComparison.ParseLine("1000-2000 r-xp 0 00:00 0   [anon:dalvik-jit] x")!.Path);
        }

        [Fact]
        public void The_snapshot_parser_keeps_executable_file_backed_mappings_whole()
        {
            var longPath = "/data/app/" + new string('x', 3000) + "/base.apk";
            var maps =
                "7f00000000-7f00001000 r-xp 00000000 fd:00 1 /system/lib64/libc.so\n"
                + "7f00001000-7f00002000 r--p 00001000 fd:00 1 /system/lib64/libc.so\n"
                + "7f00002000-7f00003000 --xp 00002000 fd:00 2 /system/lib64/libart.so\n"
                + "7f00003000-7f00004000 r-xp 00000000 00:00 0 \n"
                + "7f00004000-7f00005000 r-xp 00000000 fd:00 3 /data/app/my app/lib/arm64/libapp.so\n"
                + "7f00005000-7f00006000 r-xp 00010000 fd:00 4 " + longPath + "\n"
                + "garbage line\n";
            var m = CodeIntegrityComparison.ExecutableMappings(maps);
            Assert.Equal(4, m.Count);
            Assert.Equal("/system/lib64/libc.so", m[0].Path);
            Assert.Equal(0x7f00000000UL, m[0].Start);
            Assert.Equal("/system/lib64/libart.so", m[1].Path);
            Assert.Equal('-', m[1].Perms[0]);
            Assert.Equal("/data/app/my app/lib/arm64/libapp.so", m[2].Path);
            Assert.Equal(longPath, m[3].Path);
            Assert.Equal(0x10000UL, m[3].Offset);
        }

        [Fact]
        public void No_inventory_no_completeness_each_with_its_reason()
        {
            var unreadable = CodeIntegrityComparison.Compare(new FakeMemory { MapsFail = true }, AppOwn.None);
            var empty = CodeIntegrityComparison.Compare(new FakeMemory(), AppOwn.None);
            var none = new FakeMemory();
            none.Map(0x7f00000000, Page, "r-xp", "/system/lib64/libnothing.so");
            var nothing = CodeIntegrityComparison.Compare(none, AppOwn.None);
            Assert.Equal("maps_unreadable", (string?)unreadable["reason"]);
            Assert.Equal("maps_empty", (string?)empty["reason"]);
            Assert.Equal("no_target_mapped", (string?)nothing["reason"]);
            foreach (var result in new[] { unreadable, empty, nothing })
            {
                Assert.False((bool)result["checked"]!);
                foreach (var bucket in new[] { "core", "ext", "app" })
                {
                    Assert.False((bool)result[bucket + "_complete"]!);
                }

                Assert.Equal(0, (int)result["app_outside_count"]!);
            }
        }

        [Fact]
        public void A_failed_snapshot_is_never_a_complete_bucket_the_reviews_case()
        {
            // The review's case: libc mapped, the inventory failing after it was
            // read once. One snapshot now: it either was read, whole, or nothing
            // is compared and nothing reads complete.
            var memory = new FakeMemory { MapsFail = true };
            memory.Map(0x10000, Page, "r-xp", "/system/lib64/libc.so");
            memory.Map(0x20000, Page, "r-xp", "/system/lib64/libart.so");
            var result = CodeIntegrityComparison.Compare(memory, AppOwn.None);
            Assert.False((bool)result["core_complete"]!);
            Assert.Equal(0, Long(result, "core_expected_bytes"));
            Assert.Equal(1, memory.MapsReads);
        }

        [Fact]
        public void The_app_region_is_the_apps_own_apks_and_named_libraries_and_its_files_outside_are_named()
        {
            var own = new AppOwn(
                new[] { "/data/app/~~a==/com.x-b==/base.apk", "/data/app/~~a==/com.x-b==/split_config.arm64_v8a.apk" },
                new[] { "/data/app/~~a==/com.x-b==/", "/data/user/0/com.x/" });
            var crafted = CodeIntegrityComparison.ExecutableMappings(
                "1000-2000 r-xp 00000000 fd:00 1 /data/app/~~a==/com.x-b==/base.apk\n"
                + "2000-3000 r-xp 00000000 fd:00 2 /data/app/~~a==/com.x-b==/split_config.arm64_v8a.apk\n"
                + "3000-4000 r-xp 00000000 fd:00 3 /data/app/~~w==/com.google.android.trichromelibrary-1==/base.apk\n"
                + "4000-5000 r-xp 00000000 fd:00 4 /data/app/~~a==/com.x-b==/lib/arm64/libplugin.so\n"
                + "5000-6000 r-xp 00000000 fd:00 5 /data/app/~~a==/com.x-b==/oat/arm64/base.odex\n"
                + "6000-7000 r-xp 00000000 fd:00 6 /data/user/0/com.x/files/libaot-Example.dll.so\n"
                + "7000-8000 r-xp 00000000 fd:00 7 /data/app/~~a==/com.x-b==/lib/arm64/libmonosgen-2.0.so\n");
            var chosen = new bool[crafted.Count];
            foreach (var target in CodeIntegrityComparison.AppTargets(own))
            {
                for (var i = 0; i < crafted.Count; i++)
                {
                    chosen[i] |= CodeIntegrityComparison.Selects(target, crafted[i].Path);
                }
            }

            Assert.Equal(new[] { true, true, false, false, false, false, true }, chosen);
            var outside = CodeIntegrityComparison.OutsideFiles(crafted, chosen, own);
            Assert.Equal(3, outside.Count);
            Assert.Contains("/data/app/~~a==/com.x-b==/oat/arm64/base.odex", outside);
            Assert.Contains("/data/user/0/com.x/files/libaot-Example.dll.so", outside);

            // Through the comparison: the extracted AOT image the review found
            // unmeasured is outside the region, counted and named.
            var memory = new FakeMemory();
            foreach (var mapping in crafted)
            {
                memory.Map(mapping.Start, mapping.End - mapping.Start, mapping.Perms, mapping.Path);
            }

            var result = CodeIntegrityComparison.Compare(memory, own);
            Assert.Equal(3, (int)result["app_outside_count"]!);
            Assert.Equal(
                new[] { "base.odex", "libaot-Example.dll.so", "libplugin.so" },
                result["app_outside_files"]!.AsArray().Select(name => (string)name!).ToArray());
            Assert.Equal(3 * 0x1000L, Long(result, "app_compared_bytes"));
        }

        [Fact]
        public async Task Two_threads_never_compare_at_once()
        {
            var memory = new FakeMemory();
            memory.Map(0x10000, 4 * Page, "--xp", "/system/lib64/libc.so");
            CodeIntegrityComparison.MaxInFlight = 0;
            void Hammer()
            {
                for (var i = 0; i < 25; i++)
                {
                    CodeIntegrityComparison.Compare(memory, AppOwn.None);
                }
            }

            await Task.WhenAll(Task.Run(Hammer), Task.Run(Hammer));
            Assert.Equal(1, CodeIntegrityComparison.MaxInFlight);
            Assert.Equal(CodeIntegrityComparison.ProtExec, memory.ProtectionAt(0x10000));
        }

        [LinuxFact]
        public async Task A_real_execute_only_mapping_is_compared_put_back_and_a_changed_byte_found()
        {
            var page = (ulong)Environment.SystemPageSize;
            var content = new byte[3 * page];
            for (var i = 0; i < content.Length; i++)
            {
                content[i] = (byte)((i * 31) + 7);
            }

            var dir = Directory.CreateTempSubdirectory("code_integrity_").FullName;
            var apk = Path.Combine(dir, "fixture.apk");
            File.WriteAllBytes(apk, content);
            nint mapped;
            using (var handle = File.OpenHandle(apk, FileMode.Open, FileAccess.Read))
            {
                mapped = Posix.mmap(0, (nuint)content.Length, CodeIntegrityComparison.ProtExec, Posix.MapPrivate, (int)handle.DangerousGetHandle(), 0);
            }

            Assert.NotEqual(Posix.MapFailed, mapped);
            try
            {
                var start = unchecked((ulong)mapped);
                Assert.Equal("--xp", PermsAt(start));
                var fixture = new AppOwn(new[] { apk }, new[] { dir + "/" });

                // This process maps .NET's own libSystem.Native.so, one of the
                // named libraries: what the fixture adds is measured against it.
                var without = Long(CodeIntegrityComparison.Compare(new ProcessMemory(), AppOwn.None), "app_expected_bytes");
                var clean = CodeIntegrityComparison.Compare(new ProcessMemory(), fixture);
                Assert.True((bool)clean["checked"]!);
                Assert.Equal(without + content.Length, Long(clean, "app_expected_bytes"));
                Assert.Equal(without + content.Length, Long(clean, "app_compared_bytes"));
                Assert.Equal(0, Long(clean, "app_diff_bytes"));
                Assert.True((bool)clean["app_complete"]!);
                Assert.Equal(0, (int)clean["protect_restore_failures"]!);
                Assert.Equal("--xp", PermsAt(start));

                // A byte changed in memory is found, under the APK's name.
                Assert.Equal(0, Posix.mprotect(mapped, (nuint)page, CodeIntegrityComparison.ProtRead | CodeIntegrityComparison.ProtWrite));
                Marshal.WriteByte(mapped, 100, (byte)(Marshal.ReadByte(mapped, 100) ^ 0xff));
                Assert.Equal(0, Posix.mprotect(mapped, (nuint)page, CodeIntegrityComparison.ProtExec));
                var hooked = CodeIntegrityComparison.Compare(new ProcessMemory(), fixture);
                Assert.Equal(1, Long(hooked, "app_diff_bytes"));
                Assert.Equal("fixture.apk", (string?)hooked["diffed_libs"]);
                Assert.Equal("--xp", PermsAt(start));

                // Two threads hammering the real comparison: never inside it at once.
                CodeIntegrityComparison.MaxInFlight = 0;
                void Hammer()
                {
                    for (var i = 0; i < 25; i++)
                    {
                        CodeIntegrityComparison.Compare(new ProcessMemory(), fixture);
                    }
                }

                await Task.WhenAll(Task.Run(Hammer), Task.Run(Hammer));
                Assert.Equal(1, CodeIntegrityComparison.MaxInFlight);
                Assert.Equal("--xp", PermsAt(start));
            }
            finally
            {
                Posix.munmap(mapped, (nuint)content.Length);
                Directory.Delete(dir, recursive: true);
            }
        }

        /// <summary>The protection /proc/self/maps shows for the mapping that starts at <paramref name="start"/>.</summary>
        private static string PermsAt(ulong start) =>
            CodeIntegrityComparison.ExecutableMappings(File.ReadAllText("/proc/self/maps")).FirstOrDefault(m => m.Start == start)?.Perms ?? string.Empty;

        /// <summary>A process's memory and files: each mapping's bytes equal its file's unless patched.</summary>
        private sealed class FakeMemory : ICodeIntegrityMemory
        {
            private readonly List<(ulong Start, ulong Length, string Perms, string Path, ulong FileOffset)> mappings = new();
            private readonly Dictionary<ulong, byte> patches = new();
            private readonly Dictionary<ulong, int> protections = new();

            public bool RefuseUnlock { get; set; }

            /// <summary>The memory map cannot be read.</summary>
            public bool MapsFail { get; set; }

            /// <summary>How many times the memory map was read.</summary>
            public int MapsReads { get; private set; }

            public bool RefuseRestore { get; set; }

            /// <summary>Huge mappings without storing their bytes: every byte is a function of its file position.</summary>
            public bool Sparse { get; set; }

            public HashSet<string> Unopenable { get; } = new();

            public Dictionary<string, int> ShortFiles { get; } = new();

            public void Map(ulong start, ulong length, string perms, string path, ulong fileOffset = 0)
            {
                mappings.Add((start, length, perms, path, fileOffset));
                protections[start] = CodeIntegrityComparison.ProtectionOf(perms);
            }

            public void Patch(ulong address, int count)
            {
                for (var i = 0; i < count; i++)
                {
                    patches[address + (ulong)i] = 0xCC;
                }
            }

            public int ProtectionAt(ulong start) => protections[start];

            public string ReadMaps()
            {
                MapsReads++;
                if (MapsFail)
                {
                    throw new IOException("the memory map could not be read");
                }

                return string.Concat(mappings.Select(m => $"{m.Start:x}-{m.Start + m.Length:x} {PermsOf(m)} {m.FileOffset:x8} fd:01 42   {m.Path}\n"));
            }

            public bool Protect(ulong start, ulong length, int protection)
            {
                var unlocking = (protection & CodeIntegrityComparison.ProtRead) != 0;
                if ((unlocking && RefuseUnlock) || (!unlocking && RefuseRestore))
                {
                    return false;
                }

                protections[start] = protection;
                return true;
            }

            public void Read(ulong address, byte[] buffer, int count)
            {
                var mapping = mappings.Single(m => address >= m.Start && address < m.Start + m.Length);
                if ((protections[mapping.Start] & CodeIntegrityComparison.ProtRead) == 0)
                {
                    throw new InvalidOperationException("read of an unreadable page: a segfault");
                }

                var position = mapping.FileOffset + (address - mapping.Start);
                for (var i = 0; i < count; i++)
                {
                    buffer[i] = ByteAt(mapping.Path, position + (ulong)i);
                }

                if (patches.Count > 0)
                {
                    for (var i = 0; i < count; i++)
                    {
                        if (patches.TryGetValue(address + (ulong)i, out var patched))
                        {
                            buffer[i] = patched;
                        }
                    }
                }
            }

            public ICodeIntegrityFile? Open(string path) =>
                Unopenable.Contains(path) ? null : new FakeFile(path, ShortFiles.TryGetValue(path, out var length) ? length : (long?)null);

            private static byte ByteAt(string path, ulong position) => (byte)((position * 31) + (ulong)path.Length);

            private string PermsOf((ulong Start, ulong Length, string Perms, string Path, ulong FileOffset) mapping) => mapping.Perms;

            private sealed class FakeFile : ICodeIntegrityFile
            {
                private readonly string path;
                private readonly long? length;

                public FakeFile(string path, long? length)
                {
                    this.path = path;
                    this.length = length;
                }

                public int ReadAt(long offset, byte[] buffer, int count)
                {
                    var available = length is long end ? (int)Math.Max(0, Math.Min(count, end - offset)) : count;
                    for (var i = 0; i < available; i++)
                    {
                        buffer[i] = ByteAt(path, (ulong)(offset + i));
                    }

                    return available;
                }

                public void Dispose()
                {
                }
            }
        }
    }

    /// <summary>A test that needs Linux's /proc/self/maps and mmap: skipped elsewhere.</summary>
    public sealed class LinuxFactAttribute : FactAttribute
    {
        public LinuxFactAttribute()
        {
            if (!OperatingSystem.IsLinux())
            {
                Skip = "needs Linux's /proc/self/maps";
            }
        }
    }

    internal static class Posix
    {
        public const int MapPrivate = 0x02;
        public static readonly nint MapFailed = -1;

        [DllImport("libc", SetLastError = true)]
        public static extern nint mmap(nint address, nuint length, int protection, int flags, int fd, nint offset);

        [DllImport("libc", SetLastError = true)]
        public static extern int munmap(nint address, nuint length);

        [DllImport("libc", SetLastError = true)]
        public static extern int mprotect(nint address, nuint length, int protection);
    }
}
