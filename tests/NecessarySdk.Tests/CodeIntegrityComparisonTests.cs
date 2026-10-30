// The code comparison as the plugin's code_integrity.cpp makes it: every
// executable mapping of a target compared with its file, its coverage adding
// up -- expected = compared + skipped + unreadable -- execute-only mappings
// made readable for the copy and put back exactly, and nothing a target's
// mapping could not be read for counted as clean.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
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
            var result = CodeIntegrityComparison.Compare(memory);
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
            var result = CodeIntegrityComparison.Compare(memory);
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
            var result = CodeIntegrityComparison.Compare(memory);
            Assert.Equal(3 * (long)Page, Long(result, "core_compared_bytes"));
            Assert.Equal(2, Long(result, "core_diff_bytes"));
            Assert.Equal("libart.so", (string?)result["diffed_libs"]);
        }

        [Fact]
        public void An_execute_only_mapping_is_made_readable_for_the_copy_and_put_back()
        {
            var memory = new FakeMemory();
            memory.Map(0x10000, 2 * Page, "--xp", "/system/lib64/libc.so");
            var result = CodeIntegrityComparison.Compare(memory);
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
            var result = CodeIntegrityComparison.Compare(memory);
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
            var result = CodeIntegrityComparison.Compare(memory);
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
            var result = CodeIntegrityComparison.Compare(memory);
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
            var result = CodeIntegrityComparison.Compare(memory);
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
            var result = CodeIntegrityComparison.Compare(memory);
            Assert.False((bool)result["checked"]!);
            Assert.False((bool)result["core_complete"]!);
            Assert.Equal(0, Long(result, "core_expected_bytes"));
        }

        [Fact]
        public void Maps_lines_are_read_as_the_native_side_reads_them()
        {
            var parsed = CodeIntegrityComparison.ParseLine("7f1c2000-7f1c4000 r-xp 00012000 fd:01 1234                       /system/lib64/libc.so");
            Assert.NotNull(parsed);
            Assert.Equal(0x7f1c2000UL, parsed!.Value.Start);
            Assert.Equal(0x7f1c4000UL, parsed.Value.End);
            Assert.Equal("r-xp", parsed.Value.Perms);
            Assert.Equal(0x12000UL, parsed.Value.Offset);
            Assert.Equal("/system/lib64/libc.so", parsed.Value.Path);
            Assert.Null(CodeIntegrityComparison.ParseLine("7f1c2000-7f1c4000 rwxp 00000000 00:00 0 "));
            Assert.Equal("[anon:dalvik-jit] x", CodeIntegrityComparison.ParseLine("1000-2000 r-xp 0 00:00 0   [anon:dalvik-jit] x")!.Value.Path);
        }

        /// <summary>A process's memory and files: each mapping's bytes equal its file's unless patched.</summary>
        private sealed class FakeMemory : ICodeIntegrityMemory
        {
            private readonly List<(ulong Start, ulong Length, string Perms, string Path, ulong FileOffset)> mappings = new();
            private readonly Dictionary<ulong, byte> patches = new();
            private readonly Dictionary<ulong, int> protections = new();

            public bool RefuseUnlock { get; set; }

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

            public IReadOnlyList<string> ReadMaps() =>
                mappings.Select(m => $"{m.Start:x}-{m.Start + m.Length:x} {PermsOf(m)} {m.FileOffset:x8} fd:01 42   {m.Path}").ToList();

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
}
