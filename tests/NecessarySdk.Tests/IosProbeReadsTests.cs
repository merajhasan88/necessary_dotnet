// The iOS collector's reading: the checks of the plugin's ProbeReads.swift,
// translated -- the app-code coverage adding up, one location read per
// collection, and screen capture unknown, never "no", with no screen of the
// app's to ask.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using Xunit;
using static Necessary.IosProbeReads;

namespace Necessary.Tests
{
    public class IosProbeReadsTests
    {
        private static readonly AppImage Main = Image("Runner", Compared(180_224), main: true);
        private static readonly AppImage Flutter = Image("Frameworks/Flutter.framework/Flutter", Compared(4_194_304));
        private static readonly AppImage App = Image("Frameworks/App.framework/App", Compared(5_914_624));
        private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_792_857_600);
        private static readonly Fix Real = new Fix(24.86, 67.0, 35, Now.AddSeconds(-10), false, false);
        private static readonly Fix Mocked = new Fix(51.5, -0.12, 5, Now.AddSeconds(-9), true, false);

        private static AppImage Image(string path, ImageOutcome outcome, bool main = false) => new AppImage(path, main, outcome);

        private static ImageOutcome Compared(long bytes, long differing = 0) =>
            ImageOutcome.Compared(bytes, differing, bytes + 4096, differing);

        private static long? Int(JsonObject r, string key) => Json.Integer(r[key]);

        private static bool? Bool(JsonObject r, string key) => Json.Bool(r[key]);

        /// <summary>The figures add up, whatever the outcomes: images and bytes alike.</summary>
        private static bool AddsUp(JsonObject r)
        {
            if (Int(r, "app_images_expected") is not long expected || Int(r, "app_images_compared") is not long compared
                || Int(r, "app_images_unreadable") is not long unreadable || Int(r, "app_images_skipped") is not long skipped
                || Int(r, "app_expected_bytes") is not long expectedBytes || Int(r, "app_compared_bytes") is not long comparedBytes
                || Int(r, "app_unreadable_bytes") is not long unreadableBytes || Int(r, "app_skipped_bytes") is not long skippedBytes
                || Bool(r, "app_complete") is not bool complete)
            {
                return false;
            }

            var named = (r["app_images_not_compared"] as JsonObject)?.Count ?? 0;
            return expected == compared + unreadable + skipped
                && expectedBytes == comparedBytes + unreadableBytes + skippedBytes
                && complete == (expected > 0 && compared == expected)
                && named == Math.Min(MaxNamedImages, unreadable + skipped);
        }

        [Fact]
        public void Every_image_compared_the_main_executable_among_them_is_complete()
        {
            var r = AppCoverage(new[] { Main, Flutter, App }, 435);
            Assert.True(AddsUp(r));
            Assert.True(Bool(r, "app_complete") == true && Bool(r, "checked") == true);
            Assert.True(Bool(r, "main_executable_compared"));
            Assert.Equal(180_224 + 4_194_304 + 5_914_624, Int(r, "app_compared_bytes"));
            Assert.False(r.ContainsKey("app_images_not_compared"));
            Assert.Equal(435, Int(r, "system_images_unreadable"));
        }

        [Fact]
        public void One_readable_image_and_one_unreadable_is_partial_and_named()
        {
            var unread = Image("Frameworks/App.framework/App", ImageOutcome.Unreadable(5_914_624, "unreadable: the file could not be opened"));
            var r = AppCoverage(new[] { Main, unread }, 435);
            Assert.True(AddsUp(r));
            Assert.True(Bool(r, "app_complete") == false && Bool(r, "checked") == true);
            Assert.True(Int(r, "app_images_unreadable") == 1 && Int(r, "app_unreadable_bytes") == 5_914_624);
            Assert.Equal("unreadable: the file could not be opened", (string?)r["app_images_not_compared"]!["Frameworks/App.framework/App"]);
            Assert.Equal(435, Int(r, "system_images_unreadable"));
        }

        [Fact]
        public void One_small_framework_never_makes_the_comparison_complete()
        {
            var r = AppCoverage(
                new[]
                {
                    Image("Runner", ImageOutcome.Unreadable(180_224, "unreadable: 0 of 180224 bytes read"), main: true),
                    Image("Frameworks/small.framework/small", Compared(4096)),
                },
                101);
            Assert.True(AddsUp(r));
            Assert.True(Bool(r, "app_complete") == false && Bool(r, "main_executable_compared") == false);
        }

        [Fact]
        public void A_missing_or_invalid_text_span_is_skipped_with_no_bytes_when_the_size_is_unknown()
        {
            Assert.Equal(new CoverageProblem("no __text section in __TEXT", 0), TextSpanOf(0, 8192, 0, null).Problem);
            Assert.Equal(new CoverageProblem("an empty __text section", 0), TextSpanOf(0, 8192, 0, (4096, 0)).Problem);
            foreach (var (offset, size) in new (ulong, ulong)[] { (0, 9000), (9000, 4096), (ulong.MaxValue, 1), (4096, ulong.MaxValue) })
            {
                Assert.Equal(new CoverageProblem("__text lies outside its __TEXT segment", 0), TextSpanOf(4096, 8192, 0, (offset, size)).Problem);
            }

            var r = AppCoverage(new[] { Main, Flutter, Image("Frameworks/App.framework/App", ImageOutcome.Skipped(0, "no __text section in __TEXT")) }, 435);
            Assert.True(AddsUp(r));
            Assert.False(Bool(r, "app_complete"));
            Assert.Equal(Int(r, "app_expected_bytes"), Int(r, "app_compared_bytes"));
        }

        [Fact]
        public void A_valid_segment_beyond_the_budget_is_skipped_with_its_size()
        {
            Assert.Equal(
                new CoverageProblem("__TEXT of 70000000 bytes is over the 64 MiB budget", 60_000_000),
                TextSpanOf(0, 70_000_000, 0, (16384, 60_000_000)).Problem);
            var huge = TextSpanOf(0, ulong.MaxValue, 0, (0, ulong.MaxValue));
            Assert.Null(huge.Span);
            Assert.Equal(0, huge.Problem!.TextSize);
            Assert.Equal(new TextSpan(0, 8_716_288, 0x1000, 16384, 4_194_304), TextSpanOf(0, 8_716_288, 0x1000, (16384, 4_194_304)).Span);
        }

        [Fact]
        public void A_partial_file_read_is_unreadable_never_a_comparison_of_part()
        {
            Assert.Equal("unreadable: 4096 of 5914624 bytes read", ReadProblem(4096, 5_914_624));
            Assert.Equal("unreadable: 0 of 4096 bytes read", ReadProblem(0, 4096));
            Assert.Null(ReadProblem(4096, 4096));
        }

        [Fact]
        public void Nothing_compared_is_not_checked()
        {
            var r = AppCoverage(new[] { Image("Runner", ImageOutcome.Unreadable(180_224, "unreadable: x"), main: true) }, 435);
            Assert.True(Bool(r, "checked") == false && Bool(r, "app_complete") == false);
            var none = AppCoverage(Array.Empty<AppImage>(), 435);
            Assert.True(Bool(none, "checked") == false && Bool(none, "app_complete") == false && AddsUp(none));
        }

        [Fact]
        public void A_differing_byte_is_counted_and_its_image_named()
        {
            var r = AppCoverage(new[] { Main, Image("Frameworks/Flutter.framework/Flutter", Compared(4_194_304, differing: 16)) }, 435);
            Assert.True(Int(r, "app_diff_bytes") == 16 && Int(r, "app_libs_diff") == 1 && (string?)r["diffed_libs"] == "Flutter");
        }

        [Fact]
        public void Names_are_the_path_in_the_bundle_at_most_128_characters_and_at_most_64_named()
        {
            Assert.Equal("Frameworks/App.framework/App", BundleLabel("/var/x/Runner.app/Frameworks/App.framework/App", "/var/x/Runner.app"));
            Assert.Equal("(bundle)", BundleLabel("/var/x/Runner.app", "/var/x/Runner.app"));
            var label = BundleLabel("/b/" + string.Concat(Enumerable.Repeat("d/", 100)) + "Lib", "/b");
            Assert.True(label.Length == 128 && label.EndsWith("/Lib", StringComparison.Ordinal));
            var many = Enumerable.Range(0, 80)
                .Select(i => Image("Frameworks/F" + i + ".framework/F" + i, ImageOutcome.Skipped(10, "no live address for __TEXT")))
                .ToList();
            var r = AppCoverage(many, 0);
            Assert.True(AddsUp(r) && ((JsonObject)r["app_images_not_compared"]!).Count == 64);
        }

        [Fact]
        public void The_arithmetic_holds_for_every_mix_of_outcomes()
        {
            var outcomes = new[]
            {
                Compared(100),
                ImageOutcome.Unreadable(50, "unreadable: x"),
                ImageOutcome.Skipped(0, "no __TEXT segment"),
                ImageOutcome.Skipped(70, "over the budget"),
            };
            for (var mask = 0; mask < 256; mask++)
            {
                var images = new List<AppImage>();
                for (var slot = 0; slot < 4; slot++)
                {
                    if ((mask & (1 << slot)) != 0)
                    {
                        images.Add(Image("I" + slot, outcomes[slot], main: slot == 0));
                    }
                }

                for (var slot = 0; slot < 4; slot++)
                {
                    if ((mask & (1 << (slot + 4))) != 0)
                    {
                        images.Add(Image("J" + slot, outcomes[slot]));
                    }
                }

                Assert.True(AddsUp(AppCoverage(images, 1)), "mix " + mask);
            }
        }

        [Fact]
        public void One_read_answers_both_location_measurements()
        {
            var reads = 0;
            LocationRead Source()
            {
                reads++;
                return Read("precise", reads % 2 == 1 ? Real : Mocked, Now);
            }

            var scan = new LocationCapture(Source);
            var location = Location(scan.Value);
            var mock = MockLocation(scan.Value);
            Assert.Equal(1, reads);
            Assert.True((double)location["latitude"]! == 24.86 && Bool(mock, "mock") == false);
            Assert.True(Int(location, "fix_time") == 1_792_857_590 && Int(location, "fix_time") == Int(mock, "fix_time"));
            Assert.True(Int(location, "age_seconds") == 10 && Int(mock, "age_seconds") == 10);
            Assert.False(mock.ContainsKey("latitude") || mock.ContainsKey("longitude") || mock.ContainsKey("accuracy_m"));
            var next = new LocationCapture(Source);
            Assert.True(Bool(MockLocation(next.Value), "mock") == true && (double)Location(next.Value)["latitude"]! == 51.5 && reads == 2);
        }

        [Fact]
        public void No_permission_reads_no_fix()
        {
            var read = Read("none", Real, Now);
            Assert.Null(read.Fix);
            foreach (var answer in new[] { Location(read), MockLocation(read) })
            {
                Assert.True(answer.Count == 2 && (string?)answer["permission"] == "none");
            }
        }

        [Fact]
        public void A_permission_revoked_during_the_collection_leaves_both_on_the_one_read()
        {
            var permission = "precise";
            var scan = new LocationCapture(() => Read(permission, Real, Now));
            var location = Location(scan.Value);
            permission = "none";
            var mock = MockLocation(scan.Value);
            Assert.True((string?)location["permission"] == "precise" && (string?)mock["permission"] == "precise"
                && Int(location, "fix_time") == Int(mock, "fix_time"));
        }

        [Fact]
        public void No_fix_held_is_the_permission_alone()
        {
            var read = Read("approximate", null, Now);
            Assert.True(Location(read).Count == 2 && MockLocation(read).Count == 2);
        }

        [Fact]
        public void A_stale_fix_has_one_age_and_an_unknown_accuracy_is_not_sent()
        {
            var old = new Fix(1, 2, -1, Now.AddSeconds(-3600), null, null);
            var read = Read("precise", old, Now);
            var location = Location(read);
            var mock = MockLocation(read);
            Assert.True(Int(location, "age_seconds") == 3600 && Int(mock, "age_seconds") == 3600);
            Assert.False(location.ContainsKey("accuracy_m"));
            Assert.True(!mock.ContainsKey("mock") && !mock.ContainsKey("accessory") && Int(mock, "fix_time") == 1_792_854_000);
        }

        [Fact]
        public void A_fix_from_the_future_is_age_zero()
        {
            var ahead = new Fix(1, 2, 3, Now.AddSeconds(30), false, false);
            Assert.Equal(0, Read("precise", ahead, Now).AgeSeconds);
        }

        [Fact]
        public void Screen_capture_with_no_screen_of_the_apps_to_ask_is_unknown_never_no()
        {
            var recorded = ScreenCapture(true, 1);
            Assert.True(Bool(recorded, "recording") == true && !recorded.ContainsKey("recording_status") && Int(recorded, "external_displays") == 1);
            var clean = ScreenCapture(false, 0);
            Assert.True(Bool(clean, "recording") == false && !clean.ContainsKey("recording_status") && Int(clean, "external_displays") == 0);
            var unasked = ScreenCapture(null, 0);
            Assert.True(!unasked.ContainsKey("recording") && (string?)unasked["recording_status"] == "unavailable"
                && (string?)unasked["status"] == "ok" && Int(unasked, "external_displays") == 0);
            Assert.Equal(0, Int(ScreenCapture(false, -1), "external_displays"));
        }
    }
}
