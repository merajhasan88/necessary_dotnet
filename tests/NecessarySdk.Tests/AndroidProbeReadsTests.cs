// No failed read may become a clean negative. Each Android probe is handed an
// unreadable source, empty or malformed content, a command that did not start,
// did not finish, or whose output could not be read, and a check that threw;
// none answers a clean "no". The plugin's ProbeReadsTest.kt, translated.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Xunit;
using static Necessary.AndroidProbeReads;

namespace Necessary.Tests
{
    public class AndroidProbeReadsTests
    {
        private static readonly CommandResult Ran = new CommandResult(true, true, 0, string.Empty);
        private static readonly CommandResult NotStarted = new CommandResult(false, false, null, string.Empty, "IOException");
        private static readonly CommandResult TimedOut = new CommandResult(true, false, null, string.Empty);
        private static readonly CommandResult UnreadOutput = new CommandResult(true, false, 0, string.Empty, "output: IOException");

        // The location and mock-location measurements are one observation.
        private static readonly string[] Coordinates = { "latitude", "longitude", "accuracy_m", "provider" };

        private static bool IsError(JsonObject result) => (string?)result["status"] == "error";

        private static JsonObject? Unread(JsonObject result) => result["unread"] as JsonObject;

        private static IEnumerable<string> Keys(JsonObject? map) => map?.Select(member => member.Key) ?? Enumerable.Empty<string>();

        private static KeyValuePair<TKey, TValue> Pair<TKey, TValue>(TKey key, TValue value) => new KeyValuePair<TKey, TValue>(key, value);

        private static Fix MakeFix(long seconds, bool mock, double latitude, string provider = "fused", long age = 5) =>
            new Fix(latitude, 67.0, 12.0, age, seconds * 1_000_000_000L, provider, seconds * 1000, mock);

        [Fact]
        public void Mounts_unreadable_or_empty_is_no_measurement()
        {
            Assert.True(IsError(Mounts(null)));
            Assert.True(IsError(Mounts(Array.Empty<string>())));
        }

        [Fact]
        public void Mounts_read_are_measured()
        {
            var clean = Mounts(new[] { "/dev/block/dm-0 /system ext4 ro,seclabel 0 0" });
            Assert.Equal("ok", (string?)clean["status"]);
            Assert.Empty((JsonArray)clean["protected_rw_mounts"]!);
            var writable = Mounts(new[] { "/dev/block/dm-0 /system ext4 rw,seclabel 0 0", "garbage" });
            Assert.Equal(new[] { "/system:rw,seclabel" }, ((JsonArray)writable["protected_rw_mounts"]!).Select(n => (string)n!));
        }

        [Fact]
        public void Tracer_never_defaults_to_zero()
        {
            Assert.True(IsError(Tracer(null)));
            Assert.True(IsError(Tracer(Array.Empty<string>())));
            Assert.True(IsError(Tracer(new[] { "Name:\tapp", "State:\tR" })));
            Assert.True(IsError(Tracer(new[] { "TracerPid:\tnot-a-number" })));
            Assert.True(IsError(Tracer(new[] { "TracerPid:" })));
        }

        [Fact]
        public void Tracer_read_is_measured()
        {
            var clean = Tracer(new[] { "TracerPid:\t0", "Seccomp:\t2" });
            Assert.Equal(0, (int)clean["tracer_pid"]!);
            Assert.Equal(2, (int)clean["seccomp"]!);
            Assert.Equal(-1, (int)clean["no_new_privs"]!);
            Assert.Equal(4242, (int)Tracer(new[] { "TracerPid:\t4242" })["tracer_pid"]!);
        }

        [Fact]
        public void A_setting_that_threw_is_unread_not_off()
        {
            var failure = Outcome<bool>.Failure(new UnauthorizedAccessException("denied"));
            var oneLost = DeveloperSettings(failure, Outcome<bool>.Success(false));
            Assert.Equal("ok", (string?)oneLost["status"]);
            Assert.False(oneLost.ContainsKey("adb_enabled"));
            Assert.False((bool)oneLost["developer_options_enabled"]!);
            Assert.StartsWith("UnauthorizedAccessException", (string)Unread(oneLost)!["adb_enabled"]!, StringComparison.Ordinal);
            Assert.True(IsError(DeveloperSettings(failure, failure)));
            var both = DeveloperSettings(Outcome<bool>.Success(true), Outcome<bool>.Success(false));
            Assert.Null(Unread(both));
            Assert.True((bool)both["adb_enabled"]!);
        }

        [Fact]
        public void An_unanswered_su_lookup_is_not_no_su()
        {
            Assert.True(IsError(RootShell(NotStarted)));
            Assert.True(IsError(RootShell(TimedOut)));
            Assert.True(IsError(RootShell(UnreadOutput)));
            Assert.False((bool)RootShell(Ran)["su_found"]!);
            Assert.True((bool)RootShell(Ran with { Output = "/system/xbin/su\n" })["su_found"]!);
        }

        [Fact]
        public void A_property_not_read_is_unread_not_empty()
        {
            var some = SystemProperties(new[] { Pair("ro.secure", Ran with { Output = "1\n" }), Pair("ro.debuggable", NotStarted) });
            Assert.True(JsonNode.DeepEquals(new JsonObject { ["ro.secure"] = "1" }, some["properties"]));
            Assert.Contains("ro.debuggable", Keys(Unread(some)));
            Assert.True(IsError(SystemProperties(new[] { Pair("ro.secure", TimedOut) })));
        }

        [Fact]
        public void A_root_path_that_threw_is_unread_not_absent()
        {
            var some = RootFiles(
                new[]
                {
                    Pair("/system/xbin/su", Outcome<bool>.Success(true)),
                    Pair("/sbin/su", Outcome<bool>.Failure(new UnauthorizedAccessException("denied"))),
                    Pair("/data/adb/magisk", Outcome<bool>.Success(false)),
                },
                "release-keys");
            Assert.Equal(new[] { "/system/xbin/su" }, ((JsonArray)some["found_paths"]!).Select(n => (string)n!));
            Assert.Equal(new[] { "/sbin/su" }, Keys(Unread(some)));
            Assert.True(IsError(RootFiles(new[] { Pair("/sbin/su", Outcome<bool>.Failure(new IOException())) }, string.Empty)));
        }

        [Fact]
        public void A_port_that_could_not_be_tested_is_unread_not_closed()
        {
            var some = FridaPorts(new[] { Pair(27042, PortResult.Refused), Pair(27043, PortResult.Failure("SecurityException")) });
            Assert.Empty((JsonArray)some["open_ports"]!);
            Assert.Equal(new[] { "27043" }, Keys(Unread(some)));
            Assert.True(IsError(FridaPorts(new[] { Pair(27042, PortResult.Failure("SocketTimeoutException")) })));
            var open = FridaPorts(new[] { Pair(27042, PortResult.Opened), Pair(27043, PortResult.Refused) });
            Assert.Equal(new[] { 27042 }, ((JsonArray)open["open_ports"]!).Select(n => (int)n!));
            Assert.Null(Unread(open));
        }

        [Fact]
        public void Thread_names_not_read_are_unread()
        {
            var frida = new[] { "gum-js-loop" };
            var glib = new[] { "gmain" };
            Assert.True(IsError(Threads(Array.Empty<string>(), 3, frida, glib, Array.Empty<string>())));
            var some = Threads(new[] { "main", "RenderThread" }, 2, frida, glib, Array.Empty<string>());
            Assert.Equal(2, (int)some["thread_count"]!);
            Assert.Contains("thread_names", Keys(Unread(some)));
            var all = Threads(new[] { "main", "gum-js-loop" }, 0, frida, glib, Array.Empty<string>());
            Assert.Equal(new[] { "gum-js-loop" }, ((JsonArray)all["frida_threads"]!).Select(n => (string)n!));
            Assert.Null(Unread(all));
        }

        [Fact]
        public void The_apps_own_names_are_no_tools()
        {
            var tokens = new[] { "tool", "gadget" };
            const string name = "com.example.toolbox";
            const string install = "/data/app/~~Ztool==/" + name + "-Qgadget==/";
            var own = new[] { install, "/data/user/0/" + name + "/" };
            static string Line(string path) => "7a0000-7b0000 r-xp 00000000 fd:00 123  " + path;
            IReadOnlyList<string> Names(string text) => NamesIn(text, own, name, tokens);
            Assert.Empty(Names(Line(install + "base.apk")));
            Assert.Empty(Names(Line("/data/user/0/" + name + "/files/plugin.so")));
            Assert.Empty(Names("[anon:dalvik-classes.dex extracted in memory from " + install + "base.apk]"));
            Assert.Empty(Names(Line("/storage/emulated/0/Android/data/" + name + "/files/plugin.so")));

            // What lies inside the app's folders, and anything elsewhere, is read.
            Assert.Equal(tokens, Names(Line(install + "lib/arm64/libtool-gadget.so")));
            Assert.Equal(new[] { "tool" }, Names(Line("/data/local/tmp/TOOL-agent.so")));

            // An assembly of the app's, compiled ahead of time; only in the app's
            // own folders.
            Assert.Empty(Names(Line(install + "lib/arm64/libaot-Toolbox.Mobile.dll.so")));
            Assert.Equal(new[] { "tool" }, Names(Line("/data/local/tmp/libaot-Toolbox.dll.so")));
            Assert.Equal(new[] { "tool" }, Names(Line(install + "lib/arm64/libToolbox.so")));
        }

        [Fact]
        public void A_thread_named_for_the_app_names_no_tool()
        {
            var tokens = new[] { "tool" };
            var none = Array.Empty<string>();
            const string name = "com.example.toolbox";
            var main = Threads(new[] { "example.toolbox" }, 0, none, none, tokens, name);
            Assert.Empty((JsonArray)main["token_threads"]!);
            var tool = Threads(new[] { "example.toolbox", "tool-worker" }, 0, none, none, tokens, name);
            Assert.Equal(tokens, ((JsonArray)tool["token_threads"]!).Select(n => (string)n!));
        }

        [Fact]
        public void A_shells_complaint_is_no_path_to_su()
        {
            // As the collector runs it, the error stream merged, on a phone with
            // neither su nor which.
            var start = new ProcessStartInfo("/bin/sh") { RedirectStandardOutput = true, UseShellExecute = false };
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("exec 2>&1; " + RootShellLookup);
            start.Environment["PATH"] = "/nowhere";
            using var shell = Process.Start(start)!;
            var output = shell.StandardOutput.ReadToEnd();
            shell.WaitForExit();
            var lookup = RootShell(new CommandResult(true, true, shell.ExitCode, output));
            Assert.Equal(string.Empty, (string?)lookup["su_path"]);
            Assert.False((bool)lookup["su_found"]!);
        }

        [Fact]
        public void Splits_are_listed_apart_sorted_and_never_dropped()
        {
            var hash = string.Concat(Enumerable.Repeat("ab", 32));
            var (none, noneUnread) = SplitApks(Array.Empty<KeyValuePair<string, Outcome<string>>>());
            Assert.Empty(none);
            Assert.Empty(noneUnread);
            var (listed, unread) = SplitApks(new[]
            {
                Pair("split_config.xxhdpi.apk", Outcome<string>.Success(hash)),
                Pair("split_config.arm64_v8a.apk", Outcome<string>.Success(string.Concat(Enumerable.Repeat("cd", 32)))),
                Pair("split_feature.apk", Outcome<string>.Failure(new IOException("EACCES"))),
            });
            Assert.Equal(new[] { "split_config.arm64_v8a.apk", "split_config.xxhdpi.apk" }, listed.Select(n => (string)n!["name"]!));
            Assert.Equal(hash, (string?)listed[1]!["sha256"]);
            Assert.Equal(new[] { "split_apks:split_feature.apk" }, unread.Select(u => u.Key));
        }

        [Fact]
        public void Both_location_measurements_describe_the_one_captured_fix()
        {
            var real = MakeFix(1_761_300_000, mock: false, latitude: 24.86);
            var mocked = MakeFix(1_761_300_001, mock: true, latitude: 51.5);
            var reads = 0;

            // The provider alternates a real and a mocked fix on every read.
            FixRead Source()
            {
                reads++;
                return new FixRead("precise", reads % 2 == 1 ? real : mocked);
            }

            var scan = new LocationCapture(Source);
            var location = Location(scan.Value);
            var mock = MockLocation(scan.Value);
            Assert.Equal(1, reads);
            Assert.Equal(24.86, (double)location["latitude"]!);
            Assert.False((bool)mock["mock"]!);
            Assert.Equal(1_761_300_000L, (long)location["fix_time"]!);
            Assert.Equal((long)location["fix_time"]!, (long)mock["fix_time"]!);
            Assert.Equal((long)location["age_seconds"]!, (long)mock["age_seconds"]!);
            Assert.DoesNotContain(Keys(mock), key => Coordinates.Contains(key));

            // The next scan reads again, in either order, and gets one fix again.
            var next = new LocationCapture(Source);
            Assert.True((bool)MockLocation(next.Value)["mock"]!);
            Assert.Equal(51.5, (double)Location(next.Value)["latitude"]!);
            Assert.Equal(2, reads);
        }

        [Fact]
        public void The_newest_fix_of_changing_providers_is_the_one_described()
        {
            var read = NewestFix(
                "precise",
                new[]
                {
                    Pair("gps", Outcome<Fix?>.Success(MakeFix(1_761_300_000, mock: false, latitude: 24.86, provider: "gps"))),
                    Pair("network", Outcome<Fix?>.Success(MakeFix(1_761_300_009, mock: true, latitude: 51.5, provider: "network"))),
                    Pair("passive", Outcome<Fix?>.Success(null)),
                });
            var location = Location(read);
            var mock = MockLocation(read);
            Assert.Equal("network", (string?)location["provider"]);
            Assert.Equal(51.5, (double)location["latitude"]!);
            Assert.True((bool)mock["mock"]!);
            Assert.Equal((long)location["fix_time"]!, (long)mock["fix_time"]!);
        }

        [Fact]
        public void No_permission_reads_nothing()
        {
            var read = NewestFix("none", new[] { Pair("gps", Outcome<Fix?>.Success(MakeFix(1_761_300_000, mock: true, latitude: 24.86))) });
            foreach (var result in new[] { Location(read), MockLocation(read) })
            {
                Assert.True(JsonNode.DeepEquals(new JsonObject { ["status"] = "ok", ["permission"] = "none" }, result));
            }
        }

        [Fact]
        public void No_fix_is_measured_only_when_every_provider_was_read()
        {
            var none = NewestFix("approximate", new[] { Pair("network", Outcome<Fix?>.Success(null)) });
            var expected = new JsonObject { ["status"] = "ok", ["permission"] = "approximate" };
            Assert.True(JsonNode.DeepEquals(expected, MockLocation(none)));
            Assert.True(JsonNode.DeepEquals(expected, Location(none)));

            // A provider that threw -- the permission revoked mid-read -- is unread, not "no fix".
            var revoked = NewestFix(
                "precise",
                new[] { Pair("gps", Outcome<Fix?>.Failure(new UnauthorizedAccessException("revoked"))), Pair("network", Outcome<Fix?>.Success(null)) });
            Assert.Equal(new[] { "gps" }, Keys(Unread(MockLocation(revoked))));
            Assert.False(MockLocation(revoked).ContainsKey("mock"));
            var some = NewestFix(
                "precise",
                new[]
                {
                    Pair("gps", Outcome<Fix?>.Failure(new UnauthorizedAccessException("revoked"))),
                    Pair("network", Outcome<Fix?>.Success(MakeFix(1_761_300_000, mock: false, latitude: 24.86))),
                });
            Assert.False((bool)MockLocation(some)["mock"]!);
            Assert.Equal(new[] { "gps" }, Keys(Unread(Location(some))));
            var all = NewestFix("precise", new[] { Pair("gps", Outcome<Fix?>.Failure(new UnauthorizedAccessException("revoked"))) });
            Assert.True(IsError(Location(all)));
            Assert.True(IsError(MockLocation(all)));
        }

        [Fact]
        public void A_stale_fix_is_one_age_in_both()
        {
            var read = new FixRead("precise", MakeFix(1_761_296_400, mock: false, latitude: 24.86, age: 3600));
            Assert.Equal(3600L, (long)Location(read)["age_seconds"]!);
            Assert.Equal(3600L, (long)MockLocation(read)["age_seconds"]!);
        }

        [Fact]
        public void A_read_that_threw_fails_both_and_is_not_retried()
        {
            var reads = 0;
            var scan = new LocationCapture(() =>
            {
                reads++;
                if (reads == 1)
                {
                    throw new InvalidOperationException("provider gone");
                }

                return new FixRead("precise", MakeFix(1_761_300_000, mock: false, latitude: 24.86));
            });
            Assert.True(IsError(Location(scan.Value)));
            Assert.True(IsError(MockLocation(scan.Value)));
            Assert.Equal(1, reads);
        }
    }
}
