// The reinstall hint's bytes: what a backend keys and stores to link
// reinstalls, so a phone's hint must not change when the package's code does.
// The digests are the Flutter plugin's, computed apart by Python's hashlib.
using System.Threading.Tasks;
using Xunit;

namespace Necessary.Tests
{
    public class ReinstallHintTests
    {
        [Fact]
        public async Task Android_android_id_trimmed_and_in_lower_case()
        {
            var hint = await new Reader(NativePlatform.Android, " 9774D56D682E549C ").ReadAsync();
            Assert.Equal("android_id_sha256", hint?.Kind);
            Assert.Equal("fe8339ee3d9adfd02d18c670d45a27b139a58455c395e2972a14529d76316d24", hint?.Value);
        }

        [Fact]
        public async Task Ios_the_identifier_for_vendor_in_lower_case()
        {
            var hint = await new Reader(NativePlatform.Ios, "6F0C2A1E-7B3D-4C5E-9F8A-1B2C3D4E5F60").ReadAsync();
            Assert.Equal("idfv_sha256", hint?.Kind);
            Assert.Equal("a67ac309e7a6b8cac7fbf58e8d964b07bd525408624d1957f3a8fe7c670461e5", hint?.Value);
        }

        [Fact]
        public async Task No_identifier_or_another_platform_no_hint()
        {
            Assert.Null(await new Reader(NativePlatform.Android, string.Empty).ReadAsync());
            Assert.Null(await new Reader(NativePlatform.Android, null).ReadAsync());
            Assert.Null(await new Reader("linux", "9774d56d682e549c").ReadAsync());
        }

        [Fact]
        public async Task A_native_side_that_fails_gives_no_hint_and_stops_nothing()
        {
            Assert.Null(await new Failing().ReadAsync());
        }

        private sealed class Reader : ReinstallHintReader
        {
            private readonly string platform;
            private readonly string? identifier;

            public Reader(string platform, string? identifier)
            {
                this.platform = platform;
                this.identifier = identifier;
            }

            protected internal override string Platform => platform;

            protected internal override Task<string?> IdentifierAsync() => Task.FromResult(identifier);
        }

        private sealed class Failing : ReinstallHintReader
        {
            protected internal override string Platform => NativePlatform.Android;

            protected internal override Task<string?> IdentifierAsync() =>
                Task.FromException<string?>(new NativeKeyException("NATIVE_KEY_PLUGIN_MISSING", "no native side"));
        }
    }
}
