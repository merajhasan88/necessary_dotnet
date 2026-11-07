// The runtime measurement: what was read is said, and what was not is unread,
// never a clean value.
using System;
using System.Linq;
using System.Text.Json.Nodes;
using Xunit;
using static Necessary.RuntimeReads;

namespace Necessary.Tests
{
    public class RuntimeReadsTests
    {
        private static readonly Version Runtime9 = new Version(9, 0, 22);

        private static string[] Unread(JsonObject result) =>
            (result["unread"] as JsonObject)?.Select(member => member.Key).ToArray() ?? Array.Empty<string>();

        [Theory]
        [InlineData(0x01001000u, "1.1.0")]
        [InlineData(0x01001001u, "1.1.1")]
        [InlineData(0x01002001u, "1.2.1")]
        [InlineData(0x0100000Au, "1.0.10")]
        [InlineData(0x02ABCDEFu, "2.2748.3567")]
        public void The_decoders_version_word_reads_as_text(uint word, string text) =>
            Assert.Equal(text, DecoderVersion(word));

        [Fact]
        public void Every_value_read_is_said_with_nothing_unread()
        {
            var result = Runtime(Runtime9, true, 0x01001001u);
            Assert.Equal("ok", (string?)result["status"]);
            Assert.Equal("9.0.22", (string?)result["runtime_version"]);
            Assert.True((bool)result["brotli_decoder_present"]!);
            Assert.Equal("1.1.1", (string?)result["brotli_decoder_version"]);
            Assert.Empty(Unread(result));
        }

        [Fact]
        public void An_app_with_no_decoder_says_so_and_has_no_version_to_read()
        {
            var result = Runtime(Runtime9, false, null);
            Assert.False((bool)result["brotli_decoder_present"]!);
            Assert.False(result.ContainsKey("brotli_decoder_version"));
            Assert.Empty(Unread(result));
        }

        [Fact]
        public void A_decoder_that_gives_no_version_is_unread_never_absent()
        {
            var result = Runtime(Runtime9, true, null);
            Assert.True((bool)result["brotli_decoder_present"]!);
            Assert.Equal(new[] { "brotli_decoder_version" }, Unread(result));
        }

        [Fact]
        public void A_version_read_from_the_decoder_shows_it_is_there_whatever_the_packaging_says()
        {
            var result = Runtime(Runtime9, null, 0x01001000u);
            Assert.True((bool)result["brotli_decoder_present"]!);
            Assert.Empty(Unread(result));
        }

        [Fact]
        public void A_runtime_that_cannot_say_its_version_is_unread()
        {
            foreach (var unknown in new[] { null, new Version() })
            {
                var result = Runtime(unknown, false, null);
                Assert.False(result.ContainsKey("runtime_version"));
                Assert.Equal(new[] { "runtime_version" }, Unread(result));
            }
        }

        [Fact]
        public void Packaging_that_does_not_show_the_decoder_is_unread()
        {
            var result = Runtime(Runtime9, null, null);
            Assert.False(result.ContainsKey("brotli_decoder_present"));
            Assert.Equal(new[] { "brotli_decoder_present" }, Unread(result));
        }

        [Fact]
        public void Nothing_read_is_an_error()
        {
            Assert.Equal("error", (string?)Runtime(new Version(), null, null)["status"]);
        }
    }
}
