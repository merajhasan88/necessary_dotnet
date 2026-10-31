// The bytes Dart's jsonEncode writes -- the messages' reference -- and
// the .NET encoder's, held equal: every contract sample's report, strings with
// escapes, characters beyond ASCII and outside the BMP, and doubles at the
// edges of Dart's decimal and exponent notations. The fixture was written by
// Dart itself (tools/dart_json_fixture.dart).
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Xunit;

namespace Necessary.Tests
{
    public class DartJsonTests
    {
        private static readonly JsonObject Fixture =
            (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dart_json_fixture.json")))!;

        public static IEnumerable<object[]> Cases() =>
            ((JsonArray)Fixture["cases"]!).Select((item, index) => new object[] { index, (string)item!["name"]! });

        public static IEnumerable<object[]> Doubles() =>
            ((JsonArray)Fixture["doubles"]!).Select(item => new object[] { (string)item!["bits"]!, (string)item["dart"]! });

        [Theory]
        [MemberData(nameof(Cases))]
        public void Decoded_and_encoded_again_the_bytes_are_dart_s(int index, string name)
        {
            var dart = (string)Fixture["cases"]![index]!["dart"]!;
            Assert.True(name.Length > 0);
            Assert.Equal(dart, DartJson.Encode(JsonNode.Parse(dart)));
        }

        [Theory]
        [MemberData(nameof(Doubles))]
        public void A_double_is_written_as_dart_writes_it(string bits, string dart)
        {
            // Dart's ints are signed: a pattern with its top bit set is written negative.
            var negative = bits.StartsWith("-", StringComparison.Ordinal);
            var magnitude = ulong.Parse(negative ? bits.Substring(1) : bits, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var pattern = unchecked(negative ? -(long)magnitude : (long)magnitude);
            var value = BitConverter.Int64BitsToDouble(pattern);
            Assert.Equal(dart, DartJson.Encode(JsonValue.Create(value)));
        }

        [Fact]
        public void Values_built_in_dotnet_are_written_as_dart_writes_them()
        {
            var built = new JsonObject
            {
                ["s"] = "caf\u00e9 / \u20ac \"x\" a/b\\c \t\u0001 \U0001F600 <>&'",
                ["i"] = 5,
                ["l"] = 9007199254740993L,
                ["d"] = 5.0,
                ["b"] = true,
                ["n"] = null,
                ["a"] = new JsonArray { 1, 1.5, "x" },
            };
            Assert.Equal(
                "{\"s\":\"caf\u00e9 / \u20ac \\\"x\\\" a/b\\\\c \\t\\u0001 \U0001F600 <>&'\",\"i\":5,\"l\":9007199254740993,"
                + "\"d\":5.0,\"b\":true,\"n\":null,\"a\":[1,1.5,\"x\"]}",
                DartJson.Encode(built));
        }

        [Fact]
        public void A_lone_surrogate_is_escaped_as_dart_escapes_it()
        {
            Assert.Equal("\"a\\ud800b\"", DartJson.Encode(JsonValue.Create("a\ud800b")));
            Assert.Equal("\"\\udc00\"", DartJson.Encode(JsonValue.Create("\udc00")));
        }

        [Fact]
        public void Nan_and_infinity_are_refused_as_dart_refuses_them()
        {
            Assert.Throws<NotSupportedException>(() => DartJson.Encode(JsonValue.Create(double.NaN)));
            Assert.Throws<NotSupportedException>(() => DartJson.Encode(JsonValue.Create(double.PositiveInfinity)));
        }
    }
}
