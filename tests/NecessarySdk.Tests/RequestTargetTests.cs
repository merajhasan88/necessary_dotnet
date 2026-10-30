// A request's target, split and normalized as the Flutter plugin's Uri.parse
// does: the path and query a proof signs and the transport sends. The expected
// values were written by Dart itself (tools/dart_json_fixture.dart).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Xunit;

namespace Necessary.Tests
{
    public class RequestTargetTests
    {
        private static readonly JsonArray Targets =
            (JsonArray)JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dart_json_fixture.json")))!["targets"]!;

        public static IEnumerable<object[]> Cases() =>
            Targets.Select(item => new object[] { (string)item!["target"]!, (string)item["path"]!, (string)item["query"]! });

        [Theory]
        [MemberData(nameof(Cases))]
        public void Split_as_dart_splits_it(string target, string path, string query)
        {
            var parsed = RequestTarget.Parse(target);
            Assert.Equal(path, parsed.Path);
            Assert.Equal(query, parsed.Query);
        }

        [Fact]
        public void What_is_sent_is_what_is_signed()
        {
            Assert.Equal("/v1/x?a=b", RequestTarget.Parse("/v1/x?a=b#frag").PathAndQuery);
            Assert.Equal("/v1/x", RequestTarget.Parse("/v1/x").PathAndQuery);
            Assert.Equal("/v1/x?", RequestTarget.Parse("/v1/x?").PathAndQuery);
        }
    }
}
