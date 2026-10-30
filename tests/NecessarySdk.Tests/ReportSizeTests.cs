// The report-size rule: a report a backend would refuse for its size is never
// sent. The lists the contract lets a collector shorten are halved, and say
// truncated, until it fits; anything else is an error naming the limit --
// nothing is cut silently.
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace Necessary.Tests
{
    public class ReportSizeTests
    {
        private static JsonObject Report(JsonObject probes) => new JsonObject
        {
            ["challenge_id"] = "c",
            ["challenge_nonce"] = "n",
            ["installation_id"] = "i",
            ["platform"] = "android",
            ["collector_version"] = 8,
            ["collected_at"] = 1,
            ["probe_results"] = probes,
            ["enabled_measurements"] = new JsonArray { "accessibility" },
            ["version"] = 1,
        };

        private static int Bytes(JsonObject report) => Encoding.UTF8.GetByteCount(DartJson.Encode(report));

        private static JsonObject Service(int i) => new JsonObject
        {
            ["package"] = "com.example.service.with.a.long.name.number" + i,
            ["service"] = "com.example.service.with.a.long.name.number" + i + ".Service",
            ["system"] = false,
            ["installer"] = "com.android.vending",
        };

        [Fact]
        public void A_report_that_fits_is_sent_as_it_is()
        {
            var report = Report(new JsonObject
            {
                ["accessibility"] = new JsonObject
                {
                    ["status"] = "ok",
                    ["services"] = new JsonArray { Service(1) },
                    ["truncated"] = false,
                },
            });
            Assert.True(JsonNode.DeepEquals(report, Reports.FitReport(report)));
        }

        [Fact]
        public void A_list_the_contract_lets_shorten_is_halved_and_says_so_until_it_fits()
        {
            var services = new JsonArray();
            for (var i = 0; i < 2000; i++)
            {
                services.Add(Service(i));
            }

            var report = Report(new JsonObject
            {
                ["accessibility"] = new JsonObject
                {
                    ["status"] = "ok",
                    ["services"] = services,
                    ["settings_only"] = new JsonArray(),
                    ["truncated"] = false,
                },
                ["device"] = new JsonObject { ["status"] = "ok", ["model"] = "m" },
            });
            Assert.True(Bytes(report) > Reports.ReportByteLimit);
            var fitted = Reports.FitReport(report);
            Assert.True(Bytes(fitted) <= Reports.ReportByteLimit);
            var accessibility = fitted["probe_results"]!["accessibility"]!;
            Assert.True((bool)accessibility["truncated"]!);
            Assert.True(((JsonArray)accessibility["services"]!).Count < 2000);
            Assert.True(JsonNode.DeepEquals(
                new JsonObject { ["status"] = "ok", ["model"] = "m" },
                fitted["probe_results"]!["device"]));
            // The collector's answer itself is left as it came.
            Assert.Equal(2000, ((JsonArray)report["probe_results"]!["accessibility"]!["services"]!).Count);
        }

        [Fact]
        public void Anything_else_too_large_is_an_error_naming_the_limit()
        {
            var report = Report(new JsonObject
            {
                ["device"] = new JsonObject
                {
                    ["status"] = "ok",
                    ["model"] = new string('x', Reports.ReportByteLimit + 1),
                },
            });
            var error = Assert.Throws<ApiException>(() => Reports.FitReport(report));
            Assert.Equal("report_too_large", error.Code);
            Assert.Equal(Reports.ReportByteLimit, (int)error.Details!["limit"]!);
        }
    }
}
