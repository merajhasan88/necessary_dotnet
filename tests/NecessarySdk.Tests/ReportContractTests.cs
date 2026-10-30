// The package's reports against the published measurement contract: from the
// collector answer in each sample of contract/report-1/android-8-ios-5/, the
// package builds that sample's report -- every member but the phone's clock.
// The package judges nothing: an invalid or refused sample is built just as
// faithfully.
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Xunit;

namespace Necessary.Tests
{
    public class ReportContractTests
    {
        private const string Samples = "contract/report-1/android-8-ios-5/samples";

        public static IEnumerable<object[]> SampleFiles() =>
            Directory.GetFiles(RepositoryFiles.Directory(Samples), "*.json")
                .OrderBy(path => path, System.StringComparer.Ordinal)
                .Select(path => new object[] { Path.GetFileName(path) });

        [Fact]
        public void The_contract_has_its_samples() => Assert.Equal(11, SampleFiles().Count());

        [Theory]
        [MemberData(nameof(SampleFiles))]
        public async Task Each_sample_is_built_as_the_contract_shows_it(string file)
        {
            var sample = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(RepositoryFiles.Directory(Samples), file)))!;
            var expected = (JsonObject)sample["report"]!;
            var plan = (JsonObject)sample["plan"]!;
            var built = await Reports.CollectReportAsync(
                ScanChallenge.FromJson(new JsonObject
                {
                    ["challenge_id"] = expected["challenge_id"]!.DeepClone(),
                    ["nonce"] = expected["challenge_nonce"]!.DeepClone(),
                    ["platform"] = expected["platform"]!.DeepClone(),
                    ["required_probes"] = plan["required_probes"]?.DeepClone(),
                    ["optional_probes"] = plan["optional_probes"]?.DeepClone(),
                }),
                new InstallationIdentity(
                    (string)expected["installation_id"]!,
                    new Key(),
                    new NativeKeyMetadata(new JsonObject(), "ES256", "sample", "sample", "software", false, false, "der", false)),
                new Recorded(expected),
                ((JsonArray)expected["enabled_measurements"]!).Select(n => (string)n!).ToList());
            Assert.NotNull(Json.Integer(built.Report["collected_at"]));
            var withClock = (JsonObject)built.Report.DeepClone();
            withClock["collected_at"] = expected["collected_at"]!.DeepClone();
            Assert.True(JsonNode.DeepEquals(expected, withClock), file);

            // The payload is the report, as signed.
            var signed = JsonNode.Parse(Encoding.UTF8.GetString(Wire.DecodeBase64Url(built.Payload)));
            Assert.True(JsonNode.DeepEquals(built.Report, signed), file);
        }

        private sealed class Key : INativeInstallationKey
        {
            public Task<NativeKeyMetadata> GetOrCreateKeyAsync() => throw new System.NotImplementedException();

            public Task<string> SignPayloadAsync(string payloadBase64Url) => Task.FromResult("signed");

            public Task DeleteKeyAsync() => Task.CompletedTask;
        }

        /// <summary>Answers what the sample's collector answered.</summary>
        private sealed class Recorded : INativeIntegrityCollector
        {
            private readonly JsonObject report;

            public Recorded(JsonObject report)
            {
                this.report = report;
            }

            public Task<JsonObject> CollectAsync(
                IReadOnlyList<string> requiredProbes,
                string challengeNonce,
                IReadOnlyList<string> enabledMeasurements,
                IReadOnlyList<string> optionalProbes) =>
                Task.FromResult(new JsonObject
                {
                    ["platform"] = report["platform"]!.DeepClone(),
                    ["challenge_nonce_echo"] = challengeNonce,
                    ["collector_version"] = report["collector_version"]!.DeepClone(),
                    ["probes"] = report["probe_results"]!.DeepClone(),
                });

            public Task<string> RequestLocationPermissionAsync() => Task.FromResult("none");
        }
    }
}
