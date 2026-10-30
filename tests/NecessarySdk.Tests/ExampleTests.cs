// The example app's screen content, platform-neutral: every measurement each
// contract sample carries is listed with its status, the hooks, gadgets and
// memory changes first, each opening to its fields; the personal measurements
// switched on are shown as the code that does it; the backends named at build
// time are offered by name. The plugin example's measurements_test and
// app_test, translated to what the shared code decides.
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Necessary.Example;
using Xunit;

namespace Necessary.Tests
{
    public class ExampleTests
    {
        private const string Samples = "contract/report-1/android-8-ios-5/samples";

        public static IEnumerable<object[]> SampleFiles() =>
            Directory.GetFiles(RepositoryFiles.Directory(Samples), "*.json")
                .OrderBy(path => path, System.StringComparer.Ordinal)
                .Select(path => new object[] { Path.GetFileName(path) });

        [Theory]
        [MemberData(nameof(SampleFiles))]
        public void Every_measurement_of_a_sample_is_listed_the_hooks_first_each_with_its_fields(string file)
        {
            var sample = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(RepositoryFiles.Directory(Samples), file)))!;
            var plan = (JsonObject)sample["plan"]!;
            var report = (JsonObject)sample["report"]!;
            var results = (JsonObject)report["probe_results"]!;
            var platform = (string)report["platform"]!;
            var groups = Example.Measurements.Groups(
                platform,
                ((JsonArray)plan["required_probes"]!).Select(n => (string)n!).ToList(),
                ((JsonArray)plan["optional_probes"]!).Select(n => (string)n!).ToList(),
                results,
                ((JsonArray)report["enabled_measurements"]!).Select(n => (string)n!).ToList());
            var tiles = groups.SelectMany(group => group.Tiles).ToList();
            foreach (var (name, _) in results)
            {
                Assert.Single(tiles, tile => tile.Info.Name == name);
            }

            Assert.Equal(Example.Measurements.Title(MeasurementGroup.Hooks), groups[0].Title);
            var catalog = platform == "ios" ? Example.Measurements.Ios : Example.Measurements.Android;
            foreach (var info in catalog.Where(info => info.Group == MeasurementGroup.Hooks))
            {
                Assert.Contains(groups[0].Tiles, tile => tile.Info.Name == info.Name);
            }

            foreach (var (name, value) in results)
            {
                var fields = ((JsonObject)value!).Select(member => member.Key).Where(key => key != "status").ToList();
                if (fields.Count > 0)
                {
                    Assert.Equal(fields[0], tiles.Single(tile => tile.Info.Name == name).Fields[0].Name);
                }
            }
        }

        [Fact]
        public void The_personal_measurements_switched_on_are_shown_as_code()
        {
            Assert.Equal("trust.PersonalMeasurements = Array.Empty<PersonalMeasurement>();", Example.Measurements.PersonalCode(new PersonalMeasurement[0]));
            Assert.Contains("    PersonalMeasurement.MockLocation,", Example.Measurements.PersonalCode(PersonalMeasurements.All.ToList()), System.StringComparison.Ordinal);
        }

        [Fact]
        public void The_backends_named_at_build_time_are_offered_by_name()
        {
            var two = ExampleSetup.ParseBackends("Python=https://a.example/p;TypeScript=https://a.example/t", null);
            Assert.Equal(new[] { "Python", "TypeScript" }, two.Select(entry => entry.Key));
            Assert.Equal("https://a.example/t", two[1].Value);
            Assert.Equal("http://10.0.2.2:8787", Assert.Single(ExampleSetup.ParseBackends(null, null)).Value);
            Assert.Equal("https://one.example", Assert.Single(ExampleSetup.ParseBackends(string.Empty, "https://one.example")).Value);
        }
    }
}
