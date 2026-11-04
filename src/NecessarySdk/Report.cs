using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>A challenge for a scan, as your backend sent it.</summary>
    public sealed class ScanChallenge
    {
        /// <summary>A challenge.</summary>
        public ScanChallenge(
            string challengeId,
            string nonce,
            string platform,
            IReadOnlyList<string> requiredProbes,
            IReadOnlyList<string> optionalProbes,
            JsonObject answer)
        {
            ChallengeId = challengeId;
            Nonce = nonce;
            Platform = platform;
            RequiredProbes = requiredProbes;
            OptionalProbes = optionalProbes;
            Answer = answer;
        }

        /// <summary>The challenge's ID.</summary>
        public string ChallengeId { get; }

        /// <summary>Its nonce, as sent.</summary>
        public string Nonce { get; }

        /// <summary>The installation's platform.</summary>
        public string Platform { get; }

        /// <summary>The measurements the report must answer.</summary>
        public IReadOnlyList<string> RequiredProbes { get; }

        /// <summary>
        /// The personal measurements asked for, answered only where the app
        /// enabled them; none from a backend that names none.
        /// </summary>
        public IReadOnlyList<string> OptionalProbes { get; }

        /// <summary>The challenge whole.</summary>
        public JsonObject Answer { get; }

        /// <summary>Reads your backend's challenge.</summary>
        public static ScanChallenge FromJson(JsonObject value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            static IReadOnlyList<string> Names(JsonNode? list) =>
                list is JsonArray items
                    ? items.Select(item => Json.String(item) ?? (item is null ? "null" : item.ToJsonString())).ToList()
                    : (IReadOnlyList<string>)Array.Empty<string>();

            return new ScanChallenge(
                Json.AnswerText(value, "challenge_id"),
                Json.AnswerText(value, "nonce"),
                Json.AnswerText(value, "platform"),
                Names(value["required_probes"]),
                Names(value["optional_probes"]),
                value);
        }
    }

    /// <summary>A report as the installation key signed it.</summary>
    public sealed class SignedReport
    {
        /// <summary>A signed report.</summary>
        public SignedReport(JsonObject report, string payload, string signature)
        {
            Report = report;
            Payload = payload;
            Signature = signature;
        }

        /// <summary>The report, as signed.</summary>
        public JsonObject Report { get; }

        /// <summary><c>report_payload</c>: the base64url of the report's JSON bytes.</summary>
        public string Payload { get; }

        /// <summary><c>report_signature</c>.</summary>
        public string Signature { get; }

        /// <summary>The body that sends it.</summary>
        public JsonObject ToJson() => new JsonObject
        {
            ["report_payload"] = Payload,
            ["report_signature"] = Signature,
        };
    }

    /// <summary>The scan (the public guide, section 2): the report the installation key signs.</summary>
    public static class Reports
    {
        /// <summary>The most a backend takes: a report of 65,536 bytes of JSON (the measurement contract, section 1).</summary>
        public const int ReportByteLimit = 65536;

        /// <summary>
        /// The lists a report may shorten, by measurement -- each beside the
        /// <c>truncated</c> flag that says the phone had more (the measurement
        /// contract, section 6).
        /// </summary>
        public static IReadOnlyList<KeyValuePair<string, string[]>> ShortenableLists { get; } = new[]
        {
            new KeyValuePair<string, string[]>("accessibility", new[] { "services", "settings_only" }),
            new KeyValuePair<string, string[]>("notification_access", new[] { "listeners" }),
            new KeyValuePair<string, string[]>("other_access", new[] { "device_admins", "remote_access_apps" }),
        };

        /// <summary>
        /// <paramref name="report"/> made to fit <see cref="ReportByteLimit"/>:
        /// the longest list it may shorten is halved, and marked
        /// <c>truncated</c>, until it fits. A report that cannot fit is never cut
        /// anywhere else: the answer is an error naming the limit. The report
        /// given is left as it came.
        /// </summary>
        public static JsonObject FitReport(JsonObject report)
        {
            if (report is null)
            {
                throw new ArgumentNullException(nameof(report));
            }

            var fitted = (JsonObject)report.DeepClone();
            var probes = fitted["probe_results"] as JsonObject
                ?? throw new InvalidCastException("The report's probe_results is not an object.");
            for (var bytes = Size(fitted); bytes > ReportByteLimit; bytes = Size(fitted))
            {
                string? probe = null;
                string? field = null;
                var longest = 0;
                foreach (var entry in ShortenableLists)
                {
                    var result = probes[entry.Key] as JsonObject;
                    foreach (var list in entry.Value)
                    {
                        if (result?[list] is JsonArray items && items.Count > longest)
                        {
                            probe = entry.Key;
                            field = list;
                            longest = items.Count;
                        }
                    }
                }

                if (probe is null || field is null)
                {
                    throw new ApiException(
                        "The report would be " + bytes.ToString(CultureInfo.InvariantCulture)
                        + " bytes; a backend takes at most " + ReportByteLimit.ToString(CultureInfo.InvariantCulture) + ".",
                        code: "report_too_large",
                        details: new JsonObject { ["bytes"] = bytes, ["limit"] = ReportByteLimit });
                }

                var shortened = (JsonObject)probes[probe]!;
                var kept = (JsonArray)shortened[field]!;
                var half = new JsonArray();
                for (var i = 0; i < longest / 2; i++)
                {
                    half.Add(kept[i]?.DeepClone());
                }

                shortened[field] = half;
                shortened["truncated"] = true;
            }

            return fitted;
        }

        /// <summary>
        /// Measures what <paramref name="challenge"/> asks for -- and, of the
        /// personal measurements it asks for, those in
        /// <paramref name="enabledMeasurements"/> -- and signs the report with
        /// <paramref name="identity"/>'s key.
        /// </summary>
        public static async Task<SignedReport> CollectReportAsync(
            ScanChallenge challenge,
            InstallationIdentity identity,
            INativeIntegrityCollector collector,
            IReadOnlyList<string> enabledMeasurements)
        {
            if (challenge is null)
            {
                throw new ArgumentNullException(nameof(challenge));
            }

            if (identity is null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (collector is null)
            {
                throw new ArgumentNullException(nameof(collector));
            }

            var native = await collector.CollectAsync(
                challenge.RequiredProbes,
                challenge.Nonce,
                enabledMeasurements,
                challenge.OptionalProbes);
            if (native["probes"] is not JsonObject probes)
            {
                throw new ApiException("The native collector returned no probe map.", code: "invalid_native_integrity_result");
            }

            if (Json.String(native["platform"]) != challenge.Platform
                || Json.String(native["challenge_nonce_echo"]) != challenge.Nonce)
            {
                throw new ApiException(
                    "The native integrity response did not match the server challenge.",
                    code: "integrity_challenge_binding_failed");
            }

            var version = native["collector_version"] is null
                ? 1
                : (long)Math.Truncate(Json.Number(native["collector_version"])
                    ?? throw new InvalidCastException("The native collector_version is not a number."));
            var enabled = new JsonArray();
            foreach (var name in enabledMeasurements)
            {
                enabled.Add(name);
            }

            var report = FitReport(new JsonObject
            {
                ["challenge_id"] = challenge.ChallengeId,
                ["challenge_nonce"] = challenge.Nonce,
                ["installation_id"] = identity.InstallationId,
                ["platform"] = challenge.Platform,
                ["collector_version"] = version,
                ["collected_at"] = Wire.UnixSeconds(),
                ["probe_results"] = probes.DeepClone(),

                // The personal measurements this app enabled, whether or not this
                // scan asked for them.
                ["enabled_measurements"] = enabled,
                ["version"] = 1,
            });
            var payload = Wire.Base64UrlNoPadding(Encoding.UTF8.GetBytes(DartJson.Encode(report)));
            return new SignedReport(report, payload, await identity.SignPayloadAsync(payload));
        }

        private static int Size(JsonObject report) => Encoding.UTF8.GetByteCount(DartJson.Encode(report));
    }
}
