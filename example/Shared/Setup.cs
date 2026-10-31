// How an app sets up the package: one DeviceTrust for its backend, with the
// options it chooses. Everything else in the example uses what is made here.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Necessary.Example
{
    public static class ExampleSetup
    {
        /// <summary>
        /// The backends to choose among, by name: the build's NecessaryBackends
        /// (<c>Name=https://…;Other=https://…</c>), or its one NecessaryBackendUrl
        /// -- MSBuild properties.
        /// </summary>
        public static IReadOnlyList<KeyValuePair<string, string>> Backends { get; } = ReadBackends();

        /// <summary>Device trust against the backend at <paramref name="baseUrl"/>.</summary>
        public static DeviceTrust CreateDeviceTrust(string baseUrl, IEnumerable<PersonalMeasurement>? personalMeasurements = null) =>
            new DeviceTrust(
                baseUrl,

                // The personal measurements this app allows -- none unless it
                // names them. The backend asks for those it needs, and only what
                // both name is measured. They can change while the app runs:
                // trust.PersonalMeasurements = new[] { ... }.
                personalMeasurements: personalMeasurements,

                // Step-up: a second key, which the person unlocks to approve one
                // request. factor "passcode" (the phone's PIN, pattern or password)
                // or "biometric"; mode "per_use", or "windowed" with windowSeconds
                // (Android only). Leave it out for no step-up.
                stepUp: new StepUpOptions(factor: "passcode", mode: "per_use"),

                // The app PIN, which the backend checks for one request. Its two
                // calls default to the guide's paths. Leave it out for no app PIN.
                appPin: new AppPinOptions());

        internal static IReadOnlyList<KeyValuePair<string, string>> ParseBackends(string? list, string? url)
        {
            if (string.IsNullOrWhiteSpace(list))
            {
                return new[] { new KeyValuePair<string, string>("Sample", string.IsNullOrWhiteSpace(url) ? "http://10.0.2.2:8787" : url!.Trim()) };
            }

            return list!.Split(';')
                .Where(entry => entry.Contains('=', StringComparison.Ordinal))
                .Select(entry => new KeyValuePair<string, string>(
                    entry.Substring(0, entry.IndexOf('=', StringComparison.Ordinal)).Trim(),
                    entry.Substring(entry.IndexOf('=', StringComparison.Ordinal) + 1).Trim()))
                .ToList();
        }

        private static IReadOnlyList<KeyValuePair<string, string>> ReadBackends()
        {
            var metadata = typeof(ExampleSetup).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().ToList();
            string? Value(string key) => metadata.FirstOrDefault(item => item.Key == key)?.Value;
            return ParseBackends(Value("NecessaryBackends"), Value("NecessaryBackendUrl"));
        }
    }
}
