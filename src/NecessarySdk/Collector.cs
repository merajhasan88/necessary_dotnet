using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// The native integrity collector: measures what a challenge asks for and the
    /// app enabled, and nothing else.
    /// </summary>
    public interface INativeIntegrityCollector
    {
        /// <summary>
        /// Measures every probe in <paramref name="requiredProbes"/>, the probes
        /// every report carries, and of <paramref name="optionalProbes"/> -- the
        /// personal measurements the backend asks for -- those this platform
        /// knows; each personal measurement is taken only when it is also in
        /// <paramref name="enabledMeasurements"/>, and answers
        /// <c>not_enabled</c> otherwise.
        /// </summary>
        /// <returns>
        /// <c>platform</c>, <c>challenge_nonce_echo</c> (the nonce given),
        /// <c>collector_version</c> and <c>probes</c>: one object per
        /// measurement, as the contract describes it.
        /// </returns>
        Task<JsonObject> CollectAsync(
            IReadOnlyList<string> requiredProbes,
            string challengeNonce,
            IReadOnlyList<string> enabledMeasurements,
            IReadOnlyList<string> optionalProbes);

        /// <summary>
        /// Asks the person for the OS location permission and returns what the
        /// app now holds: <c>precise</c>, <c>approximate</c> or <c>none</c>. Only
        /// the app asks, from its own screen; a scan never prompts.
        /// </summary>
        Task<string> RequestLocationPermissionAsync();
    }
}
