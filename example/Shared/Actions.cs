// What the screen runs: each action of a section, and how the backend answered
// it -- with a check when the backend did what it should, and a cross when it
// did not. Shared by the Android and iOS screens.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary.Example
{
    /// <summary>What a backend that makes the guide's checks does with a request.</summary>
    public enum Expect
    {
        Accepted,
        Refused,
    }

    /// <summary>One action's result as shown: <see cref="AsExpected"/> when the backend did what <see cref="Expect"/> says.</summary>
    public sealed record Outcome(string Action, string Text, bool AsExpected);

    public sealed class ExampleSession
    {
        private DeviceTrust trust;

        public ExampleSession()
        {
            BackendName = ExampleSetup.Backends[0].Key;
            trust = ExampleSetup.CreateDeviceTrust(ExampleSetup.Backends[0].Value);
            Api = new SampleApi(trust);
        }

        public DeviceTrust Trust => trust;

        public SampleApi Api { get; private set; }

        public string BackendName { get; private set; }

        public string BackendUrl => ExampleSetup.Backends.First(entry => entry.Key == BackendName).Value;

        public ScanResult? LastScan { get; private set; }

        public string? LocationPermission { get; private set; }

        public Dictionary<string, Outcome> Latest { get; } = new Dictionary<string, Outcome>();

        public List<Outcome> Log { get; } = new List<Outcome>();

        /// <summary>Another backend: the same key, an installation of its own there, and the same personal measurements.</summary>
        public void Choose(string name)
        {
            var enabled = trust.PersonalMeasurements;
            trust.Close();
            BackendName = name;
            trust = ExampleSetup.CreateDeviceTrust(BackendUrl, enabled);
            Api = new SampleApi(trust);
            LastScan = null;
            Latest.Clear();
        }

        /// <summary>Runs one action of <paramref name="section"/> and keeps how the backend answered it.</summary>
        public async Task<Outcome> RunAsync(string section, string action, Func<Task<string>> step, Expect expect = Expect.Accepted)
        {
            Outcome outcome;
            try
            {
                var answer = await step();
                outcome = expect == Expect.Accepted
                    ? new Outcome(action, answer, true)
                    : new Outcome(action, "Accepted, but a backend should refuse this: " + answer, false);
            }
            catch (ApiException error)
            {
                var refusal = ((error.StatusCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty) + " " + (error.Code ?? string.Empty)).Trim();

                // A session the backend no longer takes says nothing of the check
                // a request was made wrong to test: the sample's session lasts ten
                // minutes.
                var sessionGone = error.Code == "expired_token" || error.Code == "not_signed_in";
                outcome = expect == Expect.Refused && !sessionGone
                    ? new Outcome(action, "Refused, as it should be: " + refusal, true)
                    : new Outcome(
                        action,
                        sessionGone
                            ? "Refused: " + refusal + ". The session is no longer valid: sign in again."
                            : "Refused: " + refusal + ". " + error.Message,
                        false);
            }
            catch (NativeKeyException error)
            {
                outcome = new Outcome(action, "The phone said " + error.Code + ": " + error.Message, false);
            }
#pragma warning disable CA1031 // Whatever failed is shown, as the Flutter example shows it.
            catch (Exception error)
#pragma warning restore CA1031
            {
                outcome = new Outcome(action, error.Message, false);
            }

            // Also to the device log (logcat on Android), for whoever runs a test.
            Console.WriteLine("EXAMPLE: [" + BackendName + "] " + action + " — " + outcome.Text);
            Latest[section] = outcome;
            Log.Insert(0, outcome);
            return outcome;
        }

        // --- The installation.
        public async Task<string> StartAsync()
        {
            var identity = await trust.StartAsync();
            var stepUpOff = trust.StepUpUnavailable;
            return "Installation " + identity.InstallationId + ", proved; step-up "
                + (stepUpOff is null ? "on" : "off here (" + stepUpOff.Code + ")") + ".";
        }

        public async Task<string> ProveAsync()
        {
            await trust.ProveAsync();
            return "A new installation session.";
        }

        public async Task<string> NewInstallationAsync()
        {
            await trust.ResetAsync();
            Api.Account = null;
            LastScan = null;
            return await StartAsync();
        }

        // --- The scan.
        public async Task<string> AskLocationAsync()
        {
            LocationPermission = await trust.RequestLocationPermissionAsync();
            return "The app holds: " + LocationPermission + ".";
        }

        public async Task<string> ScanAsync()
        {
            var scan = await trust.ScanAsync();
            LastScan = scan;
            var next = scan.Answer["integrity"] is JsonObject integrity && integrity["next"] is JsonValue value
                ? (value.TryGetValue<string>(out var text) ? text : value.ToJsonString())
                : "not said";
            return "The backend answered next: " + next + ", report " + (scan.ReportId ?? "not named") + ".";
        }

        // --- The account.
        public async Task<string> SignInAsync(string handle, string password)
        {
            await Api.SignInAsync(handle, password);
            return "An account session for this installation.";
        }
    }
}
