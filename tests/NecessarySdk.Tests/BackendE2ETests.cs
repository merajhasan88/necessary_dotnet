// The package end to end against a sample backend (backend/), over real HTTP
// with real P-256 signatures: only the phone's keystore and collector are
// replaced, by a software key and the contract's Android samples -- the
// complete one unless a test says otherwise.
// Runs when NECESSARY_BACKEND_URL names a backend; skipped otherwise. The tests
// that need the backend's test controls also need NECESSARY_TEST_TOKEN, the
// token they answer (backend/run_e2e.sh sets both); without it they are
// skipped, as for a deployed sample.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Xunit;

namespace Necessary.Tests
{
    /// <summary>A test that needs a sample backend: NECESSARY_BACKEND_URL.</summary>
    public sealed class BackendFactAttribute : FactAttribute
    {
        public BackendFactAttribute()
        {
            if (string.IsNullOrEmpty(BackendE2ETests.Backend))
            {
                Skip = "NECESSARY_BACKEND_URL is not set";
            }
        }
    }

    /// <summary>A test that needs the sample backend's test controls as well: NECESSARY_TEST_TOKEN.</summary>
    public sealed class BackendControlsFactAttribute : FactAttribute
    {
        public BackendControlsFactAttribute()
        {
            if (string.IsNullOrEmpty(BackendE2ETests.Backend))
            {
                Skip = "NECESSARY_BACKEND_URL is not set";
            }
            else if (string.IsNullOrEmpty(BackendE2ETests.TestToken))
            {
                Skip = "NECESSARY_TEST_TOKEN is not set";
            }
        }
    }

    [Collection("backend")]
    public class BackendE2ETests
    {
        private const string Samples = "contract/report-1/android-8-ios-5/samples";

        private static readonly HttpClient Controls = Client();
        private static readonly Random Random = new Random();

        internal static string? Backend => Environment.GetEnvironmentVariable("NECESSARY_BACKEND_URL");

        internal static string? TestToken => Environment.GetEnvironmentVariable("NECESSARY_TEST_TOKEN");

        /// <summary>
        /// The address to reach the backend's name at, when its DNS does not name
        /// it yet: NECESSARY_BACKEND_ADDRESS. TLS still checks the name.
        /// </summary>
        internal static string? Address => Environment.GetEnvironmentVariable("NECESSARY_BACKEND_ADDRESS");

        /// <summary>An HTTP client that reaches <see cref="Address"/> when one is given.</summary>
        internal static HttpClient Client()
        {
            var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
            if (!string.IsNullOrEmpty(Address))
            {
                handler.ConnectCallback = async (context, cancellation) =>
                {
                    var socket = new System.Net.Sockets.Socket(System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp) { NoDelay = true };
                    await socket.ConnectAsync(System.Net.IPAddress.Parse(Address!), context.DnsEndPoint.Port, cancellation);
                    return new System.Net.Sockets.NetworkStream(socket, ownsSocket: true);
                };
            }

            return new HttpClient(handler) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
        }

        private static JsonObject Obj(string json) => (JsonObject)JsonNode.Parse(json)!;

        /// <summary>One of the contract's sample reports, with its plan and how it is judged.</summary>
        private static JsonObject Sample(string name) =>
            Obj(File.ReadAllText(Path.Combine(RepositoryFiles.Directory(Samples), name + ".json")));

        private static DeviceTrust Trust(
            StepUpOptions? stepUp = null,
            AppPinOptions? appPin = null,
            SoftwareStepUpKey? stepUpKey = null,
            SampleCollector? collector = null) =>
            DeviceTrust.Over(
                new HttpTransport(Backend!, string.IsNullOrEmpty(Address) ? null : Client()),
                stepUp: stepUp,
                appPin: appPin,
                store: new MemoryStore(),
                collector: collector ?? new SampleCollector(),
                hintReader: new Hint(),
                stepUpKey: stepUpKey ?? new SoftwareStepUpKey());

        /// <summary>A test control, and its answer.</summary>
        private static async Task<JsonObject> Control(string path, JsonObject body)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, Backend + path)
            {
                Content = new StringContent(DartJson.Encode(body), Encoding.UTF8, "application/json"),
            };
            request.Headers.TryAddWithoutValidation("X-Test-Token", TestToken ?? string.Empty);
            using var response = await Controls.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            Assert.True(
                (int)response.StatusCode == 200,
                "the backend runs with --test-controls, answering NECESSARY_TEST_TOKEN: " + (int)response.StatusCode + " " + text);
            return Obj(text);
        }

        /// <summary>From now on the backend holds each app PIN check once it has claimed its attempt.</summary>
        private static Task HoldPinChecks() => Control("/test/pin-checks", new JsonObject { ["hold"] = true });

        /// <summary>Releases the checks held -- with <paramref name="fail"/>, as if their verifier broke.</summary>
        private static Task ReleasePinChecks(bool fail = false) =>
            Control("/test/pin-checks", new JsonObject { ["hold"] = false, ["fail"] = fail });

        /// <summary>Waits until <paramref name="count"/> app PIN checks are held.</summary>
        private static async Task PinChecksHeld(int count)
        {
            for (var i = 0; i < 200; i++)
            {
                var answer = await Control("/test/pin-checks", new JsonObject());
                if (Json.Integer(answer["waiting"]) == count)
                {
                    return;
                }

                await Task.Delay(50);
            }

            Assert.Fail("the backend never held " + count + " app PIN checks");
        }

        /// <summary>This backend's own sign-in, under the installation session: its account session for this installation.</summary>
        private static async Task<string> SignIn(DeviceTrust trust, string password = "correct horse")
        {
            var handle = "e2e-" + ((uint)RandomNumberGenerator.GetInt32(int.MaxValue)).ToString(System.Globalization.CultureInfo.InvariantCulture);
            var proof = await trust.SignRequestAsync(
                "POST",
                "/v1/demo/sign-in",
                trust.InstallationSession!,
                DartJson.Encode(new JsonObject { ["handle"] = handle, ["password"] = password }));
            return (string)(await trust.SendAsync(proof))["account_session"]!;
        }

        /// <summary>
        /// Refused with <paramref name="code"/> -- and, like every refusal here,
        /// without naming the check that failed: the phone is told what to do
        /// next, never what gave a request away.
        /// </summary>
        private static async Task Refused(string code, Func<Task> call)
        {
            var error = await Assert.ThrowsAsync<ApiException>(call);
            Assert.Equal(code, error.Code);
            Assert.False(error.Details?.ContainsKey("check") == true || error.Details?.ContainsKey("at") == true, "the failed check named");
        }

        private static string Next(ScanResult scan) => (string)scan.Answer["integrity"]!["next"]!;

        [BackendFact]
        public async Task Start_registers_and_proves_a_scan_is_answered_with_integrity_report_id()
        {
            var trust = Trust();
            await trust.StartAsync();
            var scan = await trust.ScanAsync();
            Assert.False(string.IsNullOrEmpty(scan.ReportId));
            Assert.Equal("allow", Next(scan));

            // What catches hooks, gadgets and changes in memory is asked for on
            // every scan, never left to chance.
            for (var i = 0; i < 3; i++)
            {
                var required = (await trust.ScanAsync()).Challenge.RequiredProbes;
                foreach (var probe in new[] { "runtime_maps", "frida_ports", "instrumentation_threads", "exec_mappings", "code_integrity", "tracer", "debug_state" })
                {
                    Assert.Contains(probe, required);
                }
            }

            // Every personal measurement is asked for, so that the example app
            // can show each one it enables.
            Assert.Equal(PersonalMeasurements.All.Select(m => m.WireName()), scan.Challenge.OptionalProbes);
        }

        [BackendFact]
        public async Task A_request_carries_its_proof_once()
        {
            var trust = Trust();
            await trust.StartAsync();
            var account = await SignIn(trust);
            var proof = await trust.SignRequestAsync("POST", "/v1/demo/echo", account, "{\"hello\":1}");
            Assert.Equal("/v1/demo/echo", (string?)(await trust.SendAsync(proof))["done"]);
            await Refused("proof_reused", () => trust.SendAsync(proof));
        }

        [BackendFact]
        public async Task A_scan_for_one_action_approves_that_request_once()
        {
            var trust = Trust();
            await trust.StartAsync();
            var account = await SignIn(trust);
            const string body = "{\"amount\":25,\"to\":\"payee-7\"}";
            var scan = await trust.ScanAsync(account, RequestProofs.DescribeOperation("POST", "/v1/demo/transfer", body));
            async Task<JsonObject> Transfer(string? reportId) =>
                await trust.SendAsync(await trust.SignRequestAsync("POST", "/v1/demo/transfer", account, body, reportId: reportId));
            await Refused("needs_scan", () => Transfer(null));
            Assert.Equal("/v1/demo/transfer", (string?)(await Transfer(scan.ReportId))["done"]);
            await Refused("needs_scan", () => Transfer(scan.ReportId));
        }

        [BackendFact]
        public async Task A_scan_for_one_action_approves_it_only_when_the_backend_allows_it_the_contract_judges_a_report_before_anything_else()
        {
            const string body = "{\"amount\":25,\"to\":\"payee-7\"}";
            foreach (var (sample, next) in new[] { ("android-8-complete", "allow"), ("android-8-incomplete", "scan_again"), ("android-8-invalid", "review") })
            {
                var trust = Trust(collector: new SampleCollector(sample));
                await trust.StartAsync();
                var account = await SignIn(trust);
                var scan = await trust.ScanAsync(account, RequestProofs.DescribeOperation("POST", "/v1/demo/transfer", body));
                Assert.Equal(next, Next(scan));
                Task<JsonObject> Transfer() => trust.SignRequestAsync("POST", "/v1/demo/transfer", account, body, reportId: scan.ReportId)
                    .ContinueWith(signed => trust.SendAsync(signed.Result), TaskScheduler.Default).Unwrap();
                if (next == "allow")
                {
                    Assert.Equal("/v1/demo/transfer", (string?)(await Transfer())["done"]);
                }
                else
                {
                    await Refused("needs_scan", Transfer);
                }
            }

            // A collector older than the contract is refused, never read.
            var old = Trust(collector: new SampleCollector("android-8-complete", 7));
            await old.StartAsync();
            await Refused("report_not_accepted", () => old.ScanAsync());
        }

        [BackendControlsFact]
        public async Task Every_sample_of_the_contract_is_judged_as_it_says_under_its_own_plan()
        {
            var files = Directory.GetFiles(RepositoryFiles.Directory(Samples), "*.json").OrderBy(p => p, StringComparer.Ordinal).ToList();
            Assert.Equal(11, files.Count);
            foreach (var file in files)
            {
                var sample = Obj(File.ReadAllText(file));
                var answer = await Control("/test/judge", new JsonObject
                {
                    ["report"] = sample["report"]!.DeepClone(),
                    ["required_probes"] = sample["plan"]!["required_probes"]!.DeepClone(),
                });
                Assert.True(JsonNode.DeepEquals(sample["expect"], answer["judged"]), file + ": " + answer.ToJsonString());
            }
        }

        [BackendFact]
        public async Task A_sensitive_request_needs_the_persons_approval_step_up_the_app_pin_or_both()
        {
            var trust = Trust(new StepUpOptions(), new AppPinOptions());
            await trust.StartAsync();
            var account = await SignIn(trust, "pin owner");
            async Task<JsonObject> Sensitive(bool stepUp = false, string? pin = null) =>
                await trust.SendAsync(await trust.SignRequestAsync(
                    "POST",
                    "/v1/demo/sensitive",
                    account,
                    "{\"payee\":\"payee-7\"}",
                    stepUp: stepUp,
                    appPin: pin));
            await Refused("needs_approval", () => Sensitive());
            Assert.Equal("/v1/demo/sensitive", (string?)(await Sensitive(stepUp: true))["done"]);
            await Refused("app_pin_not_set", () => Sensitive(pin: "135790"));
            var set = await trust.SetAppPinAsync(account, "135790", new JsonObject { ["password"] = "pin owner" });
            Assert.True((bool)set["app_pin_set"]!);
            await Refused("app_pin_invalid", () => Sensitive(pin: "000000"));
            Assert.Equal("/v1/demo/sensitive", (string?)(await Sensitive(pin: "135790"))["done"]);
            Assert.Equal("/v1/demo/sensitive", (string?)(await Sensitive(stepUp: true, pin: "135790"))["done"]);
        }

        [BackendFact]
        public async Task A_request_proof_is_refused_for_another_body_path_or_time_and_under_another_phones_key()
        {
            var trust = Trust();
            await trust.StartAsync();
            var account = await SignIn(trust);
            const string body = "{\"amount\":25}";
            Task<RequestProof> Echo() => trust.SignRequestAsync("POST", "/v1/demo/echo", account, body);
            await Refused("proof_not_accepted", async () => await trust.Client.SendSignedAsync(await Echo(), encodedBody: "{\"amount\":2500}"));
            await Refused("proof_not_accepted", async () => await trust.Client.SendSignedAsync(await Echo(), path: "/v1/demo/sensitive"));
            await Refused("proof_not_accepted", async () => await trust.SendAsync(await RequestProofs.SignAsync(
                trust.Identity!,
                "POST",
                "/v1/demo/echo",
                account,
                body,
                timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600)));

            // The session copied to another phone: its key cannot sign for this
            // installation, even naming it.
            var other = Trust();
            await other.StartAsync();
            await Refused("invalid_installation_signature", async () => await other.SendAsync(await RequestProofs.SignAsync(
                other.Identity!,
                "POST",
                "/v1/demo/echo",
                account,
                body,
                installationId: trust.Identity!.InstallationId)));
        }

        [BackendFact]
        public async Task Reenrolment_a_dead_step_up_key_replaced_with_the_password_for_that_account_alone()
        {
            var stepUpKey = new SoftwareStepUpKey();
            var trust = Trust(new StepUpOptions(), stepUpKey: stepUpKey);
            await trust.StartAsync();
            var account = await SignIn(trust, "key owner");
            async Task<JsonObject> Sensitive(string session) =>
                await trust.SendAsync(await trust.SignRequestAsync(
                    "POST",
                    "/v1/demo/sensitive",
                    session,
                    "{\"payee\":\"payee-7\"}",
                    stepUp: true));
            Assert.Equal("/v1/demo/sensitive", (string?)(await Sensitive(account))["done"]);

            // The screen lock removed: the key the backend holds cannot sign.
            stepUpKey.Dead = true;
            var dead = await Assert.ThrowsAsync<NativeKeyException>(() => Sensitive(account));
            Assert.Equal("STEPUP_KEY_INVALIDATED", dead.Code);
            await Refused(
                "reauthentication_failed",
                () => trust.ReenrolStepUpAsync(account, new JsonObject { ["password"] = "wrong password" }));
            var answer = await trust.ReenrolStepUpAsync(account, new JsonObject { ["password"] = "key owner" });
            Assert.True((bool)answer["stepup_key_registered"]!);
            Assert.Equal("/v1/demo/sensitive", (string?)(await Sensitive(account))["done"]);

            // Another account on the same phone gains no step-up from it.
            var second = await SignIn(trust);
            await Refused("step_up_not_accepted", () => Sensitive(second));
        }

        [BackendControlsFact]
        public async Task An_app_pin_check_settles_against_the_pin_it_compared_a_pin_set_meanwhile_is_left_alone_and_the_proofs_made_before_it_no_longer_serve()
        {
            var trust = Trust(appPin: new AppPinOptions());
            await trust.StartAsync();
            var account = await SignIn(trust, "pin owner");
            Task SetPin(string pin) => trust.SetAppPinAsync(account, pin, new JsonObject { ["password"] = "pin owner" });
            Task<RequestProof> Unlock(string pin) =>
                trust.SignRequestAsync("POST", "/v1/demo/sensitive", account, "{\"payee\":\"payee-7\"}", appPin: pin);
            async Task<JsonObject> Sensitive(string pin) => await trust.SendAsync(await Unlock(pin));
            static void Done(JsonObject answer) => Assert.Equal("/v1/demo/sensitive", (string?)answer["done"]);
            await SetPin("111111");

            // A right PIN still being checked when a new one is set unlocks
            // nothing; asked now, the old PIN is simply wrong.
            await HoldPinChecks();
            var right = Refused("app_pin_invalid", () => Unlock("111111"));
            await PinChecksHeld(1);
            await SetPin("222222");
            await ReleasePinChecks();
            await right;
            await Refused("app_pin_invalid", () => Sensitive("111111"));
            Done(await Sensitive("222222"));

            // Five wrong PINs being checked hold every attempt, so a sixth waits;
            // when a new PIN is set meanwhile they neither count against it nor
            // lock it.
            await HoldPinChecks();
            var wrong = Enumerable.Range(0, 5).Select(i => Refused("app_pin_invalid", () => Unlock("99999" + i))).ToList();
            await PinChecksHeld(5);
            await Refused("pin_busy", () => Unlock("999995"));
            await SetPin("333333");
            await ReleasePinChecks();
            await Task.WhenAll(wrong);
            Done(await Sensitive("333333"));

            // A proof made before a new PIN no longer serves.
            var made = await Unlock("333333");
            await SetPin("444444");
            await Refused("app_pin_not_accepted", () => trust.SendAsync(made));
            Done(await Sensitive("444444"));

            // A check that could not run gives its attempt back: four wrong PINs
            // after it still leave the last attempt, which two checks at once
            // cannot both take.
            await HoldPinChecks();
            var broken = Refused("pin_unavailable", () => Unlock("444444"));
            await PinChecksHeld(1);
            await ReleasePinChecks(fail: true);
            await broken;
            for (var i = 0; i < 4; i++)
            {
                await Refused("app_pin_invalid", () => Sensitive("00000" + i));
            }

            await HoldPinChecks();
            var last = Unlock("444444");
            await PinChecksHeld(1);
            await Refused("pin_busy", () => Unlock("444444"));
            await ReleasePinChecks();
            Done(await trust.SendAsync(await last));
        }

        [BackendFact]
        public async Task A_screen_lock_set_only_after_the_installation_was_registered_its_step_up_key_waits_for_reenrolment_then_approves()
        {
            var stepUpKey = new SoftwareStepUpKey { Locked = false };
            var trust = Trust(new StepUpOptions(), stepUpKey: stepUpKey);
            await trust.StartAsync();
            Assert.Equal("STEPUP_NO_DEVICE_CREDENTIAL", trust.StepUpUnavailable?.Code);
            var account = await SignIn(trust, "lock owner");

            // The lock set again, the app started again: the key it makes now is
            // not one the backend took.
            stepUpKey.Locked = true;
            await trust.StartAsync();
            Assert.Equal("STEPUP_REENROL_PENDING", trust.StepUpUnavailable?.Code);
            async Task<JsonObject> Sensitive() =>
                await trust.SendAsync(await trust.SignRequestAsync(
                    "POST",
                    "/v1/demo/sensitive",
                    account,
                    "{\"payee\":\"payee-7\"}",
                    stepUp: true));
            var pending = await Assert.ThrowsAsync<NativeKeyException>(Sensitive);
            Assert.Equal("STEPUP_REENROL_PENDING", pending.Code);
            var answer = await trust.ReenrolStepUpAsync(account, new JsonObject { ["password"] = "lock owner" });
            Assert.True((bool)answer["stepup_key_registered"]!);
            Assert.Equal("/v1/demo/sensitive", (string?)(await Sensitive())["done"]);
        }

        [BackendFact]
        public async Task A_malformed_request_is_answered_never_a_connection_dropped()
        {
            async Task Answered(string path, string body)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, Backend + path)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json"),
                };
                using var response = await Controls.SendAsync(request);
                Assert.True((int)response.StatusCode >= 400);
                Assert.IsType<JsonObject>(Obj(await response.Content.ReadAsStringAsync())["error"]);
            }

            // A payload that is valid base64url, of JSON that is no object.
            var notAnObject = Wire.Base64UrlNoPadding(Encoding.UTF8.GetBytes("[]"));
            await Answered("/v1/installations/verify", "{\"payload\":\"" + notAnObject + "\"}");
            await Answered("/v1/installations/challenge", "{\"installation_id\":[]}");
            await Answered("/v1/installations/register", "{\"installation_id\":5}");
        }

        [BackendControlsFact]
        public async Task The_guides_protocol_errors_each_acted_on_once()
        {
            var trust = Trust();
            await trust.StartAsync();

            // The installation session expired: the key is proved again.
            await Control("/test/expire-sessions", new JsonObject());
            Assert.False(string.IsNullOrEmpty((await trust.ScanAsync()).ReportId));

            // The backend lost the installation: registered again with the same key.
            await Control("/test/forget", new JsonObject { ["installation_id"] = trust.Identity!.InstallationId });
            Assert.False(string.IsNullOrEmpty((await trust.ScanAsync()).ReportId));

            // A key challenge expired before its answer: a new one, once.
            await Control("/test/refuse-next", Obj("{\"path\":\"/v1/installations/verify\",\"status\":401,\"code\":\"challenge_expired\"}"));
            Assert.False(string.IsNullOrEmpty(await trust.ProveAsync()));

            // A scan's challenge expired before its report: a new scan, once.
            await Control("/test/refuse-next", Obj("{\"path\":\"/v1/integrity/report\",\"status\":401,\"code\":\"integrity_challenge_expired\"}"));
            Assert.False(string.IsNullOrEmpty((await trust.ScanAsync()).ReportId));

            // A short wait is waited out, once.
            await Control("/test/refuse-next", Obj("{\"path\":\"/v1/integrity/challenge\",\"status\":429,\"code\":\"busy\",\"details\":{\"retry_after_seconds\":1}}"));
            Assert.False(string.IsNullOrEmpty((await trust.ScanAsync()).ReportId));

            // Any other refusal reaches the app as it came.
            await Control("/test/refuse-next", Obj("{\"path\":\"/v1/integrity/challenge\",\"status\":403,\"code\":\"installation_inactive\"}"));
            await Refused("installation_inactive", () => trust.ScanAsync());
        }

        /// <summary>A P-256 key in software: signs as the phone's keystore does, ECDSA over SHA-256 with an ASN.1 DER signature.</summary>
        private sealed class SoftwareKey : IDisposable
        {
            private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            public SoftwareKey()
            {
                var point = key.ExportParameters(false).Q;
                Jwk = new JsonObject
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["alg"] = "ES256",
                    ["x"] = Wire.Base64UrlNoPadding(point.X!),
                    ["y"] = Wire.Base64UrlNoPadding(point.Y!),
                };
            }

            public JsonObject Jwk { get; }

            public string Sign(string payloadBase64Url) =>
                Wire.Base64UrlNoPadding(key.SignData(
                    Wire.DecodeBase64Url(payloadBase64Url),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence));

            public void Dispose() => key.Dispose();
        }

        private sealed class InstallationKey : INativeInstallationKey
        {
            private readonly SoftwareKey key = new SoftwareKey();
            private bool made;

            public Task<NativeKeyMetadata> GetOrCreateKeyAsync()
            {
                var created = !made;
                made = true;
                return Task.FromResult(new NativeKeyMetadata(
                    (JsonObject)key.Jwk.DeepClone(),
                    "ES256",
                    "software",
                    "AndroidKeyStore",
                    "software",
                    false,
                    false,
                    "der",
                    created));
            }

            public Task<string> SignPayloadAsync(string payloadBase64Url) => Task.FromResult(key.Sign(payloadBase64Url));

            public Task DeleteKeyAsync()
            {
                made = false;
                return Task.CompletedTask;
            }
        }

        /// <summary>The installation ID in memory, beside the software key.</summary>
        private sealed class MemoryStore : InstallationStore
        {
            private string? stored;
            private bool reenrolPending;

            public MemoryStore()
                : base(new InstallationKey(), new InMemorySecureStorage())
            {
            }

            public override async Task<InstallationIdentity> LoadOrCreateAsync()
            {
                var metadata = await Key.GetOrCreateKeyAsync();
                if (stored is null || metadata.Created)
                {
                    stored = Guid.NewGuid().ToString("D");
                }

                return new InstallationIdentity(stored, Key, metadata);
            }

            public override Task SaveInstallationIdAsync(string installationId)
            {
                stored = installationId;
                return Task.CompletedTask;
            }

            public override Task<bool> StepUpReenrolPendingAsync() => Task.FromResult(reenrolPending);

            public override Task SetStepUpReenrolPendingAsync(bool pending)
            {
                reenrolPending = pending;
                return Task.CompletedTask;
            }
        }

        internal sealed class SoftwareStepUpKey : INativeStepUpKey
        {
            private SoftwareKey key = new SoftwareKey();

            public string ConfiguredMode { get; set; } = "per_use";

            /// <summary>The screen lock removed: the key can no longer sign.</summary>
            public bool Dead { get; set; }

            /// <summary>Whether the phone has a screen lock: without one no key is made.</summary>
            public bool Locked { get; set; } = true;

            public Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds) =>
                !Locked
                    ? Task.FromException<StepUpKeyMetadata>(new NativeKeyException("STEPUP_NO_DEVICE_CREDENTIAL", "no lock"))
                    : Task.FromResult(new StepUpKeyMetadata((JsonObject)key.Jwk.DeepClone(), factor, mode, windowSeconds, "software", false, false));

            public Task<string> SignAsync(string payloadBase64Url, string reason) =>
                Dead
                    ? Task.FromException<string>(new NativeKeyException("STEPUP_KEY_INVALIDATED", "the lock was removed"))
                    : Task.FromResult(key.Sign(payloadBase64Url));

            public Task DeleteKeyAsync()
            {
                key = new SoftwareKey();
                Dead = false;
                return Task.CompletedTask;
            }
        }

        /// <summary>Answers with one of the contract's Android samples, whatever is asked.</summary>
        internal sealed class SampleCollector : INativeIntegrityCollector
        {
            private readonly JsonObject probes;
            private readonly int collectorVersion;

            public SampleCollector(string sample = "android-8-complete", int collectorVersion = 8)
            {
                probes = (JsonObject)Sample(sample)["report"]!["probe_results"]!.DeepClone();
                this.collectorVersion = collectorVersion;
            }

            public Task<JsonObject> CollectAsync(
                IReadOnlyList<string> requiredProbes,
                string challengeNonce,
                IReadOnlyList<string> enabledMeasurements,
                IReadOnlyList<string> optionalProbes) =>
                Task.FromResult(new JsonObject
                {
                    ["platform"] = "android",
                    ["challenge_nonce_echo"] = challengeNonce,
                    ["collector_version"] = collectorVersion,
                    ["probes"] = probes.DeepClone(),
                });

            public Task<string> RequestLocationPermissionAsync() => Task.FromResult("none");
        }

        private sealed class Hint : ReinstallHintReader
        {
            public override Task<ReinstallHint?> ReadAsync()
            {
                var value = new StringBuilder(64);
                lock (Random)
                {
                    for (var i = 0; i < 64; i++)
                    {
                        value.Append("0123456789abcdef"[Random.Next(16)]);
                    }
                }

                return Task.FromResult<ReinstallHint?>(new ReinstallHint("android_id_sha256", value.ToString()));
            }
        }
    }
}
