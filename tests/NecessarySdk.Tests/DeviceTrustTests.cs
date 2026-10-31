// DeviceTrust against a backend that answers as the public guide says, with
// the phone's native side replaced: what it sends, under which session, and
// what it does about each of the guide's protocol errors.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Xunit;

namespace Necessary.Tests
{
    public class DeviceTrustTests
    {
        private static JsonObject Obj(string json) => (JsonObject)JsonNode.Parse(json)!;

        private static JsonObject Decoded(string payload) =>
            Obj(Encoding.UTF8.GetString(Wire.DecodeBase64Url(payload)));

        private static ApiException Refusal(string code, int status, JsonObject? details = null) =>
            new ApiException(code, status, code, details);

        private static NativeKeyMetadata Metadata(bool created = false) =>
            new NativeKeyMetadata(
                Obj("{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"x\",\"y\":\"y\"}"),
                "ES256",
                "test",
                "AndroidKeyStore",
                "trusted_execution_environment",
                true,
                false,
                "der",
                created);

        private static DeviceTrust Trust(
            Backend backend,
            Store? store = null,
            Collector? collector = null,
            StepUpKeyFake? stepUpKey = null,
            IEnumerable<PersonalMeasurement>? personal = null,
            StepUpOptions? stepUp = null,
            AppPinOptions? appPin = null,
            Func<JsonObject, Task>? onRegistered = null) =>
            DeviceTrust.Over(
                backend,
                personal,
                stepUp,
                appPin,
                onRegistered,
                store ?? new Store(),
                collector ?? new Collector(),
                new Hints(),
                stepUpKey ?? new StepUpKeyFake());

        /// <summary>One approval with the step-up key, for a payment.</summary>
        private static Task<RequestProof> Approve(DeviceTrust trust) =>
            trust.SignRequestAsync("POST", "/v1/pay", "account-session", stepUp: true);

        private static async Task ReenrolPending(Func<Task> call)
        {
            var error = await Assert.ThrowsAsync<NativeKeyException>(call);
            Assert.Equal("STEPUP_REENROL_PENDING", error.Code);
        }

        [Fact]
        public async Task Start_registers_the_key_with_the_step_up_key_and_proves_it()
        {
            var backend = new Backend();
            var trust = Trust(backend, stepUp: new StepUpOptions());
            await trust.StartAsync();
            Assert.Equal(new[] { "/v1/installations/register", "/v1/installations/challenge", "/v1/installations/verify" }, backend.Paths);
            var registration = backend.Calls[0].Body;
            Assert.Equal("proposed-id", (string?)registration["installation_id"]);
            Assert.Equal("android", (string?)registration["platform"]);
            Assert.Equal("EC", (string?)registration["public_key"]!["kty"]);
            Assert.True(JsonNode.DeepEquals(Obj("{\"kind\":\"android_id_sha256\",\"value\":\"hint\"}"), registration["reinstall_hint"]));
            Assert.True((bool)registration["key_security"]!["hardware_backed"]!);
            Assert.Equal("sx", (string?)registration["stepup_public_key"]!["x"]);
            Assert.True(JsonNode.DeepEquals(
                Obj("{\"factor\":\"passcode\",\"mode\":\"per_use\",\"window_seconds\":0}"),
                registration["stepup_key_auth"]));
            Assert.Equal("signed", (string?)backend.Calls[2].Body["signature"]);
            Assert.Equal("installation-session", trust.InstallationSession);
        }

        [Fact]
        public async Task The_installation_the_backend_holds_for_the_key_is_kept()
        {
            var store = new Store();
            var answers = new List<JsonObject>();
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/installations/register"] = new List<object> { Obj("{\"installation_id\":\"held-id\",\"more\":1}") },
            });
            var trust = Trust(backend, store, onRegistered: answer =>
            {
                answers.Add(answer);
                return Task.CompletedTask;
            });
            await trust.StartAsync();
            Assert.Equal("held-id", trust.Identity!.InstallationId);
            Assert.Equal("held-id", store.Saved);
            Assert.Equal("held-id", (string?)backend.Calls[1].Body["installation_id"]);
            Assert.Equal(1, (int)Assert.Single(answers)["more"]!);
        }

        [Fact]
        public async Task A_scan_under_the_installation_session_the_enabled_measurements_in_the_guides_order_the_report_id_from_integrity()
        {
            var backend = new Backend();
            var collector = new Collector();
            var trust = Trust(
                backend,
                collector: collector,
                personal: new[] { PersonalMeasurement.MockLocation, PersonalMeasurement.LocalAddresses });
            await trust.StartAsync();
            var scan = await trust.ScanAsync();
            Assert.Equal(new[] { "local_addresses", "mock_location" }, collector.Enabled);
            var challenge = backend.Calls[3];
            Assert.Equal("/v1/integrity/challenge", challenge.Path);
            Assert.Equal("installation-session", challenge.Bearer);
            Assert.Empty(challenge.Body);
            Assert.Contains("X-Access-Proof", challenge.Headers.Keys);
            var report = backend.Calls[4];
            Assert.Equal("installation-session", report.Bearer);
            var signed = Decoded((string)report.Body["report_payload"]!);
            Assert.Equal("scan-challenge", (string?)signed["challenge_id"]);
            Assert.Equal(new[] { "local_addresses", "mock_location" }, ((JsonArray)signed["enabled_measurements"]!).Select(n => (string)n!));
            Assert.Equal("report-1", scan.ReportId);
        }

        [Fact]
        public async Task The_personal_measurements_change_with_the_app_the_next_scan_follows_the_installation_and_its_step_up_key_stay()
        {
            var backend = new Backend();
            var collector = new Collector();
            var trust = Trust(backend, collector: collector, stepUp: new StepUpOptions());
            await trust.StartAsync();
            await trust.ScanAsync();
            Assert.Empty(collector.Enabled!);
            trust.PersonalMeasurements = new[] { PersonalMeasurement.Location, PersonalMeasurement.Accessibility };
            await trust.ScanAsync();
            Assert.Equal(new[] { "accessibility", "location" }, collector.Enabled);
            Assert.NotNull(trust.StepUpKey);
            Assert.Equal(3, backend.Paths.Count(p => p.StartsWith("/v1/installations", StringComparison.Ordinal)));
        }

        [Fact]
        public async Task A_step_up_key_the_keystore_cannot_vouch_for_is_kept_at_start_and_replaced_only_by_a_reenrolment()
        {
            var backend = new Backend();
            var key = new UnavailableStepUpKey();
            var trust = Trust(backend, stepUpKey: key, stepUp: new StepUpOptions());
            await trust.StartAsync();
            Assert.Equal("STEPUP_KEY_UNAVAILABLE", trust.StepUpUnavailable?.Code);
            Assert.Equal(0, key.Deleted);
            var answer = await trust.ReenrolStepUpAsync("account-session", Obj("{\"password\":\"pw\"}"));
            Assert.True((bool)answer["stepup_key_registered"]!);
            Assert.Equal(1, key.Deleted);
            Assert.Null(trust.StepUpUnavailable);
        }

        [Fact]
        public async Task Reenrolment_a_dead_step_up_key_replaced_its_proof_bound_to_the_request_proofs_nonce_and_approvals_from_then_on()
        {
            var backend = new Backend();
            var key = new DyingStepUpKey();
            var trust = Trust(backend, stepUpKey: key, stepUp: new StepUpOptions());
            await trust.StartAsync();
            var answer = await trust.ReenrolStepUpAsync("account-session", Obj("{\"password\":\"pw\"}"));
            Assert.True((bool)answer["stepup_key_registered"]!);
            Assert.Equal(1, key.Deleted);
            var call = backend.Calls[^1];
            Assert.Equal("/v1/installations/stepup-key", call.Path);
            Assert.Equal("account-session", call.Bearer);
            Assert.Equal("pw", (string?)call.Body["password"]);
            Assert.Equal("sx", (string?)call.Body["stepup_public_key"]!["x"]);
            Assert.Equal("passcode", (string?)call.Body["stepup_key_auth"]!["factor"]);
            Assert.Equal("approved", (string?)call.Body["stepup_key_signature"]);
            var proof = Decoded((string)call.Body["stepup_key_proof"]!);
            Assert.Equal(1, (int)proof["version"]!);
            Assert.Equal("stepup_reenrol", (string?)proof["purpose"]);
            Assert.Equal("proposed-id", (string?)proof["installation_id"]);
            Assert.Equal((string?)Decoded(call.Headers["X-Access-Proof"])["nonce"], (string?)proof["nonce"]);
            var approval = await trust.SignRequestAsync("POST", "/v1/pay", "account-session", stepUp: true);
            Assert.Contains("X-Step-Up-Proof", approval.Headers.Keys);
        }

        [Fact]
        public async Task A_reenrolment_the_backend_refused_leaves_approvals_waiting_for_it_across_a_restart_too_until_a_second_one_succeeds()
        {
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/installations/stepup-key"] = new List<object>
                {
                    Refusal("reauthentication_failed", 401),
                    Obj("{\"stepup_key_registered\":true}"),
                },
            });
            var store = new Store();
            var key = new DyingStepUpKey();
            DeviceTrust Started() => Trust(backend, store, stepUpKey: key, stepUp: new StepUpOptions());
            var trust = Started();
            await trust.StartAsync();
            await Assert.ThrowsAsync<ApiException>(() => trust.ReenrolStepUpAsync("account-session", Obj("{\"password\":\"wrong\"}")));

            // The dead key is gone and the new one not taken: approvals wait.
            await ReenrolPending(() => Approve(trust));
            Assert.Equal("STEPUP_REENROL_PENDING", trust.StepUpUnavailable?.Code);
            var restarted = Started();
            await restarted.StartAsync();
            await ReenrolPending(() => Approve(restarted));
            var answer = await restarted.ReenrolStepUpAsync("account-session", Obj("{\"password\":\"pw\"}"));
            Assert.True((bool)answer["stepup_key_registered"]!);
            Assert.False(store.ReenrolPending);
            Assert.Null(restarted.StepUpUnavailable);
            Assert.Contains("X-Step-Up-Proof", (await Approve(restarted)).Headers.Keys);
        }

        [Fact]
        public async Task A_reenrolment_whose_prompt_was_cancelled_then_whose_answer_was_lost_is_finished_by_the_next_one()
        {
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/installations/stepup-key"] = new List<object>
                {
                    Refusal("bad_gateway", 502),
                    Obj("{\"stepup_key_registered\":true}"),
                },
            });
            var store = new Store();
            var trust = Trust(backend, store, stepUpKey: new CancelledStepUpKey(), stepUp: new StepUpOptions());
            await trust.StartAsync();
            Task<JsonObject> Reenrol() => trust.ReenrolStepUpAsync("account-session", Obj("{\"password\":\"pw\"}"));
            var cancelled = await Assert.ThrowsAsync<NativeKeyException>(Reenrol);
            Assert.Equal("STEPUP_CANCELLED", cancelled.Code);
            await ReenrolPending(() => Approve(trust));
            await Assert.ThrowsAsync<ApiException>(Reenrol);
            await ReenrolPending(() => Approve(trust));
            Assert.True(store.ReenrolPending);
            Assert.True((bool)(await Reenrol())["stepup_key_registered"]!);
            Assert.False(store.ReenrolPending);
            Assert.Contains("X-Step-Up-Proof", (await Approve(trust)).Headers.Keys);
        }

        [Fact]
        public async Task A_backend_that_says_it_does_not_hold_the_step_up_key_offered_leaves_approvals_waiting_for_reenrolment_one_that_says_it_does_clears_that()
        {
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/installations/register"] = new List<object>
                {
                    Obj("{\"installation_id\":\"proposed-id\",\"stepup_key_registered\":false,\"stepup_key_matches\":false}"),
                    Obj("{\"installation_id\":\"proposed-id\",\"stepup_key_registered\":true,\"stepup_key_matches\":true}"),
                },
            });
            var store = new Store();
            var trust = Trust(backend, store, stepUp: new StepUpOptions());
            await trust.StartAsync();
            Assert.Equal("STEPUP_REENROL_PENDING", trust.StepUpUnavailable?.Code);
            await ReenrolPending(() => Approve(trust));
            Assert.True(store.ReenrolPending);
            await trust.StartAsync();
            Assert.Null(trust.StepUpUnavailable);
            Assert.False(store.ReenrolPending);
            Assert.Contains("X-Step-Up-Proof", (await Approve(trust)).Headers.Keys);
        }

        [Fact]
        public async Task A_step_up_key_the_phone_could_not_make_at_registration_made_at_the_next_start_waits_for_reenrolment_even_where_the_backend_says_nothing()
        {
            var backend = new Backend();
            var store = new Store();
            var trust = Trust(backend, store, stepUp: new StepUpOptions(), stepUpKey: new FlakyStepUpKey());
            await trust.StartAsync();
            Assert.Equal("STEPUP_NO_DEVICE_CREDENTIAL", trust.StepUpUnavailable?.Code);
            await trust.StartAsync();
            Assert.Equal("STEPUP_REENROL_PENDING", trust.StepUpUnavailable?.Code);
            await ReenrolPending(() => Approve(trust));
            var answer = await trust.ReenrolStepUpAsync("account-session", Obj("{\"password\":\"pw\"}"));
            Assert.True((bool)answer["stepup_key_registered"]!);
            Assert.Contains("X-Step-Up-Proof", (await Approve(trust)).Headers.Keys);
        }

        [Fact]
        public async Task Reset_deletes_the_step_up_key_with_the_installation_nothing_links_the_next_installation_to_this_one()
        {
            var key = new DyingStepUpKey();
            var trust = Trust(new Backend(), stepUpKey: key, stepUp: new StepUpOptions());
            await trust.StartAsync();
            await trust.ResetAsync();
            Assert.Equal(1, key.Deleted);
            Assert.Null(trust.StepUpKey);
        }

        [Fact]
        public async Task A_reset_while_a_reenrolment_waits_for_its_answer_waits_for_it_then_deletes_its_key_and_its_marker()
        {
            var answer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var backend = new HeldBackend("/v1/installations/stepup-key", answer.Task);
            var store = new Store();
            var key = new DyingStepUpKey();
            var trust = Trust(backend, store, stepUpKey: key, stepUp: new StepUpOptions());
            await trust.StartAsync();
            var reenrolled = Assert.ThrowsAsync<InterruptedCallException>(
                () => trust.ReenrolStepUpAsync("account-session", Obj("{\"password\":\"pw\"}")));
            await backend.Asked.Task;
            Assert.True(store.ReenrolPending);
            Assert.Equal(1, key.Deleted);
            var reset = false;
            var resetting = trust.ResetAsync().ContinueWith(_ => reset = true, TaskScheduler.Default);
            await Task.Delay(20);
            Assert.False(reset, "the reset waits for the re-enrolment");
            answer.SetResult(true);
            await reenrolled;
            await resetting;
            Assert.False(store.ReenrolPending);
            Assert.Equal(2, key.Deleted);
        }

        [Fact]
        public async Task Reenrolment_with_step_up_off_refuses_before_sending()
        {
            var backend = new Backend();
            var trust = Trust(backend);
            await trust.StartAsync();
            var error = await Assert.ThrowsAsync<NativeKeyException>(() => trust.ReenrolStepUpAsync("account-session"));
            Assert.Equal("STEPUP_OFF", error.Code);
            Assert.DoesNotContain("/v1/installations/stepup-key", backend.Paths);
        }

        [Fact]
        public async Task A_scan_for_one_operation_is_asked_under_the_account_session()
        {
            var backend = new Backend();
            var trust = Trust(backend);
            await trust.StartAsync();
            var operation = RequestProofs.DescribeOperation("POST", "/v1/pay", "{\"amount\":5}");
            Assert.Throws<ArgumentException>(() => { _ = trust.ScanAsync(operation: operation); });
            await trust.ScanAsync("account-session", operation);
            var challenge = backend.Calls[3];
            Assert.Equal("account-session", challenge.Bearer);
            Assert.True(JsonNode.DeepEquals(operation, challenge.Body["operation"]));
            Assert.Equal("account-session", backend.Calls[4].Bearer);
        }

        [Fact]
        public async Task An_expired_installation_session_is_proved_again_once_an_expired_account_session_goes_to_the_app()
        {
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/integrity/challenge"] = new List<object>
                {
                    Refusal("expired_token", 401),
                    Obj("{\"challenge_id\":\"scan-challenge\",\"nonce\":\"bm9uY2U\",\"platform\":\"android\",\"required_probes\":[\"app_identity\"]}"),
                },
            });
            var trust = Trust(backend);
            await trust.StartAsync();
            await trust.ScanAsync();
            Assert.Equal(
                new[]
                {
                    "/v1/integrity/challenge",
                    "/v1/installations/challenge",
                    "/v1/installations/verify",
                    "/v1/integrity/challenge",
                    "/v1/integrity/report",
                },
                backend.Paths.Skip(3));

            var account = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/integrity/challenge"] = new List<object> { Refusal("expired_token", 401) },
            });
            var other = Trust(account);
            await other.StartAsync();
            var error = await Assert.ThrowsAsync<ApiException>(() => other.ScanAsync("account-session", new JsonObject()));
            Assert.Equal("expired_token", error.Code);
            Assert.Single(account.Paths, p => p == "/v1/installations/verify");
        }

        [Fact]
        public async Task A_lost_installation_registers_again_under_the_installation_session_never_under_an_account_session()
        {
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/integrity/challenge"] = new List<object>
                {
                    Refusal("installation_not_found", 404),
                    Obj("{\"challenge_id\":\"scan-challenge\",\"nonce\":\"bm9uY2U\",\"platform\":\"android\",\"required_probes\":[\"app_identity\"]}"),
                },
            });
            var trust = Trust(backend);
            await trust.StartAsync();
            await trust.ScanAsync();
            Assert.Equal(
                new[]
                {
                    "/v1/integrity/challenge",
                    "/v1/installations/register",
                    "/v1/installations/challenge",
                    "/v1/installations/verify",
                },
                backend.Paths.Skip(3).Take(4));

            var account = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/integrity/challenge"] = new List<object> { Refusal("installation_not_found", 404) },
            });
            var other = Trust(account);
            await other.StartAsync();
            await Assert.ThrowsAsync<ApiException>(() => other.ScanAsync("account-session", new JsonObject()));
            Assert.Single(account.Paths, p => p == "/v1/installations/register");
        }

        [Fact]
        public async Task A_short_wait_is_waited_out_once_a_long_one_goes_to_the_app()
        {
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/integrity/report"] = new List<object>
                {
                    Refusal("too_many", 429, Obj("{\"retry_after_seconds\":0}")),
                    Obj("{\"integrity\":{\"report_id\":\"report-2\"}}"),
                },
            });
            var trust = Trust(backend);
            await trust.StartAsync();
            Assert.Equal("report-2", (await trust.ScanAsync()).ReportId);

            var slow = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/integrity/report"] = new List<object> { Refusal("too_many", 429, Obj("{\"retry_after_seconds\":30}")) },
            });
            var other = Trust(slow);
            await other.StartAsync();
            await Assert.ThrowsAsync<ApiException>(() => other.ScanAsync());
            Assert.Single(slow.Paths, p => p == "/v1/integrity/report");
        }

        [Fact]
        public async Task A_refusal_outside_the_guide_goes_to_the_app_as_it_came()
        {
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/installations/register"] = new List<object> { Refusal("try_again_later", 409) },
            });
            var error = await Assert.ThrowsAsync<ApiException>(() => Trust(backend).StartAsync());
            Assert.Equal("try_again_later", error.Code);
            Assert.Equal(new[] { "/v1/installations/register" }, backend.Paths);
        }

        [Fact]
        public async Task A_signed_request_the_person_approves_first_the_request_proof_after_on_the_same_nonce_the_pins_proof_and_the_report_join_it()
        {
            var backend = new Backend(new Dictionary<string, List<object>>
            {
                ["/v1/pay"] = new List<object> { Obj("{\"paid\":true}") },
            });
            var key = new StepUpKeyFake();
            var trust = Trust(backend, stepUpKey: key, stepUp: new StepUpOptions(), appPin: new AppPinOptions());
            await trust.StartAsync();
            var proof = await trust.SignRequestAsync(
                "post",
                "/v1/pay",
                "account-session",
                "{\"amount\":5}",
                stepUp: true,
                reason: "Approve the payment",
                appPin: "246810",
                reportId: "report-1");
            var access = Decoded(proof.Headers["X-Access-Proof"]);
            var stepUp = Decoded(proof.Headers["X-Step-Up-Proof"]);
            Assert.Equal((string?)access["nonce"], (string?)stepUp["nonce"]);
            Assert.Equal("POST", (string?)stepUp["method"]);
            Assert.Equal("passcode", (string?)stepUp["factor"]);
            Assert.Equal("approved", proof.Headers["X-Step-Up-Signature"]);
            Assert.Equal("Approve the payment", key.Reason);
            Assert.Equal("pin-proof", proof.Headers["X-App-PIN-Proof"]);
            Assert.Equal("report-1", proof.Headers["X-Integrity-Report"]);
            var pin = backend.Calls[^1];
            Assert.Equal("/v1/account/app-pin/proof", pin.Path);
            Assert.Equal("account-session", pin.Bearer);
            var expected = new JsonObject
            {
                ["pin"] = "246810",
                ["request"] = new JsonObject
                {
                    ["method"] = "POST",
                    ["path"] = "/v1/pay",
                    ["query"] = string.Empty,
                    ["body_sha256"] = Wire.Sha256Hex("{\"amount\":5}"),
                    ["nonce"] = (string?)access["nonce"],
                },
            };
            Assert.True(JsonNode.DeepEquals(expected, pin.Body), pin.Body.ToJsonString());
            await trust.SendAsync(proof);
            Assert.Equal("/v1/pay", backend.Calls[^1].Path);
            Assert.Equal(proof.Headers, backend.Calls[^1].Headers);
        }

        [Fact]
        public async Task Step_up_and_the_app_pin_are_options_off_they_refuse()
        {
            var trust = Trust(new Backend());
            await trust.StartAsync();
            await Assert.ThrowsAsync<NativeKeyException>(() => trust.SignRequestAsync("POST", "/p", "b", stepUp: true));
            await Assert.ThrowsAsync<InvalidOperationException>(() => trust.SignRequestAsync("POST", "/p", "b", appPin: "1"));
            await Assert.ThrowsAsync<InvalidOperationException>(() => trust.SetAppPinAsync("b", "1"));
        }

        [Fact]
        public async Task The_app_pin_is_set_with_the_reauthentication_the_app_gives()
        {
            var backend = new Backend();
            var trust = Trust(backend, appPin: new AppPinOptions());
            await trust.StartAsync();
            await trust.SetAppPinAsync("account-session", "246810", Obj("{\"password\":\"secret\"}"));
            Assert.Equal("/v1/account/app-pin", backend.Calls[^1].Path);
            Assert.Equal("account-session", backend.Calls[^1].Bearer);
            Assert.True(JsonNode.DeepEquals(Obj("{\"password\":\"secret\",\"pin\":\"246810\"}"), backend.Calls[^1].Body));
        }

        [Fact]
        public async Task A_phone_that_cannot_make_the_step_up_key_registers_without_it()
        {
            var backend = new Backend();
            var trust = Trust(
                backend,
                stepUp: new StepUpOptions(),
                stepUpKey: new StepUpKeyFake(new NativeKeyException("STEPUP_NO_DEVICE_CREDENTIAL", "no screen lock")));
            await trust.StartAsync();
            Assert.False(backend.Calls[0].Body.ContainsKey("stepup_public_key"));
            Assert.Equal("STEPUP_NO_DEVICE_CREDENTIAL", trust.StepUpUnavailable?.Code);
            Assert.Equal("installation-session", trust.InstallationSession);
        }

        [Fact]
        public async Task A_step_up_key_the_phone_could_not_make_at_registration_is_not_made_later_for_a_request_which_the_backend_could_not_check()
        {
            var backend = new Backend();
            var key = new FlakyStepUpKey();
            var trust = Trust(backend, stepUp: new StepUpOptions(), stepUpKey: key);
            await trust.StartAsync();
            Assert.False(backend.Calls[0].Body.ContainsKey("stepup_public_key"));
            var error = await Assert.ThrowsAsync<NativeKeyException>(() => trust.SignRequestAsync("POST", "/p", "b", stepUp: true));
            Assert.Equal("STEPUP_NO_DEVICE_CREDENTIAL", error.Code);
            Assert.Equal(1, key.Attempts);
        }

        [Fact]
        public void The_personal_measurements_are_the_published_contracts()
        {
            var schema = Obj(File.ReadAllText(RepositoryFiles.File("contract/report-1/android-8-ios-5/report.schema.json")));
            var enabled = schema["properties"]!["enabled_measurements"]!;
            Assert.Equal(
                ((JsonArray)enabled["items"]!["enum"]!).Select(n => (string)n!),
                PersonalMeasurements.All.Select(m => m.WireName()));
        }

        internal sealed class Call
        {
            public Call(string method, string path, JsonObject body, string? bearer, IReadOnlyDictionary<string, string> headers)
            {
                Method = method;
                Path = path;
                Body = body;
                Bearer = bearer;
                Headers = headers;
            }

            public string Method { get; }

            public string Path { get; }

            public JsonObject Body { get; }

            public string? Bearer { get; }

            public IReadOnlyDictionary<string, string> Headers { get; }
        }

        /// <summary>Answers each path from its queue, the last answer repeating; an ApiException in the queue is thrown.</summary>
        internal class Backend : IDeviceTrustTransport
        {
            private readonly Dictionary<string, List<object>> answers;
            private readonly object gate = new object();

            public Backend(Dictionary<string, List<object>>? answers = null)
            {
                this.answers = new Dictionary<string, List<object>>
                {
                    ["/v1/installations/register"] = new List<object> { Obj("{\"installation_id\":\"proposed-id\"}") },
                    ["/v1/installations/challenge"] = new List<object> { Obj("{\"challenge_id\":\"key-challenge\",\"payload\":\"cGF5\"}") },
                    ["/v1/installations/verify"] = new List<object> { Obj("{\"device_token\":\"installation-session\"}") },
                    ["/v1/integrity/challenge"] = new List<object>
                    {
                        Obj("{\"challenge_id\":\"scan-challenge\",\"nonce\":\"bm9uY2U\",\"platform\":\"android\",\"required_probes\":[\"app_identity\"],\"optional_probes\":[\"location\"]}"),
                    },
                    ["/v1/integrity/report"] = new List<object> { Obj("{\"integrity\":{\"report_id\":\"report-1\"}}") },
                    ["/v1/account/app-pin"] = new List<object> { Obj("{\"app_pin_set\":true}") },
                    ["/v1/account/app-pin/proof"] = new List<object> { Obj("{\"app_pin_proof\":\"pin-proof\"}") },
                    ["/v1/installations/stepup-key"] = new List<object> { Obj("{\"stepup_key_registered\":true}") },
                };
                if (answers is not null)
                {
                    foreach (var entry in answers)
                    {
                        this.answers[entry.Key] = entry.Value;
                    }
                }
            }

            public List<Call> Calls { get; } = new List<Call>();

            public List<string> Paths
            {
                get
                {
                    lock (gate)
                    {
                        return Calls.Select(call => call.Path).ToList();
                    }
                }
            }

            public virtual Task<JsonObject> SendAsync(
                string method,
                string path,
                string? encodedBody = null,
                string? bearerToken = null,
                IReadOnlyDictionary<string, string>? headers = null)
            {
                object next;
                lock (gate)
                {
                    Calls.Add(new Call(
                        method,
                        path,
                        string.IsNullOrEmpty(encodedBody) ? new JsonObject() : Obj(encodedBody),
                        bearerToken,
                        headers ?? new Dictionary<string, string>()));
                    var queue = answers[path];
                    next = queue[0];
                    if (queue.Count > 1)
                    {
                        queue.RemoveAt(0);
                    }
                }

                if (next is ApiException refusal)
                {
                    return Task.FromException<JsonObject>(refusal);
                }

                return Task.FromResult((JsonObject)((JsonObject)next).DeepClone());
            }

            public void Close()
            {
            }
        }

        /// <summary>Answers as <see cref="Backend"/> does, but holds the answer to one path until a gate opens.</summary>
        internal sealed class HeldBackend : Backend
        {
            private readonly string path;
            private readonly Task gate;

            public HeldBackend(string path, Task gate)
            {
                this.path = path;
                this.gate = gate;
            }

            public TaskCompletionSource<bool> Asked { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public override async Task<JsonObject> SendAsync(
                string method,
                string path,
                string? encodedBody = null,
                string? bearerToken = null,
                IReadOnlyDictionary<string, string>? headers = null)
            {
                if (path == this.path)
                {
                    Asked.TrySetResult(true);
                    await gate;
                }

                return await base.SendAsync(method, path, encodedBody, bearerToken, headers);
            }
        }

        private sealed class Key : INativeInstallationKey
        {
            public Task<NativeKeyMetadata> GetOrCreateKeyAsync() => Task.FromResult(Metadata());

            public Task<string> SignPayloadAsync(string payloadBase64Url) => Task.FromResult("signed");

            public Task DeleteKeyAsync() => Task.CompletedTask;
        }

        internal sealed class Store : InstallationStore
        {
            public Store()
                : base(new Key(), new InMemorySecureStorage())
            {
            }

            public string? Saved { get; private set; }

            public bool ReenrolPending { get; private set; }

            public override Task<InstallationIdentity> LoadOrCreateAsync() =>
                Task.FromResult(new InstallationIdentity("proposed-id", Key, Metadata()));

            public override Task SaveInstallationIdAsync(string installationId)
            {
                Saved = installationId;
                return Task.CompletedTask;
            }

            public override Task<bool> StepUpReenrolPendingAsync() => Task.FromResult(ReenrolPending);

            public override Task SetStepUpReenrolPendingAsync(bool pending)
            {
                ReenrolPending = pending;
                return Task.CompletedTask;
            }

            public override Task ClearAsync()
            {
                Saved = null;
                ReenrolPending = false;
                return Task.CompletedTask;
            }
        }

        internal sealed class Collector : INativeIntegrityCollector
        {
            public IReadOnlyList<string>? Enabled { get; private set; }

            public Task<JsonObject> CollectAsync(
                IReadOnlyList<string> requiredProbes,
                string challengeNonce,
                IReadOnlyList<string> enabledMeasurements,
                IReadOnlyList<string> optionalProbes)
            {
                Enabled = enabledMeasurements;
                var probes = new JsonObject();
                foreach (var probe in requiredProbes)
                {
                    probes[probe] = new JsonObject { ["status"] = "ok" };
                }

                return Task.FromResult(new JsonObject
                {
                    ["platform"] = "android",
                    ["challenge_nonce_echo"] = challengeNonce,
                    ["collector_version"] = 8,
                    ["probes"] = probes,
                });
            }

            public Task<string> RequestLocationPermissionAsync() => Task.FromResult("none");
        }

        private sealed class Hints : ReinstallHintReader
        {
            public override Task<ReinstallHint?> ReadAsync() => Task.FromResult<ReinstallHint?>(new ReinstallHint("android_id_sha256", "hint"));
        }

        internal class StepUpKeyFake : INativeStepUpKey
        {
            private readonly NativeKeyException? refuse;

            public StepUpKeyFake(NativeKeyException? refuse = null)
            {
                this.refuse = refuse;
            }

            public string ConfiguredMode { get; set; } = "per_use";

            public string? Reason { get; private set; }

            public virtual Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds)
            {
                if (refuse is not null)
                {
                    return Task.FromException<StepUpKeyMetadata>(refuse);
                }

                return Task.FromResult(new StepUpKeyMetadata(
                    Obj("{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"sx\",\"y\":\"sy\"}"),
                    factor,
                    mode,
                    windowSeconds,
                    "trusted_execution_environment",
                    true,
                    true));
            }

            public virtual Task<string> SignAsync(string payloadBase64Url, string reason)
            {
                Reason = reason;
                return Task.FromResult("approved");
            }

            // No native side: as the plugin's channel answers in a test.
            public virtual Task DeleteKeyAsync() =>
                Task.FromException(new NativeKeyException("NATIVE_STEPUP_PLUGIN_MISSING", "no native side"));
        }

        /// <summary>A key that died with the screen lock: its first signature fails, and a new one is made once it is deleted.</summary>
        internal class DyingStepUpKey : StepUpKeyFake
        {
            public int Deleted { get; private set; }

            public override Task<string> SignAsync(string payloadBase64Url, string reason)
            {
                if (Deleted == 0)
                {
                    return Task.FromException<string>(new NativeKeyException("STEPUP_KEY_INVALIDATED", "the lock was removed"));
                }

                return base.SignAsync(payloadBase64Url, reason);
            }

            public override Task DeleteKeyAsync()
            {
                Deleted += 1;
                return Task.CompletedTask;
            }
        }

        /// <summary>A key the keystore cannot vouch for (STEPUP_KEY_UNAVAILABLE) until it is replaced.</summary>
        internal sealed class UnavailableStepUpKey : StepUpKeyFake
        {
            public int Deleted { get; private set; }

            public override Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds)
            {
                if (Deleted == 0)
                {
                    return Task.FromException<StepUpKeyMetadata>(new NativeKeyException(
                        "STEPUP_KEY_UNAVAILABLE",
                        "the keystore could not say whether the key is usable"));
                }

                return base.GetOrCreateKeyAsync(factor, mode, windowSeconds);
            }

            public override Task DeleteKeyAsync()
            {
                Deleted += 1;
                return Task.CompletedTask;
            }
        }

        /// <summary>A dying key whose first prompt after its replacement is cancelled.</summary>
        internal sealed class CancelledStepUpKey : DyingStepUpKey
        {
            private bool cancelled;

            public override Task<string> SignAsync(string payloadBase64Url, string reason)
            {
                if (Deleted > 0 && !cancelled)
                {
                    cancelled = true;
                    return Task.FromException<string>(new NativeKeyException("STEPUP_CANCELLED", "the person cancelled"));
                }

                return base.SignAsync(payloadBase64Url, reason);
            }
        }

        /// <summary>Refuses the first key it is asked for, then makes one.</summary>
        internal sealed class FlakyStepUpKey : StepUpKeyFake
        {
            public int Attempts { get; private set; }

            public override Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds)
            {
                Attempts += 1;
                if (Attempts == 1)
                {
                    return Task.FromException<StepUpKeyMetadata>(new NativeKeyException("STEPUP_NO_DEVICE_CREDENTIAL", "no screen lock yet"));
                }

                return base.GetOrCreateKeyAsync(factor, mode, windowSeconds);
            }
        }
    }
}
