// The installation across a phone's life: the first start, a restart, a key
// the platform lost (an Android reinstall), and an iOS reinstall that kept the
// key but not the app's other data -- two of the package's calls at once, and
// a reset or a close while calls still run.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Xunit;

namespace Necessary.Tests
{
    public class InstallationLifecycleTests
    {
        private const string Stored = InstallationStore.InstallationIdKey;

        private static JsonObject Obj(string json) => (JsonObject)JsonNode.Parse(json)!;

        private static async Task<string?> StoredId(ISecureStorage storage) => await storage.ReadAsync(Stored);

        [Fact]
        public async Task The_first_start_makes_the_key_and_an_installation_id_a_restart_finds_both()
        {
            var storage = new InMemorySecureStorage();
            var keystore = new Keystore(holds: false);
            var first = await new InstallationStore(keystore, storage).LoadOrCreateAsync();
            Assert.True(first.CreatedThisLaunch);
            Assert.Equal(first.InstallationId, await StoredId(storage));
            var restarted = await new InstallationStore(keystore, storage).LoadOrCreateAsync();
            Assert.False(restarted.CreatedThisLaunch);
            Assert.Equal(first.InstallationId, restarted.InstallationId);
        }

        [Fact]
        public async Task A_key_the_platform_lost_is_a_new_installation_under_a_new_id()
        {
            var storage = new InMemorySecureStorage(new[] { new KeyValuePair<string, string>(Stored, "old-installation") });
            var identity = await new InstallationStore(new Keystore(holds: false), storage).LoadOrCreateAsync();
            Assert.True(identity.CreatedThisLaunch);
            Assert.NotEqual("old-installation", identity.InstallationId);
            Assert.Equal(identity.InstallationId, await StoredId(storage));
        }

        [Fact]
        public async Task A_key_kept_without_its_id_proposes_a_new_one_and_keeps_the_one_the_backend_holds_for_the_key()
        {
            var storage = new InMemorySecureStorage();
            var store = new InstallationStore(new Keystore(holds: true), storage);
            var proposed = await store.LoadOrCreateAsync();
            Assert.False(proposed.CreatedThisLaunch);
            var trust = DeviceTrust.Over(new Backend(), store: store, collector: new Collector(), hintReader: new NoHint());
            await trust.StartAsync();
            Assert.Equal("held", trust.Identity!.InstallationId);
            Assert.Equal("held", await StoredId(storage));
        }

        [Fact]
        public async Task Reset_deletes_the_key_and_the_id_the_next_start_is_a_new_installation()
        {
            var storage = new InMemorySecureStorage();
            var keystore = new Keystore(holds: false);
            var trust = DeviceTrust.Over(
                new Backend(),
                store: new InstallationStore(keystore, storage),
                collector: new Collector(),
                hintReader: new NoHint());
            await trust.StartAsync();
            await trust.ResetAsync();
            Assert.False(keystore.Holds);
            Assert.Null(await StoredId(storage));
            Assert.Null(trust.Identity);
            Assert.Null(trust.InstallationSession);
            Assert.True((await trust.LoadIdentityAsync()).CreatedThisLaunch);
        }

        [Fact]
        public async Task Two_calls_of_one_kind_at_once_share_one_run_other_scans_run_apart()
        {
            var backend = new Backend();
            var trust = DeviceTrust.Over(
                backend,
                store: new InstallationStore(new Keystore(holds: false), new InMemorySecureStorage()),
                collector: new Collector(),
                hintReader: new NoHint());
            var started = await Task.WhenAll(trust.StartAsync(), trust.StartAsync());
            Assert.Same(started[0], started[1]);
            Assert.Single(backend.Paths, p => p == "/v1/installations/register");
            Assert.Single(backend.Paths, p => p == "/v1/installations/verify");

            backend.ClearPaths();
            var pay = RequestProofs.DescribeOperation("POST", "/v1/pay", "{}");
            var payee = RequestProofs.DescribeOperation("POST", "/v1/payee", "{}");
            var scans = await Task.WhenAll(
                trust.ScanAsync(),
                trust.ScanAsync(),
                trust.ScanAsync("account", pay),
                trust.ScanAsync("account", payee));
            Assert.Same(scans[0], scans[1]);
            Assert.Equal(3, backend.Paths.Count(p => p == "/v1/integrity/challenge"));
            Assert.Equal(3, backend.Paths.Count(p => p == "/v1/integrity/report"));
        }

        [Fact]
        public async Task A_reset_while_start_waits_for_its_key_challenges_answer_the_old_answer_is_kept_nowhere_and_a_new_start_never_joins_the_old_one()
        {
            var storage = new InMemorySecureStorage();
            var backend = new HeldBackend();
            var trust = DeviceTrust.Over(
                backend,
                store: new InstallationStore(new Keystore(holds: false), storage),
                collector: new Collector(),
                hintReader: new NoHint());
            var verify = backend.Hold("/v1/installations/verify");
            var old = Assert.ThrowsAsync<InterruptedCallException>(() => trust.StartAsync());
            await backend.Asked("/v1/installations/verify");
            await trust.ResetAsync();
            var fresh = await trust.StartAsync();
            Assert.Equal("session-1", trust.InstallationSession);
            verify.SetResult(true);
            await old;
            Assert.Equal("session-1", trust.InstallationSession);
            Assert.Equal(fresh.InstallationId, trust.Identity!.InstallationId);
            Assert.Equal(fresh.InstallationId, await StoredId(storage));
        }

        [Fact]
        public async Task A_reset_while_start_waits_for_its_registration_the_id_the_old_answer_names_is_never_kept()
        {
            var storage = new InMemorySecureStorage();
            var backend = new HeldBackend();
            var trust = DeviceTrust.Over(
                backend,
                store: new InstallationStore(new Keystore(holds: false), storage),
                collector: new Collector(),
                hintReader: new NoHint());
            var register = backend.Hold("/v1/installations/register");
            var old = Assert.ThrowsAsync<InterruptedCallException>(() => trust.StartAsync());
            await backend.Asked("/v1/installations/register");
            await trust.ResetAsync();
            var fresh = await trust.StartAsync();
            Assert.Equal("held-1", fresh.InstallationId);
            register.SetResult(true);
            await old;
            Assert.Equal("held-1", trust.Identity!.InstallationId);
            Assert.Equal("held-1", await StoredId(storage));
        }

        [Fact]
        public async Task A_keystore_that_cannot_be_reached_leaves_the_installation_as_it_was()
        {
            // start() fails with KEY_UNAVAILABLE and sends nothing, and the ID is
            // kept for the key once the keystore answers.
            var storage = new InMemorySecureStorage(new[] { new KeyValuePair<string, string>(Stored, "kept-installation") });
            var keystore = new UnreachableKeystore();
            var backend = new Backend();
            var trust = DeviceTrust.Over(backend, store: new InstallationStore(keystore, storage), collector: new Collector(), hintReader: new NoHint());
            var refused = await Assert.ThrowsAsync<NativeKeyException>(() => trust.StartAsync());
            Assert.Equal("KEY_UNAVAILABLE", refused.Code);
            Assert.Empty(backend.Paths);
            Assert.Equal("kept-installation", await StoredId(storage));
            Assert.True(keystore.Holds);
            keystore.Reachable = true;
            var again = await new InstallationStore(keystore, storage).LoadOrCreateAsync();
            Assert.False(again.CreatedThisLaunch);
            Assert.Equal("kept-installation", again.InstallationId);
        }

        [Fact]
        public async Task A_reset_while_the_old_registration_writes_the_step_up_marker_waits_for_the_write_and_the_marker_never_outlives_it()
        {
            var store = new HeldMarkerStore(new InMemorySecureStorage());
            var trust = DeviceTrust.Over(
                new Backend(),
                stepUp: new StepUpOptions(),
                store: store,
                collector: new Collector(),
                hintReader: new NoHint(),
                stepUpKey: new StepUpKeystore());
            var old = Assert.ThrowsAsync<InterruptedCallException>(() => trust.StartAsync());
            await store.Reached.Task;
            var reset = false;
            var resetting = trust.ResetAsync().ContinueWith(_ => reset = true, TaskScheduler.Default);
            await Task.Delay(50);
            Assert.False(reset, "the reset waits for the write in flight");
            store.GoOn.SetResult(true);
            await resetting;
            await old;
            Assert.False(await store.StepUpReenrolPendingAsync());
        }

        [Fact]
        public async Task A_reset_while_a_request_is_signed_the_proof_is_never_handed_out()
        {
            var key = new HeldSigningKeystore();
            var trust = DeviceTrust.Over(new Backend(), store: new InstallationStore(key, new InMemorySecureStorage()), collector: new Collector(), hintReader: new NoHint());
            await trust.StartAsync();
            key.Hold = true;
            var signing = Assert.ThrowsAsync<InterruptedCallException>(() => trust.SignRequestAsync("POST", "/v1/pay", "session"));
            await key.Reached.Task;
            await trust.ResetAsync();
            key.GoOn.SetResult(true);
            await signing;
        }

        [Fact]
        public async Task A_step_up_key_the_keystore_will_not_delete_fails_the_reset_the_installation_gone_all_the_same_none_to_delete_fails_nothing()
        {
            var storage = new InMemorySecureStorage();
            var trust = DeviceTrust.Over(
                new Backend(),
                stepUp: new StepUpOptions(),
                store: new InstallationStore(new Keystore(holds: false), storage),
                collector: new Collector(),
                hintReader: new NoHint(),
                stepUpKey: new StepUpKeystore(makes: true, deleteFails: "KEY_DELETE_FAILED"));
            await trust.StartAsync();
            var refused = await Assert.ThrowsAsync<NativeKeyException>(() => trust.ResetAsync());
            Assert.Equal("KEY_DELETE_FAILED", refused.Code);
            Assert.Null(trust.Identity);
            Assert.Null(await StoredId(storage));
            var plain = DeviceTrust.Over(
                new Backend(),
                stepUp: new StepUpOptions(),
                store: new InstallationStore(new Keystore(holds: false), new InMemorySecureStorage()),
                collector: new Collector(),
                hintReader: new NoHint(),
                stepUpKey: new StepUpKeystore(deleteFails: "NATIVE_STEPUP_PLUGIN_MISSING"));
            await plain.StartAsync();
            await plain.ResetAsync();
        }

        [Fact]
        public async Task A_reset_while_a_scan_collects_its_report_is_never_sent()
        {
            var backend = new Backend();
            var collector = new HeldCollector();
            var trust = DeviceTrust.Over(
                backend,
                store: new InstallationStore(new Keystore(holds: false), new InMemorySecureStorage()),
                collector: collector,
                hintReader: new NoHint());
            await trust.StartAsync();
            var scan = Assert.ThrowsAsync<InterruptedCallException>(() => trust.ScanAsync());
            await collector.Reached.Task;
            await trust.ResetAsync();
            collector.GoOn.SetResult(true);
            await scan;
            Assert.DoesNotContain("/v1/integrity/report", backend.Paths);
        }

        [Fact]
        public async Task Close_while_start_runs_the_call_keeps_nothing()
        {
            var backend = new HeldBackend();
            var trust = DeviceTrust.Over(
                backend,
                store: new InstallationStore(new Keystore(holds: false), new InMemorySecureStorage()),
                collector: new Collector(),
                hintReader: new NoHint());
            var verify = backend.Hold("/v1/installations/verify");
            var started = Assert.ThrowsAsync<InterruptedCallException>(() => trust.StartAsync());
            await backend.Asked("/v1/installations/verify");
            trust.Close();
            verify.SetResult(true);
            await started;
            Assert.Null(trust.InstallationSession);
        }

        [Fact]
        public async Task The_store_itself_asked_twice_at_once_makes_one_id_for_one_key()
        {
            var storage = new InMemorySecureStorage();
            var store = new InstallationStore(new Keystore(holds: false), storage);
            var loaded = await Task.WhenAll(store.LoadOrCreateAsync(), store.LoadOrCreateAsync());
            Assert.Equal(loaded[0].InstallationId, loaded[1].InstallationId);
            Assert.Equal(loaded[0].InstallationId, await StoredId(storage));
        }

        [Fact]
        public async Task Two_first_loads_at_once_load_once_one_key_one_installation_id()
        {
            var storage = new InMemorySecureStorage();
            var store = new CountingStore(storage);
            var trust = DeviceTrust.Over(new Backend(), store: store, collector: new Collector(), hintReader: new NoHint());
            var loaded = await Task.WhenAll(trust.LoadIdentityAsync(), trust.LoadIdentityAsync());
            Assert.Same(loaded[0], loaded[1]);
            Assert.Equal(1, store.Loads);
            Assert.Equal(loaded[0].InstallationId, await StoredId(storage));
        }

        [Fact]
        public async Task A_scan_asked_after_the_personal_measurements_changed_never_joins_one_asked_before()
        {
            var backend = new Backend();
            var collector = new HeldCollector();
            var trust = DeviceTrust.Over(
                backend,
                store: new InstallationStore(new Keystore(holds: false), new InMemorySecureStorage()),
                collector: collector,
                hintReader: new NoHint());
            await trust.StartAsync();
            var before = trust.ScanAsync();
            await collector.Reached.Task;
            trust.PersonalMeasurements = new[] { PersonalMeasurement.Location };
            var after = trust.ScanAsync();
            Assert.NotSame(before, after);
            collector.GoOn.SetResult(true);
            var scans = await Task.WhenAll(before, after);
            Assert.Equal(2, collector.Enabled.Count);
            Assert.Empty(collector.Enabled[0]);
            Assert.Equal(new[] { "location" }, collector.Enabled[1]);
            Assert.Equal(
                new[] { "location" },
                ((JsonArray)scans[1].Report.Report["enabled_measurements"]!).Select(n => (string)n!));
        }

        /// <summary>A platform keystore holding, or not holding, the installation key.</summary>
        private sealed class Keystore : INativeInstallationKey
        {
            public Keystore(bool holds)
            {
                Holds = holds;
            }

            public bool Holds { get; private set; }

            public Task<NativeKeyMetadata> GetOrCreateKeyAsync()
            {
                var created = !Holds;
                Holds = true;
                return Task.FromResult(new NativeKeyMetadata(
                    Obj("{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"x\",\"y\":\"y\"}"),
                    "ES256",
                    "test",
                    "AndroidKeyStore",
                    "trusted_execution_environment",
                    true,
                    false,
                    "der",
                    created));
            }

            public Task<string> SignPayloadAsync(string payloadBase64Url) => Task.FromResult("signed");

            public Task DeleteKeyAsync()
            {
                Holds = false;
                return Task.CompletedTask;
            }
        }

        /// <summary>A keystore that holds the key but cannot be reached at first: the Android side then answers KEY_UNAVAILABLE and makes no key.</summary>
        private sealed class UnreachableKeystore : INativeInstallationKey
        {
            private readonly Keystore inner = new Keystore(holds: true);

            public bool Reachable { get; set; }

            public bool Holds => inner.Holds;

            public Task<NativeKeyMetadata> GetOrCreateKeyAsync() =>
                Reachable
                    ? inner.GetOrCreateKeyAsync()
                    : Task.FromException<NativeKeyMetadata>(new NativeKeyException(
                        "KEY_UNAVAILABLE",
                        "AndroidKeyStore could not be reached for the installation key; the key was kept, never replaced."));

            public Task<string> SignPayloadAsync(string payloadBase64Url) => inner.SignPayloadAsync(payloadBase64Url);

            public Task DeleteKeyAsync() => inner.DeleteKeyAsync();
        }

        /// <summary>A keystore whose signatures wait, once <see cref="Hold"/> is set, until <see cref="GoOn"/>.</summary>
        private sealed class HeldSigningKeystore : INativeInstallationKey
        {
            private readonly Keystore inner = new Keystore(holds: false);

            public bool Hold { get; set; }

            public TaskCompletionSource<bool> Reached { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public TaskCompletionSource<bool> GoOn { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public Task<NativeKeyMetadata> GetOrCreateKeyAsync() => inner.GetOrCreateKeyAsync();

            public async Task<string> SignPayloadAsync(string payloadBase64Url)
            {
                if (Hold)
                {
                    Reached.TrySetResult(true);
                    await GoOn.Task;
                }

                return await inner.SignPayloadAsync(payloadBase64Url);
            }

            public Task DeleteKeyAsync() => inner.DeleteKeyAsync();
        }

        /// <summary>A store whose first step-up marker write waits until <see cref="GoOn"/>.</summary>
        private sealed class HeldMarkerStore : InstallationStore
        {
            public HeldMarkerStore(ISecureStorage storage)
                : base(new Keystore(holds: false), storage)
            {
            }

            public TaskCompletionSource<bool> Reached { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public TaskCompletionSource<bool> GoOn { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public override async Task SetStepUpReenrolPendingAsync(bool pending)
            {
                if (Reached.TrySetResult(true))
                {
                    await GoOn.Task;
                }

                await base.SetStepUpReenrolPendingAsync(pending);
            }
        }

        /// <summary>A phone that makes no step-up key; or, given a code, one whose key the keystore will not delete.</summary>
        private sealed class StepUpKeystore : INativeStepUpKey
        {
            private readonly bool makes;
            private readonly string? deleteFails;

            public StepUpKeystore(bool makes = false, string? deleteFails = null)
            {
                this.makes = makes;
                this.deleteFails = deleteFails;
            }

            public string ConfiguredMode { get; set; } = "per_use";

            public Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds) =>
                makes
                    ? Task.FromResult(new StepUpKeyMetadata(
                        Obj("{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"sx\",\"y\":\"sy\"}"),
                        factor,
                        mode,
                        windowSeconds,
                        "trusted_execution_environment",
                        true,
                        true))
                    : Task.FromException<StepUpKeyMetadata>(new NativeKeyException("STEPUP_UNAVAILABLE", "no screen lock"));

            public Task<string> SignAsync(string payloadBase64Url, string reason) => Task.FromResult("approved");

            public Task DeleteKeyAsync() =>
                deleteFails is null ? Task.CompletedTask : Task.FromException(new NativeKeyException(deleteFails, "the keystore refused"));
        }

        /// <summary>Answers as the guide says; counts what it was asked.</summary>
        private class Backend : IDeviceTrustTransport
        {
            private readonly object gate = new object();
            private readonly List<string> paths = new List<string>();

            public List<string> Paths
            {
                get
                {
                    lock (gate)
                    {
                        return paths.ToList();
                    }
                }
            }

            public void ClearPaths()
            {
                lock (gate)
                {
                    paths.Clear();
                }
            }

            public virtual async Task<JsonObject> SendAsync(
                string method,
                string path,
                string? encodedBody = null,
                string? bearerToken = null,
                IReadOnlyDictionary<string, string>? headers = null)
            {
                lock (gate)
                {
                    paths.Add(path);
                }

                await Task.Yield();
                return path switch
                {
                    "/v1/installations/register" => Obj("{\"installation_id\":\"held\"}"),
                    "/v1/installations/challenge" => Obj("{\"challenge_id\":\"k\",\"payload\":\"cA\"}"),
                    "/v1/installations/verify" => Obj("{\"device_token\":\"session\"}"),
                    "/v1/integrity/challenge" => Obj("{\"challenge_id\":\"s\",\"nonce\":\"bg\",\"platform\":\"android\",\"required_probes\":[\"app_identity\"]}"),
                    _ => Obj("{\"integrity\":{\"report_id\":\"r\"}}"),
                };
            }

            public void Close()
            {
            }
        }

        /// <summary>
        /// Answers as <see cref="Backend"/> does, but with a new installation ID
        /// and a new session each time, in the order answered; and holds the
        /// answer to a path while a test says so.
        /// </summary>
        private sealed class HeldBackend : Backend
        {
            private readonly object gate = new object();
            private readonly Dictionary<string, TaskCompletionSource<bool>> held = new Dictionary<string, TaskCompletionSource<bool>>();
            private readonly Dictionary<string, TaskCompletionSource<bool>> asked = new Dictionary<string, TaskCompletionSource<bool>>();
            private int registered;
            private int proved;

            /// <summary>The next request to <paramref name="path"/> waits for the source's completion.</summary>
            public TaskCompletionSource<bool> Hold(string path)
            {
                var source = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                lock (gate)
                {
                    held[path] = source;
                }

                return source;
            }

            /// <summary>Completes once <paramref name="path"/> has been asked.</summary>
            public Task Asked(string path) => AskedSource(path).Task;

            public override async Task<JsonObject> SendAsync(
                string method,
                string path,
                string? encodedBody = null,
                string? bearerToken = null,
                IReadOnlyDictionary<string, string>? headers = null)
            {
                AskedSource(path).TrySetResult(true);
                TaskCompletionSource<bool>? hold;
                lock (gate)
                {
                    if (held.TryGetValue(path, out hold))
                    {
                        held.Remove(path);
                    }
                }

                if (hold is not null)
                {
                    await hold.Task;
                }

                var answer = await base.SendAsync(method, path, encodedBody, bearerToken, headers);
                return path switch
                {
                    "/v1/installations/register" => Obj("{\"installation_id\":\"held-" + Interlocked(ref registered) + "\"}"),
                    "/v1/installations/verify" => Obj("{\"device_token\":\"session-" + Interlocked(ref proved) + "\"}"),
                    _ => answer,
                };
            }

            private static string Interlocked(ref int counter) =>
                System.Threading.Interlocked.Increment(ref counter).ToString(System.Globalization.CultureInfo.InvariantCulture);

            private TaskCompletionSource<bool> AskedSource(string path)
            {
                lock (gate)
                {
                    if (!asked.TryGetValue(path, out var source))
                    {
                        source = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                        asked[path] = source;
                    }

                    return source;
                }
            }
        }

        private class Collector : INativeIntegrityCollector
        {
            public virtual Task<JsonObject> CollectAsync(
                IReadOnlyList<string> requiredProbes,
                string challengeNonce,
                IReadOnlyList<string> enabledMeasurements,
                IReadOnlyList<string> optionalProbes) =>
                Task.FromResult(new JsonObject
                {
                    ["platform"] = "android",
                    ["challenge_nonce_echo"] = challengeNonce,
                    ["collector_version"] = 8,
                    ["probes"] = new JsonObject { ["app_identity"] = new JsonObject { ["status"] = "ok" } },
                });

            public Task<string> RequestLocationPermissionAsync() => Task.FromResult("none");
        }

        private sealed class NoHint : ReinstallHintReader
        {
            public override Task<ReinstallHint?> ReadAsync() => Task.FromResult<ReinstallHint?>(null);
        }

        /// <summary>A collector that waits, at its first collection, until the test lets it go on; and notes what each collection was allowed to measure.</summary>
        private sealed class HeldCollector : Collector
        {
            private readonly object gate = new object();

            public TaskCompletionSource<bool> Reached { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public TaskCompletionSource<bool> GoOn { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public List<IReadOnlyList<string>> Enabled { get; } = new List<IReadOnlyList<string>>();

            public override async Task<JsonObject> CollectAsync(
                IReadOnlyList<string> requiredProbes,
                string challengeNonce,
                IReadOnlyList<string> enabledMeasurements,
                IReadOnlyList<string> optionalProbes)
            {
                lock (gate)
                {
                    Enabled.Add(enabledMeasurements);
                }

                Reached.TrySetResult(true);
                await GoOn.Task;
                return await base.CollectAsync(requiredProbes, challengeNonce, enabledMeasurements, optionalProbes);
            }
        }

        /// <summary>A store that counts its loads, each taking a moment.</summary>
        private sealed class CountingStore : InstallationStore
        {
            public CountingStore(ISecureStorage storage)
                : base(new Keystore(holds: false), storage)
            {
            }

            public int Loads { get; private set; }

            public override async Task<InstallationIdentity> LoadOrCreateAsync()
            {
                Loads++;
                await Task.Delay(5);
                return await base.LoadOrCreateAsync();
            }
        }
    }
}
