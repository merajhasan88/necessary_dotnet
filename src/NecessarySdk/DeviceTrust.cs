using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// The personal measurements an app may enable (the public guide, section
    /// 8). Each is collected only when the backend asks for it as well -- the
    /// location only with the person's permission too.
    /// </summary>
    public enum PersonalMeasurement
    {
        /// <summary><c>local_addresses</c>: the phone's own IP addresses, link-local ones left out.</summary>
        LocalAddresses,

        /// <summary><c>accessibility</c>: the Accessibility services that are on, and the keyboard in use (Android).</summary>
        Accessibility,

        /// <summary><c>notification_access</c>: the apps allowed to read notifications (Android).</summary>
        NotificationAccess,

        /// <summary><c>other_access</c>: device-administrator apps, and known remote-control apps installed (Android).</summary>
        OtherAccess,

        /// <summary><c>screen_capture</c>: the screen being recorded, mirrored or cast.</summary>
        ScreenCapture,

        /// <summary><c>location</c>: the last location the phone already knows -- never a fresh fix, never a prompt.</summary>
        Location,

        /// <summary><c>mock_location</c>: whether that location was faked.</summary>
        MockLocation,
    }

    /// <summary>The names the report and the backend use.</summary>
    public static class PersonalMeasurements
    {
        /// <summary>Every personal measurement, in the guide's order.</summary>
        public static IReadOnlyList<PersonalMeasurement> All { get; } = new[]
        {
            PersonalMeasurement.LocalAddresses,
            PersonalMeasurement.Accessibility,
            PersonalMeasurement.NotificationAccess,
            PersonalMeasurement.OtherAccess,
            PersonalMeasurement.ScreenCapture,
            PersonalMeasurement.Location,
            PersonalMeasurement.MockLocation,
        };

        /// <summary>The name the report and the backend use.</summary>
        public static string WireName(this PersonalMeasurement measurement) => measurement switch
        {
            PersonalMeasurement.LocalAddresses => "local_addresses",
            PersonalMeasurement.Accessibility => "accessibility",
            PersonalMeasurement.NotificationAccess => "notification_access",
            PersonalMeasurement.OtherAccess => "other_access",
            PersonalMeasurement.ScreenCapture => "screen_capture",
            PersonalMeasurement.Location => "location",
            PersonalMeasurement.MockLocation => "mock_location",
            _ => throw new ArgumentOutOfRangeException(nameof(measurement)),
        };
    }

    /// <summary>Where the backend takes the app PIN's two calls (the public guide, section 4).</summary>
    public sealed class AppPinOptions
    {
        /// <summary>The app PIN's paths; by default the guide's.</summary>
        public AppPinOptions(string path = DeviceTrustClient.AppPinPath, string proofPath = DeviceTrustClient.AppPinProofPath)
        {
            Path = path;
            ProofPath = proofPath;
        }

        /// <summary>Where the PIN is set.</summary>
        public string Path { get; }

        /// <summary>Where the PIN is proved for one request.</summary>
        public string ProofPath { get; }
    }

    /// <summary>One scan: the challenge it answered, the report as signed, and the backend's answer, whole.</summary>
    public sealed class ScanResult
    {
        /// <summary>A scan.</summary>
        public ScanResult(ScanChallenge challenge, SignedReport report, JsonObject answer)
        {
            Challenge = challenge;
            Report = report;
            Answer = answer;
        }

        /// <summary>The challenge it answered.</summary>
        public ScanChallenge Challenge { get; }

        /// <summary>The report, as signed.</summary>
        public SignedReport Report { get; }

        /// <summary>Your backend's answer, whole.</summary>
        public JsonObject Answer { get; }

        /// <summary>
        /// The stored report (<c>integrity.report_id</c>), which a scan made for
        /// one request sends back with that request.
        /// </summary>
        public string? ReportId => Answer["integrity"] is JsonObject integrity ? Json.String(integrity["report_id"]) : null;
    }

    /// <summary>
    /// The one object an app configures -- its backend, the personal
    /// measurements it enables, step-up and the app PIN -- and what it asks of
    /// it: start, scan, and sign a request (the public guide).
    /// </summary>
    /// <remarks>
    /// One installation at a time: <see cref="ResetAsync"/> and
    /// <see cref="Close"/> move on to a new generation, and a call of an earlier
    /// one ends with <see cref="InterruptedCallException"/>, keeping nothing.
    /// Calls at once share their run: <see cref="StartAsync"/>,
    /// <see cref="ProveAsync"/>, <see cref="LoadIdentityAsync"/> and the same
    /// <see cref="ScanAsync"/>. The object's own work runs one step at a time,
    /// in order, on a scheduler of its own, so <see cref="OnRegistered"/> is called there,
    /// not on the caller's thread.
    /// </remarks>
    public sealed class DeviceTrust : IDisposable
    {
        private readonly ConcurrentExclusiveSchedulerPair schedulers = new ConcurrentExclusiveSchedulerPair();
        private readonly InstallationStore store;
        private readonly INativeIntegrityCollector collector;
        private readonly ReinstallHintReader hintReader;
        private readonly INativeStepUpKey stepUpKey;
        private readonly Dictionary<string, Task<ScanResult>> scanning = new Dictionary<string, Task<ScanResult>>(StringComparer.Ordinal);

        private volatile InstallationIdentity? identity;
        private volatile string? session;
        private volatile StepUpKeyMetadata? offeredStepUpKey;
        private volatile NativeKeyException? stepUpUnavailable;
        private volatile IReadOnlyCollection<PersonalMeasurement> personalMeasurements;
        private volatile StepUpOptions? stepUp;

        // One call of each kind in flight; a second waits for the first's result.
        private Task<InstallationIdentity>? loading;
        private Task<InstallationIdentity>? starting;
        private Task<string>? proving;

        // Which installation the calls running now belong to: reset and close
        // move on to the next, and a call of an earlier one keeps nothing it finds.
        private int generation;

        // A reset's deletion, which every later load waits for; and the
        // installation ID being saved and a re-enrolment, which a reset waits for.
        private Task? resetting;
        private Task? saving;
        private Task? reenrolling;

        // The persistent writes and key changes running now (Mutate): a reset
        // waits for each before it deletes, so none outlives the deletion.
        private readonly HashSet<Task> mutations = new HashSet<Task>();
        private ReinstallHint? hint;
        private bool hintRead;

        /// <summary>
        /// Device trust over JSON and HTTPS under <paramref name="baseUrl"/>, the
        /// plugin's default API (the public guide, section 4).
        /// </summary>
        public DeviceTrust(
            string baseUrl,
            IEnumerable<PersonalMeasurement>? personalMeasurements = null,
            StepUpOptions? stepUp = null,
            AppPinOptions? appPin = null,
            Func<JsonObject, Task>? onRegistered = null)
            : this(new HttpTransport(baseUrl), personalMeasurements, stepUp, appPin, onRegistered, null, null, null, null)
        {
        }

        private DeviceTrust(
            IDeviceTrustTransport transport,
            IEnumerable<PersonalMeasurement>? personalMeasurements,
            StepUpOptions? stepUp,
            AppPinOptions? appPin,
            Func<JsonObject, Task>? onRegistered,
            InstallationStore? store,
            INativeIntegrityCollector? collector,
            ReinstallHintReader? hintReader,
            INativeStepUpKey? stepUpKey)
        {
            Client = new DeviceTrustClient(transport);
            this.personalMeasurements = new HashSet<PersonalMeasurement>(personalMeasurements ?? Array.Empty<PersonalMeasurement>());
            this.stepUp = stepUp;
            AppPin = appPin;
            OnRegistered = onRegistered;
            this.store = store ?? new InstallationStore();
            this.collector = collector ?? NativePlatform.CreateCollector();
            this.hintReader = hintReader ?? new ReinstallHintReader();
            this.stepUpKey = stepUpKey ?? NativePlatform.CreateStepUpKey();
        }

        /// <summary>The guide's calls, for an app that makes them itself.</summary>
        public DeviceTrustClient Client { get; }

        /// <summary>
        /// What this app enables; the backend asks for what it needs of them.
        /// Assign it whenever the person changes it -- in a privacy setting, say:
        /// the next scan measures what it holds then, and the installation, its
        /// session and its step-up key stay as they are.
        /// </summary>
        public IReadOnlyCollection<PersonalMeasurement> PersonalMeasurements
        {
            get => personalMeasurements;
            set => personalMeasurements = new HashSet<PersonalMeasurement>(value ?? throw new ArgumentNullException(nameof(value)));
        }

        /// <summary>
        /// How the step-up key is made, or null for no step-up. An app that takes
        /// these from its backend sets them before <see cref="StartAsync"/>.
        /// </summary>
        public StepUpOptions? StepUp
        {
            get => stepUp;
            set => stepUp = value;
        }

        /// <summary>The app PIN's calls, or null for no app PIN.</summary>
        public AppPinOptions? AppPin { get; }

        /// <summary>
        /// Every registration's answer, whole -- also those made again inside a
        /// scan, when the backend had lost the installation -- awaited before the
        /// installation goes on.
        /// </summary>
        public Func<JsonObject, Task>? OnRegistered { get; }

        /// <summary>
        /// Why step-up is off on this phone although the app turned it on -- no
        /// screen lock, say -- or null.
        /// </summary>
        public NativeKeyException? StepUpUnavailable => stepUpUnavailable;

        /// <summary>The installation, once loaded.</summary>
        public InstallationIdentity? Identity => identity;

        /// <summary>The installation session from proving the key, or null before <see cref="StartAsync"/>.</summary>
        public string? InstallationSession => session;

        /// <summary>The step-up key offered at the last registration.</summary>
        public StepUpKeyMetadata? StepUpKey => offeredStepUpKey;

        /// <summary>The wire names of <see cref="PersonalMeasurements"/>, in the guide's order.</summary>
        public IReadOnlyList<string> EnabledMeasurements
        {
            get
            {
                var enabled = personalMeasurements;
                return Necessary.PersonalMeasurements.All.Where(enabled.Contains).Select(m => m.WireName()).ToList();
            }
        }

        private TaskScheduler Loop => schedulers.ExclusiveScheduler;

        /// <summary>
        /// Device trust over the app's own <paramref name="transport"/>;
        /// <paramref name="store"/>, <paramref name="collector"/>,
        /// <paramref name="hintReader"/> and <paramref name="stepUpKey"/> replace
        /// the native ones in tests.
        /// </summary>
        public static DeviceTrust Over(
            IDeviceTrustTransport transport,
            IEnumerable<PersonalMeasurement>? personalMeasurements = null,
            StepUpOptions? stepUp = null,
            AppPinOptions? appPin = null,
            Func<JsonObject, Task>? onRegistered = null,
            InstallationStore? store = null,
            INativeIntegrityCollector? collector = null,
            ReinstallHintReader? hintReader = null,
            INativeStepUpKey? stepUpKey = null) =>
            new DeviceTrust(
                transport ?? throw new ArgumentNullException(nameof(transport)),
                personalMeasurements,
                stepUp,
                appPin,
                onRegistered,
                store,
                collector,
                hintReader,
                stepUpKey);

        /// <summary>
        /// The installation: its key, made on first use, and its ID. A key made
        /// now is a new installation (<see cref="InstallationIdentity.CreatedThisLaunch"/>):
        /// whatever the app kept for the one before belongs to that one. Calls at
        /// once share one load, so one key gets one ID.
        /// </summary>
        public Task<InstallationIdentity> LoadIdentityAsync() => OnLoop(LoadIdentity);

        /// <summary>
        /// Loads or makes the key, registers it -- with the step-up key, when
        /// step-up is on -- and proves the installation holds it: the installation
        /// session. A refusal outside the guide's protocol errors goes to the app
        /// as it came. A second call while one runs gets its result.
        /// </summary>
        public Task<InstallationIdentity> StartAsync() => OnLoop(Start);

        /// <summary>A new installation session: the key's challenge, answered. A second call while one runs gets its result.</summary>
        public Task<string> ProveAsync() => OnLoop(Prove);

        /// <summary>
        /// Deletes the key, the installation ID and the step-up key, and forgets
        /// the session: the next start is a new installation, linked to this one
        /// by nothing it holds. Calls still running end with
        /// <see cref="InterruptedCallException"/> and keep nothing; calls made from
        /// now on wait for the deletion, and never join one made before.
        /// </summary>
        public Task ResetAsync() => OnLoopTask(Reset);

        /// <summary>
        /// A scan: under the installation session -- or, for a scan that approves
        /// one <paramref name="operation"/> (<see cref="RequestProofs.DescribeOperation"/>),
        /// under the app's account <paramref name="session"/> for this
        /// installation, the one that will send that request. The guide's protocol
        /// errors are acted on once; an account session is the app's to renew. A
        /// second call for the same scan while one runs gets its result; a scan
        /// whose answer was lost is simply asked for again.
        /// </summary>
        public Task<ScanResult> ScanAsync(string? session = null, JsonObject? operation = null)
        {
            if (operation is not null && session is null)
            {
                throw new ArgumentException(
                    "a scan for one operation is asked under the account session that will send it",
                    nameof(session));
            }

            // The personal measurements enabled now are part of the scan: one
            // asked for after the person changed them never joins one asked for
            // before.
            var enabled = EnabledMeasurements;
            var operationCopy = operation?.DeepClone() as JsonObject;
            return OnLoop(() => Scan(session, operationCopy, enabled));
        }

        /// <summary>
        /// Signs one request to your backend under <paramref name="bearer"/>,
        /// your account session: <paramref name="body"/> is sent exactly as
        /// given. With <paramref name="stepUp"/> the person approves it with the
        /// step-up key -- the phone asks, saying <paramref name="reason"/>; with
        /// <paramref name="appPin"/> the backend checks the PIN for it first;
        /// <paramref name="reportId"/> names the scan made for it alone. Send it
        /// with <see cref="RequestProof.Headers"/> beside
        /// <c>Authorization: Bearer</c>, or with <see cref="SendAsync"/>; each
        /// proof serves this request once.
        /// </summary>
        public Task<RequestProof> SignRequestAsync(
            string method,
            string path,
            string bearer,
            string body = "",
            bool stepUp = false,
            string reason = "Approve this request",
            string? appPin = null,
            string? reportId = null) =>
            OnLoop(() => SignRequest(method, path, bearer, body, stepUp, reason, appPin, reportId));

        /// <summary>
        /// Re-enrols the step-up key under the account <paramref name="session"/>,
        /// with the person's own <paramref name="reauthentication"/> -- the
        /// account's password, say: <c>{"password": …}</c>. For a key the phone
        /// has lost or can no longer use -- the screen lock removed
        /// (<c>STEPUP_KEY_INVALIDATED</c>) -- or one made for other options: the
        /// person unlocks the new key to sign its proof, the phone showing
        /// <paramref name="reason"/>, and the backend takes it for that account
        /// alone (the public guide, section 3). Approvals use it from then on. A
        /// key replaced before the backend took the new one -- the person
        /// cancelled, the password was wrong, the answer was lost -- leaves step-up
        /// waiting: approvals answer <c>STEPUP_REENROL_PENDING</c>, across
        /// restarts too, until a call of this succeeds.
        /// </summary>
        public Task<JsonObject> ReenrolStepUpAsync(
            string session,
            JsonObject? reauthentication = null,
            string reason = "Confirm your new step-up key")
        {
            var given = reauthentication?.DeepClone() as JsonObject ?? new JsonObject();
            return OnLoop(() =>
            {
                var running = ReenrolStepUp(session, given, reason);

                // A reset waits for it, whatever comes of it.
                reenrolling = Swallow(running);
                return running;
            });
        }

        /// <summary>Sends <paramref name="proof"/>'s request through the plugin's transport.</summary>
        public Task<JsonObject> SendAsync(RequestProof proof) => Client.SendSignedAsync(proof);

        /// <summary>
        /// Sets the account's app PIN under the account <paramref name="session"/>,
        /// with the person's own <paramref name="reauthentication"/> -- the
        /// account's password, say: <c>{"password": …}</c>.
        /// </summary>
        public Task<JsonObject> SetAppPinAsync(string session, string pin, JsonObject? reauthentication = null)
        {
            var given = reauthentication?.DeepClone() as JsonObject;
            return OnLoop(async () =>
            {
                var options = AppPin ?? throw new InvalidOperationException(
                    "The app PIN is off: new DeviceTrust(..., appPin: new AppPinOptions()).");
                var callGeneration = Volatile.Read(ref generation);
                var installation = await LoadIdentity();
                Current(callGeneration);
                var answer = await Client.SetAppPinAsync(session, installation, pin, given, options.Path);

                // Reset, or closed, meanwhile: the answer is of an installation that
                // is gone, and is never handed out.
                Current(callGeneration);
                return answer;
            });
        }

        /// <summary>
        /// Asks the person for the location permission, for the location
        /// measurements: from a button on the app's own screen, since a scan never
        /// asks. Answers <c>precise</c>, <c>approximate</c> or <c>none</c>.
        /// </summary>
        public Task<string> RequestLocationPermissionAsync() => collector.RequestLocationPermissionAsync();

        /// <summary>
        /// Closes the transport. Calls still running end with
        /// <see cref="InterruptedCallException"/>, or with the transport's own
        /// failure, and keep nothing; the key and the installation stay as they
        /// are.
        /// </summary>
        public void Close()
        {
            if (TaskScheduler.Current == Loop)
            {
                EndCalls();
            }
            else
            {
                Task.Factory.StartNew(EndCalls, CancellationToken.None, TaskCreationOptions.DenyChildAttach, Loop).Wait();
            }

            Client.Close();
        }

        /// <summary>Closes the transport: <see cref="Close"/>.</summary>
        public void Dispose() => Close();

        /// <summary>What approvals answer while the backend does not hold the step-up key.</summary>
        private static NativeKeyException ReenrolPending() => new NativeKeyException(
            "STEPUP_REENROL_PENDING",
            "The backend does not hold this step-up key -- a re-enrolment unfinished, "
            + "or a key made after the installation was registered: ReenrolStepUpAsync() first.");

        private static async Task Swallow(Task task)
        {
            try
            {
                await task;
            }
#pragma warning disable CA1031 // Waited for whatever came of it; its own caller hears the failure.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
        }

        /// <summary>Runs <paramref name="work"/> on this object's own scheduler.</summary>
        private Task<T> OnLoop<T>(Func<Task<T>> work)
        {
            if (TaskScheduler.Current == Loop)
            {
                return work();
            }

            return Task.Factory.StartNew(work, CancellationToken.None, TaskCreationOptions.DenyChildAttach, Loop).Unwrap();
        }

        private Task OnLoopTask(Func<Task> work)
        {
            if (TaskScheduler.Current == Loop)
            {
                return work();
            }

            return Task.Factory.StartNew(work, CancellationToken.None, TaskCreationOptions.DenyChildAttach, Loop).Unwrap();
        }

        /// <summary>
        /// Throws when a reset or a close ended the installation
        /// <paramref name="callGeneration"/> belongs to: a call keeps nothing of
        /// one that is gone.
        /// </summary>
        private void Current(int callGeneration)
        {
            if (callGeneration != Volatile.Read(ref generation))
            {
                throw new InterruptedCallException(
                    "The installation was reset, or the client closed, while this call ran: nothing it found was kept.");
            }
        }

        /// <summary>
        /// A persistent write or a key change for the installation
        /// <paramref name="callGeneration"/>: refused before it starts when a reset
        /// or a close has ended that installation, and waited for by a reset that
        /// began while it ran. The order is the whole guarantee: a reset moves the
        /// generation on, on this object's scheduler, before anything else runs
        /// there, so a write asked for after that throws here without writing; one
        /// asked for before is in the set the reset waits for before it deletes.
        /// </summary>
        private Task<T> Mutate<T>(int callGeneration, Func<Task<T>> change)
        {
            Current(callGeneration);
            var running = change();
            Track(running);
            return running;
        }

        private Task Mutate(int callGeneration, Func<Task> change)
        {
            Current(callGeneration);
            var running = change();
            Track(running);
            return running;
        }

        private void Track(Task running)
        {
            var tracked = Swallow(running);
            mutations.Add(tracked);
            _ = tracked.ContinueWith(_ => mutations.Remove(tracked), CancellationToken.None, TaskContinuationOptions.None, Loop);
        }

        /// <summary>A step-up key a re-enrolment replaces: one that can never sign again, or one the keystore cannot vouch for.</summary>
        private static bool ReplaceableKey(NativeKeyException error) =>
            error.Code == "STEPUP_KEY_INVALIDATED" || error.Code == "STEPUP_KEY_UNAVAILABLE";

        /// <summary>Moves on to the next installation: the calls running now keep nothing, and the next ones start afresh.</summary>
        private void EndCalls()
        {
            Interlocked.Increment(ref generation);
            identity = null;
            session = null;
            loading = null;
            starting = null;
            proving = null;
            scanning.Clear();
        }

        private Task<InstallationIdentity> LoadIdentity()
        {
            var known = identity;
            if (known is not null)
            {
                return Task.FromResult(known);
            }

            if (loading is not null)
            {
                return loading;
            }

            var source = new TaskCompletionSource<InstallationIdentity>(TaskCreationOptions.RunContinuationsAsynchronously);
            loading = source.Task;
            _ = Shared.Complete(source, Load, () =>
            {
                if (loading == source.Task)
                {
                    loading = null;
                }
            });
            return source.Task;
        }

        private async Task<InstallationIdentity> Load()
        {
            // A reset's deletion first, so that nothing loads the key it deletes.
            var deletion = resetting;
            if (deletion is not null)
            {
                await deletion;
            }

            var callGeneration = Volatile.Read(ref generation);
            var loaded = await store.LoadOrCreateAsync();
            Current(callGeneration);
            return identity ??= loaded;
        }

        private Task<InstallationIdentity> Start()
        {
            if (starting is not null)
            {
                return starting;
            }

            var source = new TaskCompletionSource<InstallationIdentity>(TaskCreationOptions.RunContinuationsAsynchronously);
            starting = source.Task;
            _ = Shared.Complete(source, StartOnce, () =>
            {
                if (starting == source.Task)
                {
                    starting = null;
                }
            });
            return source.Task;
        }

        private async Task<InstallationIdentity> StartOnce()
        {
            var callGeneration = Volatile.Read(ref generation);
            await LoadIdentity();
            await Register(callGeneration);
            await Prove();
            Current(callGeneration);
            return identity!;
        }

        private Task<string> Prove()
        {
            if (proving is not null)
            {
                return proving;
            }

            var callGeneration = Volatile.Read(ref generation);
            var source = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            proving = source.Task;
            _ = Shared.Complete(source, () => ProveOnce(callGeneration, retried: false), () =>
            {
                if (proving == source.Task)
                {
                    proving = null;
                }
            });
            return source.Task;
        }

        private async Task<string> ProveOnce(int callGeneration, bool retried)
        {
            var installation = await LoadIdentity();
            Current(callGeneration);
            try
            {
                var challenge = await Client.CreateInstallationChallengeAsync(installation.InstallationId);
                var payload = Json.AnswerText(challenge, "payload");
                var challengeId = Json.AnswerText(challenge, "challenge_id");
                var signature = await installation.SignPayloadAsync(payload);
                var verified = await Client.VerifyInstallationAsync(installation.InstallationId, challengeId, payload, signature);
                Current(callGeneration);
                var token = Json.AnswerText(verified, "device_token");
                session = token;
                return token;
            }
            catch (ApiException error) when (!retried)
            {
                switch (Protocol.StepFor(error, deviceSession: true))
                {
                    case ProtocolStep.AskAgain:
                        break;
                    case ProtocolStep.RegisterAgain:
                        await Register(callGeneration);
                        break;
                    case ProtocolStep.WaitThenRetry:
                        await Task.Delay(Protocol.Wait(error)!.Value);
                        break;
                    default:
                        throw;
                }

                return await ProveOnce(callGeneration, retried: true);
            }
        }

        private Task Reset()
        {
            var load = loading;
            var save = saving;
            var reenrol = reenrolling;
            var earlier = resetting;
            var changing = mutations.ToList();
            EndCalls();
            offeredStepUpKey = null;
            hint = null;
            hintRead = false;
            var deleting = Delete(earlier, load, save, reenrol, changing);

            // Later loads wait for the deletion, whatever came of it; the caller
            // of reset hears what did.
            resetting = Swallow(deleting);
            return deleting;
        }

        private async Task Delete(Task? earlier, Task? load, Task? save, Task? reenrol, IReadOnlyList<Task> changing)
        {
            if (earlier is not null)
            {
                await earlier;
            }

            // A load or a save still running finishes first, so that nothing it
            // writes outlives the deletion. So does a re-enrolment: its key,
            // which a backend may already have taken, is deleted after it, and the
            // marker it writes is cleared. So does every write and key change still
            // running (Mutate): the step-up marker, a step-up key being made.
            var waits = new List<Task>(changing);
            if (load is not null)
            {
                waits.Add(Swallow(load));
            }

            if (save is not null)
            {
                waits.Add(Swallow(save));
            }

            if (reenrol is not null)
            {
                waits.Add(reenrol);
            }

            await Task.WhenAll(waits);
            await store.ClearAsync();

            // The step-up key goes with the installation, as on a reinstall: kept,
            // it would link the next installation to this one. None to delete is no
            // failure; nor is a phone or a platform with no step-up key at all. A
            // key that stays is: the reset fails with it, the installation itself
            // gone, so the app knows and may reset again.
            try
            {
                await stepUpKey.DeleteKeyAsync();
            }
            catch (NativeKeyException error) when (error.Code != "NATIVE_STEPUP_PLUGIN_MISSING" && error.Code != "UNSUPPORTED_ANDROID_VERSION")
            {
                throw new NativeKeyException(
                    error.Code,
                    "The installation was reset, but its step-up key could not be deleted: " + error.Message + " Call ResetAsync() again.",
                    error);
            }
            catch (NativeKeyException)
            {
                // No step-up key on this phone or platform: nothing to delete.
            }
        }

        private async Task Register(int callGeneration)
        {
            var installation = await LoadIdentity();
            Current(callGeneration);
            if (!hintRead)
            {
                var read = await hintReader.ReadAsync();
                Current(callGeneration);
                hint = read;
                hintRead = true;
            }

            var offered = await PrepareStepUpKey(callGeneration);
            var answer = await Client.RegisterInstallationAsync(installation, hint, offered);
            Current(callGeneration);

            // The key is the installation's identity: a backend that holds it
            // under another ID answers with that one, which is kept.
            var held = Json.String(answer["installation_id"]);
            if (!string.IsNullOrEmpty(held) && held != installation.InstallationId)
            {
                identity = installation.WithInstallationId(held!);
                var save = store.SaveInstallationIdAsync(held!);
                saving = save;
                await save;
            }

            await SettleStepUpKey(answer, offered, callGeneration);
            if (OnRegistered is not null)
            {
                await OnRegistered(answer);
            }
        }

        /// <summary>
        /// Whether the backend holds the step-up key offered: it takes one only
        /// when it first registers an installation, so a key made later -- after
        /// the screen lock was removed and set again, say -- it takes by
        /// re-enrolment alone. Its answer says so (<c>stepup_key_matches</c>, or
        /// for an installation new to it <c>stepup_key_registered</c>); until it
        /// holds this key, approvals wait for re-enrolment, across restarts too. A
        /// registration without a key, the phone unable to make one, leaves any
        /// key made later waiting the same way. A backend whose answer says
        /// nothing is taken at its word unless a re-enrolment is pending.
        /// </summary>
        private async Task SettleStepUpKey(JsonObject answer, StepUpKeyMetadata? offered, int callGeneration)
        {
            if (stepUp is null)
            {
                return;
            }

            var matches = Json.Bool(answer["stepup_key_matches"]);
            var registered = Json.Bool(answer["stepup_key_registered"]);
            var bound = offered is null ? null : matches ?? registered;
            if (offered is null || bound == false)
            {
                await Mutate(callGeneration, () => store.SetStepUpReenrolPendingAsync(true));
            }
            else if (bound == true)
            {
                await Mutate(callGeneration, () => store.SetStepUpReenrolPendingAsync(false));
            }

            var pending = offered is not null && bound != true && await store.StepUpReenrolPendingAsync();
            Current(callGeneration);
            if (pending)
            {
                offeredStepUpKey = null;
                stepUpUnavailable = ReenrolPending();
            }
        }

        /// <summary>
        /// The step-up key as <see cref="StepUp"/> asks: an existing key is kept as
        /// it is. Step-up is optional, so a key the phone cannot make leaves it
        /// off. Its use waits for the backend's answer.
        /// </summary>
        private async Task<StepUpKeyMetadata?> PrepareStepUpKey(int callGeneration)
        {
            var options = stepUp;
            if (options is null)
            {
                stepUpUnavailable = null;
                offeredStepUpKey = null;
                return null;
            }

            stepUpKey.ConfiguredMode = options.Mode;
            StepUpKeyMetadata? key = null;
            NativeKeyException? unavailable = null;
            try
            {
                key = await Mutate(callGeneration, () => stepUpKey.GetOrCreateKeyAsync(options.Factor, options.Mode, options.WindowSeconds));
            }
            catch (NativeKeyException error)
            {
                unavailable = error;
            }

            Current(callGeneration);
            stepUpUnavailable = unavailable;
            offeredStepUpKey = key;
            return key;
        }

        private Task<ScanResult> Scan(string? accountSession, JsonObject? operation, IReadOnlyList<string> enabled)
        {
            var enabledList = new JsonArray();
            foreach (var name in enabled)
            {
                enabledList.Add((JsonNode?)name);
            }

            var kind = DartJson.Encode(new JsonArray(JsonValue.Create(accountSession), operation?.DeepClone(), enabledList));
            if (scanning.TryGetValue(kind, out var running))
            {
                return running;
            }

            var callGeneration = Volatile.Read(ref generation);
            var source = new TaskCompletionSource<ScanResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            scanning[kind] = source.Task;
            _ = Shared.Complete(source, () => ScanWithRetry(callGeneration, accountSession, operation, enabled), () =>
            {
                if (scanning.TryGetValue(kind, out var current) && current == source.Task)
                {
                    scanning.Remove(kind);
                }
            });
            return source.Task;
        }

        private async Task<ScanResult> ScanWithRetry(
            int callGeneration,
            string? accountSession,
            JsonObject? operation,
            IReadOnlyList<string> enabled)
        {
            try
            {
                return await ScanOnce(callGeneration, accountSession, operation, enabled);
            }
            catch (ApiException error)
            {
                var installationSession = accountSession is null;
                switch (Protocol.StepFor(error, deviceSession: installationSession))
                {
                    case ProtocolStep.AskAgain:
                        break;
                    case ProtocolStep.ProveAgain:
                        await Prove();
                        break;
                    case ProtocolStep.RegisterAgain:
                        // An account session belongs to the installation the
                        // backend lost: the app signs in again.
                        if (!installationSession)
                        {
                            throw;
                        }

                        await Register(callGeneration);
                        await Prove();
                        break;
                    case ProtocolStep.WaitThenRetry:
                        await Task.Delay(Protocol.Wait(error)!.Value);
                        break;
                    default:
                        throw;
                }

                return await ScanOnce(callGeneration, accountSession, operation, enabled);
            }
        }

        private async Task<ScanResult> ScanOnce(
            int callGeneration,
            string? accountSession,
            JsonObject? operation,
            IReadOnlyList<string> enabled)
        {
            var installation = await LoadIdentity();
            var bearer = accountSession ?? session ?? await Prove();
            Current(callGeneration);
            var challenge = await Client.IntegrityChallengeAsync(bearer, installation, operation);
            var report = await Reports.CollectReportAsync(challenge, installation, collector, enabled);

            // A report of an installation reset meanwhile is never sent.
            Current(callGeneration);
            var answer = await Client.SubmitIntegrityReportAsync(bearer, installation, report);
            Current(callGeneration);
            return new ScanResult(challenge, report, answer);
        }

        private async Task<RequestProof> SignRequest(
            string method,
            string path,
            string bearer,
            string body,
            bool withStepUp,
            string reason,
            string? appPin,
            string? reportId)
        {
            var callGeneration = Volatile.Read(ref generation);
            var installation = await LoadIdentity();
            Current(callGeneration);
            StepUpApproval? approval = null;
            if (withStepUp)
            {
                // Only the key the backend received at registration: a key made
                // later would sign approvals the backend cannot check.
                var key = offeredStepUpKey;
                if (key is null)
                {
                    throw stepUpUnavailable ?? new NativeKeyException(
                        "STEPUP_OFF",
                        stepUp is null
                            ? "Step-up is off: new DeviceTrust(..., stepUp: new StepUpOptions())."
                            : "No step-up key was registered: StartAsync() first.");
                }

                approval = new StepUpApproval(key.Factor, payload => stepUpKey.SignAsync(payload, reason));
            }

            var proof = await RequestProofs.SignAsync(installation, method, path, bearer, body, approval);

            // The installation reset, or the client closed, while the phone
            // signed: the proof is of an installation that is gone, and is never
            // handed out.
            Current(callGeneration);
            if (appPin is not null)
            {
                var options = AppPin ?? throw new InvalidOperationException(
                    "The app PIN is off: new DeviceTrust(..., appPin: new AppPinOptions()).");
                proof = await Client.ProveAppPinAsync(bearer, installation, appPin, proof, options.ProofPath);
                Current(callGeneration);
            }

            return reportId is null ? proof : proof.WithIntegrityReport(reportId);
        }

        private async Task<JsonObject> ReenrolStepUp(string accountSession, JsonObject reauthentication, string reason)
        {
            var options = stepUp ?? throw new NativeKeyException(
                "STEPUP_OFF",
                "Step-up is off: new DeviceTrust(..., stepUp: new StepUpOptions()).");
            var callGeneration = Volatile.Read(ref generation);
            var installation = await LoadIdentity();
            Current(callGeneration);
            stepUpKey.ConfiguredMode = options.Mode;

            // From here the phone's key and the backend's differ until the backend
            // takes the new one: approvals wait for that.
            async Task HoldApprovals()
            {
                await Mutate(callGeneration, () => store.SetStepUpReenrolPendingAsync(true));
                Current(callGeneration);
                offeredStepUpKey = null;
                stepUpUnavailable = ReenrolPending();
            }

            async Task<StepUpKeyMetadata> NewKey(bool replace)
            {
                if (replace)
                {
                    await HoldApprovals();
                    await Mutate(callGeneration, () => stepUpKey.DeleteKeyAsync());
                }

                var made = await Mutate(callGeneration, () => stepUpKey.GetOrCreateKeyAsync(options.Factor, options.Mode, options.WindowSeconds));

                // None to replace, the phone having lost it: this one is as new.
                if (made.Created && !replace)
                {
                    await HoldApprovals();
                }

                return made;
            }

            // A re-enrolment is the explicit recovery: a key the keystore cannot
            // vouch for (STEPUP_KEY_UNAVAILABLE), or one that can never sign again,
            // is replaced here -- and only here.
            StepUpKeyMetadata key;
            try
            {
                key = await NewKey(replace: false);
            }
            catch (NativeKeyException error) when (ReplaceableKey(error))
            {
                key = await NewKey(replace: true);
            }

            if (!key.Created && !options.Accepts(key))
            {
                key = await NewKey(replace: true);
            }

            // The new key signs a proof bound to this request's own nonce, which
            // the request proof then signs too.
            var nonce = Wire.FreshNonce();

            async Task<JsonObject> ProveWith(StepUpKeyMetadata current)
            {
                var payload = RequestProofs.StepUpReenrolProof(
                    installation.InstallationId,
                    current.Thumbprint,
                    Wire.Base64UrlNoPadding(nonce),
                    Wire.UnixSeconds());
                var signature = await stepUpKey.SignAsync(payload, reason);
                return new JsonObject
                {
                    ["stepup_key_proof"] = payload,
                    ["stepup_key_signature"] = signature,
                };
            }

            JsonObject keyProof;
            try
            {
                keyProof = await ProveWith(key);
            }
            catch (NativeKeyException error) when (ReplaceableKey(error) || error.Code == "STEPUP_KEY_NOT_FOUND")
            {
                // A key that died with the screen lock is found only when it signs.
                key = await NewKey(replace: true);
                keyProof = await ProveWith(key);
            }

            var body = new JsonObject();
            foreach (var member in reauthentication)
            {
                body[member.Key] = member.Value?.DeepClone();
            }

            body["stepup_public_key"] = key.PublicKey.DeepClone();
            body["stepup_key_auth"] = key.AuthJson;
            foreach (var member in keyProof)
            {
                body[member.Key] = member.Value?.DeepClone();
            }

            var proof = await RequestProofs.SignAsync(
                installation,
                "POST",
                options.ReenrolPath,
                accountSession,
                DartJson.Encode(body),
                nonce: nonce);
            var answer = await Client.SendSignedAsync(proof);
            await Mutate(callGeneration, () => store.SetStepUpReenrolPendingAsync(false));
            Current(callGeneration);
            offeredStepUpKey = key;
            stepUpUnavailable = null;
            return answer;
        }
    }
}
