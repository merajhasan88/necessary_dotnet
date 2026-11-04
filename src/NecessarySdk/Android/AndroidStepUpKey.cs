using System;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Hardware.Biometrics;
using Android.OS;
using Android.Security.Keystore;
using Java.Lang;
using Java.Security;
using Java.Security.Interfaces;
using Java.Security.Spec;
using Exception = System.Exception;
using KeyStoreType = Java.Security.KeyStore;
using Signature = Java.Security.Signature;

namespace Necessary
{
    /// <summary>
    /// The optional step-up key: a second non-exportable P-256 key in Android
    /// Keystore that cannot sign without the person unlocking it. The
    /// installation key stays unattended for routine proof of possession; this
    /// key approves only sensitive operations, so a compromised app process
    /// cannot drive it as a silent signing oracle for them.
    /// </summary>
    /// <remarks>
    /// How tightly the hardware binds the authentication depends on the API
    /// level. Android 11 (API 30) and later: per-use, each signature authorised
    /// by its own prompt, the device credential (passcode) by default. Android 9
    /// and 10 with the passcode factor: Keystore cannot bind a device credential
    /// to one operation, so the key gets a short hardware-enforced window; the
    /// passcode is still asked before every signature, the window is the
    /// backstop, and it is reported as mode <c>windowed</c> so the downgrade is
    /// visible, not silent. The factor, mode and window reported are read back
    /// from KeyInfo -- what the keystore actually enforces.
    /// </remarks>
    public sealed class AndroidStepUpKey : INativeStepUpKey
    {
        /// <summary>The phone's passcode: its PIN, pattern or password.</summary>
        public const string FactorPasscode = "passcode";

        /// <summary>A biometric enrolled now.</summary>
        public const string FactorBiometric = "biometric";

        /// <summary>Unlocked for every signature.</summary>
        public const string ModePerUse = "per_use";

        /// <summary>One unlock for a while.</summary>
        public const string ModeWindowed = "windowed";

        /// <summary>The hardware window used where per-use passcode is not available (API below 30).</summary>
        public const int LegacyWindowSeconds = 30;

        private const string AndroidKeyStore = "AndroidKeyStore";
        private const string CurveName = "secp256r1";
        private const int MaxPayloadBytes = 65536;
        private const int MaxWindowSeconds = 3600;

        // Making and deleting the key run one at a time in the process, whichever
        // DeviceTrust asks (as for the installation key); never held while the
        // person is asked.
        private static readonly object KeyLock = new object();

        private readonly Context context;
        private readonly string keyAlias;

        // Never holds a key: deleting it says whether the keystore answers
        // (KeyPresence).
        private readonly string probeAlias;
        private readonly object gate = new object();
        private bool pendingConfirm;

        /// <summary>The step-up key of the app <paramref name="context"/> belongs to.</summary>
        public AndroidStepUpKey(Context context)
        {
            this.context = context ?? throw new ArgumentNullException(nameof(context));
            keyAlias = context.PackageName + ".device_recognition.stepup_key.v1";
            probeAlias = keyAlias + ".probe";
        }

        /// <inheritdoc />
        public string ConfiguredMode { get; set; } = ModePerUse;

        /// <inheritdoc />
        public Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds) =>
            AndroidNative.Run(() => GetOrCreateKey(factor, mode, windowSeconds));

        /// <inheritdoc />
        public Task<string> SignAsync(string payloadBase64Url, string reason)
        {
            var activity = NecessaryAndroid.CurrentActivity;
            if (activity is null)
            {
                return Task.FromException<string>(new NativeKeyException("NO_ACTIVITY", "The step-up prompt needs a visible activity."));
            }

            // On the main thread: it shows the system prompt, and the keystore
            // signs inside the prompt's callback.
            var answer = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var mode = ConfiguredMode;
            _ = NecessaryAndroid.OnMainThreadAsync(() =>
            {
                try
                {
                    Sign(activity, payloadBase64Url, reason ?? "Approve this operation", mode ?? ModePerUse, answer);
                }
                catch (NativeKeyException error)
                {
                    answer.TrySetException(error);
                }
                catch (Exception error)
                {
                    // Whatever failed before the prompt, said with its causes.
                    answer.TrySetException(AndroidNative.Failure("NATIVE_STEPUP_ERROR", "The step-up signature failed.", error));
                }

                return true;
            });
            return answer.Task;
        }

        /// <inheritdoc />
        public Task DeleteKeyAsync() => AndroidNative.Run(DeleteKey);

        private static KeyStoreType LoadKeyStore()
        {
            try
            {
                var keyStore = KeyStoreType.GetInstance(AndroidKeyStore)!;
                keyStore.Load(null);
                return keyStore;
            }
            catch (GeneralSecurityException error)
            {
                throw AndroidNative.Failure("KEYSTORE_UNAVAILABLE", "AndroidKeyStore is unavailable.", error);
            }
        }

        private static NativeKeyException SigningFailed(Exception error) =>
            AndroidNative.Failure("STEPUP_SIGNING_FAILED", "AndroidKeyStore could not sign with the step-up key.", error);

        private static NativeKeyException PromptError(BiometricErrorCode errorCode, string? errString)
        {
            var cancelled = errorCode == BiometricErrorCode.UserCanceled || errorCode == BiometricErrorCode.Canceled;
            return new NativeKeyException(
                cancelled ? "STEPUP_CANCELLED" : "STEPUP_AUTH_FAILED",
                "Step-up authentication did not complete: " + errString + " (code " + (int)errorCode + ")");
        }

        private static string SignNow(KeyStoreType.PrivateKeyEntry entry, byte[] payload)
        {
            var signer = Signature.GetInstance("SHA256withECDSA")!;
            signer.InitSign(entry.PrivateKey);
            signer.Update(payload);
            return Wire.Base64UrlNoPadding(signer.Sign()!);
        }

        private StepUpKeyMetadata GetOrCreateKey(string factor, string mode, int windowSeconds)
        {
            lock (KeyLock)
            {
                return LoadOrMakeKey(factor, mode, windowSeconds);
            }
        }

        private StepUpKeyMetadata LoadOrMakeKey(string factor, string mode, int windowSeconds)
        {
            if (factor != FactorPasscode && factor != FactorBiometric)
            {
                throw new NativeKeyException("INVALID_ARGUMENT", "factor must be passcode or biometric.");
            }

            if (mode != ModePerUse && mode != ModeWindowed)
            {
                throw new NativeKeyException("INVALID_ARGUMENT", "mode must be per_use or windowed.");
            }

            if (mode == ModeWindowed && (windowSeconds < 1 || windowSeconds > MaxWindowSeconds))
            {
                throw new NativeKeyException(
                    "INVALID_ARGUMENT",
                    "A windowed step-up key needs window_seconds between 1 and " + MaxWindowSeconds + ".");
            }

            // An existing key is checked before the screen lock: removing the
            // lock is what kills it, so this is where the app can say so precisely.
            // A key is made only where the keystore, answering, holds none: a
            // lookup that failed reads as "no key", and generating would replace
            // the key the backend holds.
            var keyStore = LoadKeyStore();
            var (answer, cause) = Presence(keyStore);
            var existing = answer switch
            {
                KeyPresence.Answer.Present => LiveEntry(keyStore),
                KeyPresence.Answer.Absent => null,
                _ => throw KeyUnavailable(cause),
            };

            RequireDeviceCredential();
            if (factor == FactorBiometric && !OperatingSystem.IsAndroidVersionAtLeast(28))
            {
                throw new NativeKeyException("STEPUP_UNSUPPORTED", "Biometric step-up needs Android 9 (API 28) or newer.");
            }

            var created = existing is null;
            if (created)
            {
                GenerateKeyPair(keyStore, factor, mode, windowSeconds);
            }

            var entry = existing ?? LiveEntry(keyStore);
            var publicKey = Android.Runtime.Extensions.JavaCast<IECPublicKey>(entry.Certificate!.PublicKey)
                ?? throw new NativeKeyException("INVALID_PUBLIC_KEY", "AndroidKeyStore did not return an EC public key for the step-up key.");
            var info = KeyInfoOf(entry);
            var auth = DescribeAuth(info);
            var (level, hardwareBacked) = AndroidInstallationKey.DescribeSecurity(info);
            return new StepUpKeyMetadata(
                AndroidInstallationKey.PublicJwk(publicKey),
                auth.Factor,
                auth.Mode,
                auth.WindowSeconds,
                level,
                hardwareBacked,
                created);
        }

        /// <summary>
        /// Prompts for the device authentication, then signs; on the main thread.
        /// <paramref name="configuredMode"/> is the app's setting: a windowed key
        /// the app asked to be per-use (the fallback below API 30) prompts every
        /// time; a key the app asked to be windowed signs without a prompt while
        /// its hardware window is open.
        /// </summary>
        private void Sign(Activity activity, string payloadBase64Url, string reason, string configuredMode, TaskCompletionSource<string> done)
        {
            try
            {
                lock (gate)
                {
                    if (pendingConfirm)
                    {
                        throw new NativeKeyException("STEPUP_BUSY", "A step-up authentication is already in progress.");
                    }
                }

                var payload = AndroidNative.DecodePayload(payloadBase64Url, "step-up");
                if (payload.Length > MaxPayloadBytes)
                {
                    throw new NativeKeyException("PAYLOAD_TOO_LARGE", "The step-up payload is larger than " + MaxPayloadBytes + " bytes.");
                }

                var keyStore = LoadKeyStore();
                var (answer, cause) = Presence(keyStore);
                if (answer == KeyPresence.Answer.Absent)
                {
                    throw new NativeKeyException("STEPUP_KEY_NOT_FOUND", "No step-up key exists on this installation.");
                }

                if (answer == KeyPresence.Answer.Unavailable)
                {
                    throw KeyUnavailable(cause);
                }

                var entry = LiveEntry(keyStore);
                var auth = DescribeAuth(KeyInfoOf(entry));
                if (auth.Mode == ModePerUse)
                {
                    if (!OperatingSystem.IsAndroidVersionAtLeast(28))
                    {
                        // A per-use key exists only from Android 9; this is never reached.
                        throw new NativeKeyException("STEPUP_UNSUPPORTED", "A per-use step-up key needs Android 9 (API 28) or newer.");
                    }

                    var signer = Signature.GetInstance("SHA256withECDSA")!;
                    signer.InitSign(entry.PrivateKey);
                    AuthenticateOperation(activity, signer, auth.Factor, reason, payload, done);
                    return;
                }

                if (configuredMode == ModeWindowed)
                {
                    try
                    {
                        done.TrySetResult(SignNow(entry, payload));
                        return;
                    }
                    catch (UserNotAuthenticatedException)
                    {
                        // The window is closed; authenticate below and sign.
                    }
                }

                AuthenticateThenSign(activity, entry, auth.Factor, reason, payload, done);
            }
            catch (KeyPermanentlyInvalidatedException error)
            {
                done.TrySetException(DiscardDeadKey(error));
            }
            catch (NativeKeyException error)
            {
                done.TrySetException(error);
            }
            catch (GeneralSecurityException error)
            {
                done.TrySetException(AndroidNative.Failure(
                    "STEPUP_SIGNING_FAILED",
                    "AndroidKeyStore could not prepare the step-up signature.",
                    error));
            }
        }

        /// <summary>Per-use: the prompt authorises this one Signature object.</summary>
        [System.Runtime.Versioning.SupportedOSPlatform("android28.0")]
        private void AuthenticateOperation(
            Activity activity,
            Signature signer,
            string factor,
            string reason,
            byte[] payload,
            TaskCompletionSource<string> done)
        {
            var prompt = BuildPrompt(activity, factor, reason, done);
            prompt.Authenticate(
                new BiometricPrompt.CryptoObject(signer),
                new CancellationSignal(),
                activity.MainExecutor!,
                new PromptCallback(
                    result =>
                    {
                        // Any failure here is told, a keystore's ProviderException
                        // among them: unanswered, this runs on the main thread, and
                        // an exception would end the app with the approval waiting.
                        string signature;
                        try
                        {
                            var authorised = result?.CryptoObject?.Signature ?? signer;
                            authorised.Update(payload);
                            signature = Wire.Base64UrlNoPadding(authorised.Sign()!);
                        }
#pragma warning disable CA1031 // Told to the app, whatever it was.
                        catch (Exception error)
#pragma warning restore CA1031
                        {
                            done.TrySetException(SigningFailed(error));
                            return;
                        }

                        done.TrySetResult(signature);
                    },
                    (code, text) => done.TrySetException(PromptError(code, text))));
        }

        /// <summary>Windowed: authenticate first, then sign inside the hardware window.</summary>
        private void AuthenticateThenSign(
            Activity activity,
            KeyStoreType.PrivateKeyEntry entry,
            string factor,
            string reason,
            byte[] payload,
            TaskCompletionSource<string> done)
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                var prompt = BuildPrompt(activity, factor, reason, done);
                prompt.Authenticate(
                    new CancellationSignal(),
                    activity.MainExecutor!,
                    new PromptCallback(
                        _ => SignAndReport(entry, payload, done),
                        (code, text) => done.TrySetException(PromptError(code, text))));
                return;
            }

            // Below API 30: the system confirm-credential screen (PIN, pattern or
            // password). A successful confirmation opens the key's window.
            var keyguard = (KeyguardManager?)context.GetSystemService(Context.KeyguardService);
#pragma warning disable CA1422 // The only way to confirm the device credential below API 30.
            var intent = keyguard?.CreateConfirmDeviceCredentialIntent("Approve sensitive operation", reason)
#pragma warning restore CA1422
                ?? throw new NativeKeyException(
                    "STEPUP_NO_DEVICE_CREDENTIAL",
                    "Set a screen lock (PIN, pattern or password) to use step-up.");
            lock (gate)
            {
                pendingConfirm = true;
            }

            _ = ConfirmThenSign(intent, entry, payload, done);
        }

        private async Task ConfirmThenSign(Intent intent, KeyStoreType.PrivateKeyEntry entry, byte[] payload, TaskCompletionSource<string> done)
        {
            Result result;
            try
            {
                result = await NecessaryAndroid.StartForResultAsync(intent).ConfigureAwait(false);
            }
            catch (Exception error)
            {
                lock (gate)
                {
                    pendingConfirm = false;
                }

                // The confirmation never opened, or its screen failed: nothing waits
                // for it, and the approval says why.
                done.TrySetException(AndroidNative.Failure("NATIVE_STEPUP_ERROR", "The step-up signature failed.", error));
                return;
            }

            lock (gate)
            {
                pendingConfirm = false;
            }

            if (result == Result.Ok)
            {
                SignAndReport(entry, payload, done);
            }
            else
            {
                done.TrySetException(new NativeKeyException("STEPUP_CANCELLED", "The passcode prompt was cancelled."));
            }
        }

        [System.Runtime.Versioning.SupportedOSPlatform("android28.0")]
        private BiometricPrompt BuildPrompt(Activity activity, string factor, string reason, TaskCompletionSource<string> done)
        {
            var builder = new BiometricPrompt.Builder(activity)
                .SetTitle("Approve sensitive operation")!
                .SetDescription(reason)!;
            var allowsCredential = factor == FactorPasscode && OperatingSystem.IsAndroidVersionAtLeast(30);
            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                builder.SetAllowedAuthenticators(allowsCredential
                    ? (int)BiometricManagerAuthenticators.DeviceCredential
                    : (int)BiometricManagerAuthenticators.BiometricStrong);
            }

            if (!allowsCredential)
            {
                // A biometric-only prompt must offer its own way out; a
                // device-credential prompt must not (the system provides one).
                builder.SetNegativeButton(
                    "Cancel",
                    activity.MainExecutor!,
                    new CancelListener(() => done.TrySetException(
                        new NativeKeyException("STEPUP_CANCELLED", "The biometric prompt was cancelled."))));
            }

            return builder.Build();
        }

        private void SignAndReport(KeyStoreType.PrivateKeyEntry entry, byte[] payload, TaskCompletionSource<string> done)
        {
            // After the person answered, on the main thread or on no thread that
            // anything watches: every failure is told, as in AuthenticateOperation.
            string signature;
            try
            {
                signature = SignNow(entry, payload);
            }
            catch (KeyPermanentlyInvalidatedException error)
            {
                done.TrySetException(DiscardDeadKey(error));
                return;
            }
            catch (UserNotAuthenticatedException error)
            {
                done.TrySetException(AndroidNative.Failure(
                    "STEPUP_AUTH_FAILED",
                    "The keystore did not accept the authentication for the step-up key.",
                    error));
                return;
            }
#pragma warning disable CA1031 // Told to the app, whatever it was.
            catch (Exception error)
#pragma warning restore CA1031
            {
                done.TrySetException(SigningFailed(error));
                return;
            }

            done.TrySetResult(signature);
        }

        /// <summary>
        /// Deletes a step-up key that can never sign again and reports it. The
        /// installation must then re-enrol: a backend never takes a replacement
        /// step-up key for an existing installation by registration.
        /// </summary>
        private NativeKeyException DiscardDeadKey(Exception cause)
        {
            lock (KeyLock)
            {
                // Say whether the removal actually happened: on an Android 9 phone a
                // dead key's alias survived deleteEntry while the screen lock was off.
                string removal;
                try
                {
                    var keyStore = LoadKeyStore();
                    keyStore.DeleteEntry(keyAlias);
                    removal = keyStore.ContainsAlias(keyAlias) ? "could not be removed (alias still present)" : "has been removed";
                }
#pragma warning disable CA1031 // The report says what happened, whatever happened.
                catch (Exception error)
#pragma warning restore CA1031
                {
                    // Not the key's cause: the removal's own failure, said in full here.
                    removal = "could not be removed (" + Causes.Chain(error, AndroidNative.KeystoreDetail, AndroidNative.Read) + ")";
                }

                return AndroidNative.Failure(
                    "STEPUP_KEY_INVALIDATED",
                    "The step-up key was invalidated (the screen lock or enrolled biometrics changed) and " + removal
                    + ". Re-enrol the installation to get a new one.",
                    cause);
            }
        }

        private void GenerateKeyPair(KeyStoreType keyStore, string factor, string mode, int windowSeconds)
        {
            var canTryStrongBox = OperatingSystem.IsAndroidVersionAtLeast(28)
                && context.PackageManager!.HasSystemFeature(PackageManager.FeatureStrongboxKeystore);
            if (canTryStrongBox)
            {
                try
                {
                    GenerateKeyPair(factor, mode, windowSeconds, preferStrongBox: true);
                    return;
                }
#pragma warning disable CA1031 // Same fallback as the installation key.
                catch (Exception)
                {
                    try
                    {
                        if (keyStore.ContainsAlias(keyAlias))
                        {
                            keyStore.DeleteEntry(keyAlias);
                        }
                    }
                    catch (Exception)
                    {
                    }
                }
#pragma warning restore CA1031
            }

            GenerateKeyPair(factor, mode, windowSeconds, preferStrongBox: false);
        }

        private void GenerateKeyPair(string factor, string mode, int windowSeconds, bool preferStrongBox)
        {
            try
            {
                var builder = new KeyGenParameterSpec.Builder(keyAlias, KeyStorePurpose.Sign)
                    .SetAlgorithmParameterSpec(new ECGenParameterSpec(CurveName))!
                    .SetDigests(KeyProperties.DigestSha256)!
                    .SetUserAuthenticationRequired(true)!;
                if (OperatingSystem.IsAndroidVersionAtLeast(30))
                {
                    builder.SetUserAuthenticationParameters(
                        mode == ModeWindowed ? windowSeconds : 0,
                        factor == FactorBiometric ? (int)KeyPropertiesAuthType.BiometricStrong : (int)KeyPropertiesAuthType.DeviceCredential);
                }
                else if (factor == FactorPasscode)
                {
                    // No per-operation device credential before API 30, so a short
                    // hardware window is the strongest binding.
#pragma warning disable CA1422
                    builder.SetUserAuthenticationValidityDurationSeconds(mode == ModeWindowed ? windowSeconds : LegacyWindowSeconds);
#pragma warning restore CA1422
                }
                else if (mode == ModeWindowed)
                {
#pragma warning disable CA1422
                    builder.SetUserAuthenticationValidityDurationSeconds(windowSeconds);
#pragma warning restore CA1422
                }

                // Otherwise a biometric per-use key before API 30 keeps the
                // default (-1), which demands a biometric for every operation.
                if (factor == FactorBiometric)
                {
                    builder.SetInvalidatedByBiometricEnrollment(true);
                }

                if (OperatingSystem.IsAndroidVersionAtLeast(28) && preferStrongBox)
                {
                    builder.SetIsStrongBoxBacked(true);
                }

                var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmEc, AndroidKeyStore)!;
                generator.Initialize(builder.Build());
                generator.GenerateKeyPair();
            }
            catch (Exception error)
            {
                throw AndroidNative.Failure(
                    "STEPUP_KEY_GENERATION_FAILED",
                    "AndroidKeyStore could not create the step-up key.",
                    error);
            }
        }

        /// <summary>
        /// Deletes the key, whatever a lookup says: a lookup that failed reads as
        /// "no key", and skipping the deletion then would leave the key in place
        /// after a reset. Whether one was there is for the answer only.
        /// </summary>
        private bool DeleteKey()
        {
            lock (KeyLock)
            {
                var keyStore = LoadKeyStore();
                try
                {
                    var existed = keyStore.ContainsAlias(keyAlias);
                    keyStore.DeleteEntry(keyAlias);
                    if (keyStore.ContainsAlias(keyAlias))
                    {
                        throw new NativeKeyException(
                            "KEY_DELETE_FAILED",
                            "AndroidKeyStore did not delete the step-up key: it is still present.");
                    }

                    return existed;
                }
                catch (GeneralSecurityException error)
                {
                    throw AndroidNative.Failure("KEY_DELETE_FAILED", "AndroidKeyStore could not delete the step-up key.", error);
                }
            }
        }

        private (KeyPresence.Answer Answer, Exception? Cause) Presence(KeyStoreType keyStore) =>
            KeyPresence.Of(new AndroidInstallationKey.Lookup(keyStore, keyAlias, probeAlias));

        private static NativeKeyException KeyUnavailable(Exception? cause) => AndroidNative.Failure(
            "STEPUP_KEY_UNAVAILABLE",
            "AndroidKeyStore could not be reached for the step-up key; the key was kept, never replaced. "
            + "Try again; if this persists, re-enrol to replace it.",
            cause);

        private void RequireDeviceCredential()
        {
            var keyguard = (KeyguardManager?)context.GetSystemService(Context.KeyguardService);
            if (keyguard is null || !keyguard.IsDeviceSecure)
            {
                throw new NativeKeyException("STEPUP_NO_DEVICE_CREDENTIAL", "Set a screen lock (PIN, pattern or password) to enable step-up.");
            }
        }

        /// <summary>
        /// Loads the stored step-up key. Removing the screen lock (or, for a
        /// biometric key, changing the enrolled biometrics) invalidates an
        /// auth-bound key: Android says so when a signature starts
        /// (KeyPermanentlyInvalidatedException), and only then is the key deleted
        /// and <c>STEPUP_KEY_INVALIDATED</c> reported. A lookup that cannot
        /// establish whether the key is usable keeps it:
        /// <c>STEPUP_KEY_UNAVAILABLE</c>, retryable; any other keystore failure:
        /// <c>KEY_LOOKUP_FAILED</c>, the key kept (<see cref="StepUpKeyEntry"/> decides).
        /// </summary>
        private KeyStoreType.PrivateKeyEntry LiveEntry(KeyStoreType keyStore)
        {
            // Only Android's own word that the key is dead deletes it. An alias
            // that outlived its private key on an Android 9 phone (isKeyEntry
            // false, getEntry throwing UnsupportedOperationException) used to be
            // deleted here, as did every lookup that could not say -- on Android 9
            // a binder error also reads as isKeyEntry false. Those keys are kept.
            KeyStoreType.PrivateKeyEntry? entry = null;
            Exception? cause = null;
            StepUpKeyEntry.Lookup lookup;
            if (!keyStore.IsKeyEntry(keyAlias))
            {
                lookup = StepUpKeyEntry.Lookup.NotKeyEntry;
            }
            else
            {
                try
                {
                    entry = keyStore.GetEntry(keyAlias, null) as KeyStoreType.PrivateKeyEntry;
                    lookup = entry is null ? StepUpKeyEntry.Lookup.NotPrivateKey : StepUpKeyEntry.Lookup.PrivateKey;
                }
                catch (UnrecoverableKeyException error)
                {
                    cause = error;
                    lookup = StepUpKeyEntry.Lookup.Unrecoverable;
                }
                catch (UnsupportedOperationException error)
                {
                    cause = error;
                    lookup = StepUpKeyEntry.Lookup.Unsupported;
                }
                catch (GeneralSecurityException error)
                {
                    cause = error;
                    lookup = StepUpKeyEntry.Lookup.OtherFailure;
                }
            }

            var start = StepUpKeyEntry.SignStart.NotTried;
            if (entry is not null)
            {
                try
                {
                    Signature.GetInstance("SHA256withECDSA")!.InitSign(entry.PrivateKey);
                    start = StepUpKeyEntry.SignStart.Started;
                }
                catch (KeyPermanentlyInvalidatedException error)
                {
                    cause = error;
                    start = StepUpKeyEntry.SignStart.PermanentlyInvalidated;
                }
                catch (UserNotAuthenticatedException)
                {
                    start = StepUpKeyEntry.SignStart.NeedsAuthentication;
                }
            }

            return StepUpKeyEntry.Decide(lookup, start) switch
            {
                StepUpKeyEntry.Verdict.Usable => entry!,
                StepUpKeyEntry.Verdict.Invalidated => throw DiscardDeadKey(cause!),
                StepUpKeyEntry.Verdict.Unavailable => throw AndroidNative.Failure(
                    "STEPUP_KEY_UNAVAILABLE",
                    "AndroidKeyStore could not establish whether the step-up key is usable (lookup: "
                    + StepUpKeyEntry.Name(lookup) + "); the key was kept. Try again; if this persists, re-enrol to replace it.",
                    cause),
                _ => throw AndroidNative.Failure("KEY_LOOKUP_FAILED", "AndroidKeyStore could not load the step-up key.", cause),
            };
        }

        private static KeyInfo KeyInfoOf(KeyStoreType.PrivateKeyEntry entry)
        {
            try
            {
                return AndroidInstallationKey.KeyInfoOf(entry.PrivateKey!);
            }
            catch (GeneralSecurityException error)
            {
                throw AndroidNative.Failure("KEY_LOOKUP_FAILED", "AndroidKeyStore could not describe the step-up key.", error);
            }
        }

        /// <summary>What the keystore enforces for this key, read back from KeyInfo.</summary>
        private static (string Factor, string Mode, int WindowSeconds) DescribeAuth(KeyInfo info)
        {
#pragma warning disable CA1422 // Read on every API level: what the key was made with.
            var duration = info.UserAuthenticationValidityDurationSeconds;
#pragma warning restore CA1422
            var mode = duration > 0 ? ModeWindowed : ModePerUse;
            string factor;
            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                factor = (info.UserAuthenticationType & (int)KeyPropertiesAuthType.DeviceCredential) != 0 ? FactorPasscode : FactorBiometric;
            }
            else
            {
                // KeyInfo has no auth type before API 30. A per-use key can then
                // only be unlocked by a biometric; a windowed key by any lock-screen
                // authentication, and the passcode is what is asked.
                factor = mode == ModePerUse ? FactorBiometric : FactorPasscode;
            }

            return (factor, mode, duration > 0 ? duration : 0);
        }

        [System.Runtime.Versioning.SupportedOSPlatform("android28.0")]
        private sealed class PromptCallback : BiometricPrompt.AuthenticationCallback
        {
            private readonly Action<BiometricPrompt.AuthenticationResult?> succeeded;
            private readonly Action<BiometricErrorCode, string?> failed;

            public PromptCallback(Action<BiometricPrompt.AuthenticationResult?> succeeded, Action<BiometricErrorCode, string?> failed)
            {
                this.succeeded = succeeded;
                this.failed = failed;
            }

            public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult? result) => succeeded(result);

            public override void OnAuthenticationError([Android.Runtime.GeneratedEnum] BiometricErrorCode errorCode, ICharSequence? errString) =>
                failed(errorCode, errString?.ToString());
        }

        private sealed class CancelListener : Java.Lang.Object, IDialogInterfaceOnClickListener
        {
            private readonly Action cancelled;

            public CancelListener(Action cancelled)
            {
                this.cancelled = cancelled;
            }

            public void OnClick(IDialogInterface? dialog, int which) => cancelled();
        }
    }
}
