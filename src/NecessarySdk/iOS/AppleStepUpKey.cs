using System;
using System.Threading.Tasks;
using Foundation;
using LocalAuthentication;
using Security;

namespace Necessary
{
    /// <summary>
    /// The optional step-up key on iOS: a second Secure Enclave P-256 key whose
    /// access control demands the device passcode (by default) or the current
    /// biometric set for every signature. iOS always gets per-use: each
    /// signature runs with a fresh LAContext, so an earlier authentication is
    /// never reused. The key needs a passcode to exist; removing the passcode
    /// leaves the item behind, unable to sign, so the key is checked and
    /// discarded when that happened. The factor is recorded in the key's label,
    /// so what is reported is what the key enforces. The plugin's
    /// <c>StepUpKeyManager</c> (InstallationKeyManager.swift), translated.
    /// </summary>
    public sealed class AppleStepUpKey : INativeStepUpKey
    {
        private const int MaxPayloadBytes = 65536;
        private const string LabelPrefix = "stepup:";
        private const long PasscodeNotSet = -5;
        private const long CryptoTokenKitCorruptedData = -3;
        private const string LocalAuthenticationErrorDomain = "com.apple.LocalAuthentication";
        private const string OsStatusErrorDomain = "NSOSStatusErrorDomain";

        private readonly string alias;

        /// <summary>The step-up key of this app's bundle.</summary>
        public AppleStepUpKey()
            : this(NSBundle.MainBundle.BundleIdentifier ?? "necessary")
        {
        }

        /// <summary>The step-up key under <paramref name="bundleIdentifier"/>.</summary>
        public AppleStepUpKey(string bundleIdentifier)
        {
            alias = bundleIdentifier + ".device_recognition.stepup_key.v1";
        }

        /// <inheritdoc />
        public string ConfiguredMode { get; set; } = "per_use";

        /// <inheritdoc />
        /// <remarks>iOS makes per-use keys only: <paramref name="mode"/> and <paramref name="windowSeconds"/> do not apply.</remarks>
        public Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds) =>
            AppleNative.Run(() => GetOrCreateKey(factor));

        /// <inheritdoc />
        /// <remarks>Blocks the package's serial queue until the person answers the system prompt.</remarks>
        public Task<string> SignAsync(string payloadBase64Url, string reason) =>
            AppleNative.Run(() => SignPayload(payloadBase64Url, reason ?? "Approve this operation"));

        /// <inheritdoc />
        public Task DeleteKeyAsync() => AppleNative.Run(DeleteKey);

        /// <summary>False only when iOS reports that no passcode is set: a live key is never removed on a guess.</summary>
        private static bool DevicePasscodeSet()
        {
            using var context = new LAContext();
            if (context.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthentication, out var error))
            {
                return true;
            }

            return error is null || (long)error.Code != PasscodeNotSet;
        }

        private static void RequireFactorAvailable(string factor)
        {
            using var context = new LAContext();
            var policy = factor == "biometric" ? LAPolicy.DeviceOwnerAuthenticationWithBiometrics : LAPolicy.DeviceOwnerAuthentication;
            if (!context.CanEvaluatePolicy(policy, out _))
            {
                throw factor == "biometric"
                    ? new NativeKeyException("STEPUP_NO_BIOMETRIC", "Enrol Touch ID or Face ID to enable biometric step-up.")
                    : new NativeKeyException("STEPUP_NO_DEVICE_CREDENTIAL", "Set a device passcode to enable step-up.");
            }
        }

        private static NativeKeyException SignFailure(NSError? error)
        {
            if (error is null)
            {
                return new NativeKeyException("STEPUP_SIGNING_FAILED", "The Secure Enclave could not sign with the step-up key.");
            }

            var domain = error.Domain;
            var code = (long)error.Code;
            var text = error.LocalizedDescription ?? "unknown error";

            // errSecUserCanceled; LAError userCancel, appCancel, systemCancel.
            if ((domain == OsStatusErrorDomain && code == -128)
                || (domain == LocalAuthenticationErrorDomain && (code == -2 || code == -9 || code == -4)))
            {
                return new NativeKeyException("STEPUP_CANCELLED", "Step-up authentication was cancelled: " + text);
            }

            // errSecAuthFailed, or any other LocalAuthentication failure.
            if ((domain == OsStatusErrorDomain && code == -25293) || domain == LocalAuthenticationErrorDomain)
            {
                return new NativeKeyException("STEPUP_AUTH_FAILED", "Step-up authentication failed: " + text);
            }

            return new NativeKeyException("STEPUP_SIGNING_FAILED", "The Secure Enclave could not sign with the step-up key: " + text);
        }

        private StepUpKeyMetadata GetOrCreateKey(string factor)
        {
            if (factor != "passcode" && factor != "biometric")
            {
                throw new NativeKeyException("INVALID_ARGUMENT", "factor must be passcode or biometric.");
            }

            var created = false;
            var key = LoadKey(null);
            if (key is not null && !DevicePasscodeSet())
            {
                // A passcode-bound key cannot outlive the passcode: its protection
                // is destroyed when the passcode is removed, but the item stays.
                key.Dispose();
                throw DiscardDeadKey("the device passcode was removed");
            }

            if (key is null)
            {
                RequireFactorAvailable(factor);
                key = GenerateKey(factor);
                created = true;
            }

            using (key)
            {
                var jwk = AppleNative.PublicJwk(key, out var problem);
                if (jwk is null)
                {
                    throw problem == "no public key"
                        ? new NativeKeyException("STEPUP_KEY_NOT_FOUND", "The step-up key could not be created or loaded.")
                        : new NativeKeyException("INVALID_PUBLIC_KEY", "The step-up public key is not an uncompressed P-256 point.");
                }

                return new StepUpKeyMetadata(jwk, StoredFactor() ?? factor, "per_use", 0, "secure_enclave", true, created);
            }
        }

        private string SignPayload(string payloadBase64Url, string reason)
        {
            var payload = AppleNative.DecodePayload(payloadBase64Url, "step-up");
            if (payload.Length > MaxPayloadBytes)
            {
                throw new NativeKeyException("PAYLOAD_TOO_LARGE", "The step-up payload is larger than " + MaxPayloadBytes + " bytes.");
            }

            // A fresh context per signature: an already-evaluated context would be
            // reused silently, and per-use is the whole point.
            using var context = new LAContext
            {
                LocalizedReason = reason,
                TouchIdAuthenticationAllowableReuseDuration = 0,
            };
            using var key = LoadKey(context)
                ?? throw new NativeKeyException("STEPUP_KEY_NOT_FOUND", "No step-up key exists on this installation.");
            using var data = NSData.FromArray(payload);
            using var signature = key.CreateSignature(SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256, data, out var error);
            if (signature is not null && error is null)
            {
                return Wire.Base64UrlNoPadding(signature.ToArray());
            }

            // CryptoTokenKit -3: the Secure Enclave can no longer unwrap the key.
            if (error is not null && error.Domain == "CryptoTokenKit" && (long)error.Code == CryptoTokenKitCorruptedData)
            {
                throw DiscardDeadKey("the Secure Enclave can no longer use it");
            }

            throw SignFailure(error);
        }

        /// <summary>
        /// Deletes a step-up key that can never sign again and reports it, saying
        /// truthfully whether the removal worked. The installation must then
        /// re-enrol.
        /// </summary>
        private NativeKeyException DiscardDeadKey(string reason)
        {
            var removal = "has been removed";
            try
            {
                DeleteKey();
                using var still = LoadKey(null);
                if (still is not null)
                {
                    removal = "could not be removed (still present)";
                }
            }
            catch (NativeKeyException failure)
            {
                removal = "could not be removed (" + failure.Message + ")";
            }
#pragma warning disable CA1031 // The report says what happened, whatever happened.
            catch (Exception error)
#pragma warning restore CA1031
            {
                removal = "could not be removed (" + error.Message + ")";
            }

            return new NativeKeyException(
                "STEPUP_KEY_INVALIDATED",
                "The step-up key was invalidated (" + reason + ") and " + removal + ". Re-enrol the installation to get a new one.");
        }

        private bool DeleteKey()
        {
            using var query = Query();
            var status = SecKeyChain.Remove(query);
            if (status == SecStatusCode.Success)
            {
                return true;
            }

            if (status == SecStatusCode.ItemNotFound)
            {
                return false;
            }

            throw new NativeKeyException("KEY_DELETE_FAILED", "The keychain could not delete the step-up key (OSStatus " + (int)status + ").");
        }

        private SecRecord Query() => new SecRecord(SecKind.Key)
        {
            ApplicationTag = NSData.FromString(alias, NSStringEncoding.UTF8),
            KeyType = SecKeyType.ECSecPrimeRandom,
        };

        private SecKey? LoadKey(LAContext? context)
        {
            using var query = Query();
            if (context is not null)
            {
                query.AuthenticationContext = context;
            }

            var match = SecKeyChain.QueryAsConcreteType(query, out var status);
            if (status == SecStatusCode.ItemNotFound)
            {
                return null;
            }

            if (status != SecStatusCode.Success)
            {
                throw new NativeKeyException("KEY_LOOKUP_FAILED", "The keychain could not load the step-up key (OSStatus " + (int)status + ").");
            }

            return match as SecKey
                ?? throw new NativeKeyException("KEY_LOOKUP_FAILED", "The keychain returned an item that is not a key.");
        }

        private string? StoredFactor()
        {
            using var query = Query();
            using var record = SecKeyChain.QueryAsRecord(query, out var status);
            var label = status == SecStatusCode.Success ? record?.Label : null;
            return label is not null && label.StartsWith(LabelPrefix, StringComparison.Ordinal) ? label.Substring(LabelPrefix.Length) : null;
        }

        private SecKey GenerateKey(string factor)
        {
            var flags = factor == "biometric"
                ? SecAccessControlCreateFlags.PrivateKeyUsage | SecAccessControlCreateFlags.BiometryCurrentSet
                : SecAccessControlCreateFlags.PrivateKeyUsage | SecAccessControlCreateFlags.DevicePasscode;
            SecAccessControl access;
            try
            {
                access = new SecAccessControl(SecAccessible.WhenPasscodeSetThisDeviceOnly, flags);
            }
#pragma warning disable CA1031 // Named as the plugin names it.
            catch (Exception error)
#pragma warning restore CA1031
            {
                throw new NativeKeyException("STEPUP_KEY_GENERATION_FAILED", "Could not build the step-up access control: " + error.Message, error);
            }

            var parameters = new SecKeyGenerationParameters
            {
                KeyType = SecKeyType.ECSecPrimeRandom,
                KeySizeInBits = 256,
                TokenID = SecTokenID.SecureEnclave,
                PrivateKeyAttrs = new SecKeyParameters
                {
                    IsPermanent = true,
                    ApplicationTag = NSData.FromString(alias, NSStringEncoding.UTF8),
                    Label = LabelPrefix + factor,
                    AccessControl = access,
                },
            };
            var key = SecKey.CreateRandomKey(parameters, out var error2);
            if (key is null || error2 is not null)
            {
                throw new NativeKeyException(
                    "STEPUP_KEY_GENERATION_FAILED",
                    "The Secure Enclave could not create the step-up key: " + AppleNative.Describe(error2));
            }

            return key;
        }
    }
}
