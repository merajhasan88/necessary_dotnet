using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Foundation;
using Security;
using UIKit;

namespace Necessary
{
    /// <summary>The iOS side's failures, with the codes the Android side uses.</summary>
    internal static class AppleNative
    {
        /// <summary>
        /// Runs <paramref name="operation"/> on the serial queue, a failure that is
        /// not one of the package's own named as the plugin names it.
        /// </summary>
        public static Task<T> Run<T>(Func<T> operation) => NecessaryApple.Serial(() =>
        {
            try
            {
                return operation();
            }
            catch (NativeKeyException)
            {
                throw;
            }
            catch (Exception error)
            {
                throw new NativeKeyException("NATIVE_KEY_ERROR", error.Message, error);
            }
        });

        public static string Describe(NSError? error) =>
            error is null
                ? "unknown error"
                : (error.LocalizedDescription ?? "no description") + " (" + error.Domain + " "
                    + ((long)error.Code).ToString(System.Globalization.CultureInfo.InvariantCulture) + ")";

        /// <summary>A payload's bytes, refusing an empty or malformed one as the plugin does.</summary>
        public static byte[] DecodePayload(string value, string what)
        {
            var trimmed = (value ?? string.Empty).Trim();
            if (trimmed.Length == 0)
            {
                throw new NativeKeyException("INVALID_PAYLOAD", "The " + what + " payload is empty.");
            }

            try
            {
                return Wire.DecodeBase64Url(trimmed);
            }
            catch (FormatException error)
            {
                throw new NativeKeyException("INVALID_PAYLOAD", "The " + what + " payload is not valid base64url.", error);
            }
        }

        /// <summary>The public JWK of a key in X9.63 uncompressed form: 0x04 || X(32) || Y(32).</summary>
        public static JsonObject? PublicJwk(SecKey privateKey, out string? problem)
        {
            problem = null;
            using var publicKey = privateKey.GetPublicKey();
            if (publicKey is null)
            {
                problem = "no public key";
                return null;
            }

            using var representation = publicKey.GetExternalRepresentation(out var error);
            if (representation is null || error is not null)
            {
                problem = "The public key could not be exported: " + Describe(error);
                return null;
            }

            var bytes = representation.ToArray();
            if (bytes.Length != 65 || bytes[0] != 0x04)
            {
                problem = "not an uncompressed P-256 point";
                return null;
            }

            return new JsonObject
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["alg"] = "ES256",
                ["x"] = Wire.Base64UrlNoPadding(bytes.AsSpan(1, 32).ToArray()),
                ["y"] = Wire.Base64UrlNoPadding(bytes.AsSpan(33, 32).ToArray()),
            };
        }
    }

    /// <summary>
    /// Owns one non-exportable P-256 signing key in the Secure Enclave -- or,
    /// where it refuses (the Simulator, or a configuration that declines the
    /// key), a Keychain key marked not extractable: a software key, and
    /// <c>key_security</c> says so. The plugin's <c>InstallationKeyManager.swift</c>,
    /// translated. Signatures are X9.62/DER, as Android's.
    /// </summary>
    public sealed class AppleInstallationKey : INativeInstallationKey
    {
        // Making and deleting the key run one at a time in the process, whichever
        // DeviceTrust asks: two first starts at once could each find no key and
        // each add one under the same tag. Reentrant: a key found dead is deleted
        // while it is being made.
        private static readonly object KeyLock = new object();

        private const int MaxPayloadBytes = 65536;
        private readonly string alias;

        /// <summary>The installation key of this app's bundle.</summary>
        public AppleInstallationKey()
            : this(NSBundle.MainBundle.BundleIdentifier ?? "necessary")
        {
        }

        /// <summary>The installation key under <paramref name="bundleIdentifier"/>.</summary>
        public AppleInstallationKey(string bundleIdentifier)
        {
            // The Android alias's shape, so the platforms read alike in logs.
            alias = bundleIdentifier + ".device_recognition.installation_key.v2";
        }

        /// <inheritdoc />
        public Task<NativeKeyMetadata> GetOrCreateKeyAsync() => AppleNative.Run(GetOrCreateKey);

        /// <inheritdoc />
        public Task<string> SignPayloadAsync(string payloadBase64Url) => AppleNative.Run(() => SignPayload(payloadBase64Url));

        /// <inheritdoc />
        public Task DeleteKeyAsync() => AppleNative.Run(DeleteKey);

        /// <summary>The identifier for vendor, the reinstall hint's source; empty when iOS gives none.</summary>
        internal static Task<string?> ReinstallHintIdentifierAsync() =>
            NecessaryApple.OnMainThread<string?>(() => UIDevice.CurrentDevice.IdentifierForVendor?.AsString() ?? string.Empty);

        private NativeKeyMetadata GetOrCreateKey()
        {
            lock (KeyLock)
            {
                return LoadOrMakeKey();
            }
        }

        private NativeKeyMetadata LoadOrMakeKey()
        {
            var created = false;
            var key = LoadKey();
            if (key is null)
            {
                key = GenerateKey();
                created = true;
            }

            using (key)
            {
                var jwk = AppleNative.PublicJwk(key, out var problem)
                    ?? throw new NativeKeyException(
                        "INVALID_PUBLIC_KEY",
                        problem == "no public key" ? "The Secure Enclave did not return a public key."
                        : problem == "not an uncompressed P-256 point" ? "The public key is not an uncompressed P-256 point."
                        : problem!);
                var (provider, level, hardwareBacked) = DescribeSecurity();
                return new NativeKeyMetadata(jwk, "ES256", alias, provider, level, hardwareBacked, false, "asn1_der", created);
            }
        }

        private string SignPayload(string payloadBase64Url)
        {
            var payload = AppleNative.DecodePayload(payloadBase64Url, "challenge");
            if (payload.Length > MaxPayloadBytes)
            {
                throw new NativeKeyException("PAYLOAD_TOO_LARGE", "The challenge payload is larger than " + MaxPayloadBytes + " bytes.");
            }

            using var key = LoadKey()
                ?? throw new NativeKeyException(
                    "KEY_NOT_FOUND",
                    "The iOS installation key is missing. Restart the app to create a fresh installation identity.");
            if (!key.IsAlgorithmSupported(SecKeyOperationType.Sign, SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256))
            {
                throw new NativeKeyException("SIGNING_FAILED", "The installation key does not support ECDSA-SHA256 signing.");
            }

            using var data = NSData.FromArray(payload);
            using var signature = key.CreateSignature(SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256, data, out var error);
            if (signature is null || error is not null)
            {
                throw new NativeKeyException(
                    "SIGNING_FAILED",
                    "The Secure Enclave could not sign the installation challenge: " + AppleNative.Describe(error));
            }

            return Wire.Base64UrlNoPadding(signature.ToArray());
        }

        private bool DeleteKey()
        {
            lock (KeyLock)
            {
                return DeleteKeyNow();
            }
        }

        private bool DeleteKeyNow()
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

            throw new NativeKeyException(
                "KEY_DELETE_FAILED",
                "The keychain could not delete the installation key (OSStatus " + (int)status + ").");
        }

        private SecRecord Query() => new SecRecord(SecKind.Key)
        {
            ApplicationTag = NSData.FromString(alias, NSStringEncoding.UTF8),
            KeyType = SecKeyType.ECSecPrimeRandom,
        };

        private SecKey? LoadKey()
        {
            using var query = Query();

            // QueryAsConcreteType, the single-item call: the array-returning one,
            // asked for one item, aborts once a key exists (seen on an iPhone 7).
            var match = SecKeyChain.QueryAsConcreteType(query, out var status);
            if (status == SecStatusCode.ItemNotFound)
            {
                return null;
            }

            if (status != SecStatusCode.Success)
            {
                throw new NativeKeyException(
                    "KEY_LOOKUP_FAILED",
                    "The keychain could not load the installation key (OSStatus " + (int)status + ").");
            }

            return match as SecKey
                ?? throw new NativeKeyException("KEY_LOOKUP_FAILED", "The keychain returned an item that is not a key.");
        }

        /// <summary>
        /// The Secure Enclave first, with a fallback: the Simulator has none, and
        /// some configurations refuse the key, so a failure here must not leave
        /// the app unable to enrol.
        /// </summary>
        private SecKey GenerateKey()
        {
            try
            {
                return GenerateKey(useSecureEnclave: true);
            }
#pragma warning disable CA1031 // Any refusal of the Secure Enclave falls back, as the plugin's try? does.
            catch (Exception)
            {
                // Clear any partial item the failed attempt left, so the retry is
                // not blocked by a duplicate tag.
                try
                {
                    DeleteKey();
                }
                catch (Exception)
                {
                }
            }
#pragma warning restore CA1031

            return GenerateKey(useSecureEnclave: false);
        }

        private SecKey GenerateKey(bool useSecureEnclave)
        {
            var privateKeyAttributes = new SecKeyParameters
            {
                IsPermanent = true,
                ApplicationTag = NSData.FromString(alias, NSStringEncoding.UTF8),
            };
            var parameters = new SecKeyGenerationParameters
            {
                KeyType = SecKeyType.ECSecPrimeRandom,
                KeySizeInBits = 256,
            };
            if (useSecureEnclave)
            {
                // PrivateKeyUsage only: no biometric or passcode gate, as Android's
                // setUserAuthenticationRequired(false). The key must be usable
                // unattended for background scans.
                privateKeyAttributes.AccessControl = new SecAccessControl(
                    SecAccessible.AfterFirstUnlockThisDeviceOnly,
                    SecAccessControlCreateFlags.PrivateKeyUsage);
                parameters.TokenID = SecTokenID.SecureEnclave;
            }
            else
            {
                // Best effort on a phone without a Secure Enclave: kept on this
                // device, after the first unlock, marked not extractable; the
                // backend is told the truth by security_level and hardware_backed.
                var extra = (NSMutableDictionary)privateKeyAttributes.Dictionary;
                extra[SecKeyAttributeKeys.Accessible] = SecKeyAttributeKeys.AfterFirstUnlockThisDeviceOnly;
                extra[SecKeyAttributeKeys.IsExtractable] = NSNumber.FromBoolean(false);
            }

            parameters.PrivateKeyAttrs = privateKeyAttributes;
            var key = SecKey.CreateRandomKey(parameters, out var error);
            if (key is null || error is not null)
            {
                throw new NativeKeyException(
                    "KEY_GENERATION_FAILED",
                    useSecureEnclave
                        ? "The Secure Enclave could not create the P-256 installation key: " + AppleNative.Describe(error)
                        : "The keychain could not create the P-256 installation key: " + AppleNative.Describe(error));
            }

            return key;
        }

        private (string Provider, string Level, bool HardwareBacked) DescribeSecurity()
        {
            using var query = Query();
            using var record = SecKeyChain.QueryAsRecord(query, out var status);
            if (status != SecStatusCode.Success || record is null)
            {
                return ("Keychain", "unknown", false);
            }

            return record.TokenID == SecTokenID.SecureEnclave
                ? ("SecureEnclave", "secure_enclave", true)
                : ("Keychain", "software", false);
        }
    }

    /// <summary>
    /// The Security framework's attribute names and values the bindings do not
    /// type, as Apple's SecItem.h defines them: kSecAttrAccessible,
    /// kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAttrIsExtractable.
    /// </summary>
    internal static class SecKeyAttributeKeys
    {
        public static readonly NSString Accessible = new NSString("pdmn");
        public static readonly NSString AfterFirstUnlockThisDeviceOnly = new NSString("cku");
        public static readonly NSString IsExtractable = new NSString("extr");
    }
}
