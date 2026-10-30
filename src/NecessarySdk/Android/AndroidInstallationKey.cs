using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Android.Content;
using Android.Content.PM;
using Android.Provider;
using Android.Security.Keystore;
using Java.Security;
using Java.Security.Interfaces;
using Java.Security.Spec;
using Signature = Java.Security.Signature;

namespace Necessary
{
    /// <summary>
    /// Owns one non-exportable P-256 signing key in Android Keystore. The
    /// private key object is only a handle: Android performs signing through
    /// the keystore provider, and this class returns only the public EC
    /// coordinates and DER-encoded ECDSA signatures. StrongBox is tried first
    /// where the phone has it.
    /// </summary>
    public sealed class AndroidInstallationKey : INativeInstallationKey
    {
        private const string AndroidKeyStore = "AndroidKeyStore";
        private const string CurveName = "secp256r1";
        private const int MaxPayloadBytes = 65536;

        private readonly Context context;
        private readonly string keyAlias;

        /// <summary>The installation key of the app <paramref name="context"/> belongs to.</summary>
        public AndroidInstallationKey(Context context)
        {
            this.context = context ?? throw new ArgumentNullException(nameof(context));
            keyAlias = context.PackageName + ".device_recognition.installation_key.v2";
        }

        /// <inheritdoc />
        public Task<NativeKeyMetadata> GetOrCreateKeyAsync() => AndroidNative.Run(GetOrCreateKey);

        /// <inheritdoc />
        public Task<string> SignPayloadAsync(string payloadBase64Url) => AndroidNative.Run(() => SignPayload(payloadBase64Url));

        /// <inheritdoc />
        public Task DeleteKeyAsync() => AndroidNative.Run(DeleteKey);

        /// <summary>
        /// The reinstall hint's source, ANDROID_ID: scoped to the phone, the user
        /// and the app's signing key; hashed before it leaves the phone; empty
        /// when the platform gives none.
        /// </summary>
        internal static Task<string?> ReinstallHintIdentifierAsync(Context context) =>
            AndroidNative.Run<string?>(() => Settings.Secure.GetString(context.ContentResolver, Settings.Secure.AndroidId) ?? string.Empty);

        internal static string Base64Url(byte[] value) => Wire.Base64UrlNoPadding(value);

        internal static JsonObject PublicJwk(IECPublicKey publicKey) => new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["alg"] = "ES256",
            ["x"] = Base64Url(AndroidNative.UnsignedFixed(publicKey.GetW()!.AffineX!, 32)),
            ["y"] = Base64Url(AndroidNative.UnsignedFixed(publicKey.GetW()!.AffineY!, 32)),
        };

        internal static (string Level, bool HardwareBacked) DescribeSecurity(KeyInfo info)
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(31))
            {
                return info.SecurityLevel switch
                {
                    (int)KeyStoreSecurityLevel.Strongbox => ("strongbox", true),
                    (int)KeyStoreSecurityLevel.TrustedEnvironment => ("trusted_execution_environment", true),
                    (int)KeyStoreSecurityLevel.Software => ("software", false),
                    _ => ("unknown", false),
                };
            }

#pragma warning disable CA1422 // Before Android 12, the only answer there is.
            return info.IsInsideSecureHardware ? ("secure_hardware", true) : ("software", false);
#pragma warning restore CA1422
        }

        internal static KeyInfo KeyInfoOf(IPrivateKey privateKey)
        {
            var keyFactory = KeyFactory.GetInstance(privateKey.Algorithm!, AndroidKeyStore)!;
            var spec = keyFactory.GetKeySpec(privateKey, Java.Lang.Class.FromType(typeof(KeyInfo)))!;
            return Android.Runtime.Extensions.JavaCast<KeyInfo>(spec)!;
        }

        private static KeyStore LoadKeyStore()
        {
            try
            {
                var keyStore = KeyStore.GetInstance(AndroidKeyStore)!;
                keyStore.Load(null);
                return keyStore;
            }
            catch (GeneralSecurityException error)
            {
                throw new NativeKeyException("KEYSTORE_UNAVAILABLE", "AndroidKeyStore is unavailable.", error);
            }
        }

        private NativeKeyMetadata GetOrCreateKey()
        {
            var keyStore = LoadKeyStore();
            var created = false;
            if (!keyStore.ContainsAlias(keyAlias))
            {
                GenerateKeyPair(keyStore);
                created = true;
            }

            var entry = PrivateKeyEntry(keyStore);
            if (!IsExpectedP256Key(entry))
            {
                // An interrupted development build may have left a different key
                // under the alias. Replace it, and say that a new key exists so
                // the installation ID is renewed too.
                keyStore.DeleteEntry(keyAlias);
                GenerateKeyPair(keyStore);
                created = true;
                entry = PrivateKeyEntry(keyStore);
            }

            var publicKey = Android.Runtime.Extensions.JavaCast<IECPublicKey>(entry.Certificate!.PublicKey)
                ?? throw new NativeKeyException("INVALID_PUBLIC_KEY", "AndroidKeyStore did not return an EC public key.");
            var (level, hardwareBacked) = DescribeSecurityOrUnknown(entry);
            return new NativeKeyMetadata(
                PublicJwk(publicKey),
                "ES256",
                keyAlias,
                AndroidKeyStore,
                level,
                hardwareBacked,
                false,
                "asn1_der",
                created);
        }

        private string SignPayload(string payloadBase64Url)
        {
            var payload = AndroidNative.DecodePayload(payloadBase64Url, "challenge");
            if (payload.Length > MaxPayloadBytes)
            {
                throw new NativeKeyException(
                    "PAYLOAD_TOO_LARGE",
                    "The challenge payload is larger than " + MaxPayloadBytes + " bytes.");
            }

            var keyStore = LoadKeyStore();
            if (!keyStore.ContainsAlias(keyAlias))
            {
                throw new NativeKeyException(
                    "KEY_NOT_FOUND",
                    "The Android installation key is missing. Restart the app to create a fresh installation identity.");
            }

            var entry = PrivateKeyEntry(keyStore);
            try
            {
                var signer = Signature.GetInstance("SHA256withECDSA")!;
                signer.InitSign(entry.PrivateKey);
                signer.Update(payload);

                // The JCA SHA256withECDSA signature format is ASN.1 DER.
                return Base64Url(signer.Sign()!);
            }
            catch (GeneralSecurityException error)
            {
                throw new NativeKeyException("SIGNING_FAILED", "AndroidKeyStore could not sign the installation challenge.", error);
            }
        }

        private bool DeleteKey()
        {
            var keyStore = LoadKeyStore();
            try
            {
                if (keyStore.ContainsAlias(keyAlias))
                {
                    keyStore.DeleteEntry(keyAlias);
                    return true;
                }

                return false;
            }
            catch (GeneralSecurityException error)
            {
                throw new NativeKeyException("KEY_DELETE_FAILED", "AndroidKeyStore could not delete the installation key.", error);
            }
        }

        private void GenerateKeyPair(KeyStore keyStore)
        {
            var canTryStrongBox = OperatingSystem.IsAndroidVersionAtLeast(28)
                && context.PackageManager!.HasSystemFeature(PackageManager.FeatureStrongboxKeystore);
            if (canTryStrongBox)
            {
                try
                {
                    GenerateKeyPair(preferStrongBox: true);
                    return;
                }
#pragma warning disable CA1031 // Some phones advertise StrongBox but cannot make this key: fall back.
                catch (Exception)
                {
                    // Remove any partial alias and retry with the regular provider.
                    try
                    {
                        if (keyStore.ContainsAlias(keyAlias))
                        {
                            keyStore.DeleteEntry(keyAlias);
                        }
                    }
                    catch (Exception)
                    {
                        // The normal attempt below gives the actionable error if
                        // the keystore is genuinely unusable.
                    }
                }
#pragma warning restore CA1031
            }

            GenerateKeyPair(preferStrongBox: false);
        }

        private void GenerateKeyPair(bool preferStrongBox)
        {
            try
            {
                var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmEc, AndroidKeyStore)!;
                var builder = new KeyGenParameterSpec.Builder(keyAlias, KeyStorePurpose.Sign)
                    .SetAlgorithmParameterSpec(new ECGenParameterSpec(CurveName))!
                    .SetDigests(KeyProperties.DigestSha256)!
                    .SetUserAuthenticationRequired(false)!;
                if (OperatingSystem.IsAndroidVersionAtLeast(28) && preferStrongBox)
                {
                    builder.SetIsStrongBoxBacked(true);
                }

                generator.Initialize(builder.Build());
                generator.GenerateKeyPair();
            }
            catch (Exception error) when (error is GeneralSecurityException || error is ProviderException)
            {
                throw new NativeKeyException(
                    "KEY_GENERATION_FAILED",
                    preferStrongBox
                        ? "StrongBox could not create the P-256 installation key."
                        : "AndroidKeyStore could not create the P-256 installation key.",
                    error);
            }
        }

        private KeyStore.PrivateKeyEntry PrivateKeyEntry(KeyStore keyStore)
        {
            try
            {
                return keyStore.GetEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
                    ?? throw new NativeKeyException(
                        "KEY_NOT_FOUND",
                        "The Android installation key entry is missing or has the wrong type.");
            }
            catch (GeneralSecurityException error)
            {
                throw new NativeKeyException("KEY_LOOKUP_FAILED", "AndroidKeyStore could not load the installation key.", error);
            }
        }

        private static bool IsExpectedP256Key(KeyStore.PrivateKeyEntry entry)
        {
            var publicKey = Android.Runtime.Extensions.JavaCast<IECPublicKey>(entry.Certificate?.PublicKey);
            return publicKey?.Params?.Curve?.Field?.FieldSize == 256;
        }

        private static (string Level, bool HardwareBacked) DescribeSecurityOrUnknown(KeyStore.PrivateKeyEntry entry)
        {
            try
            {
                return DescribeSecurity(KeyInfoOf(entry.PrivateKey!));
            }
#pragma warning disable CA1031 // A key whose description fails is of unknown security, never a stronger one.
            catch (Exception)
#pragma warning restore CA1031
            {
                return ("unknown", false);
            }
        }
    }
}
