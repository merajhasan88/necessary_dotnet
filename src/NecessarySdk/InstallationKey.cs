using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>The installation key as the phone's keystore describes it.</summary>
    public sealed class NativeKeyMetadata
    {
        /// <summary>A key's description.</summary>
        public NativeKeyMetadata(
            JsonObject publicKey,
            string algorithm,
            string keyAlias,
            string provider,
            string securityLevel,
            bool hardwareBacked,
            bool privateKeyExportable,
            string signatureFormat,
            bool created)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Algorithm = algorithm;
            KeyAlias = keyAlias;
            Provider = provider;
            SecurityLevel = securityLevel;
            HardwareBacked = hardwareBacked;
            PrivateKeyExportable = privateKeyExportable;
            SignatureFormat = signatureFormat;
            Created = created;
        }

        /// <summary>The public JWK: <c>kty</c>, <c>crv</c>, <c>alg</c>, <c>x</c>, <c>y</c>.</summary>
        public JsonObject PublicKey { get; }

        /// <summary><c>ES256</c>.</summary>
        public string Algorithm { get; }

        /// <summary>The key's name in the keystore.</summary>
        public string KeyAlias { get; }

        /// <summary><c>AndroidKeyStore</c>, <c>SecureEnclave</c> or <c>Keychain</c>.</summary>
        public string Provider { get; }

        /// <summary>Where the phone says the key is kept.</summary>
        public string SecurityLevel { get; }

        /// <summary>Whether the phone says the key is in secure hardware.</summary>
        public bool HardwareBacked { get; }

        /// <summary>Always false: the private key never leaves the keystore.</summary>
        public bool PrivateKeyExportable { get; }

        /// <summary>How signatures come: ASN.1 DER.</summary>
        public string SignatureFormat { get; }

        /// <summary>Whether the key was made at this launch: a new installation.</summary>
        public bool Created { get; }

        /// <summary>
        /// Reads the native side's description, refusing anything but an EC
        /// P-256 public JWK and every field present.
        /// </summary>
        public static NativeKeyMetadata FromPlatform(JsonObject value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (value["public_key"] is not JsonObject publicKey)
            {
                throw new FormatException("The native key provider returned no public key.");
            }

            string RequiredString(string field) =>
                Json.String(value[field]) is { Length: > 0 } item
                    ? item
                    : throw new FormatException("The native key provider returned an invalid " + field + ".");

            bool RequiredBool(string field) =>
                Json.Bool(value[field]) ?? throw new FormatException("The native key provider returned an invalid " + field + ".");

            if (!Json.IsEcP256(publicKey))
            {
                throw new FormatException("The native key provider did not return an EC P-256 public JWK.");
            }

            return new NativeKeyMetadata(
                (JsonObject)publicKey.DeepClone(),
                RequiredString("algorithm"),
                RequiredString("key_alias"),
                RequiredString("provider"),
                RequiredString("security_level"),
                RequiredBool("hardware_backed"),
                RequiredBool("private_key_exportable"),
                RequiredString("signature_format"),
                RequiredBool("created"));
        }
    }

    /// <summary>
    /// The installation key: one non-exportable P-256 key per installation,
    /// made and held by Android Keystore or the iOS Secure Enclave (or, where
    /// that refuses, the Keychain).
    /// </summary>
    public interface INativeInstallationKey
    {
        /// <summary>The key, made on first use.</summary>
        Task<NativeKeyMetadata> GetOrCreateKeyAsync();

        /// <summary>
        /// Signs the bytes <paramref name="payloadBase64Url"/> carries: ECDSA over
        /// SHA-256, the signature in ASN.1 DER, base64url.
        /// </summary>
        Task<string> SignPayloadAsync(string payloadBase64Url);

        /// <summary>Deletes the key.</summary>
        Task DeleteKeyAsync();
    }

    /// <summary>The installation: its ID, and its key.</summary>
    public sealed class InstallationIdentity
    {
        /// <summary>An installation.</summary>
        public InstallationIdentity(string installationId, INativeInstallationKey nativeKey, NativeKeyMetadata metadata)
        {
            InstallationId = installationId ?? throw new ArgumentNullException(nameof(installationId));
            NativeKey = nativeKey ?? throw new ArgumentNullException(nameof(nativeKey));
            Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        }

        /// <summary>The installation's ID.</summary>
        public string InstallationId { get; }

        /// <summary>The key that signs for it.</summary>
        public INativeInstallationKey NativeKey { get; }

        /// <summary>The key's description.</summary>
        public NativeKeyMetadata Metadata { get; }

        /// <summary>The public JWK.</summary>
        public JsonObject PublicKeyJson => Metadata.PublicKey;

        /// <summary><c>ES256</c>.</summary>
        public string Algorithm => Metadata.Algorithm;

        /// <summary>The key's name in the keystore.</summary>
        public string KeyAlias => Metadata.KeyAlias;

        /// <summary>The keystore.</summary>
        public string Provider => Metadata.Provider;

        /// <summary>Where the phone says the key is kept.</summary>
        public string SecurityLevel => Metadata.SecurityLevel;

        /// <summary>Whether the phone says the key is in secure hardware.</summary>
        public bool HardwareBacked => Metadata.HardwareBacked;

        /// <summary>Always false.</summary>
        public bool PrivateKeyExportable => Metadata.PrivateKeyExportable;

        /// <summary>How signatures come.</summary>
        public string SignatureFormat => Metadata.SignatureFormat;

        /// <summary>
        /// Whether the key was made at this launch: a new installation, so the
        /// app forgets what it kept for the one before.
        /// </summary>
        public bool CreatedThisLaunch => Metadata.Created;

        /// <summary>
        /// The key's RFC 7638 thumbprint: the lower-case hex SHA-256 of
        /// <c>{"crv":…,"kty":"EC","x":…,"y":…}</c>, the installation's identity
        /// to a backend.
        /// </summary>
        public string KeyThumbprint => Json.Thumbprint(PublicKeyJson);

        /// <summary>Signs a base64url payload with the installation key.</summary>
        public Task<string> SignPayloadAsync(string payloadBase64Url) => NativeKey.SignPayloadAsync(payloadBase64Url);

        /// <summary>This installation, under the ID a backend holds for its key.</summary>
        public InstallationIdentity WithInstallationId(string canonicalInstallationId) =>
            new InstallationIdentity(canonicalInstallationId, NativeKey, Metadata);
    }
}
