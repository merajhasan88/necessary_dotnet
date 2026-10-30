using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// The reinstall hint: a SHA-256 of the platform's per-app device
    /// identifier, which the backend keys before storing. Client input, never
    /// proof.
    /// </summary>
    public sealed class ReinstallHint
    {
        /// <summary>A hint of <paramref name="kind"/>.</summary>
        public ReinstallHint(string kind, string value)
        {
            Kind = kind;
            Value = value;
        }

        /// <summary><c>android_id_sha256</c> or <c>idfv_sha256</c>.</summary>
        public string Kind { get; }

        /// <summary>The SHA-256, lower-case hex.</summary>
        public string Value { get; }

        /// <summary>The hint as the registration carries it.</summary>
        public JsonObject ToJson() => new JsonObject { ["kind"] = Kind, ["value"] = Value };
    }

    /// <summary>Reads the reinstall hint: ANDROID_ID on Android, the identifier for vendor on iOS.</summary>
    public class ReinstallHintReader
    {
        /// <summary>The hint, or null where the platform gives none.</summary>
        public virtual async Task<ReinstallHint?> ReadAsync()
        {
            string kind;
            switch (Platform)
            {
                case NativePlatform.Android:
                    kind = "android_id";
                    break;
                case NativePlatform.Ios:
                    kind = "idfv";
                    break;
                default:
                    return null;
            }

            try
            {
                var value = ((await IdentifierAsync()) ?? string.Empty).Trim().ToLowerInvariant();
                if (value.Length == 0)
                {
                    return null;
                }

                var digest = Wire.Sha256Hex("device-recognition-hint-v1|" + kind + "|" + value);
                return new ReinstallHint(kind + "_sha256", digest);
            }
#pragma warning disable CA1031 // A missing hint must never stop cryptographic installation identity.
            catch (Exception)
#pragma warning restore CA1031
            {
            }

            return null;
        }

        /// <summary>The platform the hint is read for: <c>android</c>, <c>ios</c>, or another, which has none.</summary>
        protected internal virtual string Platform => NativePlatform.Name;

        /// <summary>The platform's identifier, as the native side gives it.</summary>
        protected internal virtual Task<string?> IdentifierAsync() => NativePlatform.ReinstallHintIdentifierAsync();
    }
}
