using System;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// The optional step-up key as the native side reports it.
    /// <see cref="Factor"/>, <see cref="Mode"/> and <see cref="WindowSeconds"/>
    /// describe what the platform keystore actually enforces (read back from
    /// KeyInfo on Android, from the key's label on iOS), which on Android 9 and
    /// 10 is a short hardware window rather than per-use.
    /// </summary>
    public sealed class StepUpKeyMetadata
    {
        /// <summary>A step-up key's description.</summary>
        public StepUpKeyMetadata(
            JsonObject publicKey,
            string factor,
            string mode,
            int windowSeconds,
            string securityLevel,
            bool hardwareBacked,
            bool created)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Factor = factor;
            Mode = mode;
            WindowSeconds = windowSeconds;
            SecurityLevel = securityLevel;
            HardwareBacked = hardwareBacked;
            Created = created;
        }

        /// <summary>The public JWK.</summary>
        public JsonObject PublicKey { get; }

        /// <summary><c>passcode</c> or <c>biometric</c>.</summary>
        public string Factor { get; }

        /// <summary><c>per_use</c> or <c>windowed</c>.</summary>
        public string Mode { get; }

        /// <summary>The window, for a windowed key; 0 for a per-use key.</summary>
        public int WindowSeconds { get; }

        /// <summary>Where the phone says the key is kept.</summary>
        public string SecurityLevel { get; }

        /// <summary>Whether the phone says the key is in secure hardware.</summary>
        public bool HardwareBacked { get; }

        /// <summary>Whether the key was made by this call.</summary>
        public bool Created { get; }

        /// <summary><c>stepup_key_auth</c>: what the phone says about how the key is unlocked.</summary>
        public JsonObject AuthJson => new JsonObject
        {
            ["factor"] = Factor,
            ["mode"] = Mode,
            ["window_seconds"] = WindowSeconds,
        };

        /// <summary>The key's unlock, in words.</summary>
        public string Description => Mode == "per_use"
            ? Factor + ", per-use"
            : Factor + ", " + WindowSeconds.ToString(CultureInfo.InvariantCulture) + "s hardware window";

        /// <summary>RFC 7638 thumbprint, the same form the backend derives from the JWK.</summary>
        public string Thumbprint => Json.Thumbprint(PublicKey);

        /// <summary>Reads the native side's description of the key.</summary>
        public static StepUpKeyMetadata FromPlatform(JsonObject value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (value["public_key"] is not JsonObject publicKey || value["auth"] is not JsonObject auth)
            {
                throw new FormatException("The native step-up key provider returned no public key or auth.");
            }

            if (!Json.IsEcP256(publicKey))
            {
                throw new FormatException("The native step-up key provider did not return an EC P-256 public JWK.");
            }

            var factor = Json.String(auth["factor"]);
            var mode = Json.String(auth["mode"]);
            var window = Json.Integer(auth["window_seconds"]);
            if (factor is null || mode is null || window is null)
            {
                throw new FormatException("The native step-up key provider returned an invalid auth description.");
            }

            return new StepUpKeyMetadata(
                (JsonObject)publicKey.DeepClone(),
                factor,
                mode,
                (int)window.Value,
                Json.String(value["security_level"]) ?? "unknown",
                Json.Bool(value["hardware_backed"]) == true,
                Json.Bool(value["created"]) == true);
        }
    }

    /// <summary>
    /// How the app wants its step-up key made (the public guide, section 3):
    /// <see cref="Factor"/> <c>passcode</c> or <c>biometric</c>;
    /// <see cref="Mode"/> <c>per_use</c>, or <c>windowed</c> with
    /// <see cref="WindowSeconds"/> from 1. Android 9 and 10 cannot make a
    /// per-use passcode key and make a windowed one; iOS makes per-use keys
    /// only. <see cref="ReenrolPath"/> is where the backend takes a new key
    /// (<see cref="DeviceTrust.ReenrolStepUpAsync"/>).
    /// </summary>
    public sealed class StepUpOptions
    {
        /// <summary>Step-up options; by default a per-use passcode key.</summary>
        public StepUpOptions(
            string factor = "passcode",
            string mode = "per_use",
            int windowSeconds = 0,
            string reenrolPath = StepUp.ReenrolPath)
        {
            Factor = factor;
            Mode = mode;
            WindowSeconds = windowSeconds;
            ReenrolPath = reenrolPath;
        }

        /// <summary><c>passcode</c> or <c>biometric</c>.</summary>
        public string Factor { get; }

        /// <summary><c>per_use</c> or <c>windowed</c>.</summary>
        public string Mode { get; }

        /// <summary>The window of a windowed key, in seconds.</summary>
        public int WindowSeconds { get; }

        /// <summary>Where the backend takes a re-enrolled key.</summary>
        public string ReenrolPath { get; }

        /// <summary>These options, in words.</summary>
        public string Description =>
            Factor + ", " + (Mode == "per_use" ? "per-use" : WindowSeconds.ToString(CultureInfo.InvariantCulture) + "s window");

        /// <summary>
        /// A key made with other values, or already made: whether it satisfies
        /// these options -- the same factor (a backend refuses any other), and a
        /// per-use key or a window no longer than this one. A per-use key
        /// satisfies windowed options.
        /// </summary>
        public bool Accepts(StepUpKeyMetadata key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return key.Factor == Factor
                && (key.Mode == "per_use" || (Mode == "windowed" && key.WindowSeconds <= WindowSeconds));
        }
    }

    /// <summary>The step-up key's native side: made, used and deleted in the phone's keystore.</summary>
    public interface INativeStepUpKey
    {
        /// <summary>
        /// The mode the app asks for, which decides whether a windowed key first
        /// tries to sign inside an open hardware window.
        /// </summary>
        string ConfiguredMode { get; set; }

        /// <summary>
        /// Returns the existing key as the keystore enforces it, or creates one
        /// with these values: an existing key is never changed, so a caller that
        /// needs other values deletes it first.
        /// </summary>
        Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds);

        /// <summary>
        /// Shows the system passcode (or biometric) prompt, saying
        /// <paramref name="reason"/>, and completes when the person answers it. A
        /// cancelled prompt is <c>STEPUP_CANCELLED</c>.
        /// </summary>
        Task<string> SignAsync(string payloadBase64Url, string reason);

        /// <summary>Deletes the key.</summary>
        Task DeleteKeyAsync();
    }

    /// <summary>The step-up key's paths and rules.</summary>
    public static class StepUp
    {
        /// <summary>Where a backend takes a re-enrolled step-up key by default (the public guide, section 4).</summary>
        public const string ReenrolPath = "/v1/installations/stepup-key";

        /// <summary>
        /// Whether a step-up key <paramref name="options"/> do not accept is
        /// replaced before the next registration: only where the new key can then
        /// be bound -- by a re-enrolment (<paramref name="replaceMismatched"/>),
        /// which binds it with the person's re-authentication, or by this
        /// installation's first registration, which binds the key it is offered.
        /// A known installation's registration never binds an offered key; it
        /// only says whether it matches, so replacing the key there orphans the
        /// one the backend holds.
        /// </summary>
        public static bool ReplacesKey(
            StepUpKeyMetadata key,
            StepUpOptions options,
            bool replaceMismatched,
            bool knownInstallation)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return !key.Created && !options.Accepts(key) && (replaceMismatched || !knownInstallation);
        }
    }
}
