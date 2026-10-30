using System;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>
    /// What the client does about a refusal from the device-trust API: the
    /// protocol errors of the integration guide's section 4, each acted on once.
    /// Any other refusal goes to the app as it came.
    /// </summary>
    public enum ProtocolStep
    {
        /// <summary>A challenge expired or was used: ask for a new one.</summary>
        AskAgain,

        /// <summary>The installation session expired: prove the key again.</summary>
        ProveAgain,

        /// <summary>The backend does not know the installation: register again.</summary>
        RegisterAgain,

        /// <summary>A short wait: wait, then retry.</summary>
        WaitThenRetry,

        /// <summary>Anything else: stop, and tell the app.</summary>
        Stop,
    }

    /// <summary>The protocol errors of the public guide's section 4.</summary>
    public static class Protocol
    {
        /// <summary>
        /// The longest wait the client sits through before it retries a 429
        /// itself; a longer one goes to the app.
        /// </summary>
        public const int MaxWaitSeconds = 10;

        /// <summary>
        /// What to do about <paramref name="error"/>. <paramref name="deviceSession"/>:
        /// the request ran under the session from <c>/v1/installations/verify</c>,
        /// which the client can renew by proving its key again; an account session
        /// is the app's to renew.
        /// </summary>
        public static ProtocolStep StepFor(ApiException error, bool deviceSession)
        {
            if (error is null)
            {
                throw new ArgumentNullException(nameof(error));
            }

            switch (error.Code)
            {
                case "challenge_expired":
                case "challenge_used":
                case "integrity_challenge_expired":
                case "integrity_challenge_replay":
                    return ProtocolStep.AskAgain;
                case "expired_token":
                    return deviceSession ? ProtocolStep.ProveAgain : ProtocolStep.Stop;
                case "installation_not_found":
                    return ProtocolStep.RegisterAgain;
            }

            return Wait(error) is null ? ProtocolStep.Stop : ProtocolStep.WaitThenRetry;
        }

        /// <summary>How long a 429 asks the client to wait, when that is short enough to wait.</summary>
        public static TimeSpan? Wait(ApiException error)
        {
            if (error is null)
            {
                throw new ArgumentNullException(nameof(error));
            }

            if (error.StatusCode != 429
                || error.Details is null
                || !error.Details.TryGetPropertyValue("retry_after_seconds", out var node)
                || !TryNumber(node, out var seconds)
                || seconds < 0
                || seconds > MaxWaitSeconds)
            {
                return null;
            }

            return TimeSpan.FromMilliseconds(Math.Round(seconds * 1000, MidpointRounding.AwayFromZero));
        }

        private static bool TryNumber(JsonNode? node, out double value)
        {
            value = 0;
            if (node is not JsonValue number)
            {
                return false;
            }

            if (number.TryGetValue<JsonElement>(out var element))
            {
                if (element.ValueKind != JsonValueKind.Number)
                {
                    return false;
                }

                value = element.GetDouble();
                return true;
            }

            if (number.TryGetValue<int>(out var i))
            {
                value = i;
                return true;
            }

            if (number.TryGetValue<long>(out var l))
            {
                value = l;
                return true;
            }

            return number.TryGetValue(out value);
        }
    }
}
