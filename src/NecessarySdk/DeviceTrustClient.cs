using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// The public guide's five calls (section 4) over an
    /// <see cref="IDeviceTrustTransport"/>, the two scan calls each with its
    /// request proof (section 3), and the app PIN's two calls.
    /// </summary>
    public sealed class DeviceTrustClient
    {
        /// <summary>Where the backend sets the app PIN by default (the public guide, section 4).</summary>
        public const string AppPinPath = "/v1/account/app-pin";

        /// <summary>Where the backend proves the app PIN for one request by default.</summary>
        public const string AppPinProofPath = "/v1/account/app-pin/proof";

        /// <summary>A client over <paramref name="transport"/>.</summary>
        public DeviceTrustClient(IDeviceTrustTransport transport)
        {
            Transport = transport ?? throw new ArgumentNullException(nameof(transport));
        }

        /// <summary>
        /// The fields of the guide's registration, which
        /// <see cref="RegisterInstallationAsync"/>'s <c>extra</c> cannot replace.
        /// </summary>
        public static IReadOnlyCollection<string> RegistrationFields { get; } = new HashSet<string>(StringComparer.Ordinal)
        {
            "installation_id",
            "platform",
            "public_key",
            "reinstall_hint",
            "key_security",
            "stepup_public_key",
            "stepup_key_auth",
        };

        /// <summary>The transport every call goes through.</summary>
        public IDeviceTrustTransport Transport { get; }

        /// <summary>
        /// Sends <paramref name="proof"/>'s request. <paramref name="method"/>,
        /// <paramref name="path"/> and <paramref name="encodedBody"/> replace what
        /// the proof was signed for -- only to test that a backend refuses them.
        /// </summary>
        public Task<JsonObject> SendSignedAsync(
            RequestProof proof,
            string? method = null,
            string? path = null,
            string? encodedBody = null)
        {
            if (proof is null)
            {
                throw new ArgumentNullException(nameof(proof));
            }

            var sentMethod = (method ?? proof.Method).ToUpperInvariant();
            return Transport.SendAsync(
                sentMethod,
                path ?? proof.Path,
                sentMethod == "GET" ? null : encodedBody ?? proof.EncodedBody,
                proof.BearerToken,
                proof.Headers);
        }

        /// <summary>
        /// Signs and sends one request under <paramref name="bearerToken"/>, its
        /// <paramref name="body"/> as JSON. <paramref name="installationId"/>
        /// replaces the installation the proof names, only to test that a backend
        /// refuses it.
        /// </summary>
        public async Task<JsonObject> SignAndSendAsync(
            string method,
            string path,
            string bearerToken,
            InstallationIdentity identity,
            JsonObject? body = null,
            string? installationId = null)
        {
            var proof = await RequestProofs.SignAsync(
                identity,
                method,
                path,
                bearerToken,
                DartJson.Encode(body ?? new JsonObject()),
                installationId: installationId);
            return await SendSignedAsync(proof);
        }

        /// <summary>
        /// Registers the installation's key, and with <paramref name="stepUpKey"/>
        /// the step-up key. The answer's <c>installation_id</c> is the
        /// installation your backend holds for this key, which may not be the one
        /// proposed. <paramref name="extra"/> adds fields of your backend's own.
        /// </summary>
        public Task<JsonObject> RegisterInstallationAsync(
            InstallationIdentity identity,
            ReinstallHint? hint,
            StepUpKeyMetadata? stepUpKey = null,
            JsonObject? extra = null)
        {
            if (identity is null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            var replaced = extra?.Select(member => member.Key).Where(RegistrationFields.Contains).ToList();
            if (replaced is { Count: > 0 })
            {
                throw new ArgumentException(
                    "replaces the registration fields " + string.Join(", ", replaced),
                    nameof(extra));
            }

            var body = new JsonObject
            {
                ["installation_id"] = identity.InstallationId,
                ["platform"] = NativePlatform.RegistrationName,
                ["public_key"] = identity.PublicKeyJson.DeepClone(),
                ["reinstall_hint"] = hint?.ToJson(),

                // What the platform's keystore says about how the key is
                // protected: a claim, not proof. Its value is comparative -- a
                // non-exportable hardware key cannot move into software, so the
                // same key later claiming a weaker level contradicts itself.
                ["key_security"] = new JsonObject
                {
                    ["security_level"] = identity.SecurityLevel,
                    ["hardware_backed"] = identity.HardwareBacked,
                    ["provider"] = identity.Provider,
                },
            };

            // The step-up key, and how the phone says it is unlocked: also a
            // claim, recorded and compared with what the backend requires.
            if (stepUpKey is not null)
            {
                body["stepup_public_key"] = stepUpKey.PublicKey.DeepClone();
                body["stepup_key_auth"] = stepUpKey.AuthJson;
            }

            if (extra is not null)
            {
                foreach (var member in extra)
                {
                    body[member.Key] = member.Value?.DeepClone();
                }
            }

            return Transport.SendAsync("POST", "/v1/installations/register", DartJson.Encode(body));
        }

        /// <summary>Asks for a key challenge: <c>challenge_id</c> and the <c>payload</c> to sign.</summary>
        public Task<JsonObject> CreateInstallationChallengeAsync(string installationId) =>
            Transport.SendAsync(
                "POST",
                "/v1/installations/challenge",
                DartJson.Encode(new JsonObject { ["installation_id"] = installationId }));

        /// <summary>
        /// Answers a key challenge; the answer carries <c>device_token</c>, your
        /// backend's session for this installation.
        /// </summary>
        public Task<JsonObject> VerifyInstallationAsync(
            string installationId,
            string challengeId,
            string payload,
            string signature) =>
            Transport.SendAsync(
                "POST",
                "/v1/installations/verify",
                DartJson.Encode(new JsonObject
                {
                    ["installation_id"] = installationId,
                    ["challenge_id"] = challengeId,
                    ["payload"] = payload,
                    ["signature"] = signature,
                }));

        /// <summary>
        /// Asks for a scan under <paramref name="session"/>: the installation's
        /// session, from <see cref="VerifyInstallationAsync"/> -- or, for a scan
        /// that approves one <paramref name="operation"/>
        /// (<see cref="RequestProofs.DescribeOperation"/>), your account session
        /// for this installation.
        /// </summary>
        public async Task<ScanChallenge> IntegrityChallengeAsync(
            string session,
            InstallationIdentity identity,
            JsonObject? operation = null)
        {
            var body = new JsonObject();
            if (operation is not null)
            {
                body["operation"] = operation.DeepClone();
            }

            return ScanChallenge.FromJson(await SignAndSendAsync("POST", "/v1/integrity/challenge", session, identity, body));
        }

        /// <summary>
        /// Sends <paramref name="report"/> under the <paramref name="session"/>
        /// that asked for its scan. The answer is your backend's own; for a scan
        /// that approves one request it carries <c>report_id</c>, sent with that
        /// request as <c>X-Integrity-Report</c>.
        /// </summary>
        public Task<JsonObject> SubmitIntegrityReportAsync(string session, InstallationIdentity identity, SignedReport report)
        {
            if (report is null)
            {
                throw new ArgumentNullException(nameof(report));
            }

            return SignAndSendAsync("POST", "/v1/integrity/report", session, identity, report.ToJson());
        }

        /// <summary>
        /// Sets the account's app PIN under its account <paramref name="session"/>.
        /// The backend requires the person's own re-authentication with it --
        /// <paramref name="reauthentication"/> carries it, the account's password
        /// for example: <c>{"password": …}</c>.
        /// </summary>
        public Task<JsonObject> SetAppPinAsync(
            string session,
            InstallationIdentity identity,
            string pin,
            JsonObject? reauthentication = null,
            string path = AppPinPath)
        {
            var body = new JsonObject();
            if (reauthentication is not null)
            {
                foreach (var member in reauthentication)
                {
                    body[member.Key] = member.Value?.DeepClone();
                }
            }

            body["pin"] = pin;
            return SignAndSendAsync("POST", path, session, identity, body);
        }

        /// <summary>
        /// Has the backend check the app <paramref name="pin"/> for the one
        /// signed <paramref name="request"/> -- sent once, in a signed body, never
        /// in a header -- and answers that request unlocked by its proof, valid
        /// for that request alone.
        /// </summary>
        public async Task<RequestProof> ProveAppPinAsync(
            string session,
            InstallationIdentity identity,
            string pin,
            RequestProof request,
            string path = AppPinProofPath)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var answer = await SignAndSendAsync(
                "POST",
                path,
                session,
                identity,
                RequestProofs.AppPinProofRequest(pin, request.Method, request.Path, request.EncodedBody, request.Nonce));
            var proof = Json.String(answer["app_pin_proof"]);
            if (string.IsNullOrEmpty(proof))
            {
                throw new ApiException("The backend answered no app PIN proof.", code: "app_pin_proof_missing");
            }

            return request.WithAppPinProof(proof!);
        }

        /// <summary>Closes the transport.</summary>
        public void Close() => Transport.Close();
    }
}
