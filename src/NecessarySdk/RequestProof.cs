using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// The person's approval of one request: the step-up key's
    /// <see cref="Factor"/>, and <see cref="Sign"/>, which has the step-up key
    /// sign a payload -- the phone asks the person.
    /// </summary>
    public sealed class StepUpApproval
    {
        /// <summary>An approval by a key of <paramref name="factor"/>.</summary>
        public StepUpApproval(string factor, Func<string, Task<string>> sign)
        {
            Factor = factor ?? throw new ArgumentNullException(nameof(factor));
            Sign = sign ?? throw new ArgumentNullException(nameof(sign));
        }

        /// <summary>The step-up key's factor.</summary>
        public string Factor { get; }

        /// <summary>Signs a base64url payload with the step-up key.</summary>
        public Func<string, Task<string>> Sign { get; }
    }

    /// <summary>
    /// What the installation key signed for one request -- with step-up, what
    /// the step-up key signed; with the app PIN, the backend's proof of it; for a
    /// request a scan approves, that scan's report -- and the headers that carry
    /// them beside <c>Authorization: Bearer</c>.
    /// </summary>
    public sealed class RequestProof
    {
        /// <summary>A proof, as signed.</summary>
        public RequestProof(
            string bearerToken,
            string method,
            string path,
            string encodedBody,
            string payload,
            string signature,
            long timestamp,
            string nonce,
            string? stepUpPayload = null,
            string? stepUpSignature = null,
            string? appPinProof = null,
            string? integrityReport = null)
        {
            BearerToken = bearerToken;
            Method = method;
            Path = path;
            EncodedBody = encodedBody;
            Payload = payload;
            Signature = signature;
            Timestamp = timestamp;
            Nonce = nonce;
            StepUpPayload = stepUpPayload;
            StepUpSignature = stepUpSignature;
            AppPinProof = appPinProof;
            IntegrityReport = integrityReport;
        }

        /// <summary>The session the request is sent under.</summary>
        public string BearerToken { get; }

        /// <summary>The request's method, upper case.</summary>
        public string Method { get; }

        /// <summary>The request's path, with its query.</summary>
        public string Path { get; }

        /// <summary>The exact body.</summary>
        public string EncodedBody { get; }

        /// <summary><c>X-Access-Proof</c>: the base64url of the proof's JSON bytes.</summary>
        public string Payload { get; }

        /// <summary><c>X-Access-Signature</c>.</summary>
        public string Signature { get; }

        /// <summary>When it was signed, in Unix seconds.</summary>
        public long Timestamp { get; }

        /// <summary>The proof's nonce, base64url.</summary>
        public string Nonce { get; }

        /// <summary><c>X-Step-Up-Proof</c>, for a request the person approved.</summary>
        public string? StepUpPayload { get; }

        /// <summary><c>X-Step-Up-Signature</c>.</summary>
        public string? StepUpSignature { get; }

        /// <summary>
        /// <c>X-App-PIN-Proof</c>: the backend's proof that the person entered
        /// the app PIN for this request (<see cref="DeviceTrustClient.ProveAppPinAsync"/>).
        /// </summary>
        public string? AppPinProof { get; }

        /// <summary><c>X-Integrity-Report</c>: the report of the scan made for this request alone.</summary>
        public string? IntegrityReport { get; }

        /// <summary>The headers that carry the proof, beside <c>Authorization: Bearer</c>.</summary>
        public IReadOnlyDictionary<string, string> Headers
        {
            get
            {
                var headers = new Dictionary<string, string>
                {
                    ["X-Access-Proof"] = Payload,
                    ["X-Access-Signature"] = Signature,
                };
                if (StepUpPayload is not null)
                {
                    headers["X-Step-Up-Proof"] = StepUpPayload;
                }

                if (StepUpSignature is not null)
                {
                    headers["X-Step-Up-Signature"] = StepUpSignature;
                }

                if (AppPinProof is not null)
                {
                    headers["X-App-PIN-Proof"] = AppPinProof;
                }

                if (IntegrityReport is not null)
                {
                    headers["X-Integrity-Report"] = IntegrityReport;
                }

                return headers;
            }
        }

        /// <summary>This request, unlocked by the backend's <paramref name="proof"/> of the app PIN.</summary>
        public RequestProof WithAppPinProof(string proof) => With(proof, IntegrityReport);

        /// <summary>This request, naming <paramref name="reportId"/>, the scan made for it alone.</summary>
        public RequestProof WithIntegrityReport(string reportId) => With(AppPinProof, reportId);

        private RequestProof With(string? appPinProof, string? integrityReport) =>
            new RequestProof(
                BearerToken,
                Method,
                Path,
                EncodedBody,
                Payload,
                Signature,
                Timestamp,
                Nonce,
                StepUpPayload,
                StepUpSignature,
                appPinProof,
                integrityReport);
    }

    /// <summary>
    /// Request proofs (the public guide, section 3): the installation key signs
    /// each request, so a copied session token is useless without the key; with
    /// step-up on the person approves one request with the step-up key, and with
    /// the app PIN on a request carries the backend's proof of the PIN. Also the
    /// description of the one request a scan is to approve (section 2).
    /// </summary>
    public static class RequestProofs
    {
        /// <summary>
        /// What the app sends to have its backend check the app PIN for one
        /// request: the PIN, and that request as its request proof signs it --
        /// method, path, query, the hash of the body sent and the request proof's
        /// nonce.
        /// </summary>
        public static JsonObject AppPinProofRequest(string pin, string method, string path, string encodedBody, string nonce)
        {
            var target = RequestTarget.Parse(path);
            return new JsonObject
            {
                ["pin"] = pin,
                ["request"] = new JsonObject
                {
                    ["method"] = method.ToUpperInvariant(),
                    ["path"] = target.Path,
                    ["query"] = target.Query,
                    ["body_sha256"] = Wire.Sha256Hex(encodedBody),
                    ["nonce"] = nonce,
                },
            };
        }

        /// <summary>
        /// The step-up proof, version 2, that the step-up key signs for one
        /// request: the base64url of its JSON, the members in this order.
        /// <paramref name="nonce"/> is the request proof's nonce for the same
        /// request, so the approval is used up with it.
        /// </summary>
        public static string StepUpProof(
            string installationId,
            string accessToken,
            string method,
            string path,
            string encodedBody,
            string factor,
            string nonce,
            long timestamp)
        {
            var target = RequestTarget.Parse(path);
            return Encode(new JsonObject
            {
                ["version"] = 2,
                ["purpose"] = "stepup",
                ["installation_id"] = installationId,
                ["access_token_sha256"] = Wire.Sha256Hex(accessToken),
                ["method"] = method.ToUpperInvariant(),
                ["path"] = target.Path,
                ["query"] = target.Query,
                ["body_sha256"] = Wire.Sha256Hex(encodedBody),
                ["factor"] = factor,
                ["nonce"] = nonce,
                ["timestamp"] = timestamp,
            });
        }

        /// <summary>
        /// The proof a new step-up key signs at re-enrolment: the base64url of
        /// its JSON, the members in this order. <paramref name="nonce"/> is the
        /// request proof's nonce of the re-enrolment request.
        /// </summary>
        public static string StepUpReenrolProof(string installationId, string stepUpKeyThumbprint, string nonce, long timestamp) =>
            Encode(new JsonObject
            {
                ["version"] = 1,
                ["purpose"] = "stepup_reenrol",
                ["installation_id"] = installationId,
                ["stepup_key_thumbprint"] = stepUpKeyThumbprint,
                ["nonce"] = nonce,
                ["timestamp"] = timestamp,
            });

        /// <summary>
        /// Signs <paramref name="method"/> <paramref name="path"/> with
        /// <paramref name="encodedBody"/> under <paramref name="bearerToken"/>:
        /// proof version 2, which signs the query string too, exactly as sent. A
        /// GET signs an empty body. With <paramref name="stepUp"/>, the step-up key
        /// signs first -- the phone asks the person -- and the request proof
        /// after, with the same nonce, so the time the person takes does not count
        /// against the request proof's clock window.
        /// <paramref name="installationId"/>, <paramref name="timestamp"/> and
        /// <paramref name="nonce"/> replace what the request proof would otherwise
        /// carry, for the shared test vectors and for testing a backend's refusals.
        /// </summary>
        public static async Task<RequestProof> SignAsync(
            InstallationIdentity identity,
            string method,
            string path,
            string bearerToken,
            string encodedBody = "",
            StepUpApproval? stepUp = null,
            string? installationId = null,
            long? timestamp = null,
            byte[]? nonce = null)
        {
            if (identity is null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            var normalizedMethod = method.ToUpperInvariant();
            var body = normalizedMethod == "GET" ? string.Empty : encodedBody;
            var nonceText = Wire.Base64UrlNoPadding(nonce ?? Wire.FreshNonce());
            string? stepUpPayload = null;
            string? stepUpSignature = null;
            if (stepUp is not null)
            {
                stepUpPayload = StepUpProof(
                    identity.InstallationId,
                    bearerToken,
                    normalizedMethod,
                    path,
                    body,
                    stepUp.Factor,
                    nonceText,
                    Wire.UnixSeconds());
                stepUpSignature = await stepUp.Sign(stepUpPayload);
            }

            var signedAt = timestamp ?? Wire.UnixSeconds();
            var target = RequestTarget.Parse(path);

            // The members in this order: the backend checks each against the
            // request it received, and the shared vectors hold both sides to
            // these bytes.
            var proof = new JsonObject
            {
                ["access_token_sha256"] = Wire.Sha256Hex(bearerToken),
                ["body_sha256"] = Wire.Sha256Hex(body),
                ["installation_id"] = installationId ?? identity.InstallationId,
                ["method"] = normalizedMethod,
                ["nonce"] = nonceText,
                ["path"] = target.Path,
                ["query"] = target.Query,
                ["timestamp"] = signedAt,
                ["version"] = 2,
            };

            // The key signs the exact JSON bytes this base64url value carries;
            // the private key never leaves Android Keystore or the iOS Keychain.
            var payload = Encode(proof);
            return new RequestProof(
                bearerToken,
                normalizedMethod,
                path,
                body,
                payload,
                await identity.SignPayloadAsync(payload),
                signedAt,
                nonceText,
                stepUpPayload,
                stepUpSignature);
        }

        /// <summary>
        /// The one request a scan is to approve, described exactly as it will be
        /// sent: what the challenge names as its <c>operation</c>.
        /// </summary>
        public static JsonObject DescribeOperation(string method, string path, string encodedBody)
        {
            var target = RequestTarget.Parse(path);
            return new JsonObject
            {
                ["method"] = method.ToUpperInvariant(),
                ["path"] = target.Path,
                ["query"] = target.Query,
                ["body_sha256"] = Wire.Sha256Hex(encodedBody),
            };
        }

        private static string Encode(JsonObject value) => Wire.Base64UrlNoPadding(Encoding.UTF8.GetBytes(DartJson.Encode(value)));
    }
}
