// The sample backend's own API (../../backend/README.md): how an app signs what
// it sends to its own backend -- a request proof on every request, and the
// person's approval on a sensitive one -- and requests made wrong on purpose,
// which a backend must refuse.
using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary.Example
{
    public sealed class SampleApi
    {
        private const string Echo = "/v1/demo/echo";
        private const string Sensitive = "/v1/demo/sensitive";
        private const string EchoBody = "{\"hello\":\"backend\"}";
        private const string PayeeBody = "{\"payee\":\"payee-7\"}";

        public SampleApi(DeviceTrust trust)
        {
            Trust = trust;
        }

        public DeviceTrust Trust { get; }

        /// <summary>The sample's account session for this installation, after <see cref="SignInAsync"/>.</summary>
        public string? Account { get; set; }

        private string Session => Account ?? throw new InvalidOperationException("Sign in first.");

        /// <summary>
        /// The sample's sign-in, under the installation session from start: an
        /// account session for this installation. The sample makes the account at
        /// its first sign-in.
        /// </summary>
        public async Task SignInAsync(string handle, string password)
        {
            var proof = await Trust.SignRequestAsync(
                "POST",
                "/v1/demo/sign-in",
                Trust.InstallationSession ?? throw new InvalidOperationException("Start first."),
                new JsonObject { ["handle"] = handle, ["password"] = password }.ToJsonString());
            Account = (string)(await Trust.SendAsync(proof))["account_session"]!;
        }

        /// <summary>A request with its request proof alone: only this installation's key can sign it.</summary>
        public async Task<JsonObject> ProtectedRequestAsync() =>
            await Trust.SendAsync(await Trust.SignRequestAsync("POST", Echo, Session, EchoBody));

        /// <summary>
        /// The sensitive request. With <paramref name="stepUp"/> the person
        /// approves it with the screen lock; with <paramref name="appPin"/> the
        /// backend checks the PIN for this request first. With neither the
        /// backend refuses it.
        /// </summary>
        public async Task<JsonObject> SensitiveAsync(bool stepUp = false, string? appPin = null) =>
            await Trust.SendAsync(await Trust.SignRequestAsync(
                "POST",
                Sensitive,
                Session,
                PayeeBody,
                stepUp: stepUp,
                reason: "Approve the new payee",
                appPin: appPin));

        /// <summary>A new step-up key, with the person's password.</summary>
        public Task<JsonObject> ReenrolStepUpAsync(string password) =>
            Trust.ReenrolStepUpAsync(Session, new JsonObject { ["password"] = password });

        /// <summary>Sets the account's app PIN, with the person's password.</summary>
        public Task<JsonObject> SetAppPinAsync(string pin, string password) =>
            Trust.SetAppPinAsync(Session, pin, new JsonObject { ["password"] = password });

        // --- Requests a backend must refuse.

        /// <summary>One signed request sent twice: the second is a replay.</summary>
        public async Task<JsonObject> ReplayAsync()
        {
            var proof = await SignedEcho();
            try
            {
                await Trust.SendAsync(proof);
            }
            catch (ApiException error)
            {
                // The first must go through, or the second tests nothing.
                throw new InvalidOperationException("The first send was refused: " + error.StatusCode + " " + error.Code + ".", error);
            }

            return await Trust.SendAsync(proof);
        }

        /// <summary>A signed request whose body is changed on the way.</summary>
        public async Task<JsonObject> ChangedBodyAsync() =>
            await Trust.Client.SendSignedAsync(await SignedEcho(), encodedBody: "{\"hello\":\"changed\"}");

        /// <summary>A signed request sent to another path.</summary>
        public async Task<JsonObject> OtherPathAsync() =>
            await Trust.Client.SendSignedAsync(await SignedEcho(), path: Sensitive);

        /// <summary>A request proof signed ten minutes ago.</summary>
        public async Task<JsonObject> StaleProofAsync() =>
            await Trust.SendAsync(await RequestProofs.SignAsync(
                await Trust.LoadIdentityAsync(),
                "POST",
                Echo,
                Session,
                EchoBody,
                timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600));

        /// <summary>This phone's account session and installation, to try on another phone.</summary>
        public string ShareSession() => new JsonObject
        {
            ["session"] = Session,
            ["installation_id"] = Trust.Identity!.InstallationId,
        }.ToJsonString();

        /// <summary>A session shared from another phone, used here: this phone's key signs a request naming that phone's installation.</summary>
        public async Task<JsonObject> SessionFromAnotherPhoneAsync(string shared)
        {
            var copied = (JsonObject)JsonNode.Parse(shared.Trim())!;
            return await Trust.SendAsync(await RequestProofs.SignAsync(
                await Trust.LoadIdentityAsync(),
                "POST",
                Echo,
                (string)copied["session"]!,
                EchoBody,
                installationId: (string)copied["installation_id"]!));
        }

        private Task<RequestProof> SignedEcho() => Trust.SignRequestAsync("POST", Echo, Session, EchoBody);
    }
}
