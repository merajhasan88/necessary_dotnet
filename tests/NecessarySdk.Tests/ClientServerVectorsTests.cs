// The shared client-server vectors, vectors/client_server.json: the package
// must produce, byte for byte, the request proof it signs, the operation a scan
// names, its key's thumbprint, the step-up proofs and the app PIN's request --
// the integration guide's sections 1 to 3. A backend can test itself against
// the same file.
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Xunit;

namespace Necessary.Tests
{
    public class ClientServerVectorsTests
    {
        private static readonly JsonObject Vectors =
            (JsonObject)JsonNode.Parse(File.ReadAllText(RepositoryFiles.File("vectors/client_server.json")))!;

        private static JsonObject SomeKey => (JsonObject)Vectors["thumbprint"]![0]!["jwk"]!.DeepClone();

        public static IEnumerable<object[]> Section(string name) =>
            ((JsonArray)Vectors[name]!).Select(vector => new object[] { (string)vector!["name"]! });

        private static JsonObject Vector(string section, string name) =>
            (JsonObject)((JsonArray)Vectors[section]!).Single(vector => (string)vector!["name"]! == name)!;

        private static string Unpadded(string value) => Encoding.UTF8.GetString(Wire.DecodeBase64Url(value));

        private static InstallationIdentity Identity(string installationId, JsonObject jwk) =>
            new InstallationIdentity(
                installationId,
                new VectorKey(),
                new NativeKeyMetadata(jwk, "ES256", "vector", "vector", "software", false, false, "der", false));

        [Fact]
        public void The_file_holds_the_six_sections()
        {
            foreach (var section in new[] { "access_proof", "operation", "thumbprint", "step_up_proof", "app_pin_proof_request", "step_up_reenrol_proof" })
            {
                Assert.NotEmpty((JsonArray)Vectors[section]!);
            }
        }

        [Theory]
        [MemberData(nameof(Section), "access_proof")]
        public async Task Access_proof(string name)
        {
            var vector = Vector("access_proof", name);
            var body = vector["body"];
            var proof = await RequestProofs.SignAsync(
                Identity((string)vector["installation_id"]!, SomeKey),
                (string)vector["method"]!,
                (string)vector["path"]!,
                (string)vector["bearer"]!,
                body is null ? string.Empty : DartJson.Encode(body),
                timestamp: (long)vector["timestamp"]!,
                nonce: Wire.DecodeBase64Url((string)vector["nonce"]!));
            Assert.Equal((string)vector["sent_body"]!, proof.EncodedBody);
            Assert.Equal((string)vector["proof_json"]!, Unpadded(proof.Payload));
            Assert.Equal((string)vector["proof"]!, proof.Payload);
        }

        [Theory]
        [MemberData(nameof(Section), "operation")]
        public void Operation_a_scan_names(string name)
        {
            var vector = Vector("operation", name);
            var sent = DartJson.Encode(vector["body"]);
            Assert.Equal((string)vector["sent_body"]!, sent);
            var operation = RequestProofs.DescribeOperation((string)vector["method"]!, (string)vector["path"]!, sent);
            Assert.True(JsonNode.DeepEquals(vector["operation"], operation), operation.ToJsonString());
        }

        [Theory]
        [MemberData(nameof(Section), "thumbprint")]
        public void Key_thumbprint(string name)
        {
            var vector = Vector("thumbprint", name);
            var identity = Identity("00000000-0000-4000-8000-000000000000", (JsonObject)vector["jwk"]!.DeepClone());
            Assert.Equal((string)vector["thumbprint"]!, identity.KeyThumbprint);
        }

        // The step-up proofs (the public guide, section 3): what the step-up key
        // signs for one request, and what a new step-up key signs at re-enrolment.
        [Theory]
        [MemberData(nameof(Section), "step_up_proof")]
        public void Step_up_proof_v2(string name)
        {
            var vector = Vector("step_up_proof", name);
            var sent = DartJson.Encode(vector["body"]);
            Assert.Equal((string)vector["sent_body"]!, sent);
            var payload = RequestProofs.StepUpProof(
                (string)vector["installation_id"]!,
                (string)vector["bearer"]!,
                "POST",
                (string)vector["path"]!,
                sent,
                (string)vector["factor"]!,
                (string)vector["nonce"]!,
                (long)vector["timestamp"]!);
            Assert.Equal((string)vector["proof_json"]!, Unpadded(payload));
            Assert.Equal((string)vector["proof"]!, payload);
        }

        [Theory]
        [MemberData(nameof(Section), "step_up_reenrol_proof")]
        public void Step_up_key_reenrolment_proof(string name)
        {
            var vector = Vector("step_up_reenrol_proof", name);
            var payload = RequestProofs.StepUpReenrolProof(
                (string)vector["installation_id"]!,
                (string)vector["stepup_key_thumbprint"]!,
                (string)vector["nonce"]!,
                (long)vector["timestamp"]!);
            Assert.Equal((string)vector["proof_json"]!, Unpadded(payload));
            Assert.Equal((string)vector["proof"]!, payload);
        }

        // What the app sends to have its backend check the app PIN for one
        // request (the public guide, section 3).
        [Theory]
        [MemberData(nameof(Section), "app_pin_proof_request")]
        public void App_pin_proof_request(string name)
        {
            var vector = Vector("app_pin_proof_request", name);
            var sent = DartJson.Encode(vector["body"]);
            Assert.Equal((string)vector["sent_body"]!, sent);
            Assert.Equal(
                (string)vector["asked_body"]!,
                DartJson.Encode(RequestProofs.AppPinProofRequest(
                    (string)vector["pin"]!,
                    "POST",
                    (string)vector["path"]!,
                    sent,
                    (string)vector["nonce"]!)));
        }

        /// <summary>Signs nothing: the vectors fix what is signed, and ECDSA signatures are randomized.</summary>
        private sealed class VectorKey : INativeInstallationKey
        {
            public Task<NativeKeyMetadata> GetOrCreateKeyAsync() => throw new System.NotImplementedException();

            public Task<string> SignPayloadAsync(string payloadBase64Url) => Task.FromResult("unsigned");

            public Task DeleteKeyAsync() => Task.CompletedTask;
        }
    }
}
