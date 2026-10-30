// When the app replaces a step-up key its options do not accept
// (StepUp.ReplacesKey). Under a per-use passcode policy, which Android 9
// cannot make a key for, the registration that follows each re-enrolment must
// not replace the key the server has just bound, or step-up stays unavailable.
using System.Text.Json.Nodes;
using Xunit;

namespace Necessary.Tests
{
    public class StepUpKeyTests
    {
        private static readonly StepUpOptions PerUse = new StepUpOptions();

        private static StepUpKeyMetadata Key(string mode = "windowed", bool created = false) =>
            new StepUpKeyMetadata(
                (JsonObject)JsonNode.Parse("{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"x\",\"y\":\"y\"}")!,
                "passcode",
                mode,
                mode == "windowed" ? 30 : 0,
                "tee",
                true,
                created);

        [Fact]
        public void A_known_installation_keeps_a_key_the_options_want_more_of() =>
            Assert.False(StepUp.ReplacesKey(Key(), PerUse, replaceMismatched: false, knownInstallation: true));

        [Fact]
        public void A_reenrolment_replaces_it_and_binds_the_new_one() =>
            Assert.True(StepUp.ReplacesKey(Key(), PerUse, replaceMismatched: true, knownInstallation: true));

        [Fact]
        public void An_installations_first_registration_replaces_it() =>
            Assert.True(StepUp.ReplacesKey(Key(), PerUse, replaceMismatched: false, knownInstallation: false));

        [Fact]
        public void A_key_just_made_or_one_the_options_accept_is_never_replaced()
        {
            foreach (var known in new[] { true, false })
            {
                Assert.False(StepUp.ReplacesKey(Key(created: true), PerUse, replaceMismatched: true, knownInstallation: known));
                Assert.False(StepUp.ReplacesKey(Key(mode: "per_use"), PerUse, replaceMismatched: true, knownInstallation: known));
            }
        }
    }
}
