// The step-up key is deleted only when Android says it is dead (the release
// review of 2026-10-31, item 4): the plugin's StepUpKeyEntryTest.kt, translated.
using System;
using Xunit;
using static Necessary.StepUpKeyEntry;

namespace Necessary.Tests
{
    public class StepUpKeyEntryTests
    {
        [Fact]
        public void A_loaded_key_signs() =>
            Assert.Equal(Verdict.Usable, Decide(Lookup.PrivateKey, SignStart.Started));

        [Fact]
        public void A_windowed_key_outside_its_window_only_needs_the_person() =>
            Assert.Equal(Verdict.Usable, Decide(Lookup.PrivateKey, SignStart.NeedsAuthentication));

        [Fact]
        public void A_permanently_invalidated_key_is_the_only_one_deleted()
        {
            Assert.Equal(Verdict.Invalidated, Decide(Lookup.PrivateKey, SignStart.PermanentlyInvalidated));
            foreach (Lookup lookup in Enum.GetValues(typeof(Lookup)))
            {
                if (lookup == Lookup.PrivateKey)
                {
                    continue;
                }

                foreach (SignStart start in Enum.GetValues(typeof(SignStart)))
                {
                    Assert.NotEqual(Verdict.Invalidated, Decide(lookup, start));
                }
            }
        }

        [Fact]
        public void An_ambiguous_lookup_keeps_the_key()
        {
            // Android 9 answers isKeyEntry false on a binder error; a failed
            // key-characteristics query surfaces as UnrecoverableKeyException.
            foreach (var lookup in new[] { Lookup.NotKeyEntry, Lookup.Unrecoverable, Lookup.NotPrivateKey })
            {
                Assert.Equal(Verdict.Unavailable, Decide(lookup, SignStart.NotTried));
            }
        }

        [Fact]
        public void The_android_9_orphaned_alias_is_kept_too()
        {
            // Seen on an Android 9 phone: containsAlias true, isKeyEntry false, and
            // getEntry throwing UnsupportedOperationException. Kept, retryable;
            // replacing it is the app's explicit re-enrolment.
            Assert.Equal(Verdict.Unavailable, Decide(Lookup.Unsupported, SignStart.NotTried));
            Assert.Equal(Verdict.Unavailable, Decide(Lookup.NotKeyEntry, SignStart.NotTried));
        }

        [Fact]
        public void The_same_failure_twice_is_still_no_proof_of_permanence()
        {
            for (var i = 0; i < 3; i++)
            {
                Assert.Equal(Verdict.Unavailable, Decide(Lookup.Unrecoverable, SignStart.NotTried));
            }
        }

        [Fact]
        public void Another_keystore_failure_is_reported_and_the_key_kept() =>
            Assert.Equal(Verdict.LookupFailed, Decide(Lookup.OtherFailure, SignStart.NotTried));
    }
}
