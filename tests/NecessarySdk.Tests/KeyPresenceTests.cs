// A key is made only where the keystore, answering, holds none: a lookup that
// failed never replaces the key (the release review of 2026-10-31's acceptance:
// "transient binder/keymaster error followed by recovery preserves the same
// public key"). The plugin's KeyPresenceTest.kt, translated.
using System;
using System.Collections.Generic;
using Xunit;
using static Necessary.KeyPresence;

namespace Necessary.Tests
{
    public class KeyPresenceTests
    {
        [Fact]
        public void A_key_the_keystore_reports_is_present_and_nothing_else_is_asked()
        {
            var keystore = new Keystore("held");
            Assert.Equal(Answer.Present, Of(keystore).Answer);
            Assert.Equal(1, keystore.Calls);
        }

        [Fact]
        public void No_key_with_the_keystore_answering_is_absent()
        {
            var (answer, cause) = Of(new Keystore(null));
            Assert.Equal(Answer.Absent, answer);
            Assert.Null(cause);
        }

        [Fact]
        public void An_outage_over_the_lookup_and_the_probe_is_unavailable_with_its_cause()
        {
            var keystore = new Keystore("held") { Outage = new HashSet<int> { 1, 2 } };
            var (answer, cause) = Of(keystore);
            Assert.Equal(Answer.Unavailable, answer);
            Assert.IsType<InvalidOperationException>(cause);
        }

        [Fact]
        public void A_probe_that_fails_any_other_way_is_unavailable_too()
        {
            // A keystore with no service behind it fails with a NullPointerException.
            Assert.Equal(Answer.Unavailable, Of(new NoService()).Answer);
        }

        [Fact]
        public void A_lookup_that_failed_once_is_asked_again_once_the_keystore_answers()
        {
            Assert.Equal(Answer.Present, Of(new Keystore("held") { Outage = new HashSet<int> { 1 } }).Answer);
        }

        [Fact]
        public void An_outage_at_start_then_recovery_keeps_the_same_key()
        {
            var keystore = new Keystore("registered") { Outage = new HashSet<int> { 1, 2 } };
            var refused = Assert.Throws<InvalidOperationException>(() => keystore.Start());
            Assert.Equal("KEY_UNAVAILABLE", refused.Message);
            Assert.Equal("registered", keystore.Key);
            keystore.Outage = new HashSet<int>();
            Assert.Equal("registered", keystore.Start());
        }

        [Fact]
        public void The_first_start_makes_the_key_and_the_next_finds_it()
        {
            var keystore = new Keystore(null);
            var made = keystore.Start();
            Assert.Equal(made, keystore.Start());
        }

        [Fact]
        public void The_limit_two_outages_around_an_answered_probe_read_as_absent()
        {
            // Stated, not hidden: one outage over each lookup, none over the probe.
            Assert.Equal(Answer.Absent, Of(new Keystore("held") { Outage = new HashSet<int> { 1, 3 } }).Answer);
        }

        /// <summary>AndroidKeyStore as KeyPresence sees it, with an outage over chosen calls.</summary>
        private sealed class Keystore : IKeystore
        {
            private int made;

            public Keystore(string? key)
            {
                Key = key;
            }

            public string? Key { get; private set; }

            /// <summary>The calls, counted from 1, that the keystore cannot answer.</summary>
            public HashSet<int> Outage { get; set; } = new HashSet<int>();

            public int Calls { get; private set; }

            public bool ContainsKey()
            {
                Calls++;
                return !Outage.Contains(Calls) && Key is not null;
            }

            public void DeleteProbe()
            {
                Calls++;
                if (Outage.Contains(Calls))
                {
                    throw new InvalidOperationException("Failed to delete entry");
                }
            }

            /// <summary>What a key class does with the answer: load, make, or refuse.</summary>
            public string Start()
            {
                Calls = 0;
                return Of(this).Answer switch
                {
                    Answer.Present => Key!,
                    Answer.Absent => Key = "made-" + (++made),
                    _ => throw new InvalidOperationException("KEY_UNAVAILABLE"),
                };
            }
        }

        private sealed class NoService : IKeystore
        {
            public bool ContainsKey() => false;

            public void DeleteProbe() => throw new NullReferenceException("no keystore service");
        }
    }
}
