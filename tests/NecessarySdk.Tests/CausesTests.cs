// Every failure says what failed beneath it (the release review of 2026-10-31,
// item 4: "preserve the original cause chain and available error codes"): the
// plugin's CausesTest.kt, translated.
using System;
using System.Linq;
using Xunit;

namespace Necessary.Tests
{
    public class CausesTests
    {
        /// <summary>Android 9's failed key lookup: the keystore's answer is only in the cause.</summary>
        private static Exception Android9Lookup() =>
            new Unrecoverable("Failed to obtain information about key", new KeyStoreFailure("Key blob corrupted"));

        [Fact]
        public void No_failure_says_nothing()
        {
            Assert.Equal(string.Empty, Causes.Chain(null));
            Assert.Equal("the message", Causes.WithCauses("the message", null));
        }

        [Fact]
        public void The_keystores_answer_beneath_a_failed_lookup_is_said()
        {
            Assert.Equal(
                "Unrecoverable: Failed to obtain information about key < KeyStoreFailure: Key blob corrupted",
                Causes.Chain(Android9Lookup()));
        }

        [Fact]
        public void Every_cause_is_said_outermost_first()
        {
            var failure = new InvalidOperationException("outer", new ApplicationException("middle", new ArgumentException("inner")));
            Assert.Equal(
                "InvalidOperationException: outer < ApplicationException: middle < ArgumentException: inner",
                Causes.Chain(failure));
        }

        [Fact]
        public void A_failure_without_words_is_named_by_its_kind()
        {
            Assert.Equal("Wordless", Causes.Chain(new Wordless()));
        }

        [Fact]
        public void The_detail_adds_the_keystores_code()
        {
            var chain = Causes.Chain(Android9Lookup(), error => error is KeyStoreFailure ? "code -33" : null);
            Assert.Equal(
                "Unrecoverable: Failed to obtain information about key < KeyStoreFailure: Key blob corrupted (code -33)",
                chain);
        }

        [Fact]
        public void A_cause_that_loops_is_said_once()
        {
            var first = new Looping("first");
            var second = new Looping("second") { Beneath = first };
            first.Beneath = second;
            Causes.Reader read = error => (error.GetType().Name, error.Message, (error as Looping)?.Beneath);
            Assert.Equal("Looping: first < Looping: second", Causes.Chain(first, null, read));
        }

        [Fact]
        public void A_chain_deeper_than_its_limit_says_so()
        {
            Exception failure = new InvalidOperationException("0");
            for (var depth = 1; depth <= 20; depth++)
            {
                failure = new InvalidOperationException(depth.ToString(System.Globalization.CultureInfo.InvariantCulture), failure);
            }

            var links = Causes.Chain(failure).Split(" < ");
            Assert.Equal(Causes.MaxLinks + 1, links.Length);
            Assert.Equal("…", links.Last());
        }

        [Fact]
        public void A_key_failure_reports_its_words_then_its_causes()
        {
            Assert.Equal(
                "AndroidKeyStore could not establish whether the step-up key is usable (lookup: unrecoverable). "
                + "[cause: Unrecoverable: Failed to obtain information about key < KeyStoreFailure: Key blob corrupted]",
                Causes.WithCauses(
                    "AndroidKeyStore could not establish whether the step-up key is usable (lookup: unrecoverable).",
                    Android9Lookup()));
            Assert.Equal("No cause.", Causes.WithCauses("No cause.", null));
        }

        [Fact]
        public void An_unread_part_says_its_causes_within_the_contracts_limit()
        {
            Assert.Equal(
                "Unrecoverable: Failed to obtain information about key < KeyStoreFailure: Key blob corrupted",
                AndroidProbeReads.Why(Android9Lookup()));
            Assert.True(AndroidProbeReads.Why(new InvalidOperationException(new string('x', 300))).Length <= 160);
            Assert.Equal("unknown", AndroidProbeReads.Why(null));
        }

        private sealed class Unrecoverable : Exception
        {
            public Unrecoverable(string message, Exception cause)
                : base(message, cause)
            {
            }
        }

        private sealed class KeyStoreFailure : Exception
        {
            public KeyStoreFailure(string message)
                : base(message)
            {
            }
        }

        private sealed class Wordless : Exception
        {
            public override string Message => string.Empty;
        }

        private sealed class Looping : Exception
        {
            public Looping(string message)
                : base(message)
            {
            }

            public Exception? Beneath { get; set; }
        }
    }
}
