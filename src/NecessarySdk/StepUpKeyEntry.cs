namespace Necessary
{
    /// <summary>
    /// What the step-up key's lookups found, and what that means for the key: a
    /// pure decision, so the offline tests hold it. The plugin's
    /// <c>StepUpKeyEntry.kt</c>, translated (the release review of 2026-10-31,
    /// item 4).
    /// </summary>
    /// <remarks>
    /// Only a permanent invalidation that Android itself reports
    /// (KeyPermanentlyInvalidatedException when a signature starts) deletes the
    /// key. Every other failure is ambiguous -- on Android 9, KeyStore.contains
    /// answers false on a binder error, and an unsuccessful key-characteristics
    /// query surfaces as UnrecoverableKeyException -- so the key is kept and the
    /// app hears <c>STEPUP_KEY_UNAVAILABLE</c>, which it may retry; replacing the
    /// key is an explicit re-enrolment. Nothing here counts failures: two alike
    /// are no proof of permanence either.
    /// </remarks>
    internal static class StepUpKeyEntry
    {
        /// <summary>What looking the key up found.</summary>
        public enum Lookup
        {
            /// <summary>A private-key entry, loaded.</summary>
            PrivateKey,

            /// <summary>isKeyEntry false: no key, or a keystore that could not say.</summary>
            NotKeyEntry,

            /// <summary>getEntry threw UnrecoverableKeyException.</summary>
            Unrecoverable,

            /// <summary>getEntry threw UnsupportedOperationException (the Android 9 orphaned alias).</summary>
            Unsupported,

            /// <summary>getEntry returned an entry that is not a private key's.</summary>
            NotPrivateKey,

            /// <summary>getEntry threw another GeneralSecurityException.</summary>
            OtherFailure,
        }

        /// <summary>What starting a signature with the loaded key found.</summary>
        public enum SignStart
        {
            /// <summary>The signature started.</summary>
            Started,

            /// <summary>A windowed key outside its window: the person must unlock it.</summary>
            NeedsAuthentication,

            /// <summary>KeyPermanentlyInvalidatedException: Android says it can never sign again.</summary>
            PermanentlyInvalidated,

            /// <summary>No key was loaded to start a signature with.</summary>
            NotTried,
        }

        /// <summary>What becomes of the key.</summary>
        public enum Verdict
        {
            /// <summary>Sign with it; a windowed key outside its window only needs the person.</summary>
            Usable,

            /// <summary>Android says it can never sign again: delete it, re-enrol.</summary>
            Invalidated,

            /// <summary>Could not establish whether it is usable: keep it, <c>STEPUP_KEY_UNAVAILABLE</c>.</summary>
            Unavailable,

            /// <summary>Another keystore failure: keep it, <c>KEY_LOOKUP_FAILED</c>.</summary>
            LookupFailed,
        }

        /// <summary>The verdict on what the lookup and the signature's start found.</summary>
        public static Verdict Decide(Lookup lookup, SignStart start) => lookup switch
        {
            Lookup.PrivateKey => start == SignStart.PermanentlyInvalidated ? Verdict.Invalidated : Verdict.Usable,
            Lookup.OtherFailure => Verdict.LookupFailed,
            _ => Verdict.Unavailable,
        };

        /// <summary>A lookup as the plugin's message names it: <c>not_key_entry</c>, <c>unrecoverable</c>.</summary>
        public static string Name(Lookup lookup) => lookup switch
        {
            Lookup.PrivateKey => "private_key",
            Lookup.NotKeyEntry => "not_key_entry",
            Lookup.Unrecoverable => "unrecoverable",
            Lookup.Unsupported => "unsupported",
            Lookup.NotPrivateKey => "not_private_key",
            _ => "other_failure",
        };
    }
}
