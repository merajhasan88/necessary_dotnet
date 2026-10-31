using System;

namespace Necessary
{
    /// <summary>
    /// Whether a key is in AndroidKeyStore, when its absence matters: a key is
    /// made only where there is none, and generating one replaces whatever the
    /// alias holds. The plugin's <c>KeyPresence.kt</c>, translated.
    /// </summary>
    /// <remarks>
    /// <c>KeyStore.containsAlias</c> cannot say "absent" on its own. It answers
    /// false also when the keystore cannot be reached: on Android 7 to 11
    /// <c>android.security.KeyStore.contains</c> returns false on a binder
    /// failure, and on Android 12 and later <c>AndroidKeyStoreSpi.getKeyMetadata</c>
    /// returns null on every keystore error, a lost connection included.
    /// Deleting an alias that never holds a key does say whether the keystore
    /// answered: one that answers reports it not found, which
    /// <c>deleteEntry</c> takes as done, while one that cannot be reached makes
    /// <c>deleteEntry</c> throw. So a "no" is believed only when the keystore
    /// answered the probe and then said "no" again. The limit: two outages, one
    /// over each lookup and neither over the probe between them, still read as
    /// absent. A pure decision, so the offline tests hold it.
    /// </remarks>
    internal static class KeyPresence
    {
        /// <summary>What the keystore answered.</summary>
        public enum Answer
        {
            /// <summary>The keystore holds the key.</summary>
            Present,

            /// <summary>The keystore answered, and holds no key: one may be made.</summary>
            Absent,

            /// <summary>The keystore could not be reached: no key may be made over one it may hold.</summary>
            Unavailable,
        }

        /// <summary>The two keystore calls the answer rests on.</summary>
        public interface IKeystore
        {
            /// <summary><c>containsAlias</c> for the key: false also when the keystore could not be reached.</summary>
            bool ContainsKey();

            /// <summary><c>deleteEntry</c> of an alias that never holds a key: returns when the keystore answered, throws when it could not be reached.</summary>
            void DeleteProbe();
        }

        /// <summary>The answer, and what failed when the keystore could not be reached.</summary>
        public static (Answer Answer, Exception? Cause) Of(IKeystore keystore)
        {
            if (keystore.ContainsKey())
            {
                return (Answer.Present, null);
            }

            try
            {
                keystore.DeleteProbe();
            }
#pragma warning disable CA1031 // Any failure of the probe is a keystore that did not answer: a keystore with no service behind it fails with a NullPointerException.
            catch (Exception error)
#pragma warning restore CA1031
            {
                return (Answer.Unavailable, error);
            }

            // The keystore answers now: its "no" may have been an outage that has
            // passed, so it is asked again.
            return (keystore.ContainsKey() ? Answer.Present : Answer.Absent, null);
        }
    }
}
