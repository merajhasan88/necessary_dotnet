using System;
using System.Collections.Generic;

namespace Necessary
{
    /// <summary>
    /// What failed, and everything beneath it: a failure and each of its causes,
    /// outermost first, as "Kind: words &lt; Kind: words". Every failure the
    /// Android side reports carries it, so a key that reads as unavailable or
    /// dead says what the keystore itself answered -- on Android 9 an
    /// UnrecoverableKeyException's words are always "Failed to obtain
    /// information about key", and only the exception beneath it says which
    /// failure it was. The plugin's <c>Causes.kt</c>, translated.
    /// </summary>
    /// <remarks>
    /// Kinds and words only: never a stack trace, a key or a value of the app's.
    /// A pure function, so the offline tests hold it.
    /// </remarks>
    internal static class Causes
    {
        /// <summary>How many failures a chain names: deeper ones are the same failure rewrapped.</summary>
        public const int MaxLinks = 8;

        /// <summary>How a failure is read: its kind, its words, and the failure beneath it.</summary>
        public delegate (string Kind, string? Words, Exception? Beneath) Reader(Exception error);

        /// <summary>A .NET exception: its type's name, its message and its inner exception.</summary>
        public static readonly Reader DotNet = error => (error.GetType().Name, error.Message, error.InnerException);

        /// <summary>
        /// <paramref name="error"/> and its causes. <paramref name="detail"/> adds
        /// what a failure's words leave out -- the keystore's numeric error code --
        /// or null. Empty for no error.
        /// </summary>
        public static string Chain(Exception? error, Func<Exception, string?>? detail = null, Reader? read = null)
        {
            read ??= DotNet;
            var links = new List<string>();
            var seen = new HashSet<Exception>(ReferenceEqualityComparer.Instance);
            var current = error;
            while (current is not null && links.Count < MaxLinks && seen.Add(current))
            {
                var (kind, words, beneath) = read(current);
                var message = words?.Trim() ?? string.Empty;
                var extra = detail?.Invoke(current);
                links.Add(kind
                    + (message.Length == 0 ? string.Empty : ": " + message)
                    + (string.IsNullOrEmpty(extra) ? string.Empty : " (" + extra + ")"));
                current = beneath;
            }

            if (current is not null && !seen.Contains(current))
            {
                links.Add("…");
            }

            return string.Join(" < ", links);
        }

        /// <summary><paramref name="message"/>, then what failed beneath it when anything did.</summary>
        public static string WithCauses(string message, Exception? cause, Func<Exception, string?>? detail = null, Reader? read = null)
        {
            var beneath = Chain(cause, detail, read);
            return beneath.Length == 0 ? message : message + " [cause: " + beneath + "]";
        }
    }
}
