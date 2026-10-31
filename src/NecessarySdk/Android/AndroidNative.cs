using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Java.Math;

namespace Necessary
{
    /// <summary>
    /// How the Android side runs a call: blocking work off the caller's thread,
    /// as the plugin's one worker thread does, and a failure said with
    /// everything that failed beneath it (<see cref="Causes"/>) -- a release
    /// build's log is suppressed on some phones, so the message is the only
    /// diagnostic.
    /// </summary>
    internal static class AndroidNative
    {
        public static Task<T> Run<T>(Func<T> operation) => Task.Run(() =>
        {
            try
            {
                return operation();
            }
            catch (NativeKeyException)
            {
                throw;
            }
            catch (Exception error)
            {
                throw new NativeKeyException("NATIVE_INTEGRITY_ERROR", Describe(error), error);
            }
        });

        /// <summary>An unexpected failure: what failed, everything beneath it, and where it happened.</summary>
        public static string Describe(Exception error)
        {
            var detail = new StringBuilder("The Android native operation failed: ");
            detail.Append(Causes.Chain(error, KeystoreDetail, Read));
            var frames = (error.StackTrace ?? string.Empty)
                .Split('\n')
                .Select(line => line.Trim())
                .Where(line => line.Length > 0)
                .Take(6);
            detail.Append(" at ").Append(string.Join(" < ", frames));
            return detail.ToString();
        }

        /// <summary>
        /// A failure for the app: its code, its words, then everything that failed
        /// beneath them, down to the keystore's own answer -- added here, once, so
        /// no message words its cause itself.
        /// </summary>
        public static NativeKeyException Failure(string code, string message, Exception? cause = null) =>
            new NativeKeyException(code, Causes.WithCauses(message, cause, KeystoreDetail, Read), cause);

        /// <summary>
        /// How a failure is read on Android: a Java exception by its simple class
        /// name, its words and its Java cause; a .NET exception by its type, its
        /// message and its inner exception.
        /// </summary>
        public static (string Kind, string? Words, Exception? Beneath) Read(Exception error)
        {
            if (error is Java.Lang.Throwable throwable)
            {
                return (throwable.Class?.SimpleName ?? error.GetType().Name, throwable.LocalizedMessage, (Exception?)throwable.Cause ?? error.InnerException);
            }

            return (error.GetType().Name, error.Message, error.InnerException);
        }

        /// <summary>
        /// AndroidKeyStore's own error code, which its exception's words may leave
        /// out: public from Android 13 (API 33), with whether the keystore deems
        /// the failure transient.
        /// </summary>
        public static string? KeystoreDetail(Exception error)
        {
            if (!OperatingSystem.IsAndroidVersionAtLeast(33) || error is not Android.Security.KeyStoreException keystore)
            {
                return null;
            }

            return "code " + keystore.NumericErrorCode + (keystore.IsTransientFailure ? ", transient" : string.Empty);
        }

        /// <summary>A Java exception's simple class name, as Kotlin's <c>javaClass.simpleName</c>; a .NET exception's type name.</summary>
        public static string SimpleName(Exception error) =>
            (error as Java.Lang.Throwable)?.Class?.SimpleName ?? error.GetType().Name;

        /// <summary>A coordinate as exactly <paramref name="size"/> unsigned big-endian bytes.</summary>
        public static byte[] UnsignedFixed(BigInteger value, int size)
        {
            var raw = value.ToByteArray() ?? Array.Empty<byte>();
            if (raw.Length == size + 1 && raw[0] == 0)
            {
                raw = raw.Skip(1).ToArray();
            }

            if (raw.Length > size)
            {
                throw new NativeKeyException("INVALID_PUBLIC_KEY", "The EC coordinate is larger than P-256 permits.");
            }

            var output = new byte[size];
            Array.Copy(raw, 0, output, size - raw.Length, raw.Length);
            return output;
        }

        /// <summary>A payload's bytes, refusing an empty or malformed one as the plugin does.</summary>
        public static byte[] DecodePayload(string value, string what)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new NativeKeyException("INVALID_PAYLOAD", "The " + what + " payload is empty.");
            }

            try
            {
                return Wire.DecodeBase64Url(value);
            }
            catch (FormatException error)
            {
                throw Failure("INVALID_PAYLOAD", "The " + what + " payload is not valid base64url.", error);
            }
        }
    }
}
