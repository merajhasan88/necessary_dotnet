using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Java.Math;

namespace Necessary
{
    /// <summary>
    /// How the Android side runs a call: blocking work off the caller's thread,
    /// as the plugin's one worker thread does, and an unexpected failure named
    /// with its type, its cause and where it happened -- a release build's log
    /// is suppressed on some phones, so the message is the only diagnostic.
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

        public static string Describe(Exception error)
        {
            var detail = new StringBuilder("The Android native operation failed: ");
            detail.Append(TypeName(error));
            if (!string.IsNullOrEmpty(error.Message))
            {
                detail.Append(": ").Append(error.Message);
            }

            var cause = error.InnerException ?? (error as Java.Lang.Throwable)?.Cause as Exception;
            if (cause is not null)
            {
                detail.Append(" (cause ").Append(TypeName(cause));
                if (!string.IsNullOrEmpty(cause.Message))
                {
                    detail.Append(": ").Append(cause.Message);
                }

                detail.Append(')');
            }

            var frames = (error.StackTrace ?? string.Empty)
                .Split('\n')
                .Select(line => line.Trim())
                .Where(line => line.Length > 0)
                .Take(6);
            detail.Append(" at ").Append(string.Join(" < ", frames));
            return detail.ToString();
        }

        /// <summary>A Java exception's class, as the plugin names it; a .NET exception's type.</summary>
        public static string TypeName(Exception error) =>
            (error as Java.Lang.Throwable)?.Class?.Name ?? error.GetType().FullName ?? error.GetType().Name;

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
                throw new NativeKeyException("INVALID_PAYLOAD", "The " + what + " payload is not valid base64url.", error);
            }
        }
    }
}
