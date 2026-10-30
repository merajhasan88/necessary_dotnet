using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Necessary
{
    /// <summary>How every binary value travels: base64url without padding; hashes in lower-case hex.</summary>
    public static class Wire
    {
        /// <summary>Base64url without padding.</summary>
        public static string Base64UrlNoPadding(byte[] bytes)
        {
            if (bytes is null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>32 random bytes from the platform's secure source.</summary>
        public static byte[] FreshNonce()
        {
            var nonce = new byte[32];
            RandomNumberGenerator.Fill(nonce);
            return nonce;
        }

        /// <summary>The bytes of base64url text, padded or not.</summary>
        internal static byte[] DecodeBase64Url(string text)
        {
            var standard = text.Replace('-', '+').Replace('_', '/');
            switch (standard.Length % 4)
            {
                case 2:
                    standard += "==";
                    break;
                case 3:
                    standard += "=";
                    break;
                case 1:
                    throw new FormatException("Not base64url: a length of 4n+1 characters.");
            }

            return Convert.FromBase64String(standard);
        }

        /// <summary>The lower-case hex SHA-256 of <paramref name="text"/>'s UTF-8 bytes.</summary>
        internal static string Sha256Hex(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text));

        /// <summary>The lower-case hex SHA-256 of <paramref name="bytes"/>.</summary>
        internal static string Sha256Hex(byte[] bytes)
        {
            using var sha = SHA256.Create();
            var digest = sha.ComputeHash(bytes);
            var hex = new StringBuilder(digest.Length * 2);
            foreach (var b in digest)
            {
                hex.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }

            return hex.ToString();
        }

        /// <summary>Unix seconds now, as Dart's <c>millisecondsSinceEpoch ~/ 1000</c>.</summary>
        internal static long UnixSeconds() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000;
    }
}
