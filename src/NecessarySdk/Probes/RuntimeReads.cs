using System;
using System.Globalization;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>
    /// What the <c>runtime</c> measurement makes of what it read: pure functions,
    /// so they are tested anywhere. A value not read is unread, never a clean one.
    /// </summary>
    internal static class RuntimeReads
    {
        /// <summary>The decoder's own version function.</summary>
        public const string DecoderVersionFunction = "BrotliDecoderVersion";

        /// <summary>The decoder's version word, major &lt;&lt; 24 | minor &lt;&lt; 12 | patch, as text.</summary>
        public static string DecoderVersion(uint word) =>
            string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}", word >> 24, (word >> 12) & 0xFFF, word & 0xFFF);

        /// <summary>
        /// The measurement. <paramref name="runtime"/> is the runtime's version:
        /// 0.0 is what it answers when it cannot say. <paramref name="decoderPresent"/>
        /// is null where the app's packaging does not show it, and
        /// <paramref name="decoderWord"/> null where the decoder gave no version.
        /// </summary>
        public static JsonObject Runtime(Version? runtime, bool? decoderPresent, uint? decoderWord)
        {
            var versionRead = runtime is not null && (runtime.Major != 0 || runtime.Minor != 0);
            var present = decoderWord is not null ? true : decoderPresent;
            if (!versionRead && present is null)
            {
                return new JsonObject
                {
                    ["status"] = "error",
                    ["error"] = "neither the runtime's version nor its decoder could be read",
                };
            }

            var result = new JsonObject { ["status"] = "ok" };
            var unread = new JsonObject();
            if (versionRead)
            {
                result["runtime_version"] = runtime!.ToString();
            }
            else
            {
                unread["runtime_version"] = "the runtime did not say its version";
            }

            if (present is null)
            {
                unread["brotli_decoder_present"] = "this app's packaging does not show it";
            }
            else
            {
                result["brotli_decoder_present"] = present.Value;
            }

            if (decoderWord is not null)
            {
                result["brotli_decoder_version"] = DecoderVersion(decoderWord.Value);
            }
            else if (present == true)
            {
                unread["brotli_decoder_version"] = "this build does not keep the decoder's version";
            }

            if (unread.Count > 0)
            {
                result["unread"] = unread;
            }

            return result;
        }
    }
}
