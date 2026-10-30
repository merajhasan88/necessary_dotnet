using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;

namespace Necessary
{
    /// <summary>
    /// The app's own code signature, read from the Mach-O image of its main
    /// executable: the plugin's <c>probeCodeSigning</c> parsing, translated, with
    /// no Apple framework in it. Integers are assembled byte by byte -- the
    /// offsets are not guaranteed to be aligned.
    /// </summary>
    internal static class MachOSigning
    {
        /// <summary>
        /// The code_signing probe from the executable's bytes, or null when they
        /// could not be read: <c>signing_identifier</c>, <c>team_identifier</c>,
        /// <c>get_task_allow</c> and <c>signed</c>, with <c>signature_absent</c>
        /// for an unsigned image and the parse's findings for a signed one.
        /// </summary>
        public static JsonObject CodeSigning(byte[]? executable)
        {
            var result = new JsonObject
            {
                ["status"] = "ok",
                ["signing_identifier"] = string.Empty,
                ["team_identifier"] = string.Empty,
                ["get_task_allow"] = false,
                ["signed"] = false,
            };
            if (executable is null)
            {
                result["status"] = "error";
                result["error"] = "The main executable could not be read.";
                return result;
            }

            if (SliceOffset(executable) is not int slice)
            {
                result["status"] = "error";
                result["error"] = "The main executable is not a recognised 64-bit Mach-O image.";
                return result;
            }

            if (CodeSignatureRange(executable, slice) is not { } signature)
            {
                // Unsigned: legitimate for a build installed without a signature.
                result["signature_absent"] = true;
                return result;
            }

            result["signed"] = true;
            ParseEmbeddedSignature(executable, signature.Offset, signature.Size, result);
            return result;
        }

        internal static uint? U32Le(byte[] d, long o) =>
            o < 0 || o + 4 > d.Length ? null : (uint)(d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24));

        internal static uint? U32Be(byte[] d, long o) =>
            o < 0 || o + 4 > d.Length ? null : (uint)((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]);

        /// <summary>
        /// The file offset of the 64-bit Mach-O image to inspect, a fat binary
        /// resolved to its arm64 slice. Only MH_MAGIC_64 is accepted: misparsing
        /// a byte-swapped image is worse than saying it was not recognised.
        /// </summary>
        internal static int? SliceOffset(byte[] d)
        {
            if (U32Le(d, 0) == 0xfeedfacf)
            {
                return 0;
            }

            if (U32Be(d, 0) != 0xcafebabe || U32Be(d, 4) is not uint count || count >= 64)
            {
                return null;
            }

            const uint cpuTypeArm64 = 0x0100000c;
            for (var index = 0; index < (int)count; index++)
            {
                var entry = 8 + (index * 20);
                if (U32Be(d, entry) is not uint cpu || U32Be(d, entry + 8) is not uint offset)
                {
                    return null;
                }

                if (cpu == cpuTypeArm64 && U32Le(d, offset) == 0xfeedfacf)
                {
                    return (int)offset;
                }
            }

            return null;
        }

        /// <summary>
        /// Walks the load commands for LC_CODE_SIGNATURE and returns the
        /// signature blob's range; its dataoff is relative to the slice.
        /// </summary>
        internal static (int Offset, int Size)? CodeSignatureRange(byte[] d, int sliceOffset)
        {
            if (U32Le(d, sliceOffset + 16) is not uint commandCount)
            {
                return null;
            }

            long cursor = sliceOffset + 32; // sizeof(struct mach_header_64)
            for (var i = 0; i < (int)Math.Min(commandCount, int.MaxValue); i++)
            {
                if (U32Le(d, cursor) is not uint command || U32Le(d, cursor + 4) is not uint commandSize || commandSize < 8)
                {
                    return null;
                }

                if (command == 0x1d)
                {
                    // LC_CODE_SIGNATURE
                    if (U32Le(d, cursor + 8) is not uint dataOffset || U32Le(d, cursor + 12) is not uint dataSize)
                    {
                        return null;
                    }

                    var absolute = (long)sliceOffset + dataOffset;
                    if (absolute < 0 || absolute + dataSize > d.Length)
                    {
                        return null;
                    }

                    return ((int)absolute, (int)dataSize);
                }

                cursor += commandSize;
                if (cursor >= d.Length)
                {
                    return null;
                }
            }

            return null;
        }

        /// <summary>
        /// The embedded signature SuperBlob: the CodeDirectory carries the
        /// signing identifier; the entitlements slot carries an XML plist holding
        /// the team identifier and get-task-allow. Every field here is big-endian.
        /// </summary>
        internal static void ParseEmbeddedSignature(byte[] d, int offset, int size, JsonObject result)
        {
            if (U32Be(d, offset) != 0xfade0cc0 || U32Be(d, offset + 8) is not uint blobCount || blobCount >= 128)
            {
                result["signature_parse_error"] = "Not an embedded signature SuperBlob.";
                return;
            }

            for (var index = 0; index < (int)blobCount; index++)
            {
                var entry = offset + 12 + (index * 8);
                if (U32Be(d, entry) is not uint slot || U32Be(d, entry + 4) is not uint relative)
                {
                    return;
                }

                var blob = (long)offset + relative;
                if (blob + 8 > (long)offset + size)
                {
                    continue;
                }

                switch (slot)
                {
                    case 0:
                        // CSSLOT_CODEDIRECTORY
                        if (U32Be(d, blob) != 0xfade0c02 || U32Be(d, blob + 12) is not uint flags || U32Be(d, blob + 20) is not uint identOffset)
                        {
                            continue;
                        }

                        result["code_directory_flags"] = (long)flags;
                        var start = blob + identOffset;
                        var end = start;
                        while (end < d.Length && d[end] != 0)
                        {
                            end++;
                        }

                        if (end > start && start >= 0)
                        {
                            try
                            {
                                result["signing_identifier"] = new UTF8Encoding(false, true).GetString(d, (int)start, (int)(end - start));
                            }
                            catch (DecoderFallbackException)
                            {
                                // Not UTF-8: the identifier stays empty, as Swift leaves it.
                            }
                        }

                        break;
                    case 5:
                        // CSSLOT_ENTITLEMENTS
                        if (U32Be(d, blob) != 0xfade7171 || U32Be(d, blob + 4) is not uint length || length <= 8)
                        {
                            continue;
                        }

                        var plistStart = blob + 8;
                        var stop = blob + length;
                        if (stop > d.Length || plistStart >= stop)
                        {
                            continue;
                        }

                        var parsed = Plist(d.AsSpan((int)plistStart, (int)(stop - plistStart)).ToArray());
                        if (parsed is not null)
                        {
                            result["team_identifier"] = parsed.TryGetValue("com.apple.developer.team-identifier", out var team) && team is string teamText ? teamText : string.Empty;
                            result["get_task_allow"] = parsed.TryGetValue("get-task-allow", out var allow) && allow is bool allowed && allowed;
                            result["entitlement_count"] = parsed.Count;
                        }

                        break;
                }
            }
        }

        /// <summary>An XML property list's top dictionary, or null when it is not one.</summary>
        internal static IReadOnlyDictionary<string, object?>? Plist(byte[] plist)
        {
            if (plist.Length == 0)
            {
                return null;
            }

            XDocument document;
            try
            {
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Ignore,
                    XmlResolver = null,
                    IgnoreComments = true,
                    IgnoreProcessingInstructions = true,
                };
                using var stream = new MemoryStream(plist);
                using var reader = XmlReader.Create(stream, settings);
                document = XDocument.Load(reader);
            }
            catch (XmlException)
            {
                return null;
            }

            var root = document.Root;
            if (root is null || root.Name.LocalName != "plist")
            {
                return null;
            }

            var dictionary = root.Elements().FirstOrDefault(element => element.Name.LocalName == "dict");
            return dictionary is null ? null : ReadDictionary(dictionary);
        }

        private static Dictionary<string, object?> ReadDictionary(XElement dictionary)
        {
            // A plist dict is a flat sequence of <key>name</key><value/> pairs.
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            string? pendingKey = null;
            foreach (var child in dictionary.Elements())
            {
                if (child.Name.LocalName == "key")
                {
                    pendingKey = child.Value;
                    continue;
                }

                if (pendingKey is not null)
                {
                    result[pendingKey] = ReadValue(child);
                    pendingKey = null;
                }
            }

            return result;
        }

        private static object? ReadValue(XElement element) => element.Name.LocalName switch
        {
            "string" or "date" or "data" => element.Value,
            "integer" => long.TryParse(element.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) ? number : element.Value,
            "real" => double.TryParse(element.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var real) ? real : element.Value,
            "true" => true,
            "false" => false,
            "array" => element.Elements().Select(ReadValue).ToList(),
            "dict" => ReadDictionary(element),
            _ => element.ToString(),
        };
    }
}
