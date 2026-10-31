using System;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>
    /// JSON text exactly as Dart's <c>jsonEncode</c> writes it, so
    /// that every message, header and signed payload is the same byte for byte:
    /// members in the order given, no spaces, characters beyond ASCII as they
    /// are (UTF-8), only <c>"</c>, <c>\</c> and control characters escaped, and
    /// numbers as Dart writes them (<c>1.0</c> for a double, <c>1e-7</c>,
    /// <c>1e+21</c>). <c>System.Text.Json</c>'s own writer escapes more, and
    /// would change the bytes a signature covers.
    /// </summary>
    internal static class DartJson
    {
        /// <summary>The JSON text of <paramref name="node"/>.</summary>
        public static string Encode(JsonNode? node)
        {
            var text = new StringBuilder();
            Write(text, node);
            return text.ToString();
        }

        /// <summary>The UTF-8 bytes of <see cref="Encode"/>.</summary>
        public static byte[] EncodeUtf8(JsonNode? node) => Encoding.UTF8.GetBytes(Encode(node));

        /// <summary>A JSON object from text; throws <see cref="FormatException"/> for anything else.</summary>
        public static JsonObject DecodeObject(string text)
        {
            JsonNode? node;
            try
            {
                node = JsonNode.Parse(text);
            }
            catch (JsonException error)
            {
                throw new FormatException("Not JSON: " + error.Message, error);
            }

            return node as JsonObject ?? throw new FormatException("Not a JSON object.");
        }

        /// <summary>A JSON value from text.</summary>
        public static JsonNode? Decode(string text)
        {
            try
            {
                return JsonNode.Parse(text);
            }
            catch (JsonException error)
            {
                throw new FormatException("Not JSON: " + error.Message, error);
            }
        }

        private static void Write(StringBuilder text, JsonNode? node)
        {
            switch (node)
            {
                case null:
                    text.Append("null");
                    break;
                case JsonObject members:
                    text.Append('{');
                    var first = true;
                    foreach (var member in members)
                    {
                        if (!first)
                        {
                            text.Append(',');
                        }

                        first = false;
                        WriteString(text, member.Key);
                        text.Append(':');
                        Write(text, member.Value);
                    }

                    text.Append('}');
                    break;
                case JsonArray items:
                    text.Append('[');
                    for (var i = 0; i < items.Count; i++)
                    {
                        if (i > 0)
                        {
                            text.Append(',');
                        }

                        Write(text, items[i]);
                    }

                    text.Append(']');
                    break;
                case JsonValue value:
                    WriteValue(text, value);
                    break;
                default:
                    throw new NotSupportedException("A JSON node of type " + node.GetType().Name + " cannot be encoded.");
            }
        }

        private static void WriteValue(StringBuilder text, JsonValue value)
        {
            if (value.TryGetValue<JsonElement>(out var element))
            {
                WriteElement(text, element);
                return;
            }

            if (value.TryGetValue<string>(out var s))
            {
                WriteString(text, s);
            }
            else if (value.TryGetValue<bool>(out var flag))
            {
                text.Append(flag ? "true" : "false");
            }
            else if (value.TryGetValue<int>(out var i32))
            {
                text.Append(i32.ToString(CultureInfo.InvariantCulture));
            }
            else if (value.TryGetValue<long>(out var i64))
            {
                text.Append(i64.ToString(CultureInfo.InvariantCulture));
            }
            else if (value.TryGetValue<double>(out var d))
            {
                text.Append(DartDouble(d));
            }
            else if (value.TryGetValue<float>(out var f))
            {
                text.Append(DartDouble(f));
            }
            else if (value.TryGetValue<short>(out var i16))
            {
                text.Append(i16.ToString(CultureInfo.InvariantCulture));
            }
            else if (value.TryGetValue<uint>(out var u32))
            {
                text.Append(u32.ToString(CultureInfo.InvariantCulture));
            }
            else if (value.TryGetValue<ulong>(out var u64))
            {
                text.Append(u64.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                throw new NotSupportedException("A JSON value of this type cannot be encoded: " + value.ToJsonString());
            }
        }

        private static void WriteElement(StringBuilder text, JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String:
                    WriteString(text, element.GetString()!);
                    break;
                case JsonValueKind.True:
                    text.Append("true");
                    break;
                case JsonValueKind.False:
                    text.Append("false");
                    break;
                case JsonValueKind.Null:
                    text.Append("null");
                    break;
                case JsonValueKind.Number:
                    // Dart reads an integer literal as an int and anything else
                    // as a double, and writes each its own way.
                    var raw = element.GetRawText();
                    if (raw.IndexOfAny(new[] { '.', 'e', 'E' }) < 0 && element.TryGetInt64(out var integer))
                    {
                        text.Append(integer.ToString(CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        text.Append(DartDouble(element.GetDouble()));
                    }

                    break;
                case JsonValueKind.Object:
                    Write(text, JsonObject.Create(element));
                    break;
                case JsonValueKind.Array:
                    Write(text, JsonArray.Create(element));
                    break;
                default:
                    throw new NotSupportedException("An undefined JSON value cannot be encoded.");
            }
        }

        /// <summary>A string, escaped as Dart's encoder escapes it.</summary>
        private static void WriteString(StringBuilder text, string value)
        {
            text.Append('"');
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                if (c > '\\')
                {
                    if (char.IsSurrogate(c))
                    {
                        var lone = char.IsHighSurrogate(c)
                            ? !(i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                            : !(i > 0 && char.IsHighSurrogate(value[i - 1]));
                        if (lone)
                        {
                            text.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                            continue;
                        }
                    }

                    text.Append(c);
                    continue;
                }

                if (c < ' ')
                {
                    switch (c)
                    {
                        case '\b':
                            text.Append("\\b");
                            break;
                        case '\t':
                            text.Append("\\t");
                            break;
                        case '\n':
                            text.Append("\\n");
                            break;
                        case '\f':
                            text.Append("\\f");
                            break;
                        case '\r':
                            text.Append("\\r");
                            break;
                        default:
                            text.Append("\\u00").Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                            break;
                    }
                }
                else if (c == '"' || c == '\\')
                {
                    text.Append('\\').Append(c);
                }
                else
                {
                    text.Append(c);
                }
            }

            text.Append('"');
        }

        /// <summary>
        /// A double as Dart writes it: the shortest digits that read back the
        /// same, in decimal notation from 1e-6 up to 1e21 (with <c>.0</c> on a
        /// whole number) and in exponent notation outside it.
        /// </summary>
        internal static string DartDouble(double value)
        {
            if (double.IsNaN(value) || double.IsInfinity(value))
            {
                // Dart's encoder refuses these too.
                throw new NotSupportedException("JSON has no " + value.ToString(CultureInfo.InvariantCulture) + ".");
            }

            if (value == 0)
            {
                return double.IsNegative(value) ? "-0.0" : "0.0";
            }

            // The shortest round-trip digits and the decimal exponent.
            var shortest = Math.Abs(value).ToString("R", CultureInfo.InvariantCulture);
            var exponent = 0;
            var e = shortest.IndexOfAny(new[] { 'E', 'e' });
            if (e >= 0)
            {
                exponent = int.Parse(shortest.Substring(e + 1), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
                shortest = shortest.Substring(0, e);
            }

            var point = shortest.IndexOf('.');
            var digits = point < 0 ? shortest : shortest.Remove(point, 1);
            var integerDigits = point < 0 ? shortest.Length : point;
            var leadingZeros = 0;
            while (leadingZeros < digits.Length - 1 && digits[leadingZeros] == '0')
            {
                leadingZeros++;
            }

            digits = digits.Substring(leadingZeros).TrimEnd('0');
            if (digits.Length == 0)
            {
                digits = "0";
            }

            // value = 0.d1d2...dk * 10^n
            var n = integerDigits - leadingZeros + exponent;
            var k = digits.Length;
            var sign = value < 0 ? "-" : string.Empty;
            string body;
            if (k <= n && n <= 21)
            {
                body = digits + new string('0', n - k) + ".0";
            }
            else if (0 < n && n <= 21)
            {
                body = digits.Substring(0, n) + "." + digits.Substring(n);
            }
            else if (-6 < n && n <= 0)
            {
                body = "0." + new string('0', -n) + digits;
            }
            else
            {
                var power = n - 1;
                body = digits.Substring(0, 1)
                    + (k > 1 ? "." + digits.Substring(1) : string.Empty)
                    + "e" + (power >= 0 ? "+" : "-")
                    + Math.Abs(power).ToString(CultureInfo.InvariantCulture);
            }

            return sign + body;
        }
    }
}
