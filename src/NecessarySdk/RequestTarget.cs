using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Necessary
{
    /// <summary>
    /// A request's target -- its path with the query -- split and normalized
    /// exactly as Dart's <c>Uri.parse</c> does: the fragment
    /// dropped, dot segments removed from an absolute path, a percent escape of
    /// an unreserved character decoded and any other written in upper case, and
    /// a character a path or query may not hold percent-encoded as UTF-8. A
    /// proof signs these, and the transport sends these, so the two never differ.
    /// A backslash in the path is read as a slash, as Dart reads it.
    /// </summary>
    internal readonly struct RequestTarget
    {
        // Dart's _pathCharOrSlashTable and _queryCharTable, bit (c & 15) of
        // entry (c >> 4) set for each character allowed as it is.
        private static readonly ushort[] PathTable =
        {
            0x0000, 0x0000, 0xffd2, 0x2fff, 0xffff, 0x87ff, 0xfffe, 0x47ff,
        };

        private static readonly ushort[] QueryTable =
        {
            0x0000, 0x0000, 0xffd2, 0xafff, 0xffff, 0x87ff, 0xfffe, 0x47ff,
        };

        private RequestTarget(string path, string query, bool hasQuery)
        {
            Path = path;
            Query = query;
            HasQuery = hasQuery;
        }

        /// <summary>The path, without the query.</summary>
        public string Path { get; }

        /// <summary>The query, without <c>?</c>; empty when there is none.</summary>
        public string Query { get; }

        /// <summary>Whether the target had a <c>?</c>.</summary>
        public bool HasQuery { get; }

        /// <summary>The path and query as sent.</summary>
        public string PathAndQuery => HasQuery ? Path + "?" + Query : Path;

        public static RequestTarget Parse(string target)
        {
            if (target is null)
            {
                throw new ArgumentNullException(nameof(target));
            }

            var hash = target.IndexOf('#');
            if (hash >= 0)
            {
                target = target.Substring(0, hash);
            }

            var question = target.IndexOf('?');
            var path = question < 0 ? target : target.Substring(0, question);
            var query = question < 0 ? string.Empty : target.Substring(question + 1);
            path = Normalize(path, PathTable, replaceBackslash: true);
            path = path.StartsWith("/", StringComparison.Ordinal) ? RemoveDotSegments(path) : NormalizeRelative(path);
            return new RequestTarget(path, Normalize(query, QueryTable, replaceBackslash: false), question >= 0);
        }

        private static bool Allowed(char c, ushort[] table) => c < 127 && (table[c >> 4] & (1 << (c & 0x0f))) != 0;

        private static bool Unreserved(int c) =>
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '.' || c == '_' || c == '~';

        private static int HexValue(char c) =>
            c >= '0' && c <= '9' ? c - '0'
            : c >= 'a' && c <= 'f' ? c - 'a' + 10
            : c >= 'A' && c <= 'F' ? c - 'A' + 10
            : -1;

        private static string Normalize(string component, ushort[] table, bool replaceBackslash)
        {
            StringBuilder? buffer = null;
            var sectionStart = 0;
            var index = 0;
            while (index < component.Length)
            {
                var c = component[index];
                if (Allowed(c, table))
                {
                    index++;
                    continue;
                }

                string replacement;
                int sourceLength;
                if (c == '%')
                {
                    var escape = NormalizeEscape(component, index);
                    if (escape is null)
                    {
                        index += 3;
                        continue;
                    }

                    if (escape == "%")
                    {
                        replacement = "%25";
                        sourceLength = 1;
                    }
                    else
                    {
                        replacement = escape;
                        sourceLength = 3;
                    }
                }
                else if (c == '\\' && replaceBackslash)
                {
                    // Dart reads a backslash in a path as a slash.
                    replacement = "/";
                    sourceLength = 1;
                }
                else
                {
                    sourceLength = 1;
                    var codePoint = (int)c;
                    if (char.IsHighSurrogate(c) && index + 1 < component.Length && char.IsLowSurrogate(component[index + 1]))
                    {
                        sourceLength = 2;
                        codePoint = char.ConvertToUtf32(c, component[index + 1]);
                    }

                    replacement = EscapeCodePoint(codePoint);
                }

                buffer ??= new StringBuilder();
                buffer.Append(component, sectionStart, index - sectionStart).Append(replacement);
                index += sourceLength;
                sectionStart = index;
            }

            if (buffer is null)
            {
                return component;
            }

            buffer.Append(component, sectionStart, component.Length - sectionStart);
            return buffer.ToString();
        }

        /// <summary>Null keeps the escape; <c>%</c> marks it invalid; otherwise its replacement.</summary>
        private static string? NormalizeEscape(string source, int index)
        {
            if (index + 2 >= source.Length)
            {
                return "%";
            }

            var first = source[index + 1];
            var second = source[index + 2];
            var high = HexValue(first);
            var low = HexValue(second);
            if (high < 0 || low < 0)
            {
                return "%";
            }

            var value = (high * 16) + low;
            if (Unreserved(value))
            {
                return ((char)value).ToString();
            }

            if (first >= 'a' || second >= 'a')
            {
                return source.Substring(index, 3).ToUpperInvariant();
            }

            return null;
        }

        private static string EscapeCodePoint(int codePoint)
        {
            // A lone surrogate is encoded as Dart encodes it: as its own three bytes.
            byte[] bytes;
            if (codePoint >= 0xD800 && codePoint <= 0xDFFF)
            {
                bytes = new[]
                {
                    (byte)(0xE0 | (codePoint >> 12)),
                    (byte)(0x80 | ((codePoint >> 6) & 0x3F)),
                    (byte)(0x80 | (codePoint & 0x3F)),
                };
            }
            else
            {
                bytes = Encoding.UTF8.GetBytes(char.ConvertFromUtf32(codePoint));
            }

            var text = new StringBuilder(bytes.Length * 3);
            foreach (var b in bytes)
            {
                text.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }

            return text.ToString();
        }

        private static bool MayContainDotSegments(string path) =>
            path.StartsWith(".", StringComparison.Ordinal) || path.Contains("/.", StringComparison.Ordinal);

        private static string RemoveDotSegments(string path)
        {
            if (!MayContainDotSegments(path))
            {
                return path;
            }

            var output = new List<string>();
            var appendSlash = false;
            foreach (var segment in path.Split('/'))
            {
                appendSlash = false;
                if (segment == "..")
                {
                    if (output.Count > 0)
                    {
                        output.RemoveAt(output.Count - 1);
                        if (output.Count == 0)
                        {
                            output.Add(string.Empty);
                        }
                    }

                    appendSlash = true;
                }
                else if (segment == ".")
                {
                    appendSlash = true;
                }
                else
                {
                    output.Add(segment);
                }
            }

            if (appendSlash)
            {
                output.Add(string.Empty);
            }

            return string.Join("/", output);
        }

        private static string NormalizeRelative(string path)
        {
            if (!MayContainDotSegments(path))
            {
                return path;
            }

            var output = new List<string>();
            var appendSlash = false;
            foreach (var segment in path.Split('/'))
            {
                appendSlash = false;
                if (segment == "..")
                {
                    if (output.Count > 0 && output[output.Count - 1] != "..")
                    {
                        output.RemoveAt(output.Count - 1);
                        appendSlash = true;
                    }
                    else
                    {
                        output.Add("..");
                    }
                }
                else if (segment == ".")
                {
                    appendSlash = true;
                }
                else
                {
                    output.Add(segment);
                }
            }

            if (output.Count == 0 || (output.Count == 1 && output[0].Length == 0))
            {
                return "./";
            }

            if (appendSlash || output[output.Count - 1] == "..")
            {
                output.Add(string.Empty);
            }

            return string.Join("/", output);
        }
    }
}
