using System.Text.Json;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>Typed reads of JSON nodes, as the plugin's Dart reads its maps.</summary>
    internal static class Json
    {
        /// <summary>
        /// The text <paramref name="field"/> of an answer your backend gave. A field
        /// it left out is an <see cref="ApiException"/>, as every failure of a call
        /// is, never a cast error.
        /// </summary>
        public static string AnswerText(JsonObject answer, string field)
        {
            var value = String(answer[field]);
            return string.IsNullOrEmpty(value)
                ? throw new ApiException("The backend answered no " + field + ".", code: "invalid_backend_answer")
                : value!;
        }

        /// <summary>The string a node holds, or null.</summary>
        public static string? String(JsonNode? node)
        {
            if (node is not JsonValue value)
            {
                return null;
            }

            if (value.TryGetValue<string>(out var text))
            {
                return text;
            }

            return value.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.String
                ? element.GetString()
                : null;
        }

        /// <summary>The boolean a node holds, or null.</summary>
        public static bool? Bool(JsonNode? node)
        {
            if (node is not JsonValue value)
            {
                return null;
            }

            if (value.TryGetValue<bool>(out var flag))
            {
                return flag;
            }

            return value.TryGetValue<JsonElement>(out var element)
                && (element.ValueKind == JsonValueKind.True || element.ValueKind == JsonValueKind.False)
                ? element.GetBoolean()
                : null;
        }

        /// <summary>The integer a node holds (Dart's <c>is int</c>), or null.</summary>
        public static long? Integer(JsonNode? node)
        {
            if (node is not JsonValue value)
            {
                return null;
            }

            if (value.TryGetValue<int>(out var i32))
            {
                return i32;
            }

            if (value.TryGetValue<long>(out var i64))
            {
                return i64;
            }

            if (value.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.Number)
            {
                var raw = element.GetRawText();
                if (raw.IndexOfAny(new[] { '.', 'e', 'E' }) < 0 && element.TryGetInt64(out var parsed))
                {
                    return parsed;
                }
            }

            return null;
        }

        /// <summary>The number a node holds (Dart's <c>is num</c>), or null.</summary>
        public static double? Number(JsonNode? node)
        {
            if (Integer(node) is long integer)
            {
                return integer;
            }

            if (node is not JsonValue value)
            {
                return null;
            }

            if (value.TryGetValue<double>(out var d))
            {
                return d;
            }

            if (value.TryGetValue<float>(out var f))
            {
                return f;
            }

            return value.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.Number
                ? element.GetDouble()
                : null;
        }

        /// <summary>A copy of <paramref name="node"/> that can join another tree.</summary>
        public static JsonNode? Copy(JsonNode? node) => node?.DeepClone();

        /// <summary>Whether a JWK is the plugin's: <c>EC</c>, <c>P-256</c>, <c>ES256</c>, with string coordinates.</summary>
        public static bool IsEcP256(JsonObject jwk) =>
            String(jwk["kty"]) == "EC"
            && String(jwk["crv"]) == "P-256"
            && String(jwk["alg"]) == "ES256"
            && String(jwk["x"]) is not null
            && String(jwk["y"]) is not null;

        /// <summary>The RFC 7638 thumbprint of an EC public JWK, as the plugin computes it.</summary>
        public static string Thumbprint(JsonObject jwk)
        {
            var canonical = new JsonObject
            {
                ["crv"] = Copy(jwk["crv"]),
                ["kty"] = "EC",
                ["x"] = Copy(jwk["x"]),
                ["y"] = Copy(jwk["y"]),
            };
            return Wire.Sha256Hex(DartJson.Encode(canonical));
        }
    }
}
