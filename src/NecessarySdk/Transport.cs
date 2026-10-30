using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// Sends one request to your backend and answers its JSON object. A refusal
    /// is thrown as an <see cref="ApiException"/> with the backend's <c>code</c>,
    /// <c>message</c> and <c>details</c> (the public guide, section 4, Errors).
    /// </summary>
    public interface IDeviceTrustTransport
    {
        /// <summary>
        /// Sends <paramref name="method"/> <paramref name="path"/>.
        /// <paramref name="encodedBody"/> is sent exactly as given: it is what a
        /// request proof hashes. A GET sends no body.
        /// </summary>
        Task<JsonObject> SendAsync(
            string method,
            string path,
            string? encodedBody = null,
            string? bearerToken = null,
            IReadOnlyDictionary<string, string>? headers = null);

        /// <summary>Closes the transport.</summary>
        void Close();
    }

    /// <summary>
    /// JSON over HTTPS under the base URL. A release build refuses any other
    /// scheme, so a mistyped endpoint fails loudly instead of sending tokens in
    /// the clear; each call gets 15 seconds.
    /// </summary>
    public sealed class HttpTransport : IDeviceTrustTransport
    {
        private readonly HttpClient client;
        private readonly bool ownsClient;

        /// <summary>JSON over HTTPS under <paramref name="baseUrl"/>.</summary>
        /// <param name="baseUrl">Your backend's base URL.</param>
        /// <param name="client">An <see cref="HttpClient"/> of your own; by default one of the transport's.</param>
        /// <param name="timeout">How long a call may take: 15 seconds by default.</param>
        public HttpTransport(string baseUrl, HttpClient? client = null, TimeSpan? timeout = null)
        {
            BaseUrl = baseUrl ?? string.Empty;
            Timeout = timeout ?? TimeSpan.FromSeconds(15);
            ownsClient = client is null;
            this.client = client ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = System.Threading.Timeout.InfiniteTimeSpan,
            };
        }

        /// <summary>The base URL every path is sent under.</summary>
        public string BaseUrl { get; }

        /// <summary>How long a call may take.</summary>
        public TimeSpan Timeout { get; }

        private string Base
        {
            get
            {
                if (BaseUrl.Length == 0)
                {
                    throw new ApiException("No API base URL was set for the backend.", code: "api_base_url_missing");
                }

                if (BuildMode.IsRelease && !BaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ApiException(
                        "The API base URL must be an https:// URL in a release build.",
                        code: "api_base_url_insecure");
                }

                return BaseUrl.EndsWith("/", StringComparison.Ordinal) ? BaseUrl.Substring(0, BaseUrl.Length - 1) : BaseUrl;
            }
        }

        /// <inheritdoc />
        public async Task<JsonObject> SendAsync(
            string method,
            string path,
            string? encodedBody = null,
            string? bearerToken = null,
            IReadOnlyDictionary<string, string>? headers = null)
        {
            if (method is null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (path is null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            var target = RequestTarget.Parse(path).PathAndQuery;
            using var request = new HttpRequestMessage(new HttpMethod(method), new Uri(Base + target));
            request.Headers.TryAddWithoutValidation("Accept", "application/json");
            if (bearerToken is not null)
            {
                request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearerToken);
            }

            if (method != "GET")
            {
                // As the plugin's HTTP client sends it: UTF-8, its charset named.
                request.Content = new StringContent(encodedBody ?? "{}", new UTF8Encoding(false), "application/json");
            }

            if (headers is not null)
            {
                foreach (var header in headers)
                {
                    if (string.Equals(header.Key, "Content-Type", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    request.Headers.Remove(header.Key);
                    request.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            HttpResponseMessage response;
            string body;
            using var deadline = new CancellationTokenSource(Timeout);
            try
            {
                response = await client.SendAsync(request, deadline.Token).ConfigureAwait(false);
                body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch (OperationCanceledException error) when (deadline.IsCancellationRequested)
            {
                throw new ApiException("The server did not respond before the timeout.", innerException: error);
            }
            catch (HttpRequestException error) when (error.InnerException is SocketException socket)
            {
                throw new ApiException("Network connection failed: " + socket.Message, innerException: error);
            }
            catch (HttpRequestException error)
            {
                throw new ApiException("HTTP connection failed: " + error.Message, innerException: error);
            }

            using (response)
            {
                var status = (int)response.StatusCode;
                var decoded = new JsonObject();
                if (body.Trim().Length > 0)
                {
                    try
                    {
                        decoded = DartJson.DecodeObject(body);
                    }
                    catch (FormatException)
                    {
                        throw new ApiException("The server returned a non-JSON response.", statusCode: status);
                    }
                }

                if (status < 200 || status >= 300)
                {
                    var refusal = decoded["error"] as JsonObject;
                    var message = refusal?["message"] is JsonValue m && m.TryGetValue<string>(out var text) ? text : null;
                    var code = refusal?["code"] is JsonValue c && c.TryGetValue<string>(out var codeText) ? codeText : null;
                    var details = refusal?["details"] as JsonObject;
                    throw new ApiException(
                        message ?? "The server rejected the request (" + status.ToString(System.Globalization.CultureInfo.InvariantCulture) + ").",
                        statusCode: status,
                        code: code,
                        details: details?.DeepClone() as JsonObject);
                }

                return decoded;
            }
        }

        /// <inheritdoc />
        public void Close()
        {
            if (ownsClient)
            {
                client.Dispose();
            }
        }
    }

    /// <summary>
    /// Whether this is a release build -- the plugin's <c>kReleaseMode</c>. On
    /// Android, the app's manifest is not debuggable; elsewhere, the app's own
    /// assembly was compiled with optimizations.
    /// </summary>
    internal static class BuildMode
    {
        private static readonly Lazy<bool> Detected = new Lazy<bool>(Detect);

        /// <summary>For the package's own tests, which run in a release-built test host.</summary>
        internal static bool? Override { get; set; }

        public static bool IsRelease => Override ?? Detected.Value;

        private static bool Detect()
        {
#if ANDROID
            var info = global::Android.App.Application.Context.ApplicationInfo;
            if (info is not null)
            {
                return (info.Flags & global::Android.Content.PM.ApplicationInfoFlags.Debuggable) == 0;
            }
#endif
            var app = Assembly.GetEntryAssembly();
            var debuggable = app?.GetCustomAttribute<DebuggableAttribute>();
            return debuggable is null || !debuggable.IsJITOptimizerDisabled;
        }
    }
}
