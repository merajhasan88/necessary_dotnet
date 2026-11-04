// HttpTransport: every call that got no answer is an ApiException, the one
// failure an app handles, whatever the phone's HTTP stack calls the failure.
// On an Android 9 phone a refused TLS handshake came as an HttpRequestException,
// a connection lost once it was made as the handler's own failure.
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Necessary.Tests
{
    public class TransportTests
    {
        private static HttpTransport Failing(Exception failure, TimeSpan? timeout = null) =>
            new HttpTransport("https://backend.example", new HttpClient(new Fails(failure)), timeout);

        private static Task Send(HttpTransport transport) => transport.SendAsync("POST", "/v1/installations/register");

        [Fact]
        public async Task A_connection_lost_once_made_is_an_ApiException_not_the_stacks_own_failure()
        {
            var lost = new WebException("unexpected end of stream on com.android.okhttp.Address@bd539d0a", WebExceptionStatus.UnknownError);
            var error = await Assert.ThrowsAsync<ApiException>(() => Send(Failing(lost)));
            Assert.Contains("unexpected end of stream", error.Message, StringComparison.Ordinal);
            Assert.Same(lost, error.InnerException);
            Assert.Null(error.StatusCode);
        }

        [Fact]
        public async Task So_are_a_socket_a_client_and_a_read_failure()
        {
            await Assert.ThrowsAsync<ApiException>(() => Send(Failing(new HttpRequestException("refused", new SocketException()))));
            await Assert.ThrowsAsync<ApiException>(() => Send(Failing(new HttpRequestException("closed"))));
            await Assert.ThrowsAsync<ApiException>(() => Send(Failing(new IOException("reset"))));
        }

        [Fact]
        public async Task A_failure_after_the_deadline_is_the_timeout_whatever_it_is_called()
        {
            var error = await Assert.ThrowsAsync<ApiException>(
                () => Send(Failing(new WebException("Socket closed"), TimeSpan.FromMilliseconds(50))));
            Assert.Contains("timeout", error.Message, StringComparison.Ordinal);
        }

        [Fact]
        public async Task A_call_cancelled_from_outside_stays_cancelled()
        {
            await Assert.ThrowsAsync<OperationCanceledException>(() => Send(Failing(new OperationCanceledException())));
        }

        /// <summary>Fails every request; with a deadline, only once it has passed.</summary>
        private sealed class Fails : HttpMessageHandler
        {
            private readonly Exception failure;

            public Fails(Exception failure)
            {
                this.failure = failure;
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (failure is WebException { Message: "Socket closed" })
                {
                    try
                    {
                        await Task.Delay(Timeout.Infinite, cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                    }
                }

                throw failure;
            }
        }
    }
}
