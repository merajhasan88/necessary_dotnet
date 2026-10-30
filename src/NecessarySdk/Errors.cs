using System;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>
    /// A failure of the phone's keystore or of a prompt: <see cref="Code"/> says
    /// which -- <c>STEPUP_KEY_INVALIDATED</c>, <c>STEPUP_CANCELLED</c>,
    /// <c>STEPUP_REENROL_PENDING</c> and the like -- and the message says it in
    /// words.
    /// </summary>
    public class NativeKeyException : Exception
    {
        /// <summary>A failure with its code and message.</summary>
        public NativeKeyException(string code, string message, Exception? innerException = null)
            : base(message, innerException)
        {
            Code = code;
        }

        /// <summary>What failed, for the app to act on.</summary>
        public string Code { get; }

        /// <inheritdoc />
        public override string ToString() => Message + " [" + Code + "]";
    }

    /// <summary>
    /// A refusal from your backend, or a request that did not reach it: the
    /// backend's <c>{"error": {"code", "message", "details"}}</c> (the guide,
    /// section 4), with the HTTP status.
    /// </summary>
    public class ApiException : Exception
    {
        /// <summary>A refusal, or a failure on the way.</summary>
        public ApiException(
            string message,
            int? statusCode = null,
            string? code = null,
            JsonObject? details = null,
            Exception? innerException = null)
            : base(message, innerException)
        {
            StatusCode = statusCode;
            Code = code;
            Details = details;
        }

        /// <summary>The HTTP status, when the backend answered.</summary>
        public int? StatusCode { get; }

        /// <summary>The backend's <c>code</c>: what the app acts on.</summary>
        public string? Code { get; }

        /// <summary>The backend's <c>details</c>, such as <c>retry_after_seconds</c>.</summary>
        public JsonObject? Details { get; }

        /// <inheritdoc />
        public override string ToString() => Message;
    }

    /// <summary>
    /// A call that <c>DeviceTrust.ResetAsync</c> or
    /// <c>DeviceTrust.Close</c> ended while it ran: what it found belongs
    /// to an installation that is gone, or to a client that is closed, so
    /// nothing of it was kept. After a reset, call again.
    /// </summary>
    public class InterruptedCallException : Exception
    {
        /// <summary>The call, interrupted.</summary>
        public InterruptedCallException(string message)
            : base(message)
        {
        }

        /// <inheritdoc />
        public override string ToString() => Message;
    }
}
