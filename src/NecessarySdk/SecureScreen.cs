using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// Protects the app's window while a secret is typed. Android: no
    /// screenshots, recordings or casts of the window, other apps' windows not
    /// drawn over it (Android 12 and later), and touches that passed through
    /// another app's window dropped. iOS cannot block screenshots; it covers the
    /// window while the screen is recorded or mirrored.
    /// </summary>
    /// <remarks>
    /// Calls nest: each <c>ProtectAsync(true)</c> needs its
    /// <c>ProtectAsync(false)</c>, and the window is put back as it was -- a
    /// window the app keeps secure itself stays secure -- when the last one
    /// ends. Other apps' overlays, which no public call reads, are shown again
    /// then.
    /// </remarks>
    public static class SecureScreen
    {
        /// <summary>
        /// Protects the window (<paramref name="on"/>), or lets go of one
        /// protection; answers what the window has now. Where the platform has no
        /// such protection the answer is empty, and the call still counts.
        /// </summary>
        public static async Task<JsonObject> ProtectAsync(bool on)
        {
            try
            {
                return await NativePlatform.ProtectScreenAsync(on).ConfigureAwait(false);
            }
            catch (NativeKeyException)
            {
                return new JsonObject();
            }
        }
    }
}
