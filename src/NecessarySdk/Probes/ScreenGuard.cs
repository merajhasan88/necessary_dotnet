namespace Necessary
{
    /// <summary>
    /// Screen protection that respects its host. The first caller records what
    /// the window has -- FLAG_SECURE, and whether it drops touches that passed
    /// through another app's window -- and protects it; later callers only count;
    /// the last one to finish puts back exactly what was recorded, so a host that
    /// keeps its window secure itself stays secure. Other apps' overlays, whose
    /// state no public call reads, are hidden while protected and shown again
    /// after. Kept apart from the window so that it is tested anywhere. The
    /// plugin's <c>ScreenGuard.kt</c>, translated.
    /// </summary>
    internal sealed class ScreenGuard
    {
        /// <summary>What a protected window gets.</summary>
        public static readonly Change Protected = new Change(Secure: true, DropsObscuredTouches: true, HideOverlays: true);

        private int holders;
        private WindowState? before;

        /// <summary>Whether any caller holds the protection.</summary>
        public bool Held => holders > 0;

        /// <summary>A caller protects the window; only the first changes it.</summary>
        public Change? Acquire(WindowState current)
        {
            holders += 1;
            if (holders > 1)
            {
                return null;
            }

            before = current;
            return Protected;
        }

        /// <summary>A caller is done; the last puts the window back. An extra release does nothing.</summary>
        public Change? Release()
        {
            if (holders == 0)
            {
                return null;
            }

            holders -= 1;
            if (holders > 0)
            {
                return null;
            }

            var saved = before;
            if (saved is null)
            {
                return null;
            }

            before = null;
            return new Change(saved.Secure, saved.DropsObscuredTouches, HideOverlays: false);
        }

        /// <summary>A new window for the screen -- the activity was recreated -- while protected.</summary>
        public Change? Reattach(WindowState current)
        {
            if (holders == 0)
            {
                return null;
            }

            before = current;
            return Protected;
        }

        /// <summary>What a window has, of what screen protection changes and can read.</summary>
        internal sealed record WindowState(bool Secure, bool DropsObscuredTouches);

        /// <summary>What to make of the window.</summary>
        internal sealed record Change(bool Secure, bool DropsObscuredTouches, bool HideOverlays);
    }
}
