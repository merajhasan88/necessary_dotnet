// Screen protection respects its host: it records the window before changing
// it, counts overlapping callers, and puts back only what it found when the
// last one finishes. The plugin's ScreenGuardTest.kt, translated.
using Xunit;

namespace Necessary.Tests
{
    public class ScreenGuardTests
    {
        private static readonly ScreenGuard.WindowState Plain = new ScreenGuard.WindowState(Secure: false, DropsObscuredTouches: false);
        private static readonly ScreenGuard.WindowState HostSecure = new ScreenGuard.WindowState(Secure: true, DropsObscuredTouches: false);

        [Fact]
        public void The_last_release_puts_back_what_the_host_had()
        {
            var guard = new ScreenGuard();
            Assert.Equal(ScreenGuard.Protected, guard.Acquire(HostSecure));
            Assert.Equal(new ScreenGuard.Change(Secure: true, DropsObscuredTouches: false, HideOverlays: false), guard.Release());
            Assert.False(guard.Held);
        }

        [Fact]
        public void Overlapping_callers_are_counted()
        {
            var guard = new ScreenGuard();
            Assert.Equal(ScreenGuard.Protected, guard.Acquire(Plain));
            Assert.Null(guard.Acquire(Plain));
            Assert.Null(guard.Release());
            Assert.True(guard.Held);
            Assert.Equal(new ScreenGuard.Change(Secure: false, DropsObscuredTouches: false, HideOverlays: false), guard.Release());
            Assert.False(guard.Held);
        }

        [Fact]
        public void An_extra_release_changes_nothing()
        {
            var guard = new ScreenGuard();
            Assert.Null(guard.Release());
            guard.Acquire(Plain);
            guard.Release();
            Assert.Null(guard.Release());
            Assert.Equal(ScreenGuard.Protected, guard.Acquire(Plain));
        }

        [Fact]
        public void A_recreated_window_is_protected_and_put_back_as_it_came()
        {
            var guard = new ScreenGuard();
            Assert.Null(guard.Reattach(Plain));
            guard.Acquire(Plain);
            Assert.Equal(ScreenGuard.Protected, guard.Reattach(HostSecure));
            Assert.Equal(new ScreenGuard.Change(Secure: true, DropsObscuredTouches: false, HideOverlays: false), guard.Release());
        }
    }
}
