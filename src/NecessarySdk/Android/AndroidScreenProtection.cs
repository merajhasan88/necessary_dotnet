using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Android.App;
using Android.Content.PM;
using Android.Views;

namespace Necessary
{
    /// <summary>
    /// While a secret is typed: the window cannot be captured in screenshots,
    /// recordings or casts (FLAG_SECURE); other apps' windows are not drawn over
    /// it (Android 12 and later, HIDE_OVERLAY_WINDOWS, a normal permission); and a
    /// touch that passed through another app's window is dropped.
    /// <see cref="ScreenGuard"/> decides when, and what the window gets back; a
    /// window created while the screen is protected is protected too.
    /// </summary>
    internal static class AndroidScreenProtection
    {
        private static readonly object Gate = new object();
        private static readonly ScreenGuard Guard = new ScreenGuard();
        private static bool following;

        public static Task<JsonObject> ProtectAsync(bool on) => NecessaryAndroid.OnMainThreadAsync(() =>
        {
            Follow();
            var activity = NecessaryAndroid.CurrentActivity;
            lock (Gate)
            {
                if (on)
                {
                    if (activity is null)
                    {
                        throw new NativeKeyException("NO_ACTIVITY", "Screen protection needs a visible activity.");
                    }

                    if (Guard.Acquire(WindowState(activity)) is ScreenGuard.Change change)
                    {
                        Apply(activity, change);
                    }
                }
                else
                {
                    // Counted even without a window, so a release is never lost.
                    var change = Guard.Release();
                    if (activity is not null && change is not null)
                    {
                        Apply(activity, change);
                    }
                }

                return State(activity);
            }
        });

        private static void Follow()
        {
            lock (Gate)
            {
                if (following)
                {
                    return;
                }

                following = true;
            }

            // A window recreated while the screen is protected is protected too.
            NecessaryAndroid.ActivityCreated += activity =>
            {
                lock (Gate)
                {
                    if (Guard.Reattach(WindowState(activity)) is ScreenGuard.Change change)
                    {
                        Apply(activity, change);
                    }
                }
            };
        }

        private static void Apply(Activity activity, ScreenGuard.Change change)
        {
            var window = activity.Window!;
            if (change.Secure)
            {
                window.AddFlags(WindowManagerFlags.Secure);
            }
            else
            {
                window.ClearFlags(WindowManagerFlags.Secure);
            }

            if (OverlaysHideable() && OperatingSystem.IsAndroidVersionAtLeast(31))
            {
                window.SetHideOverlayWindows(change.HideOverlays);
            }

            window.DecorView.FilterTouchesWhenObscured = change.DropsObscuredTouches;
        }

        private static bool OverlaysHideable() =>
            OperatingSystem.IsAndroidVersionAtLeast(31)
            && NecessaryAndroid.Context.CheckSelfPermission("android.permission.HIDE_OVERLAY_WINDOWS") == Permission.Granted;

        private static ScreenGuard.WindowState WindowState(Activity activity) => new ScreenGuard.WindowState(
            Secure: (activity.Window!.Attributes!.Flags & WindowManagerFlags.Secure) != 0,
            DropsObscuredTouches: activity.Window.DecorView.FilterTouchesWhenObscured);

        /// <summary>What the window has now, and whether the package holds it.</summary>
        private static JsonObject State(Activity? activity) => new JsonObject
        {
            ["held"] = Guard.Held,
            ["secure"] = activity is not null && WindowState(activity).Secure,
            ["overlays_hidden"] = Guard.Held && OverlaysHideable(),
            ["obscured_touches_dropped"] = activity is not null && WindowState(activity).DropsObscuredTouches,
        };
    }
}
