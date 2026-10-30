using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Foundation;
using UIKit;

namespace Necessary
{
    /// <summary>
    /// iOS cannot block screenshots: while protected, the window the person
    /// sees in each scene whose screen is captured -- recorded, mirrored or
    /// sent to AirPlay -- is covered, and the cover is placed again whenever a
    /// window becomes key, visible or hidden, or a scene comes to the
    /// foreground; protection asked for before any window exists covers the
    /// first one. Held until the last holder lets go. The plugin's
    /// <c>NecessaryPlugin.swift</c> covers, translated.
    /// </summary>
    internal static class AppleScreenProtection
    {
        private static readonly List<UIView> Covers = new List<UIView>();
        private static readonly List<NSObject> Observers = new List<NSObject>();
        private static int holders;
        private static bool screenProtected;

        private static readonly NSString[] CoverEvents =
        {
            UIScreen.CapturedDidChangeNotification,
            UIWindow.DidBecomeKeyNotification,
            UIWindow.DidBecomeVisibleNotification,
            UIWindow.DidBecomeHiddenNotification,
            UIScene.WillEnterForegroundNotification,
            UIScene.DidActivateNotification,
            UIScene.DidDisconnectNotification,
        };

        public static Task<JsonObject> ProtectAsync(bool on) => NecessaryApple.OnMainThread(() =>
        {
            if (on)
            {
                holders += 1;
            }
            else if (holders > 0)
            {
                holders -= 1;
            }

            SetScreenProtection(holders > 0);
            return new JsonObject
            {
                ["held"] = holders > 0,
                ["secure"] = false,
                ["covered_while_captured"] = holders > 0,
            };
        });

        private static void SetScreenProtection(bool on)
        {
            screenProtected = on;
            foreach (var observer in Observers)
            {
                NSNotificationCenter.DefaultCenter.RemoveObserver(observer);
            }

            Observers.Clear();
            if (on)
            {
                foreach (var name in CoverEvents)
                {
                    Observers.Add(NSNotificationCenter.DefaultCenter.AddObserver(name, _ => UpdateCaptureCovers()));
                }
            }

            UpdateCaptureCovers();
        }

        /// <summary>
        /// Whether the scene's screen is recorded, mirrored or sent to AirPlay:
        /// the scene's capture state from iOS 17, where its screen's flag is
        /// obsoleted, and that flag before.
        /// </summary>
        internal static bool IsCaptured(UIWindowScene scene)
        {
            if (OperatingSystem.IsIOSVersionAtLeast(17))
            {
                return scene.TraitCollection.SceneCaptureState == UISceneCaptureState.Active;
            }

#pragma warning disable CA1422 // The only flag there is below iOS 17.
            return scene.Screen.Captured;
#pragma warning restore CA1422
        }

        private static void UpdateCaptureCovers()
        {
            foreach (var cover in Covers)
            {
                cover.RemoveFromSuperview();
            }

            Covers.Clear();
            if (!screenProtected)
            {
                return;
            }

            foreach (var scene in UIApplication.SharedApplication.ConnectedScenes.ToArray().OfType<UIWindowScene>())
            {
                if (!IsCaptured(scene))
                {
                    continue;
                }

                var window = scene.Windows.FirstOrDefault(w => w.IsKeyWindow)
                    ?? scene.Windows.FirstOrDefault(w => !w.Hidden && w.WindowLevel == UIWindowLevel.Normal);
                if (window is null)
                {
                    continue;
                }

                var view = new UIView(window.Bounds)
                {
                    BackgroundColor = UIColor.Black,
                    AutoresizingMask = UIViewAutoresizing.FlexibleWidth | UIViewAutoresizing.FlexibleHeight,
                };
                window.AddSubview(view);
                Covers.Add(view);
            }
        }
    }
}
