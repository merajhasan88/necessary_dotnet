using System;
using System.Collections.Generic;
using System.Linq;
using Android.App;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Views.Accessibility;

namespace Necessary
{
    /// <summary>
    /// The app's windows watched for <see cref="TouchCounts"/>, process-wide:
    /// each activity is hooked once, and every collector that counts is fed from
    /// it while that activity is resumed. From Android 10 the app's other
    /// windows that take touches -- its dialogs -- are found in the process's
    /// window list whenever a watched window gains or loses focus, and are
    /// counted with it while it is resumed; one that cannot be watched leaves
    /// the counts out, never short. Main thread only.
    /// </summary>
    internal static class TouchWatching
    {
        private static readonly List<TouchCounts> Listeners = new List<TouchCounts>();
        private static readonly List<TouchWatch> Watches = new List<TouchWatch>();
        private static readonly List<TouchWatch> Children = new List<TouchWatch>();
        private static readonly List<View> Unwatched = new List<View>();
        private static TouchWatch? active;

        // The window list could not be read at the last look: unwatched too.
        private static bool listUnread;

        /// <summary>Whether a watched window is being counted: the resumed activity's, or one of the app's other windows while an activity is resumed.</summary>
        internal static bool Counting(TouchWatch watch) =>
            ReferenceEquals(watch, active) || (active is not null && Children.Contains(watch));

        /// <summary>Starts feeding <paramref name="counts"/>, from the window the user sees now if any.</summary>
        public static void Add(TouchCounts counts)
        {
            if (Listeners.Contains(counts))
            {
                return;
            }

            Listeners.Add(counts);
            if (active is not null)
            {
                Scan();
            }
            else if (NecessaryAndroid.ResumedActivity is Activity activity)
            {
                OnResumed(activity);
            }
        }

        /// <summary>Stops feeding <paramref name="counts"/> and drops what it counted; the last one unhooks every window.</summary>
        public static void Remove(TouchCounts counts)
        {
            if (!Listeners.Remove(counts))
            {
                return;
            }

            counts.WatchStopped();
            counts.SetUnwatchedWindows(false);
            counts.Discard();
            if (Listeners.Count == 0)
            {
                active = null;
                foreach (var watch in Watches.Concat(Children))
                {
                    watch.Detach();
                }

                Watches.Clear();
                Children.Clear();
                Unwatched.Clear();
                listUnread = false;
            }
        }

        internal static void OnResumed(Activity activity)
        {
            if (Listeners.Count == 0)
            {
                return;
            }

            var watch = Find(activity);
            if (watch is null)
            {
                watch = TouchWatch.Attach(activity);
                if (watch is null)
                {
                    return;
                }

                Watches.Add(watch);
            }

            active = watch;
            Scan();
        }

        internal static void OnPaused(Activity activity)
        {
            if (active is not null && ReferenceEquals(active.Activity, activity))
            {
                active = null;
                foreach (var counts in Listeners)
                {
                    counts.WatchStopped();
                }
            }
        }

        internal static void OnDestroyed(Activity activity)
        {
            OnPaused(activity);
            var watch = Find(activity);
            if (watch is not null)
            {
                watch.Detach();
                Watches.Remove(watch);
            }

            Prune();
        }

        /// <summary>A watched window gained or lost focus: a dialog opened or closed.</summary>
        internal static void FocusChanged()
        {
            if (Listeners.Count > 0 && active is not null)
            {
                Scan();
            }
        }

        internal static void Touch(TouchWatch watch, int action, int flags, int toolType)
        {
            if (Counting(watch))
            {
                foreach (var counts in Listeners)
                {
                    counts.OnTouch(action, flags, toolType);
                }
            }
        }

        internal static void Key(TouchWatch watch, int flags)
        {
            if (Counting(watch))
            {
                foreach (var counts in Listeners)
                {
                    counts.OnKey(flags);
                }
            }
        }

        internal static void Click(TouchWatch watch)
        {
            if (Counting(watch))
            {
                foreach (var counts in Listeners)
                {
                    counts.OnClick();
                }
            }
        }

        // The clicks are watched only when every window counted watches them.
        private static bool WatchesClicks() =>
            active is not null && active.WatchesClicks && Children.All(child => child.WatchesClicks);

        /// <summary>
        /// The app's other windows that take touches, from Android 10's window
        /// list: each dialog is watched as an activity is; one that cannot be is
        /// counted as unwatched while it is open. An activity's window, the
        /// plugin's own included, is the lifecycle's; a window that takes no
        /// touches, such as a toast, is not watched.
        /// </summary>
        private static void Scan()
        {
            Prune();
            listUnread = false;
            if (active is null || !OperatingSystem.IsAndroidVersionAtLeast(29))
            {
                Report();
                return;
            }

            IList<View>? roots;
            try
            {
                roots = Android.Views.Inspectors.WindowInspector.GlobalWindowViews;
            }
#pragma warning disable CA1031 // The list not read: the counts are left out, with why.
            catch (Exception)
#pragma warning restore CA1031
            {
                roots = null;
            }

            if (roots is null)
            {
                listUnread = true;
                Report();
                return;
            }

            foreach (var root in roots)
            {
                if (root is null || !root.IsAttachedToWindow || TakesNoTouches(root) || Known(root) || NecessaryAndroid.IsActivityWindow(root))
                {
                    continue;
                }

                var window = TouchWatch.WindowOf(root);
                if (window?.Callback is Activity)
                {
                    continue;
                }

                var watch = window is null || TouchWatch.IsCounting(window) ? null : TouchWatch.Attach(window, root);
                if (watch is null)
                {
                    if (window is null || !TouchWatch.IsCounting(window))
                    {
                        Unwatched.Add(root);
                    }

                    continue;
                }

                Children.Add(watch);
            }

            Report();
        }

        // Tells every collector which windows it counts now.
        private static void Report()
        {
            foreach (var counts in Listeners)
            {
                if (active is not null)
                {
                    counts.WatchStarted(WatchesClicks());
                }

                counts.SetUnwatchedWindows(listUnread || Unwatched.Count > 0);
            }
        }

        // A dialog closed, or an activity's window went: its watch is taken off.
        private static void Prune()
        {
            foreach (var child in Children.Where(child => !child.Root.IsAttachedToWindow).ToList())
            {
                child.Detach();
                Children.Remove(child);
            }

            Unwatched.RemoveAll(root => !root.IsAttachedToWindow);
        }

        private static bool Known(View root) =>
            Children.Any(child => Same(child.Root, root)) || Unwatched.Any(other => Same(other, root));

        private static bool TakesNoTouches(View root) =>
            root.LayoutParameters is WindowManagerLayoutParams layout
            && (layout.Flags & WindowManagerFlags.NotTouchable) != 0;

        internal static bool Same(View? a, View? b) =>
            a is not null && b is not null && JNIEnv.IsSameObject(a.Handle, b.Handle);

        private static TouchWatch? Find(Activity activity)
        {
            foreach (var watch in Watches)
            {
                if (ReferenceEquals(watch.Activity, activity))
                {
                    return watch;
                }
            }

            return null;
        }
    }

    /// <summary>
    /// One window watched, an activity's or a dialog's: every touch and key
    /// passes through the window's callback, and every click its screen reports
    /// to Accessibility through the content view's delegate. Both hand every call
    /// on, unchanged, to what was there before, and are put back on detach; one
    /// that something else has since wrapped stays in place and counts no more.
    /// </summary>
    internal sealed class TouchWatch
    {
        private static Java.Lang.Reflect.Field? decorWindow;
        private static bool decorWindowTried;

        private readonly CountingCallback callback;
        private readonly ViewGroup? content;
        private readonly CountingDelegate? accessibility;

        private TouchWatch(Activity? activity, Window window, View root, Window.ICallback original, ViewGroup? content, View.AccessibilityDelegate? delegateThere, bool delegateRead)
        {
            Activity = activity;
            Window = window;
            Root = root;
            callback = new CountingCallback(original, this);
            this.content = content;
            accessibility = content is not null && delegateRead ? new CountingDelegate(delegateThere, this) : null;
        }

        /// <summary>The activity watched; null for a dialog's window.</summary>
        public Activity? Activity { get; }

        public Window Window { get; }

        /// <summary>The window's root view.</summary>
        public View Root { get; }

        /// <summary>Whether the clicks are watched: only where the content view's own delegate could be read, so that it is kept.</summary>
        public bool WatchesClicks => accessibility is not null;

        /// <summary>Watches <paramref name="activity"/>, or null where it has no window to watch.</summary>
        public static TouchWatch? Attach(Activity activity)
        {
            var window = activity.Window;
            return window is null ? null : Attach(window, window.DecorView, activity);
        }

        /// <summary>Watches <paramref name="window"/>, whose root view is <paramref name="root"/>, or null where it cannot be.</summary>
        public static TouchWatch? Attach(Window window, View root, Activity? activity = null)
        {
            try
            {
                if (window.Callback is not Window.ICallback original || original is CountingCallback)
                {
                    return null;
                }

                var content = window.FindViewById<ViewGroup>(Android.Resource.Id.Content);
                var (read, there) = content is null ? (false, null) : ReadDelegate(content);
                var watch = new TouchWatch(activity, window, root, original, content, there, read);
                window.Callback = watch.callback;
                if (watch.content is not null && watch.accessibility is not null)
                {
                    watch.content.SetAccessibilityDelegate(watch.accessibility);
                }

                return watch;
            }
#pragma warning disable CA1031 // A window that cannot be watched is not counted; the app goes on.
            catch (Exception)
#pragma warning restore CA1031
            {
                return null;
            }
        }

        /// <summary>Whether <paramref name="window"/>'s callback is already a watch's.</summary>
        public static bool IsCounting(Window window) => window.Callback is CountingCallback;

        /// <summary>
        /// The window a root view draws, where it is a window's decor view: read
        /// from the decor view's own field, which Android lists as unsupported,
        /// not blocked, for every app. Null where it is not a decor view or the
        /// field cannot be read.
        /// </summary>
        public static Window? WindowOf(View root)
        {
            try
            {
                if (!decorWindowTried)
                {
                    decorWindowTried = true;
                    using var type = Java.Lang.Class.ForName("com.android.internal.policy.DecorView");
                    decorWindow = type.GetDeclaredField("mWindow");
                    decorWindow.Accessible = true;
                }

                if (decorWindow?.DeclaringClass is not Java.Lang.Class decor || !decor.IsInstance(root))
                {
                    return null;
                }

                return decorWindow.Get(root)?.JavaCast<Window>();
            }
#pragma warning disable CA1031 // Not read: the window is counted as unwatched.
            catch (Exception)
#pragma warning restore CA1031
            {
                return null;
            }
        }

        /// <summary>Puts back what was there, where it is still the watch's own.</summary>
        public void Detach()
        {
            callback.Counting = false;
            try
            {
                if (ReferenceEquals(Window.Callback, callback))
                {
                    Window.Callback = callback.Inner;
                }

                if (content is not null && accessibility is not null)
                {
                    accessibility.Counting = false;
                    var (read, now) = ReadDelegate(content);
                    if (read && ReferenceEquals(now, accessibility))
                    {
                        content.SetAccessibilityDelegate(accessibility.Inner);
                    }
                }
            }
#pragma warning disable CA1031 // Left in place, it hands every call on and counts nothing.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
        }

        /// <summary>
        /// The view's own delegate, which a view gives from Android 10; before,
        /// read from its field as AndroidX does. A failure to read it is a
        /// failure: no delegate is set over one that might be there.
        /// </summary>
        private static (bool Read, View.AccessibilityDelegate? Value) ReadDelegate(View view)
        {
            try
            {
                if (OperatingSystem.IsAndroidVersionAtLeast(29))
                {
                    return (true, view.GetAccessibilityDelegate());
                }

                using var type = Java.Lang.Class.FromType(typeof(View));
                using var field = type.GetDeclaredField("mAccessibilityDelegate");
                field.Accessible = true;
                var value = field.Get(view);
                return (true, value?.JavaCast<View.AccessibilityDelegate>());
            }
#pragma warning disable CA1031 // Not read: the clicks are not watched.
            catch (Exception)
#pragma warning restore CA1031
            {
                return (false, null);
            }
        }

        /// <summary>The window's callback, counting; every call goes on to the one that was there.</summary>
        private sealed class CountingCallback : Java.Lang.Object, Window.ICallback
        {
            private readonly TouchWatch watch;

            public CountingCallback(Window.ICallback inner, TouchWatch watch)
            {
                Inner = inner;
                this.watch = watch;
            }

            public Window.ICallback Inner { get; }

            public volatile bool Counting = true;

            public bool DispatchTouchEvent(MotionEvent? e)
            {
                if (Counting && e is not null)
                {
                    try
                    {
                        var action = (int)e.ActionMasked;
                        var down = action == TouchCounts.ActionDown;
                        TouchWatching.Touch(watch, action, down ? (int)e.Flags : 0, down ? (int)e.GetToolType(0) : 0);
                    }
#pragma warning disable CA1031 // Counting never stops a touch.
                    catch (Exception)
#pragma warning restore CA1031
                    {
                    }
                }

                return Inner.DispatchTouchEvent(e);
            }

            public bool DispatchKeyEvent(KeyEvent? e)
            {
                if (Counting && e is not null)
                {
                    try
                    {
                        TouchWatching.Key(watch, (int)e.Flags);
                    }
#pragma warning disable CA1031 // Counting never stops a key.
                    catch (Exception)
#pragma warning restore CA1031
                    {
                    }
                }

                return Inner.DispatchKeyEvent(e);
            }

            public bool DispatchGenericMotionEvent(MotionEvent? e) => Inner.DispatchGenericMotionEvent(e);

            public bool DispatchKeyShortcutEvent(KeyEvent? e) => Inner.DispatchKeyShortcutEvent(e);

            public bool DispatchPopulateAccessibilityEvent(AccessibilityEvent? e) => Inner.DispatchPopulateAccessibilityEvent(e);

            public bool DispatchTrackballEvent(MotionEvent? e) => Inner.DispatchTrackballEvent(e);

            public void OnActionModeFinished(ActionMode? mode) => Inner.OnActionModeFinished(mode);

            public void OnActionModeStarted(ActionMode? mode) => Inner.OnActionModeStarted(mode);

            public void OnAttachedToWindow() => Inner.OnAttachedToWindow();

            public void OnContentChanged() => Inner.OnContentChanged();

            public bool OnCreatePanelMenu(int featureId, IMenu menu) => Inner.OnCreatePanelMenu(featureId, menu);

            public View? OnCreatePanelView(int featureId) => Inner.OnCreatePanelView(featureId);

            public void OnDetachedFromWindow() => Inner.OnDetachedFromWindow();

            public bool OnMenuItemSelected(int featureId, IMenuItem item) => Inner.OnMenuItemSelected(featureId, item);

            public bool OnMenuOpened(int featureId, IMenu menu) => Inner.OnMenuOpened(featureId, menu);

            public void OnPanelClosed(int featureId, IMenu menu) => Inner.OnPanelClosed(featureId, menu);

            public bool OnPreparePanel(int featureId, View? view, IMenu menu) => Inner.OnPreparePanel(featureId, view, menu);

            public bool OnSearchRequested() => Inner.OnSearchRequested();

            public bool OnSearchRequested(SearchEvent? searchEvent) => Inner.OnSearchRequested(searchEvent);

            public void OnWindowAttributesChanged(WindowManagerLayoutParams? attrs) => Inner.OnWindowAttributesChanged(attrs);

            public void OnWindowFocusChanged(bool hasFocus)
            {
                Inner.OnWindowFocusChanged(hasFocus);
                if (Counting)
                {
                    try
                    {
                        TouchWatching.FocusChanged();
                    }
#pragma warning disable CA1031 // Looking for the app's dialogs never stops a focus change.
                    catch (Exception)
#pragma warning restore CA1031
                    {
                    }
                }
            }

            public ActionMode? OnWindowStartingActionMode(ActionMode.ICallback? callback) => Inner.OnWindowStartingActionMode(callback);

            public ActionMode? OnWindowStartingActionMode(ActionMode.ICallback? callback, ActionModeType type) => Inner.OnWindowStartingActionMode(callback, type);

            // The interface's two default methods, handed on as every other is.
            public void OnProvideKeyboardShortcuts(IList<KeyboardShortcutGroup>? data, IMenu? menu, int deviceId) =>
                Inner.OnProvideKeyboardShortcuts(data, menu, deviceId);

            public void OnPointerCaptureChanged(bool hasCapture)
            {
                if (OperatingSystem.IsAndroidVersionAtLeast(26))
                {
                    Inner.OnPointerCaptureChanged(hasCapture);
                }
            }
        }

        /// <summary>Counts the clicks; every call goes on to the delegate that was there, or to the view's own.</summary>
        private sealed class CountingDelegate : View.AccessibilityDelegate
        {
            private readonly TouchWatch watch;

            public CountingDelegate(View.AccessibilityDelegate? inner, TouchWatch watch)
            {
                Inner = inner;
                this.watch = watch;
            }

            public View.AccessibilityDelegate? Inner { get; }

            public volatile bool Counting = true;

            public override bool OnRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent e)
            {
                if (Counting)
                {
                    try
                    {
                        if (e.EventType == EventTypes.ViewClicked || e.EventType == EventTypes.ViewLongClicked)
                        {
                            TouchWatching.Click(watch);
                        }
                    }
#pragma warning disable CA1031 // Counting never stops an event.
                    catch (Exception)
#pragma warning restore CA1031
                    {
                    }
                }

                return Inner is not null
                    ? Inner.OnRequestSendAccessibilityEvent(host, child, e)
                    : base.OnRequestSendAccessibilityEvent(host, child, e);
            }

            public override void SendAccessibilityEvent(View host, EventTypes eventType)
            {
                if (Inner is not null)
                {
                    Inner.SendAccessibilityEvent(host, eventType);
                }
                else
                {
                    base.SendAccessibilityEvent(host, eventType);
                }
            }

            public override void SendAccessibilityEventUnchecked(View host, AccessibilityEvent e)
            {
                if (Inner is not null)
                {
                    Inner.SendAccessibilityEventUnchecked(host, e);
                }
                else
                {
                    base.SendAccessibilityEventUnchecked(host, e);
                }
            }

            public override bool DispatchPopulateAccessibilityEvent(View host, AccessibilityEvent e) =>
                Inner is not null ? Inner.DispatchPopulateAccessibilityEvent(host, e) : base.DispatchPopulateAccessibilityEvent(host, e);

            public override void OnPopulateAccessibilityEvent(View host, AccessibilityEvent e)
            {
                if (Inner is not null)
                {
                    Inner.OnPopulateAccessibilityEvent(host, e);
                }
                else
                {
                    base.OnPopulateAccessibilityEvent(host, e);
                }
            }

            public override void OnInitializeAccessibilityEvent(View host, AccessibilityEvent e)
            {
                if (Inner is not null)
                {
                    Inner.OnInitializeAccessibilityEvent(host, e);
                }
                else
                {
                    base.OnInitializeAccessibilityEvent(host, e);
                }
            }

            public override void OnInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfo info)
            {
                if (Inner is not null)
                {
                    Inner.OnInitializeAccessibilityNodeInfo(host, info);
                }
                else
                {
                    base.OnInitializeAccessibilityNodeInfo(host, info);
                }
            }

            public override void AddExtraDataToAccessibilityNodeInfo(View host, AccessibilityNodeInfo info, string extraDataKey, Bundle? arguments)
            {
                // Android 8 and later call it.
                if (!OperatingSystem.IsAndroidVersionAtLeast(26))
                {
                    return;
                }

                if (Inner is not null)
                {
                    Inner.AddExtraDataToAccessibilityNodeInfo(host, info, extraDataKey, arguments);
                }
                else
                {
                    base.AddExtraDataToAccessibilityNodeInfo(host, info, extraDataKey, arguments);
                }
            }

            public override AccessibilityNodeProvider? GetAccessibilityNodeProvider(View host) =>
                Inner is not null ? Inner.GetAccessibilityNodeProvider(host) : base.GetAccessibilityNodeProvider(host);

            public override bool PerformAccessibilityAction(View host, Android.Views.Accessibility.Action action, Bundle? args) =>
                Inner is not null ? Inner.PerformAccessibilityAction(host, action, args) : base.PerformAccessibilityAction(host, action, args);
        }
    }
}
