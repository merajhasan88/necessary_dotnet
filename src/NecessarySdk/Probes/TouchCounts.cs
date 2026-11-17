using System;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>
    /// How the app's screen was touched, for the <c>accessibility</c> measurement
    /// (Android collector 14): every touch, those an Accessibility service made,
    /// and the clicks with no touch or key press before them, over the time a
    /// window was watched. Counts only: no position, no view, no text. Plain
    /// logic, so it is tested anywhere; the Android host feeds it.
    /// </summary>
    /// <remarks>
    /// A gesture a service dispatches reaches the window with the unknown tool
    /// type (0), and from Android 12 also with the flag 0x800
    /// (FLAG_IS_ACCESSIBILITY_EVENT). Android 12 to 15 put that flag on a
    /// finger's touches too while a service that can perform gestures is on, so a
    /// touch is a service's only when its tool is unknown and, from Android 12, it
    /// carries the flag. A click a service performs makes no touch at all: a click
    /// counts as a service's when no touch, and no key the user pressed, came in
    /// the 2 seconds before it.
    /// </remarks>
    internal sealed class TouchCounts
    {
        /// <summary>MotionEvent.ACTION_DOWN.</summary>
        public const int ActionDown = 0;

        /// <summary>MotionEvent.TOOL_TYPE_UNKNOWN.</summary>
        public const int ToolTypeUnknown = 0;

        /// <summary>The hidden FLAG_IS_ACCESSIBILITY_EVENT, on motion and key events (Android 12 and later).</summary>
        public const int FlagIsAccessibilityEvent = 0x800;

        /// <summary>The first Android version that marks a service's input: 12.</summary>
        public const int MarkedFromSdk = 31;

        /// <summary>How long after a touch or key its click may come.</summary>
        public const long ClickAfterInputMs = 2000;

        private readonly object gate = new object();
        private readonly int sdkInt;
        private readonly Func<long> clock;
        private int touches;
        private int injected;
        private int untouchedClicks;
        private long? lastInput;
        private long? watchingSince;
        private long watchedMs;
        private bool watched;

        // The clicks were not watched for some of the time: their count is left out.
        private bool clicksMissed;
        private bool watchingClicks;

        /// <summary>Counts for Android <paramref name="sdkInt"/>, timed by <paramref name="clock"/> in milliseconds.</summary>
        public TouchCounts(int sdkInt, Func<long> clock)
        {
            this.sdkInt = sdkInt;
            this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        }

        /// <summary>A window is watched from now; its clicks too when <paramref name="clicks"/>.</summary>
        public void WatchStarted(bool clicks)
        {
            lock (gate)
            {
                watchingSince ??= clock();
                watched = true;
                watchingClicks = clicks;
                if (!clicks)
                {
                    clicksMissed = true;
                }
            }
        }

        /// <summary>No window is watched from now.</summary>
        public void WatchStopped()
        {
            lock (gate)
            {
                if (watchingSince is long since)
                {
                    watchedMs += clock() - since;
                }

                watchingSince = null;
            }
        }

        /// <summary>The app no longer counts: what was counted is dropped.</summary>
        public void Discard()
        {
            lock (gate)
            {
                Reset();
                watchedMs = 0;
                watched = watchingSince is not null;
                if (watched)
                {
                    watchingSince = clock();
                }

                clicksMissed = watched && !watchingClicks;
            }
        }

        /// <summary>A motion event: <paramref name="flags"/> and <paramref name="toolType"/> are read only on a down.</summary>
        public void OnTouch(int action, int flags, int toolType)
        {
            lock (gate)
            {
                if (action == ActionDown)
                {
                    touches++;
                    var marked = sdkInt < MarkedFromSdk || (flags & FlagIsAccessibilityEvent) != 0;
                    if (toolType == ToolTypeUnknown && marked)
                    {
                        injected++;
                    }
                }

                lastInput = clock();
            }
        }

        /// <summary>A key event: one the user made explains a click, one a service sent does not.</summary>
        public void OnKey(int flags)
        {
            lock (gate)
            {
                if ((flags & FlagIsAccessibilityEvent) == 0)
                {
                    lastInput = clock();
                }
            }
        }

        /// <summary>A click or long click the screen reported to Accessibility.</summary>
        public void OnClick()
        {
            lock (gate)
            {
                if (lastInput is not long last || clock() - last > ClickAfterInputMs)
                {
                    untouchedClicks++;
                }
            }
        }

        /// <summary>
        /// The counts since the last read, which start afresh: <c>touches</c>,
        /// <c>touches_injected</c>, <c>clicks_without_touch</c> (left out when the
        /// clicks were not watched all the time) and <c>counted_seconds</c>; null
        /// when no window was watched since the last read.
        /// </summary>
        public JsonObject? Take()
        {
            lock (gate)
            {
                if (!watched)
                {
                    return null;
                }

                var now = clock();
                var ms = watchedMs + (watchingSince is long since ? now - since : 0L);
                var counts = new JsonObject
                {
                    ["touches"] = touches,
                    ["touches_injected"] = injected,
                };
                if (!clicksMissed)
                {
                    counts["clicks_without_touch"] = untouchedClicks;
                }

                counts["counted_seconds"] = (int)(Math.Max(ms, 0L) / 1000);
                Reset();
                watchedMs = 0;
                if (watchingSince is not null)
                {
                    watchingSince = now;
                }

                watched = watchingSince is not null;
                clicksMissed = watched && !watchingClicks;
                return counts;
            }
        }

        private void Reset()
        {
            touches = 0;
            injected = 0;
            untouchedClicks = 0;
        }
    }
}
