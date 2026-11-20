// How the app's screen was touched (Android collector 14): a service's taps and
// clicks are counted, a finger's and a keyboard's are not, and nothing watched
// is no reading.
using System.Linq;
using System.Text.Json.Nodes;
using Xunit;

namespace Necessary.Tests
{
    public class TouchCountsTests
    {
        private const int Finger = 1;
        private const int Unknown = TouchCounts.ToolTypeUnknown;
        private const int Marked = TouchCounts.FlagIsAccessibilityEvent;
        private const int Down = TouchCounts.ActionDown;
        private const int Up = 1;

        private long now = 1_000_000L;

        private TouchCounts Counts(int sdk = 36) => new TouchCounts(sdk, () => now);

        private void Tap(TouchCounts counts, int flags, int tool)
        {
            counts.OnTouch(Down, flags, tool);
            now += 60;
            counts.OnTouch(Up, flags, tool);
        }

        private static int Int(JsonObject read, string name) => read[name]!.GetValue<int>();

        [Fact]
        public void Nothing_watched_is_no_reading()
        {
            var counts = Counts();
            Tap(counts, 0, Finger);
            Assert.Null(counts.Take());
        }

        [Fact]
        public void A_services_gesture_is_counted_and_a_fingers_is_not()
        {
            var counts = Counts();
            counts.WatchStarted(clicks: true);
            Tap(counts, 0, Finger);

            // Android 12 to 15 mark a finger's touches too while a service that can perform gestures is on.
            Tap(counts, Marked, Finger);
            Tap(counts, Marked, Unknown);
            now += 5_000;
            var read = counts.Take()!;
            Assert.Equal(3, Int(read, "touches"));
            Assert.Equal(1, Int(read, "touches_injected"));
            Assert.Equal(0, Int(read, "clicks_without_touch"));
            Assert.Equal(5, Int(read, "counted_seconds"));
        }

        [Fact]
        public void Before_Android_12_the_tool_alone_tells()
        {
            var counts = Counts(sdk: 29);
            counts.WatchStarted(clicks: true);
            Tap(counts, 0, Unknown);
            Tap(counts, 0, Finger);
            Assert.Equal(1, Int(counts.Take()!, "touches_injected"));

            // From Android 12 an unmarked touch of no tool is not a service's.
            var newer = Counts(sdk: 31);
            newer.WatchStarted(clicks: true);
            Tap(newer, 0, Unknown);
            Assert.Equal(0, Int(newer.Take()!, "touches_injected"));
        }

        [Fact]
        public void A_click_with_no_touch_or_key_before_it_is_counted()
        {
            var counts = Counts();
            counts.WatchStarted(clicks: true);
            counts.OnClick();                      // nothing before it
            Tap(counts, 0, Finger);
            now += 300;
            counts.OnClick();                      // the tap's
            now += TouchCounts.ClickAfterInputMs;
            counts.OnClick();                      // long after it
            counts.OnKey(0);
            now += 100;
            counts.OnClick();                      // a key the user pressed
            now += TouchCounts.ClickAfterInputMs + 1;
            counts.OnKey(Marked);
            counts.OnClick();                      // a key a service sent explains nothing
            Assert.Equal(3, Int(counts.Take()!, "clicks_without_touch"));
        }

        [Fact]
        public void Clicks_not_watched_all_the_time_are_left_out()
        {
            var counts = Counts();
            counts.WatchStarted(clicks: false);
            counts.OnClick();
            var read = counts.Take()!;
            Assert.False(read.ContainsKey("clicks_without_touch"));
            Assert.Equal(0, Int(read, "touches"));
        }

        [Fact]
        public void Each_read_starts_afresh_and_counts_only_watched_time()
        {
            var counts = Counts();
            counts.WatchStarted(clicks: true);
            Tap(counts, Marked, Unknown);
            now += 2_000;
            counts.WatchStopped();
            now += 60_000;
            var first = counts.Take()!;
            Assert.Equal(1, Int(first, "touches_injected"));
            Assert.Equal(2, Int(first, "counted_seconds"));

            // Not watched since: no reading.
            Assert.Null(counts.Take());
            counts.WatchStarted(clicks: true);
            now += 3_000;
            var second = counts.Take()!;
            Assert.Equal(0, Int(second, "touches"));
            Assert.Equal(3, Int(second, "counted_seconds"));
        }

        [Fact]
        public void A_window_that_could_not_be_watched_leaves_the_counts_out_with_why()
        {
            var counts = Counts();
            counts.WatchStarted(clicks: true);
            Tap(counts, Marked, Unknown);
            counts.SetUnwatchedWindows(true);   // a dialog opened that could not be watched
            now += 1_000;
            counts.SetUnwatchedWindows(false);  // and closed
            now += 1_000;
            var read = counts.Take()!;
            Assert.False(read.ContainsKey("touches") || read.ContainsKey("touches_injected") || read.ContainsKey("clicks_without_touch"));
            var unread = (JsonObject)read["unread"]!;
            Assert.Equal(new[] { "touches", "touches_injected", "clicks_without_touch" }, unread.Select(part => part.Key));
            Assert.Equal(2, Int(read, "counted_seconds"));

            // Closed before this read began: the next one is whole.
            Tap(counts, 0, Finger);
            var next = counts.Take()!;
            Assert.Equal(1, Int(next, "touches"));
            Assert.False(next.ContainsKey("unread"));
        }

        [Fact]
        public void A_window_still_open_that_could_not_be_watched_leaves_the_next_read_out_too()
        {
            var counts = Counts();
            counts.WatchStarted(clicks: true);
            counts.SetUnwatchedWindows(true);
            Assert.True(counts.Take()!.ContainsKey("unread"));
            Assert.True(counts.Take()!.ContainsKey("unread"));
            counts.SetUnwatchedWindows(false);
            Assert.True(counts.Take()!.ContainsKey("unread"));   // it was open during this read
            Assert.Equal(0, Int(counts.Take()!, "touches"));

            // Discarded while one is open: what follows still says so.
            counts.SetUnwatchedWindows(true);
            counts.Discard();
            Assert.True(counts.Take()!.ContainsKey("unread"));
        }

        [Fact]
        public void Discard_drops_what_was_counted()
        {
            var counts = Counts();
            counts.WatchStarted(clicks: true);
            Tap(counts, Marked, Unknown);
            counts.WatchStopped();
            counts.Discard();
            Assert.Null(counts.Take());
        }
    }
}
