using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;

namespace Necessary
{
    /// <summary>
    /// What the iOS collector makes of what it read: pure functions with no
    /// Apple framework in them, so they are tested anywhere. The plugin's
    /// <c>ProbeReads.swift</c>, translated. The collector reads Mach-O headers,
    /// files and Core Location; these decide what the reads mean.
    /// </summary>
    internal static class IosProbeReads
    {
        /// <summary>The largest __TEXT segment read from disk for one comparison.</summary>
        public const ulong MaxTextSegment = 64UL * 1024 * 1024;

        /// <summary>Images not compared that are named, at most.</summary>
        public const int MaxNamedImages = 64;

        /// <summary>
        /// The __text section of a __TEXT segment, or why it cannot be compared.
        /// The section is checked before the segment's budget is applied, so an
        /// image over the budget is skipped with its size rather than dropped
        /// unseen; the header's unsigned values are checked before any becomes an
        /// int. <paramref name="section"/> is null when the segment names no __text.
        /// </summary>
        public static (TextSpan? Span, CoverageProblem? Problem) TextSpanOf(
            ulong segmentFileOffset,
            ulong segmentFileSize,
            ulong segmentVMAddress,
            (ulong Offset, ulong Size)? section)
        {
            if (section is not { } text)
            {
                return (null, new CoverageProblem("no __text section in __TEXT", 0));
            }

            var size = text.Size;
            if (size == 0)
            {
                return (null, new CoverageProblem("an empty __text section", 0));
            }

            if (text.Offset < segmentFileOffset || size > segmentFileSize || text.Offset - segmentFileOffset > segmentFileSize - size)
            {
                return (null, new CoverageProblem("__text lies outside its __TEXT segment", 0));
            }

            if (segmentFileSize > MaxTextSegment)
            {
                return (null, new CoverageProblem(
                    "__TEXT of " + segmentFileSize.ToString(CultureInfo.InvariantCulture) + " bytes is over the 64 MiB budget",
                    size <= 1UL << 40 ? (long)size : 0));
            }

            return (new TextSpan(
                (long)Math.Min(segmentFileOffset, long.MaxValue),
                (long)segmentFileSize,
                segmentVMAddress,
                (long)(text.Offset - segmentFileOffset),
                (long)size), null);
        }

        /// <summary>
        /// Whether an image's encryption keeps its __text from being compared, or
        /// null. The App Store encrypts an app's code on disk
        /// (LC_ENCRYPTION_INFO_64, <c>cryptid</c> 1) and iOS decrypts it as it maps
        /// it, so a genuine image's file and memory differ in every encrypted byte.
        /// An encrypted range that overlaps __text makes the image one that cannot
        /// be compared: skipped, with its __text bytes -- never compared, never
        /// clean. Offsets are the file's, as <paramref name="span"/>'s are;
        /// <c>cryptid</c> 0 is an image stored in the clear (collector 7).
        /// </summary>
        public static CoverageProblem? EncryptionProblem(uint cryptOffset, uint cryptSize, uint cryptId, TextSpan span)
        {
            if (cryptId == 0 || cryptSize == 0)
            {
                return null;
            }

            var textStart = (ulong)span.SegmentFileOffset + (ulong)span.TextOffsetInSegment;
            var textEnd = textStart + (ulong)span.TextSize;
            var cryptStart = (ulong)cryptOffset;
            var cryptEnd = cryptStart + cryptSize;
            if (cryptStart >= textEnd || textStart >= cryptEnd)
            {
                return null;
            }

            return new CoverageProblem("encrypted on disk (App Store): its code cannot be compared with its file", span.TextSize);
        }

        /// <summary>
        /// Where the arm64 image starts in its file: 0 when the file is a 64-bit
        /// Mach-O image; the arm64 slice's offset in a universal ("fat") file, the
        /// form a build keeps its frameworks in when nothing thinned them (an ad
        /// hoc or enterprise install, say); null when it is neither. The image's own
        /// offsets count from there, never from the file's start (collector 8).
        /// </summary>
        public static long? Arm64Slice(IReadOnlyList<byte> head)
        {
            long? Big(int at) => at + 4 <= head.Count
                ? ((long)head[at] << 24) | ((long)head[at + 1] << 16) | ((long)head[at + 2] << 8) | head[at + 3]
                : null;
            if (head.Count < 8)
            {
                return null;
            }

            var little = (long)head[0] | ((long)head[1] << 8) | ((long)head[2] << 16) | ((long)head[3] << 24);
            if (little == 0xfeedfacf)
            {
                return 0;
            }

            if (Big(0) != 0xcafebabe || Big(4) is not { } count || count >= 64)
            {
                return null;
            }

            for (var index = 0; index < count; index++)
            {
                if (Big(8 + (index * 20)) is not { } cpu || Big(8 + (index * 20) + 8) is not { } offset)
                {
                    return null;
                }

                if (cpu == 0x0100000c)
                {
                    return offset; // CPU_TYPE_ARM64
                }
            }

            return null;
        }

        /// <summary>
        /// The LC_UUID of a 64-bit Mach-O image, from its header and load commands
        /// as read from its file, or null when they hold none or cannot be walked.
        /// </summary>
        public static byte[]? MachOUuid(IReadOnlyList<byte> bytes)
        {
            long Word(int at) => (long)bytes[at] | ((long)bytes[at + 1] << 8) | ((long)bytes[at + 2] << 16) | ((long)bytes[at + 3] << 24);
            if (bytes.Count < 32 || Word(0) != 0xfeedfacf)
            {
                return null;
            }

            long offset = 32;
            var commands = Word(16);
            for (long index = 0; index < commands; index++)
            {
                if (offset + 8 > bytes.Count)
                {
                    return null;
                }

                var command = Word((int)offset);
                var size = Word((int)offset + 4);
                if (size < 8 || offset + size > bytes.Count)
                {
                    return null;
                }

                if (command == 0x1b)
                {
                    // LC_UUID
                    return size >= 24 ? bytes.Skip((int)offset + 8).Take(16).ToArray() : null;
                }

                offset += size;
            }

            return null;
        }

        /// <summary>
        /// Whether the file on disk is the build that was loaded: its LC_UUID
        /// against the loaded image's. An app updated while it ran -- TrollStore
        /// installs over a running app, an in-place update, a development install
        /// -- runs the old code with the new file on disk, and the two then differ
        /// in many bytes nobody changed: such an image is skipped with its __text
        /// bytes, never compared. Null when they match, or the loaded image has no
        /// LC_UUID to tell by (collector 8).
        /// </summary>
        public static CoverageProblem? BuildProblem(byte[]? loaded, byte[]? onDisk, long textSize)
        {
            if (loaded is null || (onDisk is not null && loaded.AsSpan().SequenceEqual(onDisk)))
            {
                return null;
            }

            return new CoverageProblem(
                "another build on disk than the one running (LC_UUID differs): the app was updated while it ran",
                textSize);
        }

        /// <summary>
        /// An image dyld counts but gives no name or header for (it is being
        /// unloaded as the list is walked): never dropped unsaid. It may be the
        /// app's, so it is an app image that could not be read, with no bytes.
        /// </summary>
        public static AppImage UnlistedImage(int index) =>
            new AppImage("image " + index.ToString(CultureInfo.InvariantCulture), false, ImageOutcome.Unreadable(0, "dyld gave no name or header for it"));

        /// <summary>The images whose names dyld did not give, as <c>unread</c> says it: never a shorter list read as all of them.</summary>
        public static IReadOnlyDictionary<string, string> UnnamedImages(int missing, int total) =>
            missing > 0
                ? new Dictionary<string, string>
                {
                    ["image_names"] = missing.ToString(CultureInfo.InvariantCulture) + " of " + total.ToString(CultureInfo.InvariantCulture) + " could not be read",
                }
                : new Dictionary<string, string>();

        /// <summary>Why a read of <paramref name="wanted"/> bytes is not the whole of them, or null: a short read is unreadable, never a comparison of part.</summary>
        public static string? ReadProblem(long got, long wanted) =>
            got == wanted
                ? null
                : "unreadable: " + got.ToString(CultureInfo.InvariantCulture) + " of " + wanted.ToString(CultureInfo.InvariantCulture) + " bytes read";

        /// <summary>An image's path in the bundle, as the report names it: at most 128 characters, its end kept; "(bundle)" for the bundle itself.</summary>
        public static string BundleLabel(string imagePath, string bundlePath)
        {
            var rest = imagePath.Length >= bundlePath.Length ? imagePath.Substring(bundlePath.Length) : string.Empty;
            var inBundle = rest.TrimStart('/');
            return inBundle.Length == 0 ? "(bundle)" : inBundle.Length <= 128 ? inBundle : inBundle.Substring(inBundle.Length - 128);
        }

        /// <summary>
        /// The app bucket's figures from every bundle image's outcome: every image
        /// expected, and each compared, unreadable or skipped, with its __text
        /// bytes; each one not compared named with why; complete only when every
        /// image was compared -- the images decide, since one whose size could not
        /// be read adds no bytes. <c>checked</c> means the app bucket was genuinely
        /// compared: not one image, nothing measured.
        /// </summary>
        public static JsonObject AppCoverage(IReadOnlyList<AppImage> images, int systemImagesUnreadable)
        {
            int compared = 0, unreadable = 0, skipped = 0;
            long expectedBytes = 0, comparedBytes = 0, unreadableBytes = 0, skippedBytes = 0;
            long differing = 0, segmentCompared = 0, segmentDiffering = 0;
            var imagesDiffering = 0;
            var diffed = new List<string>();
            var notCompared = new JsonObject();
            var mainCompared = false;

            void Name(AppImage image, string why)
            {
                if (notCompared.Count < MaxNamedImages)
                {
                    notCompared[image.Path] = why.Length <= 160 ? why : why.Substring(0, 160);
                }
            }

            foreach (var image in images)
            {
                var outcome = image.Outcome;
                switch (outcome.Kind)
                {
                    case ImageOutcomeKind.Compared:
                        compared++;
                        expectedBytes += outcome.TextBytes;
                        comparedBytes += outcome.TextBytes;
                        segmentCompared += outcome.SegmentBytes;
                        segmentDiffering += outcome.SegmentDiffering;
                        if (image.IsMainExecutable)
                        {
                            mainCompared = true;
                        }

                        if (outcome.TextDiffering > 0)
                        {
                            differing += outcome.TextDiffering;
                            imagesDiffering++;
                            var parts = image.Path.Split('/', StringSplitOptions.RemoveEmptyEntries);
                            diffed.Add(parts.Length > 0 ? parts[^1] : image.Path);
                        }

                        break;
                    case ImageOutcomeKind.Unreadable:
                        unreadable++;
                        expectedBytes += outcome.TextBytes;
                        unreadableBytes += outcome.TextBytes;
                        Name(image, outcome.Why);
                        break;
                    default:
                        skipped++;
                        expectedBytes += outcome.TextBytes;
                        skippedBytes += outcome.TextBytes;
                        Name(image, outcome.Why);
                        break;
                }
            }

            var result = new JsonObject
            {
                ["checked"] = compared > 0,
                ["app_compared_bytes"] = comparedBytes,
                ["app_diff_bytes"] = differing,
                ["app_libs_diff"] = imagesDiffering,
                ["app_images_compared"] = compared,
                ["system_images_unreadable"] = systemImagesUnreadable,
                ["app_images_expected"] = images.Count,
                ["app_images_unreadable"] = unreadable,
                ["app_images_skipped"] = skipped,
                ["app_expected_bytes"] = expectedBytes,
                ["app_unreadable_bytes"] = unreadableBytes,
                ["app_skipped_bytes"] = skippedBytes,
                ["app_complete"] = images.Count > 0 && compared == images.Count,
                ["main_executable_compared"] = mainCompared,

                // Telemetry only: the rest of __TEXT, which has no clean baseline.
                ["app_segment_compared_bytes"] = segmentCompared,
                ["app_segment_diff_bytes"] = segmentDiffering,
                ["diffed_libs"] = string.Join(",", diffed),
            };
            if (notCompared.Count > 0)
            {
                result["app_images_not_compared"] = notCompared;
            }

            return result;
        }

        /// <summary>One location read: the permission, the fix the phone already held -- none without the permission -- and its age when read.</summary>
        public static LocationRead Read(string permission, Fix? fix, DateTimeOffset now)
        {
            var held = permission == "none" ? null : fix;
            var age = held is null ? 0L : Math.Max(0L, (long)(now - held.Timestamp).TotalSeconds);
            return new LocationRead(permission, held, age);
        }

        /// <summary>The last known location: the coordinates of the read's fix.</summary>
        public static JsonObject Location(LocationRead read)
        {
            var result = new JsonObject { ["status"] = "ok", ["permission"] = read.Permission };
            if (read.Fix is not Fix fix)
            {
                return result;
            }

            result["latitude"] = fix.Latitude;
            result["longitude"] = fix.Longitude;
            if (fix.HorizontalAccuracy >= 0)
            {
                result["accuracy_m"] = fix.HorizontalAccuracy;
            }

            result["age_seconds"] = read.AgeSeconds;
            result["fix_time"] = UnixSeconds(fix.Timestamp);
            return result;
        }

        /// <summary>
        /// Whether the read's fix was simulated by software or produced by an
        /// accessory: never its coordinates. Before iOS 15 the fix cannot say.
        /// </summary>
        public static JsonObject MockLocation(LocationRead read)
        {
            var result = new JsonObject { ["status"] = "ok", ["permission"] = read.Permission };
            if (read.Fix is not Fix fix)
            {
                return result;
            }

            if (fix.SimulatedBySoftware is bool simulated)
            {
                result["mock"] = simulated;
            }

            if (fix.ProducedByAccessory is bool accessory)
            {
                result["accessory"] = accessory;
            }

            result["age_seconds"] = read.AgeSeconds;
            result["fix_time"] = UnixSeconds(fix.Timestamp);
            return result;
        }

        /// <summary>
        /// Screen capture: <c>recording</c> when a screen showing the app's window
        /// could be asked. With none -- the app in the background, or before its
        /// first window -- recording is not measured, never "no", and
        /// <c>recording_status</c> says why: <c>unavailable</c>. The other screens
        /// attached are counted either way.
        /// </summary>
        public static JsonObject ScreenCapture(bool? captured, int otherScreens)
        {
            var result = new JsonObject { ["status"] = "ok", ["external_displays"] = Math.Max(0, otherScreens) };
            if (captured is bool recording)
            {
                result["recording"] = recording;
            }
            else
            {
                result["recording_status"] = "unavailable";
            }

            return result;
        }

        private static long UnixSeconds(DateTimeOffset time) =>
            (long)Math.Truncate((time - DateTimeOffset.UnixEpoch).TotalSeconds);

        /// <summary>Where an image's __text lies, as its load commands state it.</summary>
        internal sealed record TextSpan(
            long SegmentFileOffset,
            long SegmentSize,
            ulong SegmentVMAddress,
            long TextOffsetInSegment,
            long TextSize);

        /// <summary>Why one app image's __text was not compared, and how many __text bytes that leaves out: 0 when its size could not be read.</summary>
        internal sealed record CoverageProblem(string Reason, long TextSize);

        internal enum ImageOutcomeKind
        {
            Compared,
            Unreadable,
            Skipped,
        }

        /// <summary>How one app image's comparison ended.</summary>
        internal sealed record ImageOutcome(
            ImageOutcomeKind Kind,
            long TextBytes,
            long TextDiffering,
            long SegmentBytes,
            long SegmentDiffering,
            string Why)
        {
            /// <summary>Compared: its __text bytes and how many differ, and the same for the whole __TEXT segment (telemetry).</summary>
            public static ImageOutcome Compared(long textBytes, long textDiffering, long segmentBytes, long segmentDiffering) =>
                new ImageOutcome(ImageOutcomeKind.Compared, textBytes, textDiffering, segmentBytes, segmentDiffering, string.Empty);

            /// <summary>Its file could not be read in full.</summary>
            public static ImageOutcome Unreadable(long textBytes, string why) =>
                new ImageOutcome(ImageOutcomeKind.Unreadable, textBytes, 0, 0, 0, why);

            /// <summary>Not compared: no usable __text, a __TEXT over the budget, no live address. Its __text bytes when known, else 0.</summary>
            public static ImageOutcome Skipped(long textBytes, string why) =>
                new ImageOutcome(ImageOutcomeKind.Skipped, textBytes, 0, 0, 0, why);
        }

        /// <summary>One image the loader mapped from the app's bundle.</summary>
        internal sealed record AppImage(string Path, bool IsMainExecutable, ImageOutcome Outcome);

        /// <summary>One fix as the collector captured it from Core Location.</summary>
        internal sealed record Fix(
            double Latitude,
            double Longitude,
            double HorizontalAccuracy,
            DateTimeOffset Timestamp,
            bool? SimulatedBySoftware,
            bool? ProducedByAccessory);

        /// <summary>One location read.</summary>
        internal sealed record LocationRead(string Permission, Fix? Fix, long AgeSeconds);

        /// <summary>
        /// The collection's one location read: made on first use and never
        /// again, so the coordinates and the mock flag describe one fix. Each
        /// collection makes its own.
        /// </summary>
        internal sealed class LocationCapture
        {
            private readonly Func<LocationRead> read;
            private LocationRead? made;

            public LocationCapture(Func<LocationRead> read)
            {
                this.read = read;
            }

            public LocationRead Value => made ??= read();
        }
    }
}
