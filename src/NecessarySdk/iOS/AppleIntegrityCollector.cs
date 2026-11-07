using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using CoreLocation;
using Foundation;
using UIKit;
using static Necessary.IosProbeReads;

namespace Necessary
{
    /// <summary>
    /// The iOS integrity collector, version 6: measures what the challenge asks
    /// for and the app enabled, and nothing else. The plugin's
    /// <c>IntegrityProbeManager.swift</c>, translated; what the reads mean is in
    /// <see cref="IosProbeReads"/> and <see cref="MachOSigning"/>, which need no
    /// Apple framework and are tested anywhere.
    /// </summary>
    /// <remarks>
    /// These are evidence, not remote attestation: on a jailbroken phone an
    /// attacker may lie about local state, so your backend weighs them with what
    /// it observes itself, and never takes a score from the phone.
    /// </remarks>
    public sealed partial class AppleIntegrityCollector : INativeIntegrityCollector
    {
        // 1 was the baseline probe set; 2 adds code_integrity; 3 volunteers
        // device and network and answers the optional measurements; 4 adds
        // screen capture, location and mock locations, and the OS build; 5
        // reports the app's code coverage image by image, and one location read
        // answers both location measurements; 6 sends the page size with device,
        // and asks screen capture of the screen showing the app; 9 adds the
        // runtime measurement, volunteered on every scan.
        private const int CollectorVersion = 9;
        private const int MaxTextLength = 8192;

        private static readonly string[] VolunteeredProbes = { "device", "network", "runtime" };

        private static readonly HashSet<string> OptionalMeasurements = new HashSet<string>(StringComparer.Ordinal)
        {
            "local_addresses", "accessibility", "notification_access", "other_access",
            "screen_capture", "location", "mock_location",
        };

        // Loaded-image names that indicate instrumentation or a hooking runtime:
        // the counterpart of the maps token scan, with the same weakness -- a
        // renamed library evades it; code_integrity is the structural answer.
        private static readonly string[] SuspiciousImageTokens =
        {
            "frida", "gadget", "objection", "cynject", "cycript",
            "substrate", "mobilesubstrate", "substitute", "libhooker",
            "ellekit", "cydia", "shadow", "flex", "libsparkapplist",
        };

        // Classic jailbreak filesystem artifacts, rootless (/var/jb) layouts too.
        private static readonly string[] JailbreakPaths =
        {
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries",
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/usr/libexec/ssh-keysign",
            "/bin/bash",
            "/bin/sh",
            "/etc/apt",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/stash",
            "/usr/libexec/ellekit",
            "/var/jb",
            "/var/jb/usr/lib/TweakInject",
            "/.bootstrapped_electra",
            "/taurine",
            "/.installed_unc0ver",
        };

        private CLLocationManager? permissionManager;
        private TaskCompletionSource<string>? pendingLocation;

        /// <inheritdoc />
        public Task<JsonObject> CollectAsync(
            IReadOnlyList<string> requiredProbes,
            string challengeNonce,
            IReadOnlyList<string> enabledMeasurements,
            IReadOnlyList<string> optionalProbes)
        {
            if (requiredProbes is null || challengeNonce is null)
            {
                return Task.FromException<JsonObject>(new NativeKeyException(
                    "INVALID_ARGUMENT",
                    "challenge_nonce must be a string and required_probes a list of strings."));
            }

            var optional = optionalProbes ?? Array.Empty<string>();
            var enabled = new HashSet<string>(enabledMeasurements ?? Array.Empty<string>(), StringComparer.Ordinal);
            return AppleNative.Run(() => Collect(requiredProbes, challengeNonce, optional, enabled));
        }

        /// <inheritdoc />
        public Task<string> RequestLocationPermissionAsync() => NecessaryApple.OnMainThread(() =>
        {
            var manager = permissionManager ??= new CLLocationManager();
            var state = LocationState(manager);
            if (state != "undetermined" || pendingLocation is not null)
            {
                return Task.FromResult(state == "undetermined" ? "none" : state);
            }

            var pending = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            pendingLocation = pending;
            manager.Delegate = new PermissionDelegate(this);
            manager.RequestWhenInUseAuthorization();
            return pending.Task;
        }).Unwrap();

        private static string LocationState(CLLocationManager manager) => manager.AuthorizationStatus switch
        {
            CLAuthorizationStatus.AuthorizedWhenInUse or CLAuthorizationStatus.AuthorizedAlways =>
                manager.AccuracyAuthorization == CLAccuracyAuthorization.ReducedAccuracy ? "approximate" : "precise",
            CLAuthorizationStatus.NotDetermined => "undetermined",
            _ => "none",
        };

        private JsonObject Collect(
            IReadOnlyList<string> requiredProbes,
            string challengeNonce,
            IReadOnlyList<string> optionalProbes,
            HashSet<string> enabledMeasurements)
        {
            var probes = new JsonObject();

            // One location read per collection, made only if an enabled location
            // measurement asks: both answer from it.
            var location = new LocationCapture(LastLocation);
            foreach (var probe in requiredProbes.Distinct())
            {
                probes[probe] = RunProbe(probe, enabledMeasurements, location);
            }

            // code_integrity is reported whether or not the backend asked for it.
            if (!probes.ContainsKey("code_integrity"))
            {
                probes["code_integrity"] = RunProbe("code_integrity", new HashSet<string>(), location);
            }

            foreach (var probe in VolunteeredProbes)
            {
                if (!probes.ContainsKey(probe))
                {
                    probes[probe] = RunProbe(probe, enabledMeasurements, location);
                }
            }

            foreach (var probe in optionalProbes)
            {
                if (!probes.ContainsKey(probe) && OptionalMeasurements.Contains(probe))
                {
                    probes[probe] = RunProbe(probe, enabledMeasurements, location);
                }
            }

            return new JsonObject
            {
                ["collector_version"] = CollectorVersion,
                ["platform"] = "ios",
                ["challenge_nonce_echo"] = challengeNonce,
                ["os_version"] = OsVersion(),
                ["probes"] = probes,
            };
        }

        private JsonObject RunProbe(string name, HashSet<string> enabled, LocationCapture location) => name switch
        {
            "app_identity" => ProbeAppIdentity(),
            "code_signing" => ProbeCodeSigning(),
            "debugger" => ProbeDebugger(),
            "jailbreak_files" => ProbeJailbreakFiles(),
            "sandbox" => ProbeSandbox(),
            "dyld_images" => ProbeDyldImages(),
            "environment" => ProbeEnvironment(),
            "simulator" => ProbeSimulator(),
            "code_integrity" => ProbeCodeIntegrity(),
            "device" => ProbeDevice(),
            "network" => ProbeNetwork(),
            "runtime" => ProbeRuntime(),

            // Asked for by the backend, declined by this app.
            "local_addresses" => enabled.Contains(name) ? ProbeLocalAddresses() : NotEnabled(),

            // iOS shows an app no other app: nothing to list.
            "accessibility" or "notification_access" or "other_access" => enabled.Contains(name)
                ? new JsonObject { ["status"] = "unsupported", ["reason"] = "iOS shows an app no other app." }
                : NotEnabled(),
            "screen_capture" => enabled.Contains(name) ? ProbeScreenCapture() : NotEnabled(),
            "location" => enabled.Contains(name) ? Location(location.Value) : NotEnabled(),
            "mock_location" => enabled.Contains(name) ? MockLocation(location.Value) : NotEnabled(),
            _ => new JsonObject { ["status"] = "unsupported", ["reason"] = "Unknown probe requested by server" },
        };

        private static JsonObject NotEnabled() => new JsonObject { ["status"] = "not_enabled" };

        /// <summary>The OS version and build, the hardware model, and the memory page size.</summary>
        private static JsonObject ProbeDevice() => new JsonObject
        {
            ["status"] = "ok",
            ["os_version"] = OsVersion(),
            ["os_build"] = OsBuild(),
            ["model_identifier"] = ModelIdentifier(),
            ["page_size"] = Native.getpagesize(),
        };

        /// <summary>
        /// Whether the screen showing the app is being recorded, mirrored or sent
        /// to AirPlay, asked of the screen of each window scene in the
        /// foreground, and how many other screens are attached.
        /// </summary>
        private static JsonObject ProbeScreenCapture() => NecessaryApple.OnMainThread(() =>
        {
            var shown = UIApplication.SharedApplication.ConnectedScenes.ToArray()
                .OfType<UIWindowScene>()
                .Where(scene => scene.ActivationState == UISceneActivationState.ForegroundActive
                    || scene.ActivationState == UISceneActivationState.ForegroundInactive)
                .ToList();
            return ScreenCapture(
                shown.Count == 0 ? null : shown.Any(AppleScreenProtection.IsCaptured),
                UIScreen.Screens.Length - 1);
        }).GetAwaiter().GetResult();

        /// <summary>
        /// The collection's one location read: the last location the phone
        /// already holds -- never a fresh fix, never a prompt.
        /// </summary>
        private static LocationRead LastLocation() => NecessaryApple.OnMainThread(() =>
        {
            using var manager = new CLLocationManager();
            var state = LocationState(manager);
            var permission = state == "precise" || state == "approximate" ? state : "none";
            var held = permission == "none" ? null : manager.Location;
            return Read(permission, held is null ? null : FixOf(held), DateTimeOffset.UtcNow);
        }).GetAwaiter().GetResult();

        /// <summary>iOS 15 and later say whether a location was simulated by software or produced by an accessory.</summary>
        private static Fix FixOf(CLLocation location)
        {
            bool? simulated = null;
            bool? accessory = null;
            var source = location.SourceInformation;
            if (source is not null)
            {
                simulated = source.IsSimulatedBySoftware;
                accessory = source.IsProducedByAccessory;
            }

            return new Fix(
                location.Coordinate.Latitude,
                location.Coordinate.Longitude,
                location.HorizontalAccuracy,
                DateTimeOffset.FromUnixTimeMilliseconds((long)(location.Timestamp.SecondsSince1970 * 1000)),
                simulated,
                accessory);
        }

        private static string OsVersion()
        {
            var version = NSProcessInfo.ProcessInfo.OperatingSystemVersion;
            return version.Major + "." + version.Minor + "." + version.PatchVersion;
        }

        /// <summary>The OS build, for example "21F90" (kern.osversion).</summary>
        private static string OsBuild()
        {
            var size = IntPtr.Zero;
            if (Native.sysctlbyname("kern.osversion", IntPtr.Zero, ref size, IntPtr.Zero, IntPtr.Zero) != 0 || size == IntPtr.Zero)
            {
                return string.Empty;
            }

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (Native.sysctlbyname("kern.osversion", buffer, ref size, IntPtr.Zero, IntPtr.Zero) != 0)
                {
                    return string.Empty;
                }

                return Marshal.PtrToStringUTF8(buffer) ?? string.Empty;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>The hardware model, uname's machine: "iPhone9,3", say.</summary>
        private static string ModelIdentifier()
        {
            // struct utsname: five fields of 256 bytes; machine is the fifth.
            var buffer = Marshal.AllocHGlobal(5 * 256);
            try
            {
                if (Native.uname(buffer) != 0)
                {
                    return string.Empty;
                }

                return Marshal.PtrToStringUTF8(buffer + (4 * 256)) ?? string.Empty;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint DecoderVersionFunction();

        private sealed class PermissionDelegate : CLLocationManagerDelegate
        {
            private readonly AppleIntegrityCollector owner;

            public PermissionDelegate(AppleIntegrityCollector owner)
            {
                this.owner = owner;
            }

            public override void DidChangeAuthorization(CLLocationManager manager)
            {
                var state = LocationState(manager);
                var pending = owner.pendingLocation;
                if (state == "undetermined" || pending is null)
                {
                    return;
                }

                owner.pendingLocation = null;
                pending.TrySetResult(state);
            }
        }

        private static class Native
        {
            private const string LibSystem = "/usr/lib/libSystem.dylib";

            /// <summary>RTLD_DEFAULT: every image the process has loaded.</summary>
            public static readonly IntPtr DefaultSearch = new IntPtr(-2);

            [DllImport(LibSystem)]
            public static extern IntPtr dlsym(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string symbol);

            [DllImport(LibSystem)]
            public static extern int getpagesize();

            [DllImport(LibSystem, SetLastError = true)]
            public static extern int sysctl(int[] name, uint nameLength, IntPtr oldp, ref IntPtr oldlenp, IntPtr newp, IntPtr newlen);

            [DllImport(LibSystem, SetLastError = true)]
            public static extern int sysctlbyname([MarshalAs(UnmanagedType.LPUTF8Str)] string name, IntPtr oldp, ref IntPtr oldlenp, IntPtr newp, IntPtr newlen);

            [DllImport(LibSystem)]
            public static extern int uname(IntPtr buffer);

            [DllImport(LibSystem)]
            public static extern uint _dyld_image_count();

            [DllImport(LibSystem)]
            public static extern IntPtr _dyld_get_image_name(uint index);

            [DllImport(LibSystem)]
            public static extern IntPtr _dyld_get_image_header(uint index);

            [DllImport(LibSystem)]
            public static extern IntPtr _dyld_get_image_vmaddr_slide(uint index);

            [DllImport(LibSystem)]
            public static extern int getifaddrs(out IntPtr head);

            [DllImport(LibSystem)]
            public static extern void freeifaddrs(IntPtr head);

            [DllImport(LibSystem)]
            public static extern int getnameinfo(IntPtr address, uint addressLength, byte[] host, uint hostLength, IntPtr service, uint serviceLength, int flags);
        }
    }
}
