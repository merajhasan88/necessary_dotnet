using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using Android.AccessibilityServices;
using Android.App.Admin;
using Android.Content;
using Android.Content.PM;
using Android.Hardware.Display;
using Android.Locations;
using Android.Net;
using Android.OS;
using Android.Provider;
using Android.Views;
using Android.Views.Accessibility;
using Java.Net;
using static Necessary.AndroidProbeReads;

namespace Necessary
{
    public sealed partial class AndroidIntegrityCollector
    {
        /// <summary>The OS and the hardware model, and how current the security patches are.</summary>
        private static JsonObject ProbeDevice() => Ok(
            ("release", Build.VERSION.Release ?? string.Empty),
            ("sdk_int", (int)Build.VERSION.SdkInt),
            ("security_patch", Build.VERSION.SecurityPatch ?? string.Empty),
            ("manufacturer", Build.Manufacturer ?? string.Empty),
            ("brand", Build.Brand ?? string.Empty),
            ("model", Build.Model ?? string.Empty),
            ("device", Build.Device ?? string.Empty),
            ("build_id", Build.Id ?? string.Empty),
            ("fingerprint", Take(Build.Fingerprint ?? string.Empty, 256)),

            // The ABI this process runs as: a 32-bit app on a 64-bit phone maps
            // different code, so a runtime baseline is per ABI.
            ("abi", ProcessAbi()),

            // The memory page size: 4 KiB, or 16 KiB on phones built for it from
            // Android 15 -- a runtime baseline is per page size too.
            ("page_size", (int)Android.Systems.Os.Sysconf(Android.Systems.OsConstants.ScPagesize)));

        private static string ProcessAbi()
        {
            var abis = Android.OS.Process.Is64Bit() ? Build.Supported64BitAbis : Build.Supported32BitAbis;
            return abis?.FirstOrDefault() ?? string.Empty;
        }

        /// <summary>
        /// Whether a VPN is up and an HTTP proxy is set, as the system's own
        /// connectivity service says. A VPN is a network of its own, so every
        /// network is asked, not only the default one. Interface names only --
        /// never an address.
        /// </summary>
        private JsonObject ProbeNetwork()
        {
            if (context.GetSystemService(Context.ConnectivityService) is not ConnectivityManager manager)
            {
                return Unavailable("ConnectivityManager is not available");
            }

            var transports = new List<string>();
            var active = manager.ActiveNetwork;
            var capabilities = active is null ? null : manager.GetNetworkCapabilities(active);
            if (capabilities is not null)
            {
                if (capabilities.HasTransport(TransportType.Wifi))
                {
                    transports.Add("wifi");
                }

                if (capabilities.HasTransport(TransportType.Cellular))
                {
                    transports.Add("cellular");
                }

                if (capabilities.HasTransport(TransportType.Ethernet))
                {
                    transports.Add("ethernet");
                }

                if (capabilities.HasTransport(TransportType.Vpn))
                {
                    transports.Add("vpn");
                }
            }

#pragma warning disable CA1422 // Every network, the VPN's among them: the only list there is.
            var vpn = (manager.GetAllNetworks() ?? Array.Empty<Network>())
                .Any(network => manager.GetNetworkCapabilities(network)?.HasTransport(TransportType.Vpn) == true);
#pragma warning restore CA1422
            var proxy = manager.DefaultProxy is not null
                || !string.IsNullOrWhiteSpace(Java.Lang.JavaSystem.GetProperty("http.proxyHost"));
            // Names are context; the two answers above stand without them. A
            // listing that failed, whole or for one interface, is in unread: an
            // empty or short list would read as "no such interface".
            var interfaces = new List<string>();
            string? interfacesUnread = null;
            try
            {
                var all = NetworkInterface.NetworkInterfaces;
                while (all is not null && all.HasMoreElements)
                {
                    try
                    {
                        if (all.NextElement() is NetworkInterface item && item.IsUp && !item.IsLoopback)
                        {
                            interfaces.Add(Take(item.Name ?? string.Empty, 32));
                        }
                    }
#pragma warning disable CA1031 // One interface that could not be read: said in unread.
                    catch (Exception error)
#pragma warning restore CA1031
                    {
                        interfacesUnread ??= Why(error);
                    }
                }
            }
#pragma warning disable CA1031 // The listing that failed: said in unread.
            catch (Exception error)
#pragma warning restore CA1031
            {
                interfacesUnread = Why(error);
            }

            var result = Ok(
                ("vpn_active", vpn),
                ("http_proxy_configured", proxy),
                ("transports", transports),
                ("interfaces", interfaces.Distinct().Take(32).ToList()));
            if (interfacesUnread is not null)
            {
                result["unread"] = new JsonObject { ["interfaces"] = interfacesUnread };
            }

            return result;
        }

        /// <summary>
        /// The phone's own IP addresses, per interface -- an optional measurement.
        /// Link-local addresses are left out: they can carry the hardware address,
        /// which the platforms deliberately hide.
        /// </summary>
        private static JsonObject ProbeLocalAddresses()
        {
            var all = NetworkInterface.NetworkInterfaces;
            if (all is null)
            {
                return Unavailable("no network interface could be listed");
            }

            var addresses = new JsonArray();

            // More than a list holds is said, never cut off unsaid.
            var truncated = false;
            while (all.HasMoreElements)
            {
                if (all.NextElement() is not NetworkInterface item || !item.IsUp || item.IsLoopback)
                {
                    continue;
                }

                var inet = item.InetAddresses;
                while (inet is not null && inet.HasMoreElements)
                {
                    if (inet.NextElement() is not InetAddress address || address.IsLoopbackAddress || address.IsLinkLocalAddress)
                    {
                        continue;
                    }

                    if (addresses.Count >= 32)
                    {
                        truncated = true;
                        break;
                    }

                    var host = address.HostAddress ?? string.Empty;
                    var percent = host.IndexOf('%', StringComparison.Ordinal);
                    addresses.Add(new JsonObject
                    {
                        ["interface"] = Take(item.Name ?? string.Empty, 32),
                        ["address"] = Take(percent < 0 ? host : host.Substring(0, percent), 64),
                    });
                }
            }

            return Ok(("addresses", addresses), ("truncated", truncated));
        }

        /// <summary>
        /// One app holding a capability: its package and component class, whether
        /// it is part of the system, and which package installed it ("" for none
        /// -- adb, or an installer that names nobody). system and installer are
        /// left out where Android hides the app from this one; a backend then calls
        /// its source unknown, which is never evidence.
        /// </summary>
        private JsonObject AppEntry(string packageName, string? component = null, ApplicationInfo? knownInfo = null)
        {
            var entry = new JsonObject { ["package"] = Take(packageName, 128) };
            if (component is not null)
            {
                entry["service"] = Take(component, 200);
            }

            var pm = context.PackageManager!;
            var info = knownInfo;
            if (info is null)
            {
                try
                {
                    info = ApplicationInfoOf(pm, packageName);
                }
#pragma warning disable CA1031 // Hidden from this app: system and installer are left out.
                catch (Exception)
                {
                    info = null;
                }
            }

            string? installer;
            try
            {
                installer = InstallerOf(pm, packageName) ?? string.Empty;
            }
            catch (Exception)
            {
                installer = null;
            }
#pragma warning restore CA1031

            if (info is not null)
            {
                entry["system"] = (info.Flags & ApplicationInfoFlags.System) != 0;
                if (installer is not null)
                {
                    entry["installer"] = Take(installer, 128);
                }
            }

            return entry;
        }

        private static ApplicationInfo? ApplicationInfoOf(PackageManager pm, string packageName)
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(33))
            {
                return pm.GetApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.Of(0));
            }

#pragma warning disable CA1422 // The only call there is below Android 13.
            return pm.GetApplicationInfo(packageName, 0);
#pragma warning restore CA1422
        }

        private static string? InstallerOf(PackageManager pm, string packageName)
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                return pm.GetInstallSourceInfo(packageName).InstallingPackageName;
            }

#pragma warning disable CA1422 // The only call there is below Android 11.
            return pm.GetInstallerPackageName(packageName);
#pragma warning restore CA1422
        }

        /// <summary>
        /// Every Accessibility service that is on, and the keyboard in use -- the
        /// two ways banking trojans read what is typed. The Accessibility manager's
        /// list is compared with the system setting it is built from: a service
        /// the setting names that the manager does not report is hiding, as an
        /// Android bug allowed until the December 2022 patch.
        /// </summary>
        private JsonObject ProbeAccessibility()
        {
            if (context.GetSystemService(Context.AccessibilityService) is not AccessibilityManager manager)
            {
                return Unavailable("AccessibilityManager is not available");
            }

            var services = new JsonArray();
            var reported = new HashSet<string>(StringComparer.Ordinal);
            var undescribed = 0;
            foreach (var info in manager.GetEnabledAccessibilityServiceList(Android.AccessibilityServices.FeedbackFlags.AllMask) ?? new List<AccessibilityServiceInfo>())
            {
                var service = info.ResolveInfo?.ServiceInfo;
                if (service?.PackageName is not string package || service.Name is not string name)
                {
                    // The manager reports it, but not its app: counted as unread,
                    // and never read as a service hiding from the manager.
                    if (info.Id is string id && ComponentName.UnflattenFromString(id.Trim())?.FlattenToString() is string listed)
                    {
                        reported.Add(listed);
                    }

                    undescribed++;
                    continue;
                }

                if (!reported.Add(new ComponentName(package, name).FlattenToString()))
                {
                    continue;
                }

                if (services.Count < MaxApps)
                {
                    services.Add(AppEntry(package, name, service.ApplicationInfo));
                }
            }

            var hidden = (Settings.Secure.GetString(context.ContentResolver, Settings.Secure.EnabledAccessibilityServices) ?? string.Empty)
                .Split(':')
                .Select(item => ComponentName.UnflattenFromString(item.Trim())?.FlattenToString())
                .Where(item => item is not null && !reported.Contains(item))
                .Select(item => item!)
                .Distinct()
                .ToList();
            var settingsOnly = new JsonArray();
            foreach (var item in hidden.Take(MaxApps))
            {
                settingsOnly.Add(Take(item, 200));
            }

            var result = new JsonObject
            {
                ["status"] = "ok",
                ["services"] = services,
                ["settings_only"] = settingsOnly,

                // More than this collector sends: the backend is told, never left to guess.
                ["truncated"] = reported.Count > MaxApps || hidden.Count > MaxApps,
            };
            var keyboard = Settings.Secure.GetString(context.ContentResolver, Settings.Secure.DefaultInputMethod);
            var component = keyboard is null ? null : ComponentName.UnflattenFromString(keyboard.Trim());
            if (component?.PackageName is string keyboardPackage)
            {
                result["keyboard"] = AppEntry(keyboardPackage, component.ClassName);
            }

            if (undescribed > 0)
            {
                result["unread"] = new JsonObject { ["services"] = undescribed + " enabled services the system did not describe" };
            }

            return result;
        }

        /// <summary>Every app allowed to read the phone's notifications -- one-time codes among them.</summary>
        private JsonObject ProbeNotificationAccess()
        {
            // Not a public constant; AndroidX's NotificationManagerCompat reads the
            // same setting. Unreadable, it throws, and the probe answers error.
            var all = (Settings.Secure.GetString(context.ContentResolver, "enabled_notification_listeners") ?? string.Empty)
                .Split(':')
                .Select(item => ComponentName.UnflattenFromString(item.Trim()))
                .Where(item => item is not null)
                .Select(item => item!)
                .GroupBy(item => item.FlattenToString())
                .Select(group => group.First())
                .ToList();
            var listeners = new JsonArray();
            foreach (var item in all.Take(MaxApps))
            {
                listeners.Add(AppEntry(item.PackageName, item.ClassName));
            }

            return Ok(("listeners", listeners), ("truncated", all.Count > MaxApps));
        }

        /// <summary>The active device administrators, and the known remote-control apps installed.</summary>
        private JsonObject ProbeOtherAccess()
        {
            if (context.GetSystemService(Context.DevicePolicyService) is not DevicePolicyManager policy)
            {
                return Unavailable("DevicePolicyManager is not available");
            }

            var active = policy.ActiveAdmins ?? new List<ComponentName>();
            var admins = new JsonArray();
            foreach (var item in active.Take(MaxApps))
            {
                admins.Add(AppEntry(item.PackageName, item.ClassName));
            }

            var pm = context.PackageManager!;
            var remote = new JsonArray();
            foreach (var name in RemoteAccessPackages)
            {
                bool installed;
                try
                {
                    PackageInfoOf(pm, name, 0);
                    installed = true;
                }
                catch (PackageManager.NameNotFoundException)
                {
                    installed = false;
                }

                if (installed)
                {
                    remote.Add(AppEntry(name));
                }
            }

            return Ok(("device_admins", admins), ("remote_access_apps", remote), ("truncated", active.Count > MaxApps));
        }

        /// <summary>
        /// Whether this app's window is being recorded (Android 15 and later, with
        /// DETECT_SCREEN_RECORDING, a normal permission the package declares), and
        /// how many displays besides the phone's own are on and public: casting,
        /// mirroring, an external screen -- which this cannot tell apart. When
        /// recording cannot be measured it is left out -- unknown, not "no" -- and
        /// recording_status says why: unsupported below Android 15, no_permission
        /// without DETECT_SCREEN_RECORDING, unavailable with no window to ask.
        /// </summary>
        private JsonObject ProbeScreenCapture()
        {
            var result = new JsonObject { ["status"] = "ok" };
            var window = NecessaryAndroid.CurrentActivity?.WindowManager;
            var granted = context.CheckSelfPermission("android.permission.DETECT_SCREEN_RECORDING") == Permission.Granted;
            if (OperatingSystem.IsAndroidVersionAtLeast(35) && window is not null && granted)
            {
                var callback = new IntConsumer();
                try
                {
                    var state = window.AddScreenRecordingCallback(new InlineExecutor(), callback);
                    result["recording"] = state == (int)ScreenRecordingState.Visible;
                }
                finally
                {
                    window.RemoveScreenRecordingCallback(callback);
                }
            }
            else
            {
                result["recording_status"] =
                    !OperatingSystem.IsAndroidVersionAtLeast(35) ? "unsupported"
                    : !granted ? "no_permission"
                    : "unavailable";
            }

            if (context.GetSystemService(Context.DisplayService) is not DisplayManager displays)
            {
                return Unavailable("DisplayManager is not available");
            }

            result["external_displays"] = (displays.GetDisplays() ?? Array.Empty<Display>()).Count(display =>
                display.DisplayId != Display.DefaultDisplay
                && display.State == DisplayState.On
                && (display.Flags & DisplayFlags.Private) == 0);
            return result;
        }

        /// <summary>
        /// The collection's one location read: the permission, then the newest
        /// fix any enabled provider already holds -- never a fresh fix (no GPS
        /// power, no waiting) and never a prompt; only the app asks for the
        /// permission, on its own screen.
        /// </summary>
        private FixRead ReadLocation()
        {
            var permission = LocationPermission();
            if (permission == "none")
            {
                return new FixRead(permission);
            }

            if (context.GetSystemService(Context.LocationService) is not LocationManager manager)
            {
                return new FixRead(permission, failure: "the location service is unavailable");
            }

            var now = SystemClock.ElapsedRealtimeNanos();
            var providers = new List<KeyValuePair<string, Outcome<Fix?>>>();
            foreach (var provider in manager.GetProviders(true))
            {
                providers.Add(new KeyValuePair<string, Outcome<Fix?>>(
                    provider,
                    Outcome<Fix?>.Of(() => manager.GetLastKnownLocation(provider) is Android.Locations.Location fix ? FixOf(fix, now) : null)));
            }

            return NewestFix(permission, providers);
        }

        private static Fix FixOf(Android.Locations.Location fix, long now)
        {
            bool mock;
            if (OperatingSystem.IsAndroidVersionAtLeast(31))
            {
                mock = fix.Mock;
            }
            else
            {
#pragma warning disable CA1422 // The only flag there is below Android 12.
                mock = fix.IsFromMockProvider;
#pragma warning restore CA1422
            }

            return new Fix(
                fix.Latitude,
                fix.Longitude,
                fix.HasAccuracy ? fix.Accuracy : null,
                Math.Max(0L, (now - fix.ElapsedRealtimeNanos) / 1_000_000_000L),
                fix.ElapsedRealtimeNanos,
                fix.Provider ?? string.Empty,
                fix.Time,
                mock);
        }

        private sealed class IntConsumer : Java.Lang.Object, Java.Util.Functions.IConsumer
        {
            public void Accept(Java.Lang.Object? t)
            {
            }
        }

        private sealed class InlineExecutor : Java.Lang.Object, Java.Util.Concurrent.IExecutor
        {
            public void Execute(Java.Lang.IRunnable? command) => command?.Run();
        }
    }
}
