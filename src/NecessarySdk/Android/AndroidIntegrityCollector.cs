using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Android;
using Android.Content;
using Android.Content.PM;
using Java.IO;
using static Necessary.AndroidProbeReads;
using File = System.IO.File;

namespace Necessary
{
    /// <summary>
    /// The Android integrity collector, version 8: measures what the challenge
    /// asks for and the app enabled, and nothing else. The plugin's
    /// <c>IntegrityProbeManager.kt</c>, translated.
    /// </summary>
    /// <remarks>
    /// These measurements are evidence, not remote attestation: on a fully
    /// compromised OS an attacker may lie about local state, so your backend
    /// weighs them with what it observes itself, and never takes a score from
    /// the phone.
    /// </remarks>
    public sealed partial class AndroidIntegrityCollector : INativeIntegrityCollector
    {
        // 1 = name-based hook detection only (runtime_maps token scan).
        // 2 = the structural probes: instrumentation_threads, exec_mappings, and
        //     the code_integrity buckets.
        // 4 = device and network volunteered on every scan, and the optional
        //     measurements the backend asks for.
        // 5 = the optional measurements of what can read or drive the phone,
        //     screen capture, location and mock locations.
        // 6 = sizes of writable-executable and unlabelled executable memory, and
        //     the process ABI, for runtime baselines.
        // 7 = the page size, and the current signers apart from the lineage.
        // 8 = a failed read is never a clean negative: the probe answers an
        //     error, or names the parts it could not read in "unread". One
        //     location read answers both location measurements, which carry its
        //     fix_time.
        private const int CollectorVersion = 10;

        // Apps listed per capability, at most.
        private const int MaxApps = 32;
        private const int MaxText = 8192;

        // Every shell command is bounded: one hung child would block its probe,
        // and the whole scan, indefinitely.
        private const int CommandTimeoutMs = 3000;

        // Sent with every scan whether or not the backend asked.
        private static readonly string[] VolunteeredProbes = { "device", "network" };

        // The optional measurements this collector knows. Each is collected only
        // when the backend asks for it AND the app enabled it.
        private static readonly HashSet<string> OptionalMeasurements = new HashSet<string>(StringComparer.Ordinal)
        {
            "local_addresses", "accessibility", "notification_access", "other_access",
            "screen_capture", "location", "mock_location",
        };

        // Remote-control apps scammers have their victims install. Android 11 and
        // later show an app only the packages it names in advance, so the same
        // names are in the manifest's queries.
        private static readonly string[] RemoteAccessPackages =
        {
            "com.anydesk.anydeskandroid",
            "com.teamviewer.quicksupport.market",
            "com.carriez.flutter_hbb",
            "com.sand.airdroid",
        };

        private static readonly string[] SuspiciousRuntimeTokens =
        {
            "frida", "gadget", "objection", "xposed", "lsposed",
            "substrate", "cydia", "zygisk", "riru", "magisk",
            "kernelsu", "apatch",
        };

        private static readonly string[] RootPaths =
        {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/sbin/magisk",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/ksu",
            "/data/adb/ap",
            "/metadata/adb/magisk",
        };

        private readonly Context context;

        // The installed APKs do not change under a running process (an update
        // restarts it): the base hash and, once every split was hashed, the
        // split inventory are kept.
        private volatile string? cachedApkSha256;
        private volatile IReadOnlyList<(string Name, string Sha256)>? cachedSplits;

        // The app's own request for the location permission, answered when the
        // person chooses; the collector itself never asks.
        private int locationRequestPending;

        /// <summary>The collector of the app <paramref name="context"/> belongs to.</summary>
        public AndroidIntegrityCollector(Context context)
        {
            this.context = context ?? throw new ArgumentNullException(nameof(context));
            AndroidProbeReads.Read = AndroidNative.Read;
        }

        /// <inheritdoc />
        public Task<JsonObject> CollectAsync(
            IReadOnlyList<string> requiredProbes,
            string challengeNonce,
            IReadOnlyList<string> enabledMeasurements,
            IReadOnlyList<string> optionalProbes)
        {
            if (requiredProbes is null)
            {
                return Task.FromException<JsonObject>(new NativeKeyException("INVALID_ARGUMENT", "required_probes must be a list of strings."));
            }

            if (challengeNonce is null)
            {
                return Task.FromException<JsonObject>(new NativeKeyException("INVALID_ARGUMENT", "challenge_nonce must be a string."));
            }

            var optional = optionalProbes ?? Array.Empty<string>();
            var enabled = new HashSet<string>(enabledMeasurements ?? Array.Empty<string>(), StringComparer.Ordinal);
            return AndroidNative.Run(() => Collect(requiredProbes, challengeNonce, optional, enabled));
        }

        /// <inheritdoc />
        public async Task<string> RequestLocationPermissionAsync()
        {
            // Asks the person once, from a button on the app's own screen.
            if (LocationPermission() == "precise" || NecessaryAndroid.CurrentActivity is null
                || Interlocked.CompareExchange(ref locationRequestPending, 1, 0) != 0)
            {
                return LocationPermission();
            }

            try
            {
                await NecessaryAndroid.RequestPermissionsAsync(new[]
                {
                    Manifest.Permission.AccessFineLocation,
                    Manifest.Permission.AccessCoarseLocation,
                }).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Exchange(ref locationRequestPending, 0);
            }

            return LocationPermission();
        }

        private static JsonObject Unavailable(string reason) => new JsonObject
        {
            ["status"] = "error",
            ["error"] = reason,
        };

        private static JsonObject Unsupported(string reason) => new JsonObject
        {
            ["status"] = "unsupported",
            ["reason"] = reason,
        };

        private static JsonObject NotEnabled() => new JsonObject { ["status"] = "not_enabled" };

        /// <summary>A file's lines, or null when it could not be read: never an empty "nothing found".</summary>
        private static IReadOnlyList<string>? ReadLines(string path)
        {
            try
            {
                return File.ReadAllLines(path);
            }
#pragma warning disable CA1031 // Null is the answer "could not be read".
            catch (Exception)
#pragma warning restore CA1031
            {
                return null;
            }
        }

        private static string Sha256Hex(byte[] bytes) => Wire.Sha256Hex(bytes);

        private static string Sha256File(string path)
        {
            using var sha = SHA256.Create();
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1024 * 1024);
            var digest = sha.ComputeHash(input);
            var hex = new StringBuilder(digest.Length * 2);
            foreach (var b in digest)
            {
                hex.Append(b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
            }

            return hex.ToString();
        }

        /// <summary>
        /// Runs one command with a deadline, and says how it went: started or
        /// not, finished within the deadline or not (the child is then killed),
        /// its exit code, and its output (at most 8192 characters, standard error
        /// with it) when it was read to the end. The caller decides what an
        /// unanswered command means for its probe; it is never an empty answer.
        /// </summary>
        private static CommandResult RunCommand(params string[] command)
        {
            Java.Lang.Process process;
            try
            {
                process = new Java.Lang.ProcessBuilder(command).RedirectErrorStream(true)!.Start()!;
            }
#pragma warning disable CA1031 // Never "": a command that did not start answered nothing.
            catch (Exception error)
#pragma warning restore CA1031
            {
                return new CommandResult(false, false, null, string.Empty, Why(error));
            }

            var output = new StringBuilder();
            string? readError = null;
            var reader = new Thread(() =>
            {
                try
                {
                    using var input = new BufferedReader(new InputStreamReader(process.InputStream!));
                    string? line;
                    while ((line = input.ReadLine()) is not null)
                    {
                        lock (output)
                        {
                            if (output.Length < MaxText)
                            {
                                output.Append(line).Append('\n');
                            }
                        }
                    }
                }
#pragma warning disable CA1031 // Its output could not be read to the end: said so below.
                catch (Exception error)
#pragma warning restore CA1031
                {
                    readError = Why(error);
                }
            })
            {
                IsBackground = true,
            };
            reader.Start();
            var exited = Task.Run(() => process.WaitFor());
            if (!exited.Wait(CommandTimeoutMs))
            {
                Destroy(process);
                return new CommandResult(true, false, null, string.Empty);
            }

            reader.Join(500);
            if (readError is string failed)
            {
                return new CommandResult(true, false, process.ExitValue(), string.Empty, "output: " + failed);
            }

            string text;
            lock (output)
            {
                text = Take(output.ToString(), MaxText);
            }

            return new CommandResult(true, true, process.ExitValue(), text);
        }

        private static void Destroy(Java.Lang.Process process)
        {
            try
            {
                if (OperatingSystem.IsAndroidVersionAtLeast(26))
                {
                    process.DestroyForcibly();
                }
                else
                {
                    process.Destroy();
                }
            }
#pragma warning disable CA1031 // Gone already.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
        }

        private JsonObject Collect(
            IReadOnlyList<string> requiredProbes,
            string challengeNonce,
            IReadOnlyList<string> optionalProbes,
            HashSet<string> enabledMeasurements)
        {
            // One location read per collection, made only if an enabled location
            // measurement asks: both answer from it.
            var location = new LocationCapture(ReadLocation);
            var probes = new JsonObject();
            foreach (var probe in requiredProbes.Distinct())
            {
                probes[probe] = RunProbe(probe, enabledMeasurements, location);
            }

            foreach (var probe in VolunteeredProbes)
            {
                if (!probes.ContainsKey(probe))
                {
                    probes[probe] = RunProbe(probe, enabledMeasurements, location);
                }
            }

            foreach (var probe in optionalProbes.Distinct())
            {
                if (!probes.ContainsKey(probe) && OptionalMeasurements.Contains(probe))
                {
                    probes[probe] = RunProbe(probe, enabledMeasurements, location);
                }
            }

            return new JsonObject
            {
                ["collector_version"] = CollectorVersion,
                ["platform"] = "android",
                ["challenge_nonce_echo"] = challengeNonce,
                ["sdk_int"] = (int)Android.OS.Build.VERSION.SdkInt,
                ["probes"] = probes,
            };
        }

        private JsonObject RunProbe(string probe, HashSet<string> enabled, LocationCapture location)
        {
            try
            {
                return probe switch
                {
                    "app_identity" => ProbeAppIdentity(),
                    "debug_state" => ProbeDebugState(),
                    "root_files" => ProbeRootFiles(),
                    "root_shell" => ProbeRootShell(),
                    "system_properties" => ProbeSystemProperties(),
                    "selinux" => ProbeSelinux(),
                    "mounts" => ProbeMounts(),
                    "runtime_maps" => ProbeRuntimeMaps(),
                    "tracer" => ProbeTracer(),
                    "frida_ports" => ProbeFridaPorts(),
                    "emulator" => ProbeEmulator(),
                    "developer_settings" => ProbeDeveloperSettings(),
                    "instrumentation_threads" => ProbeInstrumentationThreads(),
                    "exec_mappings" => ProbeExecMappings(),
                    "code_integrity" => ProbeCodeIntegrity(),
                    "device" => ProbeDevice(),
                    "network" => ProbeNetwork(),
                    "local_addresses" => enabled.Contains(probe) ? ProbeLocalAddresses() : NotEnabled(),
                    "accessibility" => enabled.Contains(probe) ? ProbeAccessibility() : NotEnabled(),
                    "notification_access" => enabled.Contains(probe) ? ProbeNotificationAccess() : NotEnabled(),
                    "other_access" => enabled.Contains(probe) ? ProbeOtherAccess() : NotEnabled(),
                    "screen_capture" => enabled.Contains(probe) ? ProbeScreenCapture() : NotEnabled(),
                    "location" => enabled.Contains(probe) ? Location(location.Value) : NotEnabled(),
                    "mock_location" => enabled.Contains(probe) ? MockLocation(location.Value) : NotEnabled(),
                    _ => Unsupported("Unknown probe requested by server"),
                };
            }
#pragma warning disable CA1031 // A probe that threw answers error, with what threw.
            catch (Exception error)
#pragma warning restore CA1031
            {
                // Its words, then every cause beneath them: the kind alone
                // (error_type) says little of an Android 9 keystore failure.
                var (_, words, beneath) = AndroidNative.Read(error);
                return new JsonObject
                {
                    ["status"] = "error",
                    ["error_type"] = AndroidNative.SimpleName(error),
                    ["error"] = Take(
                        Causes.WithCauses(string.IsNullOrEmpty(words) ? "probe failed" : words!, beneath, AndroidNative.KeystoreDetail, AndroidNative.Read),
                        240),
                };
            }
        }

        private string LocationPermission() =>
            context.CheckSelfPermission(Manifest.Permission.AccessFineLocation) == Permission.Granted ? "precise"
            : context.CheckSelfPermission(Manifest.Permission.AccessCoarseLocation) == Permission.Granted ? "approximate"
            : "none";
    }
}
