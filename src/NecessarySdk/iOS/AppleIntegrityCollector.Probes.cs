using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using CoreFoundation;
using Foundation;
using ObjCRuntime;
using static Necessary.IosProbeReads;

namespace Necessary
{
    public sealed partial class AppleIntegrityCollector
    {
        /// <summary>
        /// Whether a VPN or an HTTP proxy is in use. iOS gives other apps no VPN
        /// API, so a VPN is inferred from the interfaces the system proxy settings
        /// are scoped to -- a heuristic, so their names are sent with it. Names
        /// only, never an address.
        /// </summary>
        private static JsonObject ProbeNetwork()
        {
            var settings = CoreFoundation.CFNetwork.GetSystemProxySettings()?.Dictionary;
            if (settings is null)
            {
                return new JsonObject { ["status"] = "error", ["error"] = "The system proxy settings could not be read." };
            }

            var scoped = new List<string>();
            if (settings[new NSString("__SCOPED__")] is NSDictionary scopes)
            {
                scoped = scopes.Keys.Select(key => key.ToString()).OrderBy(name => name, StringComparer.Ordinal).ToList();
            }

            var tunnels = new[] { "utun", "ipsec", "ppp", "tun", "tap" };
            var vpn = scoped.Any(name => tunnels.Any(prefix => name.StartsWith(prefix, StringComparison.Ordinal)));
            var proxy = new[] { "HTTPEnable", "HTTPSEnable", "ProxyAutoConfigEnable" }
                .Any(key => settings[new NSString(key)] is NSNumber number && number.Int32Value == 1);
            var interfaces = new JsonArray();
            foreach (var name in scoped.Take(32))
            {
                interfaces.Add(name);
            }

            return new JsonObject
            {
                ["status"] = "ok",
                ["vpn_active"] = vpn,
                ["http_proxy_configured"] = proxy,
                ["scoped_interfaces"] = interfaces,
            };
        }

        /// <summary>
        /// The phone's own IP addresses, per interface -- an optional measurement.
        /// Link-local addresses are left out: they can carry the hardware address
        /// the platform deliberately hides.
        /// </summary>
        private static JsonObject ProbeLocalAddresses()
        {
            const uint IffUp = 0x1;
            const uint IffLoopback = 0x8;
            const int AfInet = 2;
            const int AfInet6 = 30;
            const int NiNumericHost = 0x2;
            const int NiMaxHost = 1025;
            if (Native.getifaddrs(out var head) != 0 || head == IntPtr.Zero)
            {
                return new JsonObject { ["status"] = "error", ["error"] = "The network interfaces could not be listed." };
            }

            try
            {
                var addresses = new JsonArray();
                var host = new byte[NiMaxHost];
                for (var entry = head; entry != IntPtr.Zero && addresses.Count < 32;)
                {
                    // struct ifaddrs: next, name, flags (with padding), addr, ...
                    var next = Marshal.ReadIntPtr(entry, 0);
                    var namePointer = Marshal.ReadIntPtr(entry, IntPtr.Size);
                    var flags = (uint)Marshal.ReadInt32(entry, 2 * IntPtr.Size);
                    var address = Marshal.ReadIntPtr(entry, 3 * IntPtr.Size);
                    entry = next;
                    if ((flags & IffUp) == 0 || (flags & IffLoopback) != 0 || address == IntPtr.Zero)
                    {
                        continue;
                    }

                    var length = Marshal.ReadByte(address, 0);
                    var family = Marshal.ReadByte(address, 1);
                    if (family != AfInet && family != AfInet6)
                    {
                        continue;
                    }

                    Array.Clear(host, 0, host.Length);
                    if (Native.getnameinfo(address, length, host, (uint)host.Length, IntPtr.Zero, 0, NiNumericHost) != 0)
                    {
                        continue;
                    }

                    var end = Array.IndexOf(host, (byte)0);
                    var numeric = System.Text.Encoding.UTF8.GetString(host, 0, end < 0 ? host.Length : end);
                    var text = numeric.Split('%')[0];
                    if (text.Length == 0 || text.ToLowerInvariant().StartsWith("fe80", StringComparison.Ordinal)
                        || text.StartsWith("169.254", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    addresses.Add(new JsonObject
                    {
                        ["interface"] = Marshal.PtrToStringUTF8(namePointer) ?? string.Empty,
                        ["address"] = text,
                    });
                }

                return new JsonObject { ["status"] = "ok", ["addresses"] = addresses };
            }
            finally
            {
                Native.freeifaddrs(head);
            }
        }

        private static JsonObject ProbeAppIdentity()
        {
            var bundle = NSBundle.MainBundle;
            var info = bundle.InfoDictionary;
            var result = new JsonObject
            {
                ["status"] = "ok",
                ["bundle_id"] = bundle.BundleIdentifier ?? string.Empty,
                ["version_name"] = (info?[new NSString("CFBundleShortVersionString")] as NSString)?.ToString() ?? string.Empty,
                ["version_code"] = (info?[new NSString("CFBundleVersion")] as NSString)?.ToString() ?? string.Empty,
            };

            // The main executable's hash, which a backend compares with a record
            // of the release when it holds one.
            var executable = ReadExecutable();
            if (executable is not null)
            {
                result["executable_sha256"] = Wire.Sha256Hex(executable);
                result["executable_bytes"] = executable.Length;
            }
            else
            {
                result["executable_sha256"] = string.Empty;
            }

            return result;
        }

        private static byte[]? ReadExecutable()
        {
            var path = NSBundle.MainBundle.ExecutablePath;
            if (string.IsNullOrEmpty(path))
            {
                return null;
            }

            try
            {
                return File.ReadAllBytes(path);
            }
#pragma warning disable CA1031 // Unreadable: said so by the probe.
            catch (Exception)
#pragma warning restore CA1031
            {
                return null;
            }
        }

        /// <summary>
        /// This app's own code-signing identity, read from the Mach-O signature
        /// embedded in its executable on disk: what is actually in the file, and an
        /// unsigned build reported as unsigned instead of being mistaken for a
        /// clean signed app.
        /// </summary>
        private static JsonObject ProbeCodeSigning() => MachOSigning.CodeSigning(ReadExecutable());

        /// <summary>
        /// Each bundle image's __TEXT,__text in memory against the same bytes on
        /// disk. Only the app's own code can be compared on iOS: the system
        /// libraries live in the dyld shared cache, with no file to open, so they
        /// are counted as unreadable -- never as clean.
        /// </summary>
        private static JsonObject ProbeCodeIntegrity()
        {
            var result = new JsonObject
            {
                ["status"] = "ok",
                ["checked"] = false,
                ["core_compared_bytes"] = 0,
                ["core_diff_bytes"] = 0,
                ["diff_bytes"] = 0,
                ["ext_compared_bytes"] = 0,
                ["ext_diff_bytes"] = 0,
                ["ext_libs_diff"] = 0,
                ["app_compared_bytes"] = 0,
                ["app_diff_bytes"] = 0,
                ["app_libs_diff"] = 0,
                ["diffed_libs"] = string.Empty,
                ["system_images_unreadable"] = 0,
                ["system_bucket_reason"] = "dyld_shared_cache_has_no_backing_files",
            };
            var bundlePath = NSBundle.MainBundle.BundlePath;
            var mainName = Path.GetFileName(NSBundle.MainBundle.ExecutablePath ?? string.Empty);
            var images = new List<AppImage>();
            var systemUnreadable = 0;
            var count = Native._dyld_image_count();
            for (uint index = 0; index < count; index++)
            {
                var namePointer = Native._dyld_get_image_name(index);
                var header = Native._dyld_get_image_header(index);
                if (namePointer == IntPtr.Zero || header == IntPtr.Zero)
                {
                    continue;
                }

                var path = Marshal.PtrToStringUTF8(namePointer) ?? string.Empty;

                // Anything outside the bundle is in the shared cache: counted, not
                // compared, and never treated as clean.
                if (!path.StartsWith(bundlePath, StringComparison.Ordinal))
                {
                    systemUnreadable++;
                    continue;
                }

                var label = BundleLabel(path, bundlePath);
                images.Add(new AppImage(label, label == mainName, CompareImage(path, header, Native._dyld_get_image_vmaddr_slide(index))));
            }

            foreach (var figure in AppCoverage(images, systemUnreadable))
            {
                result[figure.Key] = figure.Value?.DeepClone();
            }

            return result;
        }

        /// <summary>One bundle image's __TEXT in memory against its file.</summary>
        private static ImageOutcome CompareImage(string path, IntPtr header, IntPtr slide)
        {
            var (span, problem) = TextSpanOfImage(header);
            if (span is null)
            {
                return ImageOutcome.Skipped(problem!.TextSize, problem.Reason);
            }

            var (onDisk, readProblem) = ReadFileRange(path, span.SegmentFileOffset, span.SegmentSize);
            if (onDisk is null)
            {
                // A bundle image that cannot be read is not clean.
                return ImageOutcome.Unreadable(span.TextSize, readProblem!);
            }

            var live = unchecked((nint)(span.SegmentVMAddress + (ulong)(long)slide));
            if (live == 0)
            {
                return ImageOutcome.Skipped(span.TextSize, "no live address for __TEXT");
            }

            // One pass over the whole __TEXT segment, each differing byte
            // attributed to __text or to the rest: __text is what counts; the rest
            // is telemetry with no clean baseline yet.
            var memory = new byte[onDisk.Length];
            Marshal.Copy(live, memory, 0, memory.Length);
            long textDiffering = 0;
            long segmentDiffering = 0;
            var textStart = span.TextOffsetInSegment;
            var textEnd = textStart + span.TextSize;
            for (var offset = 0; offset < onDisk.Length; offset++)
            {
                if (memory[offset] != onDisk[offset])
                {
                    segmentDiffering++;
                    if (offset >= textStart && offset < textEnd)
                    {
                        textDiffering++;
                    }
                }
            }

            return ImageOutcome.Compared(span.TextSize, textDiffering, onDisk.Length, segmentDiffering);
        }

        /// <summary>The __TEXT segment and its __text section, read from an image's load commands in memory.</summary>
        private static (TextSpan? Span, CoverageProblem? Problem) TextSpanOfImage(IntPtr header)
        {
            const uint MhMagic64 = 0xfeedfacf;
            const uint LcSegment64 = 0x19;
            const int HeaderSize = 32;
            const int SegmentCommandSize = 72;
            const int SectionSize = 80;
            if ((uint)Marshal.ReadInt32(header, 0) != MhMagic64)
            {
                return (null, new CoverageProblem("not a 64-bit Mach-O image", 0));
            }

            var commands = (uint)Marshal.ReadInt32(header, 16);
            var cursor = header + HeaderSize;
            for (uint i = 0; i < commands; i++)
            {
                var command = (uint)Marshal.ReadInt32(cursor, 0);
                var commandSize = (uint)Marshal.ReadInt32(cursor, 4);
                if (command == LcSegment64 && FixedName(cursor + 8) == "__TEXT")
                {
                    var vmaddr = (ulong)Marshal.ReadInt64(cursor, 24);
                    var fileoff = (ulong)Marshal.ReadInt64(cursor, 40);
                    var filesize = (ulong)Marshal.ReadInt64(cursor, 48);
                    var sections = (uint)Marshal.ReadInt32(cursor, 64);
                    (ulong Offset, ulong Size)? text = null;
                    var section = cursor + SegmentCommandSize;
                    for (uint s = 0; s < sections; s++)
                    {
                        if (FixedName(section) == "__text")
                        {
                            // section_64: sectname[16], segname[16], addr, size, offset ...
                            text = ((uint)Marshal.ReadInt32(section, 48), (ulong)Marshal.ReadInt64(section, 40));
                            break;
                        }

                        section += SectionSize;
                    }

                    return TextSpanOf(fileoff, filesize, vmaddr, text);
                }

                cursor += (int)commandSize;
            }

            return (null, new CoverageProblem("no __TEXT segment", 0));
        }

        /// <summary>A 16-byte Mach-O name field, not necessarily NUL-terminated.</summary>
        private static string FixedName(IntPtr field)
        {
            var bytes = new byte[16];
            Marshal.Copy(field, bytes, 0, 16);
            var end = Array.IndexOf(bytes, (byte)0);
            return System.Text.Encoding.UTF8.GetString(bytes, 0, end < 0 ? 16 : end);
        }

        /// <summary>Exactly <paramref name="length"/> bytes of the file from <paramref name="offset"/>, or why not.</summary>
        private static (byte[]? Data, string? Problem) ReadFileRange(string path, long offset, long length)
        {
            FileStream stream;
            try
            {
                stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
#pragma warning disable CA1031 // Unreadable, with why.
            catch (Exception)
            {
                return (null, "unreadable: the file could not be opened");
            }

            using (stream)
            {
                try
                {
                    stream.Seek(offset, SeekOrigin.Begin);
                    var data = new byte[length];
                    var got = 0;
                    while (got < length)
                    {
                        var read = stream.Read(data, got, (int)(length - got));
                        if (read <= 0)
                        {
                            break;
                        }

                        got += read;
                    }

                    var problem = ReadProblem(got, length);
                    return problem is null ? (data, null) : (null, problem);
                }
                catch (Exception error)
                {
                    var described = error.ToString();
                    return (null, "unreadable: " + (described.Length <= 120 ? described : described.Substring(0, 120)));
                }
#pragma warning restore CA1031
            }
        }

        /// <summary>P_TRACED via sysctl: the standard, non-private debugger check.</summary>
        private static JsonObject ProbeDebugger()
        {
            // sysctl(KERN_PROC, KERN_PROC_PID, pid) fills a kinfo_proc; P_TRACED is
            // in kp_proc.p_flag, at 32 bytes on 64-bit Darwin.
            const int CtlKern = 1;
            const int KernProc = 14;
            const int KernProcPid = 1;
            const int PFlagOffset = 32;
            const int PTraced = 0x00000800;
            const int KinfoProcSize = 648;
            var name = new[] { CtlKern, KernProc, KernProcPid, Environment.ProcessId };
            var size = (IntPtr)KinfoProcSize;
            var buffer = Marshal.AllocHGlobal(KinfoProcSize);
            try
            {
                if (Native.sysctl(name, (uint)name.Length, buffer, ref size, IntPtr.Zero, IntPtr.Zero) != 0)
                {
                    return new JsonObject
                    {
                        ["status"] = "error",
                        ["error"] = "sysctl failed with errno " + Marshal.GetLastPInvokeError(),
                    };
                }

                return new JsonObject
                {
                    ["status"] = "ok",
                    ["traced"] = (Marshal.ReadInt32(buffer, PFlagOffset) & PTraced) != 0,
                };
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static JsonObject ProbeJailbreakFiles()
        {
            // The Simulator's filesystem is the Mac's, and macOS ships /bin/bash,
            // /bin/sh, /usr/bin/ssh and /usr/sbin/sshd: there the check would be a
            // confident false positive, so it is skipped with a reason.
            if (Runtime.Arch == Arch.SIMULATOR)
            {
                return new JsonObject
                {
                    ["status"] = "unsupported",
                    ["reason"] = "simulator_filesystem_is_the_host",
                    ["found_paths"] = new JsonArray(),
                };
            }

            var found = new JsonArray();
            foreach (var path in JailbreakPaths)
            {
                // On a clean phone the sandbox makes most of these unreadable,
                // which is indistinguishable from absent: a safe false negative.
                if (NSFileManager.DefaultManager.FileExists(path))
                {
                    found.Add(path);
                }
            }

            return new JsonObject
            {
                ["status"] = "ok",
                ["found_paths"] = found,
                ["checked_count"] = JailbreakPaths.Length,
            };
        }

        /// <summary>A write outside the app container: on a sandboxed phone it must fail.</summary>
        private static JsonObject ProbeSandbox()
        {
            const string path = "/private/devicetrust_sandbox_probe.txt";
            using var probe = NSData.FromString("probe", NSStringEncoding.UTF8);
            var succeeded = probe.Save(path, true, out _);
            if (succeeded)
            {
                // Leave nothing behind on a phone where this unexpectedly works.
                NSFileManager.DefaultManager.Remove(path, out _);
            }

            return new JsonObject
            {
                ["status"] = "ok",
                ["write_outside_sandbox_succeeded"] = succeeded,
                ["probe_path"] = path,
            };
        }

        /// <summary>The images actually loaded into this process, scanned for instrumentation names.</summary>
        private static JsonObject ProbeDyldImages()
        {
            var tokens = new SortedSet<string>(StringComparer.Ordinal);
            var suspiciousCount = 0;
            var imageCount = Native._dyld_image_count();
            for (uint index = 0; index < imageCount; index++)
            {
                var raw = Native._dyld_get_image_name(index);
                if (raw == IntPtr.Zero)
                {
                    continue;
                }

                var name = (Marshal.PtrToStringUTF8(raw) ?? string.Empty).ToLowerInvariant();
                var matched = false;
                foreach (var token in SuspiciousImageTokens)
                {
                    if (name.Contains(token, StringComparison.Ordinal))
                    {
                        tokens.Add(token);
                        matched = true;
                    }
                }

                if (matched)
                {
                    suspiciousCount++;
                }
            }

            var list = new JsonArray();
            foreach (var token in tokens)
            {
                list.Add(token);
            }

            return new JsonObject
            {
                ["status"] = "ok",
                ["suspicious_tokens"] = list,
                ["suspicious_image_count"] = suspiciousCount,
                ["image_count"] = (int)imageCount,
            };
        }

        private static JsonObject ProbeEnvironment()
        {
            var inserted = Environment.GetEnvironmentVariable("DYLD_INSERT_LIBRARIES") ?? string.Empty;
            return new JsonObject
            {
                ["status"] = "ok",
                ["dyld_insert_libraries"] = inserted.Length <= MaxTextLength ? inserted : inserted.Substring(0, MaxTextLength),
            };
        }

        private static JsonObject ProbeSimulator() => new JsonObject
        {
            ["status"] = "ok",
            ["is_simulator"] = Runtime.Arch == Arch.SIMULATOR || Environment.GetEnvironmentVariable("SIMULATOR_DEVICE_NAME") is not null,
            ["model"] = ModelIdentifier(),
        };
    }
}
