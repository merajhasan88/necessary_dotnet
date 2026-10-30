// Reading a scan: every measurement the signed report carried, each with its
// status and its fields as the phone sent them, grouped by what it catches --
// the hooks, gadgets and changes in memory first. A measurement the backend
// did not ask for shows as not asked rather than disappearing. The titles and
// descriptions follow the integration guide's sections 6 and 8.
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;

namespace Necessary.Example
{
    /// <summary>What a group of measurements catches.</summary>
    public enum MeasurementGroup
    {
        Hooks,
        App,
        System,
        Device,
        Personal,
    }

    /// <summary>A measurement's name in the report, a title, what it tells a backend, and its group.</summary>
    public sealed record MeasurementInfo(string Name, string Title, string About, MeasurementGroup Group);

    /// <summary>One field row: its name, its value, and how deep it is nested.</summary>
    public sealed record FieldRow(string Name, string Value, int Depth);

    /// <summary>One measurement as shown: its title and status, and what it opens to.</summary>
    public sealed record MeasurementTile(
        MeasurementInfo Info,
        string Status,
        bool Warning,
        bool Unread,
        bool Truncated,
        IReadOnlyList<string> Notes,
        IReadOnlyList<FieldRow> Fields);

    /// <summary>A group of tiles, with its title and note.</summary>
    public sealed record TileGroup(string Title, string Note, IReadOnlyList<MeasurementTile> Tiles);

    public static class Measurements
    {
        public static readonly IReadOnlyList<MeasurementInfo> Android = new[]
        {
            new MeasurementInfo("runtime_maps", "Memory map", "Instrumentation and hooking frameworks named in the app's memory map: Frida, its gadget, Objection, Xposed and others.", MeasurementGroup.Hooks),
            new MeasurementInfo("frida_ports", "Frida ports", "Frida's default local ports accepting connections.", MeasurementGroup.Hooks),
            new MeasurementInfo("instrumentation_threads", "Instrumentation threads", "Threads an instrumentation runtime creates, even renamed.", MeasurementGroup.Hooks),
            new MeasurementInfo("exec_mappings", "Executable memory", "Memory both writable and executable, executable memory from deleted files, unlabelled executable regions: where injected code lives.", MeasurementGroup.Hooks),
            new MeasurementInfo("code_integrity", "Code integrity", "The app's native code and the system libraries in memory compared with their files: an inline hook changes bytes, and diff_bytes counts them.", MeasurementGroup.Hooks),
            new MeasurementInfo("tracer", "Tracer", "Another process tracing the app.", MeasurementGroup.Hooks),
            new MeasurementInfo("debug_state", "Debugger", "A Java debugger attached or awaited.", MeasurementGroup.Hooks),
            new MeasurementInfo("app_identity", "App identity", "The installed app: package, the base APK hash, signing certificates, flags, install source and split APKs.", MeasurementGroup.App),
            new MeasurementInfo("root_files", "Root files", "Known root, su and framework paths that exist; a test-keys build.", MeasurementGroup.System),
            new MeasurementInfo("root_shell", "Root shell", "Whether su resolves from the app's shell.", MeasurementGroup.System),
            new MeasurementInfo("system_properties", "System properties", "Build and boot-security properties.", MeasurementGroup.System),
            new MeasurementInfo("selinux", "SELinux", "The SELinux mode, read two ways.", MeasurementGroup.System),
            new MeasurementInfo("mounts", "Mounts", "System partitions mounted writable.", MeasurementGroup.System),
            new MeasurementInfo("developer_settings", "Developer settings", "Developer options and USB debugging.", MeasurementGroup.System),
            new MeasurementInfo("emulator", "Emulator", "Build values typical of an emulator.", MeasurementGroup.System),
            new MeasurementInfo("device", "Device", "The OS version, security patch level, model, build, the app's ABI and memory page size.", MeasurementGroup.Device),
            new MeasurementInfo("network", "Network", "A VPN up on any network; an HTTP proxy set.", MeasurementGroup.Device),
        };

        public static readonly IReadOnlyList<MeasurementInfo> Ios = new[]
        {
            new MeasurementInfo("dyld_images", "Loaded libraries", "Instrumentation and jailbreak names among the loaded libraries: Frida, its gadget, Cycript, Substrate and others.", MeasurementGroup.Hooks),
            new MeasurementInfo("environment", "Environment", "Libraries injected through the environment.", MeasurementGroup.Hooks),
            new MeasurementInfo("code_integrity", "Code integrity", "The app's code in memory compared with its file, image by image: an inline hook changes bytes, and app_diff_bytes counts them.", MeasurementGroup.Hooks),
            new MeasurementInfo("debugger", "Debugger", "A debugger tracing the process.", MeasurementGroup.Hooks),
            new MeasurementInfo("app_identity", "App identity", "The installed app and its executable's hash.", MeasurementGroup.App),
            new MeasurementInfo("code_signing", "Code signing", "The executable's own code signature.", MeasurementGroup.App),
            new MeasurementInfo("jailbreak_files", "Jailbreak files", "Known jailbreak paths that exist.", MeasurementGroup.System),
            new MeasurementInfo("sandbox", "Sandbox", "Whether the app can write outside its sandbox.", MeasurementGroup.System),
            new MeasurementInfo("simulator", "Simulator", "The simulator, and the hardware model.", MeasurementGroup.System),
            new MeasurementInfo("device", "Device", "The OS version and build, the model and the memory page size.", MeasurementGroup.Device),
            new MeasurementInfo("network", "Network", "A VPN, inferred from the interfaces the proxy settings are scoped to; an HTTP proxy.", MeasurementGroup.Device),
        };

        /// <summary>The personal measurements, in the order of <see cref="PersonalMeasurement"/>.</summary>
        public static readonly IReadOnlyList<MeasurementInfo> Personal = new[]
        {
            new MeasurementInfo("local_addresses", "Local addresses", "The phone's own IP addresses, link-local ones left out.", MeasurementGroup.Personal),
            new MeasurementInfo("accessibility", "Accessibility", "The Accessibility services that are on, and the keyboard in use. Android only.", MeasurementGroup.Personal),
            new MeasurementInfo("notification_access", "Notification access", "The apps allowed to read notifications. Android only.", MeasurementGroup.Personal),
            new MeasurementInfo("other_access", "Other access", "Device-administrator apps, and known remote-control apps installed. Android only.", MeasurementGroup.Personal),
            new MeasurementInfo("screen_capture", "Screen capture", "The screen being recorded, mirrored or cast.", MeasurementGroup.Personal),
            new MeasurementInfo("location", "Location", "The last location the phone already knows: never a fresh fix, never a prompt. Needs the location permission.", MeasurementGroup.Personal),
            new MeasurementInfo("mock_location", "Mock location", "Whether that location was faked.", MeasurementGroup.Personal),
        };

        /// <summary>A measurement's status as the badge says it: whether the phone measured it, never whether what it found is good or bad.</summary>
        private static readonly Dictionary<string, string> StatusLabels = new Dictionary<string, string>
        {
            ["ok"] = "measured",
            ["error"] = "failed",
            ["not_enabled"] = "off",
        };

        public static string Title(MeasurementGroup group) => group switch
        {
            MeasurementGroup.Hooks => "Hooks, gadgets and memory changes",
            MeasurementGroup.App => "The app as built",
            MeasurementGroup.System => "Root, jailbreak and the system",
            MeasurementGroup.Device => "Device and network",
            _ => "Personal measurements",
        };

        public static string Note(MeasurementGroup group) => group switch
        {
            MeasurementGroup.Hooks => "Frida and other instrumentation, found by name, by port, by thread and by memory layout; debuggers and tracers; and the code in memory compared with its file, where an inline hook changes bytes. A backend asks for every one of these on every scan.",
            MeasurementGroup.App => "What is installed: its identity, its hashes and its signer.",
            MeasurementGroup.System => "Traces of root or a jailbreak, and how the system is set up.",
            MeasurementGroup.Device => "Sent with every scan, asked for or not.",
            _ => "Asked for by the backend, and measured only where this app turned them on.",
        };

        /// <summary>What a personal measurement reports, for its switch.</summary>
        public static MeasurementInfo PersonalInfo(PersonalMeasurement measurement) =>
            Personal.First(info => info.Name == measurement.WireName());

        /// <summary>The code for the personal measurements chosen.</summary>
        public static string PersonalCode(IReadOnlyCollection<PersonalMeasurement> enabled)
        {
            if (enabled.Count == 0)
            {
                return "trust.PersonalMeasurements = Array.Empty<PersonalMeasurement>();";
            }

            var lines = new List<string> { "trust.PersonalMeasurements = new[]", "{" };
            foreach (var measurement in PersonalMeasurements.All)
            {
                if (enabled.Contains(measurement))
                {
                    lines.Add("    PersonalMeasurement." + measurement + ",");
                }
            }

            lines.Add("};");
            return string.Join("\n", lines);
        }

        /// <summary>
        /// One scan as the phone sent it: the backend's plan -- required and the
        /// personal measurements it asked for -- and the report's results, every
        /// measurement in its group, the hooks first.
        /// </summary>
        public static IReadOnlyList<TileGroup> Groups(
            string platform,
            IReadOnlyList<string> required,
            IReadOnlyList<string> optional,
            JsonObject results,
            IReadOnlyList<string> enabled)
        {
            var catalog = (platform == "ios" ? Ios : Android).Concat(Personal).ToList();
            MeasurementTile Tile(MeasurementInfo info) =>
                MakeTile(info, results[info.Name] as JsonObject, required.Contains(info.Name) || optional.Contains(info.Name));

            var groups = new List<TileGroup>();
            foreach (var group in new[] { MeasurementGroup.Hooks, MeasurementGroup.App, MeasurementGroup.System, MeasurementGroup.Device, MeasurementGroup.Personal })
            {
                var members = catalog
                    .Where(info => info.Group == group
                        && (group != MeasurementGroup.Personal || optional.Contains(info.Name) || results.ContainsKey(info.Name)))
                    .ToList();
                groups.Add(new TileGroup(
                    Title(group),
                    group == MeasurementGroup.Personal
                        ? Note(group) + " On: " + (enabled.Count == 0 ? "none" : string.Join(", ", enabled)) + "."
                        : Note(group),
                    members.Select(Tile).ToList()));
            }

            var other = results.Select(member => member.Key).Where(name => catalog.All(info => info.Name != name)).ToList();
            if (other.Count > 0)
            {
                groups.Add(new TileGroup(
                    "Other measurements",
                    "In the report as sent.",
                    other.Select(name => Tile(new MeasurementInfo(name, name, "Not described here.", MeasurementGroup.Device))).ToList()));
            }

            return groups;
        }

        /// <summary>Every field, nested objects and lists indented under their name.</summary>
        public static IReadOnlyList<FieldRow> FieldRows(JsonObject fields, int depth = 0)
        {
            var rows = new List<FieldRow>();
            foreach (var (name, value) in fields)
            {
                if (value is JsonObject map && map.Count > 0)
                {
                    rows.Add(new FieldRow(name, string.Empty, depth));
                    rows.AddRange(FieldRows(map, depth + 1));
                }
                else if (value is JsonArray list && list.Any(item => item is JsonObject))
                {
                    rows.Add(new FieldRow(name, list.Count.ToString(CultureInfo.InvariantCulture), depth));
                    for (var i = 0; i < list.Count; i++)
                    {
                        if (list[i] is JsonObject item)
                        {
                            var numbered = new JsonObject();
                            foreach (var (key, entry) in item)
                            {
                                numbered[(i + 1).ToString(CultureInfo.InvariantCulture) + ". " + key] = entry?.DeepClone();
                            }

                            rows.AddRange(FieldRows(numbered, depth + 1));
                        }
                        else
                        {
                            rows.Add(new FieldRow((i + 1).ToString(CultureInfo.InvariantCulture) + ".", Scalar(list[i]), depth + 1));
                        }
                    }
                }
                else
                {
                    rows.Add(new FieldRow(name, Scalar(value), depth));
                }
            }

            return rows;
        }

        private static MeasurementTile MakeTile(MeasurementInfo info, JsonObject? value, bool asked)
        {
            var partly = value?["unread"] is JsonObject unread && unread.Count > 0;
            var status = value is null
                ? (asked ? "missing" : "not asked")
                : value["status"] is JsonValue s && s.TryGetValue<string>(out var text) ? text : "no status";
            var notes = new List<string>();
            var fields = new List<FieldRow>();
            if (value is null)
            {
                notes.Add(asked
                    ? "Asked for, but not in the report: a backend refuses such a report."
                    : "Not asked for in this scan, so not measured.");
            }
            else
            {
                if (status == "not_enabled")
                {
                    notes.Add("The backend asked; this app has not turned it on.");
                }

                if (partly)
                {
                    notes.Add("Parts it could not read are not measured: never read them as a clean \"no\".");
                }

                var shown = new JsonObject();
                foreach (var (key, entry) in value)
                {
                    if (key != "status")
                    {
                        shown[key] = entry?.DeepClone();
                    }
                }

                fields.AddRange(FieldRows(shown));
            }

            var truncated = value?["truncated"] is JsonValue t && t.TryGetValue<bool>(out var cut) && cut;
            return new MeasurementTile(
                info,
                StatusLabels.TryGetValue(status, out var label) ? label : status,
                status == "error" || status == "missing" || (status == "not asked" && info.Group == MeasurementGroup.Hooks),
                partly,
                truncated,
                notes,
                fields);
        }

        private static string Scalar(JsonNode? value)
        {
            switch (value)
            {
                case null:
                    return "null";
                case JsonArray list:
                    return list.Count == 0 ? "none" : string.Join(", ", list.Select(Scalar));
                case JsonObject:
                    return "none";
                case JsonValue scalar:
                    if (scalar.TryGetValue<bool>(out var flag))
                    {
                        return flag ? "yes" : "no";
                    }

                    var text = scalar.TryGetValue<string>(out var s) ? s : scalar.ToJsonString();
                    return text.Length == 0 ? "\"\"" : text;
                default:
                    return value.ToJsonString();
            }
        }
    }
}
