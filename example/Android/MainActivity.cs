// The package against its sample backends (../../backend), section by section:
// the installation, the scan with every measurement it sent, an account,
// requests with and without the person's approval, and requests a backend
// must refuse. ../Shared holds what the iOS screen shares: the setup, the
// sample's API, the measurements view's content and the action runner; this
// file is the Android screen.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Graphics;
using Android.OS;
using Android.Text;
using Android.Views;
using Android.Widget;

namespace Necessary.Example
{
    [Activity(
        Label = "Necessary .NET",
        MainLauncher = true,
        Exported = true,
        Theme = "@android:style/Theme.Material.Light.DarkActionBar",
        ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.KeyboardHidden
            | ConfigChanges.Keyboard | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.UiMode,
        WindowSoftInputMode = SoftInput.AdjustResize)]
    public class MainActivity : Activity
    {
        private readonly HashSet<string> open = new HashSet<string> { "Installation" };
        private readonly HashSet<string> openTiles = new HashSet<string>();
        private ExampleSession session = null!;
        private LinearLayout content = null!;
        private EditText handle = null!;
        private EditText password = null!;
        private EditText pin = null!;
        private EditText shared = null!;
        private View? useItHere;
        private bool busy;
        private bool screenProtected;

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            // The package tracks the activity in the foreground: the step-up
            // prompt, screen protection and the location request need it.
            NecessaryAndroid.Init(this);
            session = new ExampleSession();
            handle = Input("Handle", "example", InputTypes.ClassText);
            password = Input("Password", "example password", InputTypes.ClassText | InputTypes.TextVariationPassword);
            pin = Input("App PIN (6 digits)", string.Empty, InputTypes.ClassNumber | InputTypes.NumberVariationPassword);
            pin.SetFilters(new IInputFilter[] { new InputFilterLengthFilter(6) });
            shared = Input("A session from another phone", string.Empty, InputTypes.ClassText | InputTypes.TextFlagMultiLine);
            shared.TextChanged += (_, _) =>
            {
                if (useItHere is not null)
                {
                    useItHere.Enabled = !busy && session.Trust.InstallationSession is not null && (shared.Text ?? string.Empty).Trim().Length > 0;
                }
            };

            // No screenshots or recordings of the window while a secret is typed.
            password.FocusChange += (_, _) => ProtectSecrets();
            pin.FocusChange += (_, _) => ProtectSecrets();
            var scroll = new ScrollView(this);
            content = new LinearLayout(this) { Orientation = Orientation.Vertical };
            content.SetPadding(Dp(12), Dp(12), Dp(12), Dp(32));
            scroll.AddView(content);
            SetContentView(scroll);
            Render();
        }

        protected override void OnDestroy()
        {
            if (screenProtected)
            {
                _ = SecureScreen.ProtectAsync(false);
            }

            session.Trust.Close();
            base.OnDestroy();
        }

        private void ProtectSecrets()
        {
            var typing = password.HasFocus || pin.HasFocus;
            if (typing != screenProtected)
            {
                screenProtected = typing;
                _ = SecureScreen.ProtectAsync(typing);
            }
        }

        private int Dp(int value) => (int)(value * Resources!.DisplayMetrics!.Density);

        private EditText Input(string hint, string text, InputTypes type)
        {
            var input = new EditText(this) { Hint = hint, InputType = type };
            input.Text = text;
            return input;
        }

        private async Task Run(string section, string action, Func<Task<string>> step, Expect expect = Expect.Accepted)
        {
            busy = true;
            Render();
            await session.RunAsync(section, action, step, expect);
            busy = false;
            Render();
        }

        // --- The screen, drawn again after every action.
        private void Render()
        {
            if (content is null)
            {
                return;
            }

            foreach (var input in new[] { handle, password, pin, shared })
            {
                (input.Parent as ViewGroup)?.RemoveView(input);
            }

            content.RemoveAllViews();
            var trust = session.Trust;
            var started = trust.InstallationSession is not null;
            var signedIn = session.Api.Account is not null;
            if (ExampleSetup.Backends.Count > 1)
            {
                content.AddView(Actions(ExampleSetup.Backends.Select(entry =>
                    (View)ButtonView(entry.Key, !busy && entry.Key != session.BackendName, () =>
                    {
                        session.Choose(entry.Key);
                        Render();
                    })).ToArray()));
            }

            content.AddView(Small("Backend: " + session.BackendUrl + (busy ? "   …working" : string.Empty)));
            Section("Installation", started ? "Its key made, registered and proved" : "Start: make the key, register it, prove it", Installation(started));
            var scan = session.LastScan;
            Section(
                "Measurements",
                scan is null ? "What the phone measures, signed with its key" : ((JsonObject)scan.Report.Report["probe_results"]!).Count + " sent in the last scan",
                MeasurementsSection(started));
            Section("Account", signedIn ? "Signed in" : "Sign in to the sample backend", Account(started, signedIn));
            Section("Requests", "A proof on each; the person's approval on a sensitive one", Requests(signedIn));
            Section("Requests a backend must refuse", "Made wrong on purpose", Refusals(started, signedIn));
            Section("Log", session.Log.Count + " results, the latest first", session.Log.Select(OutcomeLine).ToList());
        }

        private List<View> Installation(bool started)
        {
            var trust = session.Trust;
            var identity = trust.Identity;
            var stepUp = trust.StepUpKey;
            var stepUpOff = trust.StepUpUnavailable;
            var views = new List<View>
            {
                Actions(
                    Button("Installation", started ? "Start again" : "Start", session.StartAsync),
                    Button("Installation", "Prove again", session.ProveAsync, started),
                    ButtonView("New installation", !busy && identity is not null, ConfirmNewInstallation)),
                LatestLine("Installation"),
            };
            if (identity is not null)
            {
                views.Add(Field("Installation ID", identity.InstallationId));
                views.Add(Field("Key thumbprint", identity.KeyThumbprint));
                views.Add(Field("Key", identity.Algorithm + ", " + identity.Provider + ", " + identity.SecurityLevel));
                views.Add(Field("Hardware-backed", identity.HardwareBacked ? "yes" : "no"));
                views.Add(Field("Can leave the phone", identity.PrivateKeyExportable ? "yes" : "no"));
                views.Add(Field("New this launch", identity.CreatedThisLaunch ? "yes" : "no"));
                views.Add(Field(
                    "Step-up key",
                    stepUp is not null ? stepUp.Description + ", " + stepUp.SecurityLevel
                    : stepUpOff is not null ? "off on this phone: " + stepUpOff.Code
                    : "made at start"));
            }

            return views;
        }

        private void ConfirmNewInstallation()
        {
            new AlertDialog.Builder(this)
                .SetTitle("A new installation?")!
                .SetMessage("This deletes the installation key, its ID and the step-up key, as a reinstall would, and starts again with new keys.")!
                .SetNegativeButton("Cancel", (_, _) => { })!
                .SetPositiveButton("Start again", async (_, _) => await Run("Installation", "New installation", session.NewInstallationAsync))!
                .Show();
        }

        private List<View> MeasurementsSection(bool started)
        {
            var trust = session.Trust;
            var enabled = trust.PersonalMeasurements;
            var locationOn = enabled.Contains(PersonalMeasurement.Location) || enabled.Contains(PersonalMeasurement.MockLocation);
            var views = new List<View>
            {
                Heading("Personal measurements"),
                Small("Measured only when this app turns one on and the backend asks for it. None is on until the app says so."),
                Switch("All of them", null, enabled.Count == PersonalMeasurements.All.Count, on =>
                    trust.PersonalMeasurements = on ? PersonalMeasurements.All.ToArray() : Array.Empty<PersonalMeasurement>()),
            };
            foreach (var measurement in PersonalMeasurements.All)
            {
                var info = Measurements.PersonalInfo(measurement);
                views.Add(Switch(info.Title, info.About, enabled.Contains(measurement), on =>
                    trust.PersonalMeasurements = on
                        ? enabled.Append(measurement).ToArray()
                        : enabled.Where(item => item != measurement).ToArray()));
            }

            views.Add(Code(Measurements.PersonalCode(trust.PersonalMeasurements)));
            if (locationOn)
            {
                views.Add(Actions(Button(
                    "Measurements",
                    session.LocationPermission is null ? "Ask for the location permission" : "Location permission: " + session.LocationPermission,
                    session.AskLocationAsync)));
            }

            views.Add(Actions(Button("Measurements", "Scan", session.ScanAsync, started)));
            views.Add(LatestLine("Measurements"));
            var scan = session.LastScan;
            if (scan is not null)
            {
                views.Add(Italic("The phone reports what it measured; your backend decides what it means."));
                var groups = Measurements.Groups(
                    scan.Challenge.Platform,
                    scan.Challenge.RequiredProbes,
                    scan.Challenge.OptionalProbes,
                    (JsonObject)scan.Report.Report["probe_results"]!,
                    ((JsonArray)scan.Report.Report["enabled_measurements"]!).Select(item => (string)item!).ToList());
                foreach (var group in groups)
                {
                    views.Add(Heading(group.Title));
                    views.Add(Small(group.Note));
                    if (group.Tiles.Count == 0)
                    {
                        views.Add(Small("The backend asked for none."));
                    }

                    foreach (var tile in group.Tiles)
                    {
                        views.AddRange(Tile(tile));
                    }
                }
            }

            return views;
        }

        private IEnumerable<View> Tile(MeasurementTile tile)
        {
            var badges = (tile.Unread ? "  [unread]" : string.Empty) + (tile.Truncated ? "  [truncated]" : string.Empty) + "  [" + tile.Status + "]";
            var header = new TextView(this) { Text = tile.Info.Title + badges + "\n" + tile.Info.Name };
            header.SetTypeface(Typeface.Monospace, TypefaceStyle.Normal);
            header.SetTextColor(tile.Warning || tile.Unread ? Color.Rgb(176, 0, 32) : Color.Black);
            header.SetPadding(0, Dp(6), 0, Dp(6));
            var key = tile.Info.Name;
            header.Click += (_, _) =>
            {
                if (!openTiles.Remove(key))
                {
                    openTiles.Add(key);
                }

                Render();
            };
            yield return header;
            if (!openTiles.Contains(key))
            {
                yield break;
            }

            yield return Small(tile.Info.About);
            foreach (var note in tile.Notes)
            {
                yield return Small(note);
            }

            foreach (var row in tile.Fields)
            {
                var line = new TextView(this) { Text = row.Name + (row.Value.Length > 0 ? ": " + row.Value : string.Empty) };
                line.SetTextIsSelectable(true);
                line.SetPadding(Dp(12 * row.Depth), Dp(1), 0, Dp(1));
                line.TextSize = 12;
                yield return line;
            }
        }

        private List<View> Account(bool started, bool signedIn) => new List<View>
        {
            handle,
            password,
            Small("The sample makes the account at its first sign-in"),
            Actions(
                Button("Account", "Sign in", () => session.SignInAsync(handle.Text ?? string.Empty, password.Text ?? string.Empty), started),
                ButtonView("Sign out", !busy && signedIn, () =>
                {
                    session.Api.Account = null;
                    Render();
                })),
            LatestLine("Account"),
        };

        private List<View> Requests(bool signedIn) => new List<View>
        {
            Small("Each request carries a proof signed by this installation's key. The sensitive one also needs the person's approval: the step-up key, unlocked with the screen lock, or the app PIN."),
            Actions(
                Button("Requests", "Protected request", async () => (await session.Api.ProtectedRequestAsync()).ToJsonString(), signedIn),
                Button("Requests", "Sensitive, without approval", async () => (await session.Api.SensitiveAsync()).ToJsonString(), signedIn, Expect.Refused),
                Button("Requests", "Sensitive, with step-up", async () => (await session.Api.SensitiveAsync(stepUp: true)).ToJsonString(), signedIn),
                Button("Requests", "Re-enrol the step-up key", async () => (await session.Api.ReenrolStepUpAsync(password.Text ?? string.Empty)).ToJsonString(), signedIn)),
            pin,
            Small("The screen is protected while it is typed"),
            Actions(
                Button("Requests", "Set the app PIN", async () =>
                {
                    await session.Api.SetAppPinAsync(pin.Text ?? string.Empty, password.Text ?? string.Empty);
                    return "Set, with the account password.";
                }, signedIn),
                Button("Requests", "Sensitive, with the app PIN", async () => (await session.Api.SensitiveAsync(appPin: pin.Text ?? string.Empty)).ToJsonString(), signedIn)),
            LatestLine("Requests"),
        };

        private List<View> Refusals(bool started, bool signedIn) => new List<View>
        {
            Small("Each of these is a request made wrong on purpose. A backend that makes the guide's checks refuses every one."),
            Actions(
                Refusal("Send one request twice", session.Api.ReplayAsync, signedIn),
                Refusal("Change the body after signing", session.Api.ChangedBodyAsync, signedIn),
                Refusal("Send it to another path", session.Api.OtherPathAsync, signedIn),
                Refusal("A proof ten minutes old", session.Api.StaleProofAsync, signedIn)),
            Heading("A session copied to another phone"),
            Small("Copy this phone's session, get it to another phone running this example, paste it there and use it: that phone's key cannot sign for this installation."),
            Actions(ButtonView("Copy this phone's session", !busy && signedIn, CopySession)),
            shared,
            Actions(useItHere = Refusal("Use it here", () => session.Api.SessionFromAnotherPhoneAsync(shared.Text ?? string.Empty), started && (shared.Text ?? string.Empty).Trim().Length > 0)),
            LatestLine("Refusals"),
        };

        private void CopySession()
        {
            var clipboard = GetSystemService(ClipboardService) as Android.Content.ClipboardManager;
            if (clipboard is not null)
            {
                clipboard.PrimaryClip = ClipData.NewPlainText("session", session.Api.ShareSession());
            }
            Toast.MakeText(this, "Copied this phone's session", ToastLength.Short)?.Show();
        }

        // --- Pieces of the screen.
        private void Section(string title, string subtitle, List<View> children)
        {
            var header = new TextView(this) { Text = (open.Contains(title) ? "▾ " : "▸ ") + title + "\n" + subtitle };
            header.TextSize = 17;
            header.SetPadding(0, Dp(14), 0, Dp(6));
            header.SetTextColor(Color.Rgb(0, 105, 92));
            header.Click += (_, _) =>
            {
                if (!open.Remove(title))
                {
                    open.Add(title);
                }

                Render();
            };
            content.AddView(header);
            if (!open.Contains(title))
            {
                return;
            }

            foreach (var child in children)
            {
                content.AddView(child);
            }
        }

        private View Button(string section, string label, Func<Task<string>> step, bool enabled = true, Expect expect = Expect.Accepted) =>
            ButtonView(label, !busy && enabled, async () => await Run(section, label, step, expect));

        private View Refusal(string label, Func<Task<JsonObject>> step, bool enabled) =>
            Button("Refusals", label, async () => (await step()).ToJsonString(), enabled, Expect.Refused);

        private View ButtonView(string label, bool enabled, Action click)
        {
            var button = new Android.Widget.Button(this) { Text = label, Enabled = enabled };
            button.SetAllCaps(false);
            button.Click += (_, _) => click();
            return button;
        }

        private View Actions(params View[] buttons)
        {
            var row = new LinearLayout(this) { Orientation = Orientation.Vertical };
            foreach (var button in buttons)
            {
                row.AddView(button);
            }

            return row;
        }

        private View Switch(string title, string? about, bool on, Action<bool> changed)
        {
            var toggle = new Android.Widget.Switch(this) { Text = about is null ? title : title + "\n" + about, Checked = on, Enabled = !busy };
            toggle.CheckedChange += (_, args) =>
            {
                changed(args.IsChecked);
                Render();
            };
            return toggle;
        }

        private View LatestLine(string section) =>
            session.Latest.TryGetValue(section, out var outcome) ? OutcomeLine(outcome) : new View(this);

        private View OutcomeLine(Outcome outcome)
        {
            var line = new TextView(this) { Text = (outcome.AsExpected ? "✓ " : "✗ ") + outcome.Action + ": " + outcome.Text };
            line.SetTextIsSelectable(true);
            line.SetTextColor(outcome.AsExpected ? Color.Rgb(0, 105, 92) : Color.Rgb(176, 0, 32));
            line.SetPadding(0, Dp(4), 0, Dp(4));
            return line;
        }

        private View Field(string label, string value)
        {
            var line = new TextView(this) { Text = label + ": " + value };
            line.SetTextIsSelectable(true);
            return line;
        }

        private View Heading(string text)
        {
            var title = new TextView(this) { Text = text };
            title.SetTypeface(null, TypefaceStyle.Bold);
            title.SetPadding(0, Dp(10), 0, Dp(2));
            return title;
        }

        private View Small(string text) => new TextView(this) { Text = text, TextSize = 12 };

        private View Italic(string text)
        {
            var view = new TextView(this) { Text = text, TextSize = 12 };
            view.SetTypeface(null, TypefaceStyle.Italic);
            return view;
        }

        private View Code(string text)
        {
            var view = new TextView(this) { Text = text, TextSize = 12 };
            view.SetTypeface(Typeface.Monospace, TypefaceStyle.Normal);
            view.SetBackgroundColor(Color.Rgb(236, 239, 241));
            view.SetPadding(Dp(10), Dp(10), Dp(10), Dp(10));
            view.SetTextIsSelectable(true);
            return view;
        }
    }
}
