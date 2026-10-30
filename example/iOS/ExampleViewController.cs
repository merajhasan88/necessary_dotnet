// The package against its sample backends (../../backend), section by section,
// on iOS: the same sections, actions and texts as the Android screen, from the
// same ../Shared code.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using CoreGraphics;
using Foundation;
using UIKit;

namespace Necessary.Example
{
    public sealed class ExampleViewController : UIViewController
    {
        private static readonly UIColor Teal = UIColor.FromRGB(0, 105, 92);
        private static readonly UIColor Red = UIColor.FromRGB(176, 0, 32);

        private readonly HashSet<string> open = new HashSet<string> { "Installation" };
        private readonly HashSet<string> openTiles = new HashSet<string>();
        private readonly ExampleSession session = new ExampleSession();
        private readonly UIStackView stack = new UIStackView { Axis = UILayoutConstraintAxis.Vertical, Spacing = 6 };
        private readonly UITextField handle = Field("Handle", "example", secure: false, numeric: false);
        private readonly UITextField password = Field("Password", "example password", secure: true, numeric: false);
        private readonly UITextField pin = Field("App PIN (6 digits)", string.Empty, secure: true, numeric: true);
        private readonly UITextField shared = Field("A session from another phone", string.Empty, secure: false, numeric: false);
        private UIButton? useItHere;
        private bool busy;
        private bool screenProtected;

        public override void ViewDidLoad()
        {
            base.ViewDidLoad();
            Title = "Necessary";
            View!.BackgroundColor = UIColor.SystemBackground;
            var scroll = new UIScrollView { TranslatesAutoresizingMaskIntoConstraints = false, KeyboardDismissMode = UIScrollViewKeyboardDismissMode.OnDrag };
            stack.TranslatesAutoresizingMaskIntoConstraints = false;
            scroll.AddSubview(stack);
            View.AddSubview(scroll);
            NSLayoutConstraint.ActivateConstraints(new[]
            {
                scroll.TopAnchor.ConstraintEqualTo(View.SafeAreaLayoutGuide.TopAnchor),
                scroll.BottomAnchor.ConstraintEqualTo(View.BottomAnchor),
                scroll.LeadingAnchor.ConstraintEqualTo(View.LeadingAnchor),
                scroll.TrailingAnchor.ConstraintEqualTo(View.TrailingAnchor),
                stack.TopAnchor.ConstraintEqualTo(scroll.TopAnchor, 12),
                stack.BottomAnchor.ConstraintEqualTo(scroll.BottomAnchor, -32),
                stack.LeadingAnchor.ConstraintEqualTo(scroll.LeadingAnchor, 12),
                stack.TrailingAnchor.ConstraintEqualTo(scroll.TrailingAnchor, -12),
                stack.WidthAnchor.ConstraintEqualTo(scroll.WidthAnchor, 1, -24),
            });

            // No recordings of the window while a secret is typed: on iOS, a cover
            // whenever the screen is captured.
            foreach (var secret in new[] { password, pin })
            {
                secret.EditingDidBegin += (_, _) => ProtectSecrets();
                secret.EditingDidEnd += (_, _) => ProtectSecrets();
            }

            shared.EditingChanged += (_, _) =>
            {
                if (useItHere is not null)
                {
                    useItHere.Enabled = !busy && session.Trust.InstallationSession is not null && (shared.Text ?? string.Empty).Trim().Length > 0;
                }
            };
            Render();
        }

        private static UITextField Field(string placeholder, string text, bool secure, bool numeric) => new UITextField
        {
            Placeholder = placeholder,
            Text = text,
            SecureTextEntry = secure,
            KeyboardType = numeric ? UIKeyboardType.NumberPad : UIKeyboardType.Default,
            AutocorrectionType = UITextAutocorrectionType.No,
            AutocapitalizationType = UITextAutocapitalizationType.None,
            BorderStyle = UITextBorderStyle.RoundedRect,
        };

        private void ProtectSecrets()
        {
            var typing = password.IsFirstResponder || pin.IsFirstResponder;
            if (typing != screenProtected)
            {
                screenProtected = typing;
                _ = SecureScreen.ProtectAsync(typing);
            }
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
            foreach (var view in stack.ArrangedSubviews)
            {
                stack.RemoveArrangedSubview(view);
                view.RemoveFromSuperview();
            }

            var trust = session.Trust;
            var started = trust.InstallationSession is not null;
            var signedIn = session.Api.Account is not null;
            if (ExampleSetup.Backends.Count > 1)
            {
                foreach (var entry in ExampleSetup.Backends)
                {
                    Append(ButtonView(entry.Key, !busy && entry.Key != session.BackendName, () =>
                    {
                        session.Choose(entry.Key);
                        Render();
                    }));
                }
            }

            Append(Small("Backend: " + session.BackendUrl + (busy ? "   …working" : string.Empty)));
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

        private List<UIView> Installation(bool started)
        {
            var trust = session.Trust;
            var identity = trust.Identity;
            var stepUp = trust.StepUpKey;
            var stepUpOff = trust.StepUpUnavailable;
            var views = new List<UIView>
            {
                Button("Installation", started ? "Start again" : "Start", session.StartAsync),
                Button("Installation", "Prove again", session.ProveAsync, started),
                ButtonView("New installation", !busy && identity is not null, ConfirmNewInstallation),
                LatestLine("Installation"),
            };
            if (identity is not null)
            {
                views.Add(Line("Installation ID: " + identity.InstallationId));
                views.Add(Line("Key thumbprint: " + identity.KeyThumbprint));
                views.Add(Line("Key: " + identity.Algorithm + ", " + identity.Provider + ", " + identity.SecurityLevel));
                views.Add(Line("Hardware-backed: " + (identity.HardwareBacked ? "yes" : "no")));
                views.Add(Line("Can leave the phone: " + (identity.PrivateKeyExportable ? "yes" : "no")));
                views.Add(Line("New this launch: " + (identity.CreatedThisLaunch ? "yes" : "no")));
                views.Add(Line("Step-up key: " + (
                    stepUp is not null ? stepUp.Description + ", " + stepUp.SecurityLevel
                    : stepUpOff is not null ? "off on this phone: " + stepUpOff.Code
                    : "made at start")));
            }

            return views;
        }

        private void ConfirmNewInstallation()
        {
            var alert = UIAlertController.Create(
                "A new installation?",
                "This deletes the installation key, its ID and the step-up key, as a reinstall would, and starts again with new keys.",
                UIAlertControllerStyle.Alert);
            alert.AddAction(UIAlertAction.Create("Cancel", UIAlertActionStyle.Cancel, null));
            alert.AddAction(UIAlertAction.Create("Start again", UIAlertActionStyle.Default, async _ =>
                await Run("Installation", "New installation", session.NewInstallationAsync)));
            PresentViewController(alert, true, null);
        }

        private List<UIView> MeasurementsSection(bool started)
        {
            var trust = session.Trust;
            var enabled = trust.PersonalMeasurements;
            var locationOn = enabled.Contains(PersonalMeasurement.Location) || enabled.Contains(PersonalMeasurement.MockLocation);
            var views = new List<UIView>
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
                views.Add(Button(
                    "Measurements",
                    session.LocationPermission is null ? "Ask for the location permission" : "Location permission: " + session.LocationPermission,
                    session.AskLocationAsync));
            }

            views.Add(Button("Measurements", "Scan", session.ScanAsync, started));
            views.Add(LatestLine("Measurements"));
            var scan = session.LastScan;
            if (scan is not null)
            {
                views.Add(Small("The phone reports what it measured; your backend decides what it means."));
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

        private IEnumerable<UIView> Tile(MeasurementTile tile)
        {
            var badges = (tile.Unread ? "  [unread]" : string.Empty) + (tile.Truncated ? "  [truncated]" : string.Empty) + "  [" + tile.Status + "]";
            var key = tile.Info.Name;
            var header = ButtonView(tile.Info.Title + badges + "\n" + tile.Info.Name, true, () =>
            {
                if (!openTiles.Remove(key))
                {
                    openTiles.Add(key);
                }

                Render();
            });
            header.SetTitleColor(tile.Warning || tile.Unread ? Red : UIColor.Label, UIControlState.Normal);
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
                yield return Small(new string(' ', 3 * row.Depth) + row.Name + (row.Value.Length > 0 ? ": " + row.Value : string.Empty));
            }
        }

        private List<UIView> Account(bool started, bool signedIn) => new List<UIView>
        {
            handle,
            password,
            Small("The sample makes the account at its first sign-in"),
            Button("Account", "Sign in", () => session.SignInAsync(handle.Text ?? string.Empty, password.Text ?? string.Empty), started),
            ButtonView("Sign out", !busy && signedIn, () =>
            {
                session.Api.Account = null;
                Render();
            }),
            LatestLine("Account"),
        };

        private List<UIView> Requests(bool signedIn) => new List<UIView>
        {
            Small("Each request carries a proof signed by this installation's key. The sensitive one also needs the person's approval: the step-up key, unlocked with the screen lock, or the app PIN."),
            Button("Requests", "Protected request", async () => (await session.Api.ProtectedRequestAsync()).ToJsonString(), signedIn),
            Button("Requests", "Sensitive, without approval", async () => (await session.Api.SensitiveAsync()).ToJsonString(), signedIn, Expect.Refused),
            Button("Requests", "Sensitive, with step-up", async () => (await session.Api.SensitiveAsync(stepUp: true)).ToJsonString(), signedIn),
            Button("Requests", "Re-enrol the step-up key", async () => (await session.Api.ReenrolStepUpAsync(password.Text ?? string.Empty)).ToJsonString(), signedIn),
            pin,
            Small("The screen is protected while it is typed"),
            Button("Requests", "Set the app PIN", async () =>
            {
                await session.Api.SetAppPinAsync(pin.Text ?? string.Empty, password.Text ?? string.Empty);
                return "Set, with the account password.";
            }, signedIn),
            Button("Requests", "Sensitive, with the app PIN", async () => (await session.Api.SensitiveAsync(appPin: pin.Text ?? string.Empty)).ToJsonString(), signedIn),
            LatestLine("Requests"),
        };

        private List<UIView> Refusals(bool started, bool signedIn)
        {
            useItHere = Refusal("Use it here", () => session.Api.SessionFromAnotherPhoneAsync(shared.Text ?? string.Empty), started && (shared.Text ?? string.Empty).Trim().Length > 0);
            return new List<UIView>
            {
                Small("Each of these is a request made wrong on purpose. A backend that makes the guide's checks refuses every one."),
                Refusal("Send one request twice", session.Api.ReplayAsync, signedIn),
                Refusal("Change the body after signing", session.Api.ChangedBodyAsync, signedIn),
                Refusal("Send it to another path", session.Api.OtherPathAsync, signedIn),
                Refusal("A proof ten minutes old", session.Api.StaleProofAsync, signedIn),
                Heading("A session copied to another phone"),
                Small("Copy this phone's session, get it to another phone running this example, paste it there and use it: that phone's key cannot sign for this installation."),
                ButtonView("Copy this phone's session", !busy && signedIn, () =>
                {
                    UIPasteboard.General.String = session.Api.ShareSession();
                    var copied = UIAlertController.Create(null, "Copied this phone's session", UIAlertControllerStyle.Alert);
                    copied.AddAction(UIAlertAction.Create("OK", UIAlertActionStyle.Default, null));
                    PresentViewController(copied, true, null);
                }),
                shared,
                useItHere,
                LatestLine("Refusals"),
            };
        }

        // --- Pieces of the screen.
        private void Append(UIView view) => stack.AddArrangedSubview(view);

        private void Section(string title, string subtitle, List<UIView> children)
        {
            var header = ButtonView((open.Contains(title) ? "▾ " : "▸ ") + title + "\n" + subtitle, true, () =>
            {
                if (!open.Remove(title))
                {
                    open.Add(title);
                }

                Render();
            });
            header.SetTitleColor(Teal, UIControlState.Normal);
            header.TitleLabel.Font = UIFont.BoldSystemFontOfSize(17);
            Append(header);
            if (!open.Contains(title))
            {
                return;
            }

            foreach (var child in children)
            {
                Append(child);
            }
        }

        private UIButton Button(string section, string label, Func<Task<string>> step, bool enabled = true, Expect expect = Expect.Accepted) =>
            ButtonView(label, !busy && enabled, async () => await Run(section, label, step, expect));

        private UIButton Refusal(string label, Func<Task<JsonObject>> step, bool enabled) =>
            Button("Refusals", label, async () => (await step()).ToJsonString(), enabled, Expect.Refused);

        private static UIButton ButtonView(string label, bool enabled, Action tap)
        {
            var button = UIButton.FromType(UIButtonType.System);
            button.SetTitle(label, UIControlState.Normal);
            button.TitleLabel.Lines = 0;
            button.HorizontalAlignment = UIControlContentHorizontalAlignment.Leading;
            button.Enabled = enabled;
            button.TouchUpInside += (_, _) => tap();
            return button;
        }

        private UIView Switch(string title, string? about, bool on, Action<bool> changed)
        {
            var toggle = new UISwitch { On = on, Enabled = !busy };
            toggle.ValueChanged += (_, _) =>
            {
                changed(toggle.On);
                Render();
            };
            var label = new UILabel { Text = about is null ? title : title + "\n" + about, Lines = 0, Font = UIFont.SystemFontOfSize(14) };
            var row = new UIStackView(new UIView[] { label, toggle }) { Axis = UILayoutConstraintAxis.Horizontal, Spacing = 8, Alignment = UIStackViewAlignment.Center };
            return row;
        }

        private UIView LatestLine(string section) =>
            session.Latest.TryGetValue(section, out var outcome) ? OutcomeLine(outcome) : new UIView();

        private static UIView OutcomeLine(Outcome outcome) => new UILabel
        {
            Text = (outcome.AsExpected ? "✓ " : "✗ ") + outcome.Action + ": " + outcome.Text,
            Lines = 0,
            TextColor = outcome.AsExpected ? Teal : Red,
            Font = UIFont.SystemFontOfSize(14),
        };

        private static UIView Line(string text) => new UILabel { Text = text, Lines = 0, Font = UIFont.SystemFontOfSize(14) };

        private static UIView Heading(string text) => new UILabel { Text = text, Lines = 0, Font = UIFont.BoldSystemFontOfSize(15) };

        private static UIView Small(string text) => new UILabel { Text = text, Lines = 0, Font = UIFont.SystemFontOfSize(12) };

        private static UIView Code(string text) => new UILabel
        {
            Text = text,
            Lines = 0,
            Font = UIFont.FromName("Menlo", 12) ?? UIFont.SystemFontOfSize(12),
            BackgroundColor = UIColor.SecondarySystemBackground,
        };
    }
}
