# necessary for .NET

Device integrity for .NET apps on Android and iOS. The package gives your app a key it never exports — made
in the phone's keystore, in secure hardware where the phone has it and in software where it does not —
signed measurements of the phone and of the app running on it, and a proof on each request your app
sends — and, if you turn them on, a second key the person must unlock to approve a request, and a
PIN your backend checks. **It never scores and never decides: your backend does.**

It is the .NET translation of the Flutter plugin
[`necessary`](https://pub.dev/packages/necessary) 0.1.5: the same calls, the same messages byte for
byte, the same measurements and fields, the same behaviour when calls overlap, fail or are interrupted.
A backend written for one serves both.

Android 7.0 (API 24) and later, from `net9.0-android`; iOS 15 and later, from `net9.0-ios`. The
`net8.0` assembly carries the protocol alone, for code that brings its own key and collector.

## Documentation

- [The integration guide](doc/integration_guide.md) — the protocol: what the package sends, and how
  your backend checks it.
- [The measurements](doc/measurements.md) — everything the package measures on the phone, field by
  field: what each measurement is, how it is taken, and what a complete answer holds.
- [The measurement contract](contract/report-1/android-8-ios-5/) — the report's schema, its rules and
  sample reports. The folder's name is two versions: `report-1` is the report's format, and
  `android-8-ios-5` the lowest versions of the measuring code, the collector, that the contract
  accepts — 8 on Android and 5 on iOS (`collector_version`; this package's are 10 and 8). They are not
  the Android or iOS versions the package runs on, which are above.
- [The example app](example/) puts every piece below in a working app, on Android and on iOS, against
  the [sample backends](backend/) (in the repository, not the package). [Try the example
  app](#try-the-example-app), below, installs it and tests it step by step.

## Install

```sh
dotnet add package NecessarySdk
```

The package declares what its own features need — on Android its permissions and package queries are
merged into your manifest. Your app adds only what you choose to use:

- **Location measurements**: on Android `ACCESS_COARSE_LOCATION` (and `ACCESS_FINE_LOCATION` for a
  precise location) in your manifest; on iOS `NSLocationWhenInUseUsageDescription` in `Info.plist`.
  The package never asks by itself: call `trust.RequestLocationPermissionAsync()` from your own screen.
- **Biometric step-up on iOS**: `NSFaceIDUsageDescription` in `Info.plist`.
- **On Android**, tell the package which activity is in the foreground, once, from your first
  activity — the step-up prompt, screen protection and the location request use it:

  ```csharp
  protected override void OnCreate(Bundle? savedInstanceState)
  {
      base.OnCreate(savedInstanceState);
      NecessaryAndroid.Init(this);
  }
  ```

  The package follows every activity after it, and runs prompts for results and permissions through a
  transparent activity of its own: your activity forwards nothing.

## Start

```csharp
using Necessary;

var trust = new DeviceTrust(
    "https://api.example.com",
    // The personal measurements your app allows; your backend asks for what it needs of them.
    personalMeasurements: new[] { PersonalMeasurement.ScreenCapture });

await trust.StartAsync(); // loads or makes the key, registers it, proves it holds it
```

`StartAsync()` makes the guide's first three calls under the base URL: register the installation, ask
for a key challenge, answer it. Your backend answers each as the guide says. A new key is a new
installation: `trust.Identity!.CreatedThisLaunch` tells your app to forget what it kept for the old one.

## Scan

```csharp
ScanResult scan = await trust.ScanAsync();
JsonObject answer = scan.Answer; // your backend's answer, whole
```

The package measures what your backend's challenge asks for — and, of the personal measurements it
asks for, the ones your app enabled — signs the report with the installation key and sends it. It acts
on the guide's protocol errors once (a challenge expired, the installation session expired, the backend
lost the installation, a short wait); any other refusal reaches your app as an `ApiException`.

## Personal measurements

Seven measurements identify a person's phone, network or habits. Each is collected only when your app
enables it **and** your backend's challenge asks for it (`optional_probes`); otherwise the report says
`not_enabled`. None is on unless your app turns it on:

```csharp
trust.PersonalMeasurements = new[]
{
    PersonalMeasurement.ScreenCapture, // the screen recorded, mirrored or cast
    PersonalMeasurement.Location,      // the last location the phone already knows
};
```

Set them in the constructor, or change them whenever the person does — in a privacy setting: the next
scan follows, and the installation and its step-up key stay as they are.

| `PersonalMeasurement` | What it reports | Platforms |
|---|---|---|
| `LocalAddresses` | the phone's own IP addresses, link-local ones left out | both |
| `Accessibility` | the Accessibility services that are on, and the keyboard in use | Android |
| `NotificationAccess` | the apps allowed to read notifications | Android |
| `OtherAccess` | device-administrator apps, and known remote-control apps installed | Android |
| `ScreenCapture` | the screen being recorded, mirrored or cast | both |
| `Location` | the last location the phone already knows — never a fresh fix, never a prompt | both |
| `MockLocation` | whether that location was faked | both |

The location needs the person's permission as well: declare it (Install, above) and ask from your own
screen with `await trust.RequestLocationPermissionAsync()`, which answers `precise`, `approximate` or
`none`. On iOS the three Android-only measurements answer `unsupported`.

## Prove your own requests

Every request your app sends to your own API can carry a proof that this installation's key signed it,
so a copied session token is useless on another phone:

```csharp
var body = "{\"amount\":25,\"to\":\"payee-7\"}";
RequestProof proof = await trust.SignRequestAsync(
    "POST",
    "/v1/transfer",
    accountSession,   // your backend's session for this installation
    body);            // sent exactly as signed

using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/v1/transfer")
{
    Content = new StringContent(body, Encoding.UTF8, "application/json"),
};
request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accountSession);
foreach (var header in proof.Headers)  // X-Access-Proof, X-Access-Signature
{
    request.Headers.Add(header.Key, header.Value);
}
```

Each proof serves its request once. `trust.SendAsync(proof)` sends it through the package's transport
instead.

## A scan for one action

For a request that matters — a payment, a new payee — have the scan name it, under the account session
that will send it, and send the scan's report with the request:

```csharp
var operation = RequestProofs.DescribeOperation("POST", "/v1/transfer", body);
var scan = await trust.ScanAsync(accountSession, operation);
var proof = await trust.SignRequestAsync(
    "POST",
    "/v1/transfer",
    accountSession,
    body,
    reportId: scan.ReportId); // X-Integrity-Report
```

## Step-up: the person approves one request

Turn it on, and choose how the key is unlocked:

```csharp
var trust = new DeviceTrust(
    "https://api.example.com",
    stepUp: new StepUpOptions(factor: "passcode", mode: "per_use"));
await trust.StartAsync(); // registers the step-up key with the installation

if (trust.StepUpUnavailable is not null)
{
    // This phone cannot make the key -- no screen lock, say. Step-up is off here.
}

var proof = await trust.SignRequestAsync(
    "POST",
    "/v1/transfer",
    accountSession,
    body,
    stepUp: true,
    reason: "Approve the transfer of 25"); // what the phone shows the person
```

| Option | Values |
|---|---|
| `factor` | `passcode` (the phone's PIN, pattern or password) or `biometric` (a fingerprint or face enrolled now) |
| `mode` | `per_use` (unlocked for every signature) or `windowed` with `windowSeconds` (one unlock for a while; Android only) |

Android 9 and 10 cannot ask for the passcode at every signature: there a passcode key is windowed, and
says so to your backend. iOS makes per-use keys only. An app whose backend sets the policy assigns
`trust.StepUp` before `StartAsync()`.

Removing the screen lock, or enrolling another biometric for a biometric key, makes the key unusable:
an approval then fails with `NativeKeyException` `STEPUP_KEY_INVALIDATED`. On Android the package
deletes the key only when Android itself says so; when the keystore cannot establish whether the key is
usable, or cannot be reached at all — a failure it may recover from — the approval fails with
`STEPUP_KEY_UNAVAILABLE` and the key is kept: try again later. The person re-enrols a new key with their
own re-authentication, which also replaces a key that stays unavailable:

```csharp
await trust.ReenrolStepUpAsync(
    accountSession,
    new JsonObject { ["password"] = password }); // as your backend requires
```

A new key is made, the person unlocks it to sign its proof, and your backend takes it for that account
alone; approvals use it from then on. The call goes to `/v1/installations/stepup-key`, or to your API's
own path: `new StepUpOptions(reenrolPath: ...)`. Until your backend has taken the new key — the person
cancelled the prompt, the password was wrong, the answer was lost — approvals fail with
`STEPUP_REENROL_PENDING`, across restarts too: call `ReenrolStepUpAsync` again. The same holds for a key
the phone made after the installation was registered — the screen lock was off at the first start and
set later, say — since your backend takes a step-up key only at an installation's first registration:
`StartAsync()` reports `StepUpUnavailable` `STEPUP_REENROL_PENDING`, and re-enrolment registers the key.

## The app PIN: the person's PIN for one request

Turn it on; the two paths default to the guide's and can be your API's own:

```csharp
var trust = new DeviceTrust(
    "https://api.example.com",
    appPin: new AppPinOptions()); // path: "/v1/account/app-pin", proofPath: "/v1/account/app-pin/proof"

// Setting it: with the person's own re-authentication, as your backend requires.
await trust.SetAppPinAsync(accountSession, pin, new JsonObject { ["password"] = password });

// Using it: your backend checks the PIN for this one request, and the request carries its proof.
var proof = await trust.SignRequestAsync("POST", "/v1/transfer", accountSession, body, appPin: pin);
```

The PIN travels once, in a signed body, never in a header, and the package never stores it. Protect the
screen while it is typed:

```csharp
await SecureScreen.ProtectAsync(true);  // Android: no screenshots or recording; iOS: covered while captured
// ... the PIN is typed ...
await SecureScreen.ProtectAsync(false);
```

Calls nest — each `ProtectAsync(true)` needs its `ProtectAsync(false)` — and when the last one ends the
window gets back what it had: a window your app keeps secure itself stays secure. On iOS the cover is
over your app's window, not the system keyboard. Opening Control Center to start a recording closes the
keyboard, so protect whenever the field has focus, as the example does.

Your backend's refusals reach your app as `ApiException` with the guide's codes: `app_pin_not_set`,
`app_pin_invalid` (it counts), `app_pin_locked` (a new PIN, set with the re-authentication, unlocks it).
Step-up and the app PIN combine: your backend decides which requests need which.

## What happens when

| When | What the package does |
|---|---|
| The key is lost — an Android reinstall, a cleared keystore | `StartAsync()` makes a new key and a new installation ID; `trust.Identity!.CreatedThisLaunch` is true, so forget what you kept for the old installation. Your backend links the two only provisionally, by the reinstall hint |
| Android's keystore cannot be reached | its lookups answer "no such key" then too, so the package makes a key only where the keystore, answering, holds none: `StartAsync()` fails with `NativeKeyException` `KEY_UNAVAILABLE`, sends nothing and keeps the installation as it is — call it again later; if it persists, `ResetAsync()` starts a new installation. Signing answers the same, and a step-up key `STEPUP_KEY_UNAVAILABLE` |
| iOS keeps the key across a reinstall | with its ID, the same installation comes back; without it, the package proposes a new ID, your backend answers with the one it holds for the key, and the package keeps that one |
| The app's process restarts | nothing is kept in memory: `StartAsync()` again finds the same key and installation, and proves it for a new installation session |
| The activity, a scene or a window is replaced | screen protection follows: Android sets it on each new window; on iOS the cover is placed again, on the window the person sees in each scene, whenever a window becomes key, visible or hidden or a scene comes to the foreground — and protection asked for before any window exists covers the first one. A step-up prompt the recreation cancelled answers `STEPUP_CANCELLED`: ask again |
| Two calls at once | `StartAsync()`, `ProveAsync()`, `LoadIdentityAsync()` and the same `ScanAsync()` run once, and the second caller gets the first's result; scans for different operations, or asked after the personal measurements changed, run apart. A `DeviceTrust` does its own work one step at a time, in order, on a scheduler of its own |
| A step-up prompt is open | on iOS the package's other calls — a scan, a request's signature — wait until the person answers it; Android runs them meanwhile |
| `ResetAsync()` or `Close()` while calls run | the calls end with `InterruptedCallException` and keep nothing — no session, no installation ID, no report sent, no request proof or app PIN answer handed out; a reset first waits for every write and key change still running, so none outlives it; after a reset, new calls wait for the deletion and never join one made before. A proof handed out before the reset, or a request already sent, is beyond it: reset is local |
| A key cannot be deleted | `ResetAsync()` fails with that `NativeKeyException` (`KEY_DELETE_FAILED`): call it again. If it is the installation key, the installation stays as it was, its ID with it; if it is the step-up key, the installation itself is already gone. None to delete, or no step-up on the phone, is no failure |
| A native call fails on Android | the `NativeKeyException`'s message says what failed, then everything beneath it — `[cause: …]`, each failure's kind and words down to the keystore's own answer, and from Android 13 the keystore's numeric code wherever Android passes it on — so a key that reads as unavailable or dead says what the keystore answered. A probe's `error` and each `unread` reason carry the same, within the contract's lengths |
| A call abandoned, or its answer lost | a scan is simply asked for again — a challenge serves once; the package never sends a signed request twice: sign it again, and let your backend decide whether the first one reached it |
| A report over 65,536 bytes | it is never sent: the app lists the contract lets a collector shorten are shortened, and say `truncated`; anything else answers an `ApiException` `report_too_large` |

## A release build talks only HTTPS

A release build refuses an `http://` base URL (`ApiException` `api_base_url_insecure`), and gives each
call 15 seconds. On Android a release build is one whose manifest is not debuggable; elsewhere, one whose
app assembly was compiled with optimizations.

## Your own transport

```csharp
var trust = DeviceTrust.Over(new MyTransport()); // implements IDeviceTrustTransport
```

A transport sends each message the package builds and answers your backend's JSON object, or throws an
`ApiException` with its `Code`, `Message` and `Details`. To carry the messages over an API of your own
shape instead, use the pieces directly — `trust.Client`, `Reports.CollectReportAsync`,
`RequestProofs.SignAsync` — and make the guide's checks in your backend.

## .NET and the memory a runtime compiles into

The measurements are the Flutter plugin's, field for field, and so is what they mean — with one
difference that comes from the runtime, not from the package. A Flutter app runs compiled Dart: the
memory both writable and executable that its release maps (`exec_mappings`: `wx_bytes`,
`wx_size_classes`, `wx_largest_bytes`) changed little between scans in the plugin's tests. **The .NET runtime
we tested on Android (Mono, as .NET 9 ships it) compiles each method the first time it runs it**, into
memory both writable and executable, and keeps it while the process runs: a .NET app's figures grow as
the app is used — after a sign-in, a step-up, every screen the person opens. On the phones we tested
it grew in 64 KiB blocks; that is an observation of the configurations tested, not a guarantee of .NET, and
no way to tell an attacker apart — one need not allocate differently.

So record your release's envelope as the integration guide's section 7.2 says, from your own runs of the
installed release build, but **over whole sessions, through your app's main features, not at a cold
start**: the most of each your release maps, per OS version, processor and page size, with the runtime
and build configuration you ship. A build compiled ahead of time (`-p:RunAOTCompilation=true`) maps
less. On iOS .NET is compiled ahead of time and maps none. Read these figures together with the other
measurements, against profiles of your own releases, and start in observation mode until you know what
your genuine users' phones show.

The code in memory (`code_integrity`) is compared with its files as the plugin compares it. On Android
the `app` region is the app's own: the APKs it was installed from, by their exact paths, and the .NET
runtime and its host by name (`libmonosgen-2.0.so`, `libmonodroid.so`, `libxamarin-app.so` and the
`System.*` native libraries), so `app_expected_bytes` is theirs. `app_complete` is complete over that
region, not over all of the app's code: the app's own executable files mapped outside it — an assembly
compiled ahead of time and extracted (`libaot-*.dll.so`), another library — are counted in
`app_outside_count` and named in `app_outside_files`. Code the runtime compiles while the app runs has no
file to compare with, and is not compared.

## What the package never does

It never scores, decides, or tells your app a score; never stores your account session; never sends the
PIN in a header; and uses no platform attestation (Play Integrity, SafetyNet, App Attest, DeviceCheck).
It never exports a private key, but it cannot prove to your backend where a key is kept: the
registration's `key_security` is the phone's own word, and where the secure hardware declines — the iOS
Simulator, some configurations — the key is a software key, which a compromised phone can copy. A fully
compromised phone can falsify what it measures and can use a genuine key to sign what it likes: the
measurements raise the cost of fraud, and your backend weighs them with its own business logic.

## Try the example app

The example app (`example/`) puts every piece above in a working app, against a sample backend. It is
the Flutter example's, screen for screen, so the steps below are the plugin's.

### Install it

The sample backends live in the repository, not in the package, so start from a clone.

1. Clone the repository and go into it.
2. Start a sample backend on your computer. It answers on `127.0.0.1` only. In Python 3.10 or later:

   ```sh
   pip install --require-hashes -r backend/python/requirements.txt
   python3 backend/python/server.py --port 8787 --schema contract/report-1/android-8-ios-5/report.schema.json
   ```

   The TypeScript and C# samples run the same way; their commands are in
   [`backend/README.md`](backend/README.md).
3. Build and run the example app, which needs the .NET 9 SDK with the `android` workload (and `ios`, on
   a Mac):
   - **On an Android emulator**, a debug build reaches your computer at `10.0.2.2`:

     ```sh
     dotnet build example/Android -t:Run -p:NecessaryBackendUrl=http://10.0.2.2:8787
     ```

   - **On an Android phone** connected by USB with USB debugging on, forward the port first:

     ```sh
     adb reverse tcp:8787 tcp:8787
     dotnet build example/Android -t:Run -p:NecessaryBackendUrl=http://127.0.0.1:8787
     ```

   - **A release build**, on Android or iOS, talks only HTTPS: the package refuses an `http://` address
     in a release build. Put the sample behind an HTTPS proxy on a name the phone can resolve, with a
     certificate the phone trusts, and give that address:

     ```sh
     dotnet publish example/Android -c Release -p:NecessaryBackendUrl=https://backend.example.com
     ```

   - **On an iPhone**, build `example/iOS` on a Mac with your signing identity, with the address of the
     HTTPS proxy: an iPhone reaches your computer over your network.

   To offer several backends, name each, the semicolons escaped for MSBuild:
   `-p:NecessaryBackends="Python=https://…%3BTypeScript=https://…"`.
   A debug build measures itself as one — `debuggable` in `app_identity` — so judge the measurements on
   a release build.

### Test it on a phone, step by step

With several backends, tap one at the top and run the steps once for each. Every result line carries a ✓
when the backend did what it should, a ✗ when it did not.

1. **Installation → Start.** Expect: `Installation …, proved; step-up on.` On a phone without a screen
   lock, step-up is off: `step-up off here (…)`, and step 7 cannot pass.
2. **Measurements:** switch on **All of them**, tap **Ask for the location permission** and allow it.
   Once is enough; the switches reset when the app restarts.
3. **Scan.** Expect: `The backend answered next: allow, report …` — the sample backends answer
   `scan_again` when a measurement could not be read, and `review` when its figures contradict each
   other. Under **Hooks, gadgets and memory changes** every row reads `measured`, none `not asked`. Tap
   any row for the fields the phone sent.
4. **Account → Sign in.** Expect: `An account session for this installation.`
5. **Requests → Protected request.** Expect: ✓ `{"done":"/v1/demo/echo"}`.
6. **Sensitive, without approval.** Expect: ✓ `Refused, as it should be: 403 needs_approval`.
7. **Sensitive, with step-up**, then unlock with the phone's passcode. Expect: ✓
   `{"done":"/v1/demo/sensitive"}`.
8. Type 6 digits in **App PIN**, then **Set the app PIN**. Expect: ✓ `Set, with the account password.`
9. **Sensitive, with the app PIN.** Expect: ✓ `{"done":"/v1/demo/sensitive"}`.
10. **Requests a backend must refuse:** tap each of the four. Expect a ✓ on each: `Refused, as it should
    be: 401 proof_reused` for the request sent twice, `401 proof_not_accepted` for the other three.

If the phone's screen lock is removed and set again, the step-up key dies: step 7 then shows `The phone
said STEPUP_KEY_INVALIDATED`. Tap **Re-enrol the step-up key** and unlock with the passcode — expect ✓
`{"stepup_key_registered":true}` — and step 7 passes again. The new key is that account's alone. If the
lock was off at step 1 and set afterwards, **Start again** says `step-up off here
(STEPUP_REENROL_PENDING)`: the backend took the installation without a step-up key, so re-enrol the same
way after step 4.

The app PIN belongs to the account, not to the phone. Phones signed in with the same handle share it: a
PIN set on one unlocks requests on the other, and before any is set, step 9 answers `app_pin_not_set`.
Sign in with another handle for an account of its own.

### A session copied to another phone

A session token copied off one phone must be useless on another. You need two phones running the
example against the same backend.

1. **Phone A:** steps 1 and 4 above, then **Requests a backend must refuse → Copy this phone's session**.
   Expect: `Copied this phone's session`.
2. Get the copied text to phone B, for example in a note or a message to yourself. It holds phone A's
   session and installation ID; the sample's sessions last ten minutes.
3. **Phone B:** step 1 above, on the same backend.
4. **Phone B:** paste the text into **A session from another phone**, then tap **Use it here**. Expect: ✓
   `Refused, as it should be: 401 invalid_installation_signature`. Phone B's key cannot sign for phone A's
   installation, even when the request names it.

If step 4 reads `The session is no longer valid: sign in again`, phone A's session has expired: sign in
again on phone A and copy it again.

### Measurement by measurement

What each measurement is and every field it carries: [`doc/measurements.md`](doc/measurements.md). On
a phone of your own you can watch these change, one at a time: make the change, tap **Scan**, open the
measurement's row, and change it back afterwards.

| Measurement | Change | The row then shows |
|---|---|---|
| `developer_settings` (Android) | Settings → About phone → tap Build number seven times; then Developer options → USB debugging | `developer_options_enabled`, then `adb_enabled`, true |
| `network` | turn on a VPN app; or set a manual proxy on your Wi-Fi network | `vpn_active` true, the tunnel's interface in `interfaces` (Android) or `scoped_interfaces` (iOS); `http_proxy_configured` true |
| `local_addresses` | switch between Wi-Fi and mobile data | the phone's own addresses, per interface |
| `screen_capture` | start the screen recorder (Android 15 and later; on iOS from Control Center); connect an external display | `recording` true; `external_displays` 1 |
| `location` | tap **Ask for the location permission** and allow it | the `permission`, the coordinates and their `age_seconds` |
| `mock_location` | Android: Developer options → Select mock location app, and run a mock-location app; iOS: simulate a location from Xcode while the app runs from it | `mock` true |
| `accessibility` (Android) | Settings → Accessibility → turn on a service such as Select to Speak; or choose another keyboard | the service in `services`; the keyboard in `keyboard` |
| `notification_access` (Android) | Settings → Notification access (under Special app access) → allow an app | the app in `listeners` |
| `other_access` (Android) | install AnyDesk, TeamViewer QuickSupport, RustDesk or AirDroid; or make an app a device administrator | the app in `remote_access_apps`; in `device_admins` |
| `app_identity` | install a build of the example made with other code | other hashes; a debug build reads `debuggable` true |
| `debug_state` (Android) | attach a Java debugger to a debug build | `debugger_connected` true |
| `code_signing` (iOS) | run a development build from Xcode | `get_task_allow` true |

The rest — root and jailbreak traces, Frida and other hooking tools, code changed in memory, an emulator
or the Simulator — needs a device you are allowed to change: never a phone you depend on. On an Android
emulator `emulator.suspected` is true, and a `userdebug` image shows a debuggable, test-keys build in
`system_properties` and `root_files`; on the iOS Simulator `simulator.is_simulator` is true. Frida on a
test device shows in `runtime_maps`, `frida_ports`, `instrumentation_threads`, `exec_mappings` and
`code_integrity` on Android, and in `dyld_images` and `code_integrity` on iOS.

## Licence

Copyright 2026 Meraj Hasan. Licensed under the Apache License, Version 2.0 (`LICENSE`, `NOTICE`).
