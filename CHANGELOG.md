# Changelog

## 0.1.13

- Android: `other_access` names the default SMS app (`sms_app`), whose installer and system flag tell an app
  the user chose from one that made itself the SMS app to read one-time codes. A call app and an SMS app
  that could not be read are each named in `unread`, with why.
- `doc/measurements.md` and the integration guide say which clicks a screen reports, and, in section 7.7,
  who shows a call or SMS app from outside a store genuinely.
- Android: the touch counts also cover your app's dialogs, from Android 10. While a window of your app's
  that takes touches cannot be watched, the counts are left out and named in `unread`, with why. The README
  says which clicks the SDK counts, in a .NET MAUI app too.
- The Android collector is version 15.

## 0.1.12

- iOS: `app_identity` says whether the app's main executable is stored encrypted (`executable_encrypted`),
  as Apple stores an app it distributes through the App Store or TestFlight. A copy decrypted and installed
  some other way, and a development, ad hoc or enterprise build, keeps it in the clear.
  `doc/measurements.md` says how to read it.
- Android: `accessibility` names the services that declare themselves tools for users with disabilities
  (`tool_services`, Android 12 and later) and those that can tap and swipe on the screen
  (`gesture_services`), and says whether a service pressed your app's buttons: with the measurement on
  when `StartAsync()` runs, the SDK counts the touches on your app's screen (`touches`), those an
  Accessibility service made (`touches_injected`) and the clicks with no touch or key press before them
  (`clicks_without_touch`), over `counted_seconds`, and each scan that carries the measurement starts
  them afresh. Counts only: no position, no screen and no text, and nothing is counted while the
  measurement is off. `doc/measurements.md` says how to read them, and the integration guide's section
  7.7 who shows them genuinely.
- `INativeIntegrityCollector` has `WatchTouchesAsync`, which starts and stops those counts; by default it
  does nothing.
- `doc/measurements.md` and the integration guide say what both readings showed on phones: a service's
  taps and clicks counted on Android 10 and Android 16, a finger's touches and a keyboard's presses not;
  a TestFlight build's code stored encrypted on iOS 27 and an app installed outside the App Store in the
  clear on iOS 15.8. The guide also says that a build from the App Store or TestFlight never compares its
  main executable, so `app_complete` is false there on every phone.
- The Android example app acts on a button, a switch or a heading once its click is over.
- The README gives this package's collector versions, 14 and 10.
- The iOS collector is version 10; the Android collector is version 14.

## 0.1.11

- Android: every scan carries `app_host`, whether another app runs yours inside its own: where Android says
  your app's package file and data are, whether its process runs under your app's own user ID, which other
  apps Android names for that user ID, which other apps' libraries the processes your app starts are made
  to load first, and which other apps' code is in its memory. `doc/measurements.md` says how to read it.
- Android: `debug_state` says whether the runtime's debugger thread runs in your app (`jdwp_thread`).
- Android: `other_access` names the app that handles calls (`call_app`).
- Android: a command that exits with an error is not a reading: `root_shell` and `system_properties` say
  why they could not read, rather than taking what the command printed as the answer.
- Android: `emulator` also reads the processor and what the device is (`form_factor`, `cpu_vendor`,
  `cpu_implementers`, `cpu_model`, `hypervisor`, `abis`, `machine`). On a phone or tablet, an x86
  processor, a hypervisor or Apple's cores count as reasons (`cpu`, `hypervisor`, `abi`), whatever the
  build values say; on a Chromebook, a PC, a car, a TV or a watch they do not.
- The Android collector is version 13.
- The integration guide's new section 7.7 is on genuine users who show a strong reading, and what to do.
- The Python sample backend's steps use Python 3.11 with its packages in a virtual environment, and the
  sample stops quietly on Ctrl+C.

## 0.1.10

- A new measurement, `runtime`, sent with every scan (Android collector 12, iOS collector 9): the .NET
  runtime's version, whether the app carries a Brotli decoder, and that decoder's version where it can
  be read. A backend compares them with the versions a flaw was fixed in.
- iOS: `code_integrity` compares `__managedcode` beside `__text`: an app built with NativeAOT keeps its
  .NET code there. Other apps have no such section, and their figures are as before.

## 0.1.9

- `runtime_maps`, `instrumentation_threads` and iOS `dyld_images` leave the app's own folders, package
  name, main executable and compiled assemblies out of what they read as names.
- Android: `root_shell` keeps the shell's error stream out of `su_path`.
- Android: a step-up signature that fails after the person approved answers the app, whatever failed.
- A step-up key the phone lost and a re-enrolment made again leaves approvals waiting until the backend
  takes it, like a key replaced.
- Every call that got no answer is an `ApiException`, on a phone too; so is a backend's answer that lacks
  a field the package needs (`invalid_backend_answer`).
- The Python sample backend answers a malformed request with a refusal.
- `doc/measurements.md`: `installer_package` is left out or null when no installer is named; every SDK
  sends its report in the same format. `doc/integration_guide.md`, section 7.2: how a runtime that compiles
  code as the app runs shows itself.
- The package's title, description and tags say device integrity.

## 0.1.8

- The package's website, [necessarysdk.com](https://necessarysdk.com), is named in the README and is
  the package's project URL, so nuget.org shows it as the project website; the source repository stays
  GitHub. The package's README, description, documents, comments and tests describe it on its own. No code
  changed.

## 0.1.7

- Android: a library whose executable segment ends inside its file's last page -- 19 of a .NET
  release's extracted libraries, many of them ahead-of-time compiled assemblies -- is compared to its
  end: the zeros the kernel fills that page with are compared with zeros, so code put in that slack is
  found. 0.1.6 counted those bytes unreadable, and `app_complete` read false on a genuine phone (the
  OPPO, Android 9: 4,856 bytes). More than a page past a file's end is never touched and stays
  unreadable.

## 0.1.6

- Android (collector 11): the `app` region of the code comparison is all of the app's own code in
  files. Besides the app's APKs and the .NET runtime's libraries by name, every executable file of the
  app's own that is mapped is compared, each under its own name: the assemblies a release build compiles
  ahead of time and extracts (`libaot-*.dll.so`), the runtime's other libraries, the Java and Kotlin
  Android compiled (`base.odex`). A hook in an extracted assembly is now found, where 0.1.5 named such
  files in `app_outside_count` without comparing them; `app_outside_count` is now 0. This closes the
  release review's item 5 for .NET; the earlier region (collector 10) is narrower, and the
  collector version tells them apart.

## 0.1.5

The answer to a release review of this package; the wire is unchanged — every
message, header and signed payload, the shared vectors and the contract's fields.

- Android (collector 10): the code comparison reads the memory map once, whole, and takes every region
  from that one snapshot; a map that cannot be read answers `checked` false with `reason`
  `maps_unreadable` (or `maps_empty`, `no_target_mapped`), never a region read as complete. One
  comparison runs at a time in the process, whichever `DeviceTrust` or thread asks: a comparison makes
  execute-only pages readable while it reads them. (Review items 1 and 2.)
- Android: the `app` region is the app's own — its APKs by their exact paths and the .NET runtime's
  libraries by name — where it took every mapping ending in `.apk`; the app's own executable files
  mapped outside it, an extracted ahead-of-time assembly (`libaot-*.dll.so`) among them, are counted in
  `app_outside_count` and named in `app_outside_files`. (Review item 5.)
- Android: the step-up key is deleted only when Android says it can never sign again
  (`KeyPermanentlyInvalidatedException`); a lookup that cannot establish whether it is usable keeps it
  and answers the new `STEPUP_KEY_UNAVAILABLE`, which an app may retry, and `ReenrolStepUpAsync`
  replaces such a key. (Review item 4.)
- Android: a key is made only where the keystore, answering, holds none: `containsAlias` also answers
  "no" when the keystore cannot be reached, and a new key used to be generated over the old one. Now
  `StartAsync()` fails with the new `KEY_UNAVAILABLE` and makes nothing; signing answers `KEY_NOT_FOUND`
  only when the keystore says so; deleting a key deletes whatever a lookup said, and fails with
  `KEY_DELETE_FAILED` when it stays. Making and deleting a key run one at a time in the process, on
  Android and on iOS.
- Android: every failure says what failed beneath it — a `NativeKeyException`'s message ends with
  `[cause: …]`, down to the keystore's own answer, with its numeric code from Android 13; a probe's
  `error` and each `unread` reason carry the same, within the contract's lengths; a listing of the
  network interfaces that failed is in `unread`; an Accessibility service the system did not describe
  is counted in `unread`. A step-up approval waiting for the passcode screen ends as `STEPUP_CANCELLED`
  when the activity that asked is gone for good, never holding the next.
- `ResetAsync()` and `Close()` hold for every call (review item 3): `SignRequestAsync` and
  `SetAppPinAsync` end with `InterruptedCallException` when the installation was reset meanwhile,
  handing out nothing; every persistent write and key change is refused once a reset has begun and
  waited for when it began before. A step-up key that will not delete fails `ResetAsync()` with
  `KEY_DELETE_FAILED`, the installation itself gone.
- iOS (collector 8): an image the App Store encrypted on disk is skipped, never compared (collector
  7, review item 6); an image is compared only with the build that is running (`LC_UUID`); a universal
  framework file is compared through its arm64 image; an image dyld cannot name is counted, in
  `code_integrity` and in `dyld_images`' `unread`.
- Both platforms: `local_addresses` says `truncated` when the phone had more than 32 addresses.
- The documents and the contract are the plugin's 0.1.5: the product is named Necessary, the category
  device integrity; `ok` means measured, never "all clear"; the README says what the `app` region
  covers and that .NET's memory figures are observations of the configurations tested.

## 0.1.1

The first release.

- `DeviceTrust`: start, prove, scan, request proofs, step-up with its re-enrolment, the app PIN, reset
  and close; one installation generation at a time; calls at once share one run.
- The installation key in Android Keystore (StrongBox first) and the Secure Enclave (a Keychain key
  where it declines); the step-up key; the app PIN's two calls; screen protection.
- The collectors: Android 8 and iOS 6, as the plugin's; the measurement contract
  `report-1/android-8-ios-5`.
- Targets: `net8.0` (the protocol alone), `net9.0-android` (Android 7.0 and later), `net9.0-ios`
  (iOS 15 and later).
- The shared client-server vectors, all six sections, byte for byte; the plugin's tests translated;
  the end-to-end test, 11 of 11 against each of the three sample backends.
