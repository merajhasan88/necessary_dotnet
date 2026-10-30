# Changelog

## 0.1.1

The .NET translation of the Flutter plugin `necessary` 0.1.1 (necessary_flutter `4a4c0e0`): the same
calls, the same messages byte for byte, the same measurements and fields, the same lifecycle.

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
