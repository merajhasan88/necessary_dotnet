using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// The phone's native side, chosen by the platform the package was built
    /// for: Android Keystore and the Android collector, the Secure Enclave and
    /// the iOS collector -- or, on any other platform, a native side that is
    /// missing and says so when it is used.
    /// </summary>
    internal static class NativePlatform
    {
        public const string Android = "android";
        public const string Ios = "ios";

        /// <summary>For the package's own tests: the platform to act as.</summary>
        internal static string? Override { get; set; }

        /// <summary><c>android</c>, <c>ios</c>, or another platform's name.</summary>
        public static string Name => Override ?? Detected;

        /// <summary>The platform a registration names: <c>android</c>, and <c>ios</c> for any other, as the plugin does.</summary>
        public static string RegistrationName => Name == Android ? Android : Ios;

        private static string Detected =>
            OperatingSystem.IsAndroid() ? Android
            : OperatingSystem.IsIOS() ? Ios
            : OperatingSystem.IsMacOS() ? "macos"
            : OperatingSystem.IsWindows() ? "windows"
            : "linux";

        public static INativeInstallationKey CreateInstallationKey()
        {
#if ANDROID
            return new AndroidInstallationKey(NecessaryAndroid.Context);
#elif IOS
            return new AppleInstallationKey();
#else
            return new MissingInstallationKey();
#endif
        }

        public static INativeStepUpKey CreateStepUpKey()
        {
#if ANDROID
            return new AndroidStepUpKey(NecessaryAndroid.Context);
#elif IOS
            return new AppleStepUpKey();
#else
            return new MissingStepUpKey();
#endif
        }

        public static INativeIntegrityCollector CreateCollector()
        {
#if ANDROID
            return new AndroidIntegrityCollector(NecessaryAndroid.Context);
#elif IOS
            return new AppleIntegrityCollector();
#else
            return new MissingCollector();
#endif
        }

        public static ISecureStorage CreateSecureStorage()
        {
#if ANDROID
            return new AndroidSecureStorage(NecessaryAndroid.Context);
#elif IOS
            return new AppleKeychainStorage();
#else
            return new MissingStorage();
#endif
        }

        public static Task<string?> ReinstallHintIdentifierAsync()
        {
#if ANDROID
            return AndroidInstallationKey.ReinstallHintIdentifierAsync(NecessaryAndroid.Context);
#elif IOS
            return AppleInstallationKey.ReinstallHintIdentifierAsync();
#else
            return Task.FromException<string?>(Missing("NATIVE_KEY_PLUGIN_MISSING", "installation-key"));
#endif
        }

        public static Task<JsonObject> ProtectScreenAsync(bool on)
        {
#if ANDROID
            return AndroidScreenProtection.ProtectAsync(on);
#elif IOS
            return AppleScreenProtection.ProtectAsync(on);
#else
            return Task.FromException<JsonObject>(Missing("NATIVE_SCREEN_PLUGIN_MISSING", "screen-protection"));
#endif
        }

        internal static NativeKeyException Missing(string code, string part) =>
            new NativeKeyException(
                code,
                "This platform has no native " + part + " side: the package's keys, collectors and screen protection are Android's and iOS's.");

#if !ANDROID && !IOS
        private sealed class MissingInstallationKey : INativeInstallationKey
        {
            public Task<NativeKeyMetadata> GetOrCreateKeyAsync() =>
                Task.FromException<NativeKeyMetadata>(Missing("NATIVE_KEY_PLUGIN_MISSING", "installation-key"));

            public Task<string> SignPayloadAsync(string payloadBase64Url) =>
                Task.FromException<string>(Missing("NATIVE_KEY_PLUGIN_MISSING", "installation-key"));

            public Task DeleteKeyAsync() => Task.FromException(Missing("NATIVE_KEY_PLUGIN_MISSING", "installation-key"));
        }

        private sealed class MissingStepUpKey : INativeStepUpKey
        {
            public string ConfiguredMode { get; set; } = "per_use";

            public Task<StepUpKeyMetadata> GetOrCreateKeyAsync(string factor, string mode, int windowSeconds) =>
                Task.FromException<StepUpKeyMetadata>(Missing("NATIVE_STEPUP_PLUGIN_MISSING", "step-up key"));

            public Task<string> SignAsync(string payloadBase64Url, string reason) =>
                Task.FromException<string>(Missing("NATIVE_STEPUP_PLUGIN_MISSING", "step-up key"));

            public Task DeleteKeyAsync() => Task.FromException(Missing("NATIVE_STEPUP_PLUGIN_MISSING", "step-up key"));
        }

        private sealed class MissingCollector : INativeIntegrityCollector
        {
            public Task<JsonObject> CollectAsync(
                System.Collections.Generic.IReadOnlyList<string> requiredProbes,
                string challengeNonce,
                System.Collections.Generic.IReadOnlyList<string> enabledMeasurements,
                System.Collections.Generic.IReadOnlyList<string> optionalProbes) =>
                Task.FromException<JsonObject>(Missing("NATIVE_INTEGRITY_PLUGIN_MISSING", "integrity collector"));

            public Task<string> RequestLocationPermissionAsync() =>
                Task.FromException<string>(Missing("NATIVE_INTEGRITY_PLUGIN_MISSING", "integrity collector"));
        }

        private sealed class MissingStorage : ISecureStorage
        {
            public Task<string?> ReadAsync(string key) =>
                Task.FromException<string?>(Missing("NATIVE_STORAGE_MISSING", "secure storage"));

            public Task WriteAsync(string key, string value) =>
                Task.FromException(Missing("NATIVE_STORAGE_MISSING", "secure storage"));

            public Task DeleteAsync(string key) =>
                Task.FromException(Missing("NATIVE_STORAGE_MISSING", "secure storage"));
        }
#endif
    }
}
