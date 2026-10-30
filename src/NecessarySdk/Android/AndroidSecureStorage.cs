using System;
using System.Text;
using System.Threading.Tasks;
using Android.Content;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;

namespace Necessary
{
    /// <summary>
    /// The plugin's few values on Android: each encrypted with AES-GCM under a
    /// key held in Android Keystore, and kept in the app's private preferences.
    /// A value whose key is gone -- the app's data restored onto another phone,
    /// say -- reads as absent; so does its installation key, so the next start is
    /// a new installation either way.
    /// </summary>
    public sealed class AndroidSecureStorage : ISecureStorage
    {
        private const string AndroidKeyStore = "AndroidKeyStore";
        private const string Transformation = "AES/GCM/NoPadding";
        private const string PreferencesName = "necessarysdk.secure_storage.v1";

        private readonly Context context;
        private readonly string keyAlias;
        private readonly object gate = new object();

        /// <summary>The storage of the app <paramref name="context"/> belongs to.</summary>
        public AndroidSecureStorage(Context context)
        {
            this.context = context ?? throw new ArgumentNullException(nameof(context));
            keyAlias = context.PackageName + ".necessarysdk.storage_key.v1";
        }

        /// <inheritdoc />
        public Task<string?> ReadAsync(string key) => AndroidNative.Run(() =>
        {
            lock (gate)
            {
                var stored = Preferences().GetString(key, null);
                if (stored is null)
                {
                    return null;
                }

                try
                {
                    return Decrypt(stored);
                }
#pragma warning disable CA1031 // Its key is gone: the value is gone.
                catch (Exception)
#pragma warning restore CA1031
                {
                    Preferences().Edit()!.Remove(key)!.Commit();
                    return null;
                }
            }
        });

        /// <inheritdoc />
        public Task WriteAsync(string key, string value) => AndroidNative.Run(() =>
        {
            lock (gate)
            {
                if (!Preferences().Edit()!.PutString(key, Encrypt(value))!.Commit())
                {
                    throw new NativeKeyException("STORAGE_WRITE_FAILED", "The value could not be stored.");
                }

                return true;
            }
        });

        /// <inheritdoc />
        public Task DeleteAsync(string key) => AndroidNative.Run(() =>
        {
            lock (gate)
            {
                Preferences().Edit()!.Remove(key)!.Commit();
                return true;
            }
        });

        private ISharedPreferences Preferences() =>
            context.GetSharedPreferences(PreferencesName, FileCreationMode.Private)!;

        private IKey Key()
        {
            var keyStore = KeyStore.GetInstance(AndroidKeyStore)!;
            keyStore.Load(null);
            if (keyStore.GetKey(keyAlias, null) is IKey existing)
            {
                return existing;
            }

            var generator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, AndroidKeyStore)!;
            generator.Init(new KeyGenParameterSpec.Builder(keyAlias, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                .SetBlockModes(KeyProperties.BlockModeGcm)
                .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
                .SetKeySize(256)
                .Build());
            return generator.GenerateKey()!;
        }

        private string Encrypt(string value)
        {
            var cipher = Cipher.GetInstance(Transformation)!;
            cipher.Init(CipherMode.EncryptMode, Key());
            var iv = cipher.GetIV()!;
            var sealedBytes = cipher.DoFinal(Encoding.UTF8.GetBytes(value))!;
            return Wire.Base64UrlNoPadding(iv) + "." + Wire.Base64UrlNoPadding(sealedBytes);
        }

        private string Decrypt(string stored)
        {
            var dot = stored.IndexOf('.', StringComparison.Ordinal);
            if (dot <= 0)
            {
                throw new FormatException("Not a stored value.");
            }

            var cipher = Cipher.GetInstance(Transformation)!;
            cipher.Init(CipherMode.DecryptMode, Key(), new GCMParameterSpec(128, Wire.DecodeBase64Url(stored.Substring(0, dot))));
            return Encoding.UTF8.GetString(cipher.DoFinal(Wire.DecodeBase64Url(stored.Substring(dot + 1)))!);
        }
    }
}
