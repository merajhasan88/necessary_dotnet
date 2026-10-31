using System.Text;
using System.Threading.Tasks;
using Foundation;
using Security;

namespace Necessary
{
    /// <summary>
    /// The package's few values in the iOS Keychain: on this device only,
    /// readable after the first unlock, never synchronized. A value can outlive
    /// the app, as the installation key can: the same installation comes back
    /// with it. It is apart from the keys' serial queue.
    /// </summary>
    public sealed class AppleKeychainStorage : ISecureStorage
    {
        private readonly string service;

        /// <summary>The storage of this app's bundle.</summary>
        public AppleKeychainStorage()
            : this((NSBundle.MainBundle.BundleIdentifier ?? "necessary") + ".necessarysdk.storage.v1")
        {
        }

        /// <summary>The storage under the Keychain service <paramref name="service"/>.</summary>
        public AppleKeychainStorage(string service)
        {
            this.service = service;
        }

        /// <inheritdoc />
        public Task<string?> ReadAsync(string key) => Task.Run<string?>(() =>
        {
            using var query = Query(key);
            using var record = SecKeyChain.QueryAsRecord(query, out var status);
            if (status == SecStatusCode.ItemNotFound)
            {
                return null;
            }

            if (status != SecStatusCode.Success)
            {
                throw new NativeKeyException("STORAGE_READ_FAILED", "The Keychain could not read a stored value (OSStatus " + (int)status + ").");
            }

            return record?.ValueData is NSData value ? Encoding.UTF8.GetString(value.ToArray()) : null;
        });

        /// <inheritdoc />
        public Task WriteAsync(string key, string value) => Task.Run(() =>
        {
            using (var existing = Query(key))
            {
                SecKeyChain.Remove(existing);
            }

            using var record = Query(key);
            record.ValueData = NSData.FromArray(Encoding.UTF8.GetBytes(value));
            record.Accessible = SecAccessible.AfterFirstUnlockThisDeviceOnly;
            var status = SecKeyChain.Add(record);
            if (status != SecStatusCode.Success)
            {
                throw new NativeKeyException("STORAGE_WRITE_FAILED", "The Keychain could not store a value (OSStatus " + (int)status + ").");
            }
        });

        /// <inheritdoc />
        public Task DeleteAsync(string key) => Task.Run(() =>
        {
            using var query = Query(key);
            var status = SecKeyChain.Remove(query);
            if (status != SecStatusCode.Success && status != SecStatusCode.ItemNotFound)
            {
                throw new NativeKeyException("STORAGE_DELETE_FAILED", "The Keychain could not remove a stored value (OSStatus " + (int)status + ").");
            }
        });

        private SecRecord Query(string key) => new SecRecord(SecKind.GenericPassword)
        {
            Service = service,
            Account = key,
            Synchronizable = false,
        };
    }
}
