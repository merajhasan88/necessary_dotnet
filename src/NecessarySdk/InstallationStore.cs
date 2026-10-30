using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Necessary
{
    /// <summary>
    /// The platform's secure storage for the plugin's few values: on iOS the
    /// Keychain, on this device only, readable after the first unlock and never
    /// synchronized; on Android values encrypted under a key held in Android
    /// Keystore.
    /// </summary>
    public interface ISecureStorage
    {
        /// <summary>The value under <paramref name="key"/>, or null.</summary>
        Task<string?> ReadAsync(string key);

        /// <summary>Keeps <paramref name="value"/> under <paramref name="key"/>.</summary>
        Task WriteAsync(string key, string value);

        /// <summary>Removes the value under <paramref name="key"/>.</summary>
        Task DeleteAsync(string key);
    }

    /// <summary>Storage in memory, gone with the process: for tests, and for code that keeps its own.</summary>
    public sealed class InMemorySecureStorage : ISecureStorage
    {
        private readonly ConcurrentDictionary<string, string> values = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        /// <summary>Storage holding <paramref name="initial"/>.</summary>
        public InMemorySecureStorage(IEnumerable<KeyValuePair<string, string>>? initial = null)
        {
            if (initial is not null)
            {
                foreach (var entry in initial)
                {
                    values[entry.Key] = entry.Value;
                }
            }
        }

        /// <summary>What it holds now.</summary>
        public IReadOnlyDictionary<string, string> Values => new Dictionary<string, string>(values, StringComparer.Ordinal);

        /// <inheritdoc />
        public Task<string?> ReadAsync(string key) =>
            Task.FromResult(values.TryGetValue(key, out var value) ? value : null);

        /// <inheritdoc />
        public Task WriteAsync(string key, string value)
        {
            values[key] = value;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task DeleteAsync(string key)
        {
            values.TryRemove(key, out _);
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Where the plugin keeps the installation ID, and whether a step-up
    /// re-enrolment is pending: in the platform's secure storage beside the
    /// key.
    /// </summary>
    public class InstallationStore
    {
        /// <summary>Where the installation ID is kept.</summary>
        public const string InstallationIdKey = "recognition.installation_id.v2";

        /// <summary>Where a pending step-up re-enrolment is marked.</summary>
        public const string StepUpReenrolKey = "recognition.stepup_reenrol_pending.v1";

        private readonly ISecureStorage storage;
        private readonly object gate = new object();
        private Task<InstallationIdentity>? loading;

        /// <summary>
        /// The store over <paramref name="key"/> and <paramref name="storage"/>;
        /// by default the phone's own.
        /// </summary>
        public InstallationStore(INativeInstallationKey? key = null, ISecureStorage? storage = null)
        {
            Key = key ?? NativePlatform.CreateInstallationKey();
            this.storage = storage ?? NativePlatform.CreateSecureStorage();
        }

        /// <summary>The installation key.</summary>
        public INativeInstallationKey Key { get; }

        /// <summary>
        /// The installation: its key, made on first use, and its ID. A key made
        /// now (<see cref="InstallationIdentity.CreatedThisLaunch"/>) is a new
        /// installation, so it gets a new ID even where one was stored: that ID
        /// belongs to the key that was lost, and a backend refuses a known ID
        /// under another key. Calls at once share one load, so that one key never
        /// gets two IDs.
        /// </summary>
        public virtual Task<InstallationIdentity> LoadOrCreateAsync()
        {
            TaskCompletionSource<InstallationIdentity> source;
            lock (gate)
            {
                if (loading is not null)
                {
                    return loading;
                }

                source = new TaskCompletionSource<InstallationIdentity>(TaskCreationOptions.RunContinuationsAsynchronously);
                loading = source.Task;
            }

            _ = Shared.Complete(source, LoadOrCreateOnceAsync, () =>
            {
                lock (gate)
                {
                    if (loading == source.Task)
                    {
                        loading = null;
                    }
                }
            });
            return source.Task;
        }

        /// <summary>
        /// Keeps the installation your backend answered for this key, which may
        /// not be the ID proposed. Only this opaque ID is stored here; the private
        /// key never leaves the platform's keystore.
        /// </summary>
        public virtual Task SaveInstallationIdAsync(string installationId) => storage.WriteAsync(InstallationIdKey, installationId);

        /// <summary>
        /// Whether a step-up key was replaced and the backend has not yet taken
        /// the new one (<see cref="DeviceTrust.ReenrolStepUpAsync"/>) -- kept
        /// across restarts.
        /// </summary>
        public virtual async Task<bool> StepUpReenrolPendingAsync() => await storage.ReadAsync(StepUpReenrolKey) is not null;

        /// <summary>Marks, or clears, a pending step-up re-enrolment.</summary>
        public virtual Task SetStepUpReenrolPendingAsync(bool pending) =>
            pending ? storage.WriteAsync(StepUpReenrolKey, "1") : storage.DeleteAsync(StepUpReenrolKey);

        /// <summary>Deletes the key and the installation ID: the next start is a new installation.</summary>
        public virtual async Task ClearAsync()
        {
            await Key.DeleteKeyAsync();
            await storage.DeleteAsync(InstallationIdKey);
            await storage.DeleteAsync(StepUpReenrolKey);
        }

        private async Task<InstallationIdentity> LoadOrCreateOnceAsync()
        {
            var stored = await storage.ReadAsync(InstallationIdKey);
            var metadata = await Key.GetOrCreateKeyAsync();
            var installationId = stored ?? string.Empty;
            if (installationId.Length == 0 || metadata.Created)
            {
                installationId = Guid.NewGuid().ToString("D");
                await SaveInstallationIdAsync(installationId);
            }

            return new InstallationIdentity(installationId, Key, metadata);
        }
    }

    /// <summary>One run shared by every caller that asks while it runs.</summary>
    internal static class Shared
    {
        /// <summary>
        /// Runs <paramref name="work"/> and completes <paramref name="source"/>
        /// with its outcome -- after <paramref name="done"/>, so that a caller
        /// that hears the outcome no longer finds the run in flight.
        /// </summary>
        public static async Task Complete<T>(TaskCompletionSource<T> source, Func<Task<T>> work, Action done)
        {
            T result;
            try
            {
                result = await work();
            }
            catch (OperationCanceledException)
            {
                done();
                source.TrySetCanceled();
                return;
            }
            catch (Exception error)
            {
                done();
                source.TrySetException(error);
                return;
            }

            done();
            source.TrySetResult(result);
        }
    }
}
