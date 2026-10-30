using System;
using System.Threading;
using System.Threading.Tasks;
using CoreFoundation;
using Foundation;

namespace Necessary
{
    /// <summary>
    /// How the iOS side runs: one serial queue for the keys, the collector and
    /// step-up -- a scan or a request's signature asked while a step-up prompt
    /// is open waits for the person's answer -- and UIKit read on the main
    /// thread.
    /// </summary>
    internal static class NecessaryApple
    {
        private static readonly SemaphoreSlim Queue = new SemaphoreSlim(1, 1);

        /// <summary>Runs <paramref name="work"/> on the plugin's serial queue, after every call before it.</summary>
        internal static async Task<T> Serial<T>(Func<Task<T>> work)
        {
            await Queue.WaitAsync().ConfigureAwait(false);
            try
            {
                return await Task.Run(work).ConfigureAwait(false);
            }
            finally
            {
                Queue.Release();
            }
        }

        /// <summary>Runs <paramref name="work"/> on the plugin's serial queue, after every call before it.</summary>
        internal static Task<T> Serial<T>(Func<T> work) => Serial<T>(() => Task.FromResult(work()));

        /// <summary>Runs <paramref name="work"/> on the main thread and answers its result.</summary>
        internal static Task<T> OnMainThread<T>(Func<T> work)
        {
            if (NSThread.IsMain)
            {
                try
                {
                    return Task.FromResult(work());
                }
                catch (Exception error)
                {
                    return Task.FromException<T>(error);
                }
            }

            var answer = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
            DispatchQueue.MainQueue.DispatchAsync(() =>
            {
                try
                {
                    answer.TrySetResult(work());
                }
                catch (Exception error)
                {
                    answer.TrySetException(error);
                }
            });
            return answer.Task;
        }
    }
}
