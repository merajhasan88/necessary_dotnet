using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Runtime;

namespace Necessary
{
    /// <summary>
    /// The Android host: the activity in the foreground -- for the step-up
    /// prompt, screen protection and the location request -- and the windows
    /// screen protection must follow. Call <see cref="Init"/> from your first
    /// activity's <c>OnCreate</c>; the plugin tracks every activity after it.
    /// </summary>
    public static class NecessaryAndroid
    {
        private static readonly object Gate = new object();
        private static LifecycleTracker? tracker;
        private static WeakReference<Activity>? current;

        /// <summary>
        /// Starts tracking the app's activities from <paramref name="activity"/>,
        /// the one in the foreground now. Calling it again is harmless.
        /// </summary>
        public static void Init(Activity activity)
        {
            if (activity is null)
            {
                throw new ArgumentNullException(nameof(activity));
            }

            EnsureTracking(activity.Application);
            SetCurrent(activity);
        }

        /// <summary>The application context.</summary>
        internal static Context Context => Application.Context;

        /// <summary>The activity in the foreground, or null before any is known.</summary>
        internal static Activity? CurrentActivity
        {
            get
            {
                EnsureTracking(Application.Context as Application);
                lock (Gate)
                {
                    return current is not null && current.TryGetTarget(out var activity)
                        && !activity.IsFinishing && !activity.IsDestroyed
                        ? activity
                        : null;
                }
            }
        }

        /// <summary>Raised on the main thread when an activity is created: a new window.</summary>
        internal static event Action<Activity>? ActivityCreated;

        /// <summary>Runs <paramref name="work"/> on the main thread and answers its result.</summary>
        internal static Task<T> OnMainThreadAsync<T>(Func<T> work)
        {
            if (Looper.MyLooper() == Looper.MainLooper)
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
            using var handler = new Handler(Looper.MainLooper!);
            handler.Post(() =>
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

        /// <summary>
        /// Asks the person for <paramref name="permissions"/> from the activity in
        /// the foreground, through the plugin's own transparent activity, and
        /// completes when they answer. Without an activity it completes at once.
        /// </summary>
        internal static Task RequestPermissionsAsync(string[] permissions)
        {
            var request = new ProxyRequest(null, permissions);
            return ProxyActivity.Run(request);
        }

        /// <summary>
        /// Starts <paramref name="intent"/> for a result through the plugin's own
        /// transparent activity, so the app forwards nothing.
        /// </summary>
        internal static async Task<Result> StartForResultAsync(Intent intent)
        {
            var request = new ProxyRequest(intent, null);
            await ProxyActivity.Run(request).ConfigureAwait(false);
            return request.ResultCode;
        }

        private static void EnsureTracking(Application? application)
        {
            if (application is null)
            {
                return;
            }

            lock (Gate)
            {
                if (tracker is not null)
                {
                    return;
                }

                tracker = new LifecycleTracker();
                application.RegisterActivityLifecycleCallbacks(tracker);
            }
        }

        private static void SetCurrent(Activity activity)
        {
            if (activity is ProxyActivity)
            {
                return;
            }

            lock (Gate)
            {
                current = new WeakReference<Activity>(activity);
            }
        }

        private static void Forget(Activity activity)
        {
            lock (Gate)
            {
                if (current is not null && current.TryGetTarget(out var known) && ReferenceEquals(known, activity))
                {
                    current = null;
                }
            }
        }

        private sealed class LifecycleTracker : Java.Lang.Object, Application.IActivityLifecycleCallbacks
        {
            public void OnActivityCreated(Activity activity, Bundle? savedInstanceState)
            {
                if (activity is ProxyActivity)
                {
                    return;
                }

                SetCurrent(activity);
                ActivityCreated?.Invoke(activity);
            }

            public void OnActivityDestroyed(Activity activity)
            {
                Forget(activity);

                // Gone for good, not recreated for a configuration change: a
                // request it launched whose screen never opened would wait for an
                // answer that can never come, and hold every later approval.
                if (activity.IsFinishing && !activity.IsChangingConfigurations)
                {
                    ProxyActivity.CancelLaunchedBy(activity);
                }
            }

            public void OnActivityPaused(Activity activity)
            {
            }

            public void OnActivityResumed(Activity activity) => SetCurrent(activity);

            public void OnActivitySaveInstanceState(Activity activity, Bundle outState)
            {
            }

            public void OnActivityStarted(Activity activity) => SetCurrent(activity);

            public void OnActivityStopped(Activity activity)
            {
            }
        }
    }

    /// <summary>One request carried by <see cref="ProxyActivity"/>.</summary>
    internal sealed class ProxyRequest
    {
        public ProxyRequest(Intent? intent, string[]? permissions)
        {
            Intent = intent;
            Permissions = permissions;
        }

        public Intent? Intent { get; }

        public string[]? Permissions { get; }

        public Result ResultCode { get; set; } = Result.Canceled;

        /// <summary>The activity that asked: a request it launched that never opened ends when it is gone.</summary>
        public WeakReference<Activity>? Launcher { get; set; }

        /// <summary>Whether its transparent activity opened, and now owns the answer.</summary>
        public bool Started { get; set; }

        public TaskCompletionSource<bool> Done { get; } =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    /// <summary>
    /// A transparent activity that starts one intent for its result, or asks for
    /// permissions, and finishes, so the app need not forward
    /// <c>OnActivityResult</c>.
    /// </summary>
    [Activity(
        Name = "com.meraj.necessarysdk.ProxyActivity",
        Theme = "@android:style/Theme.Translucent.NoTitleBar",
        Exported = false,
        NoHistory = false,
        ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.ScreenLayout
            | ConfigChanges.SmallestScreenSize | ConfigChanges.KeyboardHidden | ConfigChanges.Keyboard
            | ConfigChanges.UiMode | ConfigChanges.Density)]
    internal sealed class ProxyActivity : Activity
    {
        private const string RequestExtra = "com.meraj.necessarysdk.request";
        private const int RequestCode = 0x4E43; // "NC"
        private static readonly ConcurrentDictionary<int, ProxyRequest> Pending =
            new ConcurrentDictionary<int, ProxyRequest>();
        private static int nextId;

        private int requestId;

        internal static Task Run(ProxyRequest request)
        {
            var activity = NecessaryAndroid.CurrentActivity;
            if (activity is null)
            {
                request.Done.TrySetResult(false);
                return request.Done.Task;
            }

            var id = Interlocked.Increment(ref nextId);
            request.Launcher = new WeakReference<Activity>(activity);
            Pending[id] = request;
            _ = NecessaryAndroid.OnMainThreadAsync(() =>
            {
                try
                {
                    var intent = new Intent(activity, typeof(ProxyActivity));
                    intent.PutExtra(RequestExtra, id);
                    activity.StartActivity(intent);
                }
                catch (Exception error)
                {
                    if (Pending.TryRemove(id, out var failed))
                    {
                        failed.Done.TrySetException(error);
                    }
                }

                return true;
            });
            return request.Done.Task;
        }

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            requestId = Intent?.GetIntExtra(RequestExtra, 0) ?? 0;
            if (savedInstanceState is not null)
            {
                // Recreated: the request is already out, and its answer comes here.
                return;
            }

            if (!Pending.TryGetValue(requestId, out var request))
            {
                Finish();
                return;
            }

            request.Started = true;

            try
            {
                if (request.Intent is not null)
                {
                    StartActivityForResult(request.Intent, RequestCode);
                }
                else if (request.Permissions is not null && OperatingSystem.IsAndroidVersionAtLeast(23))
                {
                    RequestPermissions(request.Permissions, RequestCode);
                }
                else
                {
                    Complete(Result.Canceled);
                }
            }
            catch (Exception error)
            {
                if (Pending.TryRemove(requestId, out var failed))
                {
                    failed.Done.TrySetException(error);
                }

                Finish();
            }
        }

        protected override void OnActivityResult(int requestCode, [GeneratedEnum] Result resultCode, Intent? data)
        {
            base.OnActivityResult(requestCode, resultCode, data);
            if (requestCode == RequestCode)
            {
                Complete(resultCode);
            }
        }

        public override void OnRequestPermissionsResult(
            int requestCode,
            string[] permissions,
            [GeneratedEnum] Permission[] grantResults)
        {
            base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
            if (requestCode == RequestCode)
            {
                Complete(Result.Ok);
            }
        }

        protected override void OnDestroy()
        {
            // Finished by the system before an answer: the request ends cancelled.
            if (IsFinishing && Pending.TryRemove(requestId, out var request))
            {
                request.ResultCode = Result.Canceled;
                request.Done.TrySetResult(false);
            }

            base.OnDestroy();
        }

        /// <summary>Ends, as cancelled, every request <paramref name="launcher"/> launched whose screen never opened.</summary>
        internal static void CancelLaunchedBy(Activity launcher)
        {
            foreach (var pending in Pending)
            {
                var request = pending.Value;
                if (!request.Started
                    && request.Launcher is not null
                    && request.Launcher.TryGetTarget(out var asked)
                    && ReferenceEquals(asked, launcher)
                    && Pending.TryRemove(pending.Key, out _))
                {
                    request.ResultCode = Result.Canceled;
                    request.Done.TrySetResult(false);
                }
            }
        }

        private void Complete(Result resultCode)
        {
            if (Pending.TryRemove(requestId, out var request))
            {
                request.ResultCode = resultCode;
                request.Done.TrySetResult(true);
            }

            Finish();
        }
    }
}
