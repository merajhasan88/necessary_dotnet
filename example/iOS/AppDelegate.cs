using Foundation;
using UIKit;

namespace Necessary.Example
{
    [Register("AppDelegate")]
    public sealed class AppDelegate : UIApplicationDelegate
    {
        public override UIWindow? Window { get; set; }

        public override bool FinishedLaunching(UIApplication application, NSDictionary? launchOptions)
        {
            // UIWindow(CGRect) is obsoleted on iOS 26 in favour of a scene-based
            // window; this example keeps the single-window app its iOS 15 floor
            // allows, and says so here rather than working around it.
#pragma warning disable CA1422
            Window = new UIWindow(UIScreen.MainScreen.Bounds)
#pragma warning restore CA1422
            {
                RootViewController = new UINavigationController(new ExampleViewController()),
            };
            Window.MakeKeyAndVisible();
            return true;
        }
    }

    public static class Program
    {
        private static void Main(string[] args) => UIApplication.Main(args, null, typeof(AppDelegate));
    }
}
