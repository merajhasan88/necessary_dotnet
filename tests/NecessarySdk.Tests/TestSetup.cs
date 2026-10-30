using System.IO;
using System.Runtime.CompilerServices;

namespace Necessary.Tests
{
    /// <summary>What every test runs under: the plugin's tests run on Android, in a debug build.</summary>
    internal static class TestSetup
    {
        [ModuleInitializer]
        internal static void Initialize()
        {
            NativePlatform.Override = NativePlatform.Android;
            // A release build talks only HTTPS: NECESSARY_TEST_RELEASE_BUILD=1 runs
            // the tests as one, against a backend behind HTTPS.
            BuildMode.Override = System.Environment.GetEnvironmentVariable("NECESSARY_TEST_RELEASE_BUILD") == "1";
        }
    }

    /// <summary>
    /// The files the tests share with the backends: the measurement contract and
    /// the client-server vectors, in the nearest folder from here up that holds them.
    /// </summary>
    internal static class RepositoryFiles
    {
        public static string File(string path) => Nearest(path, System.IO.File.Exists);

        public static string Directory(string path) => Nearest(path, System.IO.Directory.Exists);

        private static string Nearest(string path, System.Func<string, bool> exists)
        {
            var folder = new DirectoryInfo(System.AppContext.BaseDirectory);
            while (folder is not null)
            {
                var candidate = Path.Combine(folder.FullName, path);
                if (exists(candidate))
                {
                    return candidate;
                }

                folder = folder.Parent;
            }

            throw new FileNotFoundException(path + ": in no folder from " + System.AppContext.BaseDirectory + " up");
        }
    }
}
