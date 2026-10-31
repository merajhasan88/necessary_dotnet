using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Necessary
{
    /// <summary>
    /// This process, as the code comparison reads it: its memory map, its memory
    /// read by pointer, mprotect and pread. Linux's, so Android's -- and the
    /// offline tests run it on this machine against a real execute-only mapping.
    /// </summary>
    internal sealed class ProcessMemory : ICodeIntegrityMemory
    {
        private readonly string mapsPath;

        /// <summary>This process; <paramref name="mapsPath"/> is <c>/proc/self/maps</c> but in a test.</summary>
        public ProcessMemory(string mapsPath = "/proc/self/maps")
        {
            this.mapsPath = mapsPath;
        }

        public string ReadMaps() => File.ReadAllText(mapsPath);

        public bool Protect(ulong start, ulong length, int protection) =>
            NativeMethods.Mprotect(unchecked((nint)start), unchecked((nuint)length), protection) == 0;

        public void Read(ulong address, byte[] buffer, int count) =>
            Marshal.Copy(unchecked((nint)address), buffer, 0, count);

        public ICodeIntegrityFile? Open(string path)
        {
            try
            {
                return new HandleFile(File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            }
#pragma warning disable CA1031 // Not opened: its bytes are unreadable, counted as such.
            catch (Exception)
#pragma warning restore CA1031
            {
                return null;
            }
        }

        private sealed class HandleFile : ICodeIntegrityFile
        {
            private readonly SafeFileHandle handle;

            public HandleFile(SafeFileHandle handle)
            {
                this.handle = handle;
            }

            public int ReadAt(long offset, byte[] buffer, int count)
            {
                try
                {
                    return RandomAccess.Read(handle, buffer.AsSpan(0, count), offset);
                }
#pragma warning disable CA1031 // A read that failed ends the comparison of this mapping.
                catch (Exception)
#pragma warning restore CA1031
                {
                    return -1;
                }
            }

            public void Dispose() => handle.Dispose();
        }

        private static class NativeMethods
        {
            [DllImport("libc", EntryPoint = "mprotect", SetLastError = true)]
            public static extern int Mprotect(nint address, nuint length, int protection);
        }
    }
}
