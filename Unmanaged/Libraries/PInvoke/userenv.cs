using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Libraries
{
    public sealed class userenv
    {
        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateEnvironmentBlock(
            ref IntPtr lpEnvironment,
            IntPtr hToken,
            [MarshalAs(UnmanagedType.Bool)]
            bool bInherit
        );
    }
}
