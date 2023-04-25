﻿using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    public sealed class userenv
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool CreateEnvironmentBlock(
            ref IntPtr lpEnvironment,
            IntPtr hToken,
            [MarshalAs(UnmanagedType.Bool)]
            bool bInherit
        );
    }
}
