﻿using System;
using System.Runtime.InteropServices;

using USHORT = System.UInt16;

using ULONG = System.UInt32;

using HANDLE = System.IntPtr;
using PVOID = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class wudfwdm
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct _UNICODE_STRING
        {
            public USHORT Length;
            public USHORT MaximumLength;
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct _OBJECT_ATTRIBUTES
        {
            public ULONG Length;
            public HANDLE RootDirectory;
            public IntPtr ObjectName;
            public ULONG Attributes;
            public PVOID SecurityDescriptor;
            public PVOID SecurityQualityOfService;
        }

    }
}
