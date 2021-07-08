using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    class Rpcdce
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct _GUID
        {
            internal int Data1;
            internal short Data2;
            internal short Data3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            internal byte[] Data4;
        }
    }
}