using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries
{
    public sealed class ole32
    {
        [DllImport("ole32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint CoCreateInstance(
            [In, MarshalAs(UnmanagedType.LPStruct)]
            Guid rclsid,
            IntPtr pUnkOuter,
            [MarshalAs(UnmanagedType.U4)]
            Wtypesbase.CLSCTX dwClsContext,
            [In, MarshalAs(UnmanagedType.LPStruct)] Guid riid,
            [MarshalAs(UnmanagedType.IUnknown)] out object rReturnedComObject
        );

        [DllImport("ole32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint CLSIDFromProgID(
            [In, MarshalAs(UnmanagedType.LPWStr)]
            string lpszProgID,
            out Guid clsid
        );

        [DllImport("ole32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint ProgIDFromCLSID(
            [In] ref Guid clsid,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string lplpszProgID
        );
    }
}
