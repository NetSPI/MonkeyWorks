using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

using DWORD = System.UInt32;

using LPBYTE = System.IntPtr;

using LPCWSTR = System.Text.StringBuilder;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class netapi32
    {
        [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint NetUserGetLocalGroups(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string username,
            DWORD level,
            DWORD flags,
            LPBYTE bufptr,
            int prefmaxlen,
            ref DWORD entriesread,
            ref DWORD totalentries
        );

        [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint NetUserGetLocalGroups(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string username,
            DWORD level,
            DWORD flags,
            out IntPtr bufptr,
            int prefmaxlen,
            ref DWORD entriesread,
            ref DWORD totalentries
        );

        [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint NetUserGetGroups(
            string servername,
            string username,
            DWORD level,
            IntPtr bufptr,
            DWORD prefmaxlen,
            ref DWORD entriesread,
            ref DWORD totalentries
        );

        [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint NetUserGetGroups(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string username,
            DWORD level,
            out IntPtr bufptr,
            int prefmaxlen,
            ref DWORD entriesread,
            ref DWORD totalentries
        );
    }
}
