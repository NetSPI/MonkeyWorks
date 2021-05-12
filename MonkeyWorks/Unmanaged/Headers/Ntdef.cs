using System;
using System.Runtime.InteropServices;

using HANDLE = System.IntPtr;
using WORD = System.UInt16;
using LONG = System.UInt32;
using ULONG = System.UInt32;
using DWORD = System.UInt32;
using QWORD = System.UInt64;
using ULONGLONG = System.UInt64;
using LARGE_INTEGER = System.UInt64;

using PSID = System.IntPtr;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;
using SIZE_T = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class Ntdef
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _OBJECT_ATTRIBUTES
        {
            public ULONG Length;
            public HANDLE RootDirectory;
            public wudfwdm._UNICODE_STRING ObjectName;
            public ULONG Attributes;
            public PVOID SecurityDescriptor;
            public PVOID SecurityQualityOfService;
        }
       /*
        * typedef struct _OBJECT_ATTRIBUTES {
        *   ULONG Length;
        *   HANDLE RootDirectory;
        *   PUNICODE_STRING ObjectName;
        *   ULONG Attributes;
        *   PVOID SecurityDescriptor;
        *   PVOID SecurityQualityOfService;
        * } OBJECT_ATTRIBUTES;
        */
    }
}
