using System;
using System.Runtime.InteropServices;

using BOOLEAN = System.Boolean;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using HANDLE = System.IntPtr;
using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

using ULONG = System.UInt32;
using ULONG32 = System.UInt32;
using ULONG64 = System.UInt64;

using BOOL = System.Boolean;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;
using Microsoft.Win32.SafeHandles;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    sealed class dbghelp
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _LOADED_IMAGE {
            public string ModuleName;
            public HANDLE hFile;
            public IntPtr MappedAddress;
            public Winnt._IMAGE_NT_HEADERS FileHeader;
            public Winnt._IMAGE_SECTION_HEADER LastRvaSection;
            public ULONG NumberOfSections;
            public Winnt._IMAGE_SECTION_HEADER Sections;
            public ULONG Characteristics;
            public BOOLEAN fSystemImage;
            public BOOLEAN fDOSImage;
            public BOOLEAN fReadOnly;
            public IntPtr Version;
            public Winternl._LIST_ENTRY Links;
            public ULONG SizeOfImage;
        }

        [DllImport("dbghelp.dll", SetLastError = true)]
        public static extern Boolean MiniDumpCallback(
            PVOID CallbackParam,
            IntPtr CallbackInput,
            IntPtr CallbackOutput
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool MiniDumpWriteDump(
            IntPtr hProcess,
            [MarshalAs(UnmanagedType.U4)]
            uint ProcessId,
            SafeFileHandle hFile,
            [MarshalAs(UnmanagedType.U4)]
            Minidumpapiset._MINIDUMP_TYPE DumpType,
            IntPtr ExceptionParam,
            IntPtr UserStreamParam,
            IntPtr CallbackParam
        );

    }
}