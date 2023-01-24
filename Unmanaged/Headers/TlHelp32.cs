using System.Runtime.InteropServices;

using HMODULE = System.IntPtr;
using ULONG_PTR = System.IntPtr;
using LONG = System.Int32;
using DWORD = System.UInt32;
using TCHAR = System.Text.StringBuilder;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class TiHelp32
    {
        public const DWORD TH32CS_INHERIT = 0x80000000;
        public const DWORD TH32CS_SNAPHEAPLIST = 0x00000001;
        public const DWORD TH32CS_SNAPMODULE = 0x00000008;
        public const DWORD TH32CS_SNAPMODULE32 = 0x00000010;
        public const DWORD TH32CS_SNAPPROCESS = 0x00000002;
        public const DWORD TH32CS_SNAPTHREAD = 0x00000004;
        public const DWORD TH32CS_SNAPALL = TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD; 
    
        [StructLayout(LayoutKind.Sequential)]
        public struct tagMODULEENTRY32 
        {
            [MarshalAs(UnmanagedType.U4)]
            public DWORD dwSize;
            [MarshalAs(UnmanagedType.U4)]
            public DWORD th32ModuleID;
            [MarshalAs(UnmanagedType.U4)]
            public DWORD th32ProcessID;
            [MarshalAs(UnmanagedType.U4)]
            public DWORD GlblcntUsage;
            [MarshalAs(UnmanagedType.U4)]
            public DWORD ProccntUsage;
            public System.IntPtr modBaseAddr;
            [MarshalAs(UnmanagedType.U4)]
            public DWORD modBaseSize;
            public HMODULE hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct tagPROCESSENTRY32 
        {
            public DWORD dwSize;
            public DWORD cntUsage;
            public DWORD th32ProcessID;
            public ULONG_PTR th32DefaultHeapID;
            public DWORD th32ModuleID;
            public DWORD cntThreads;
            public DWORD th32ParentProcessID;
            public LONG pcPriClassBase;
            public DWORD dwFlags;
            //[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public TCHAR szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct tagTHREADENTRY32
        {
            public DWORD dwSize;
            public DWORD cntUsage;
            public DWORD th32ThreadID;
            public DWORD th32OwnerProcessID;
            public LONG tpBasePri;
            public LONG tpDeltaPri;
            public DWORD dwFlags;
        }
        //THREADENTRY32
    }
}