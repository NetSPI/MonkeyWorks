using System;
using System.Runtime.InteropServices;

using BOOL = System.Boolean;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class Winbase
    {
        public const uint SECTION_ALL_ACCESS =
            STANDARD_RIGHTS_REQUIRED |
            SECTION_QUERY |
            SECTION_MAP_WRITE |
            SECTION_MAP_READ |
            SECTION_MAP_EXECUTE |
            SECTION_EXTEND_SIZE;

        /// <summary>Win32 constants</summary>
        public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        /// <summary>Win32 constants</summary>
        public const uint SECTION_QUERY = 0x0001;
        /// <summary>Win32 constants</summary>
        public const uint SECTION_MAP_WRITE = 0x0002;
        /// <summary>Win32 constants</summary>
        public const uint SECTION_MAP_READ = 0x0004;
        /// <summary>Win32 constants</summary>
        public const uint SECTION_MAP_EXECUTE = 0x0008;
        /// <summary>Win32 constants</summary>
        public const uint SECTION_EXTEND_SIZE = 0x0010;

        /// <summary>Win32 constants</summary>
        public const uint FILE_MAP_COPY = SECTION_QUERY;
        /// <summary>Win32 constants</summary>
        public const uint FILE_MAP_WRITE = SECTION_MAP_WRITE;
        /// <summary>Win32 constants</summary>
        public const uint FILE_MAP_READ = SECTION_MAP_READ;
        /// <summary>Win32 constants</summary>
        public const uint FILE_MAP_ALL_ACCESS = SECTION_ALL_ACCESS;


        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms682434(v=vs.85).aspx
        [Flags]
        public enum CREATION_FLAGS : uint
        {
            NONE = 0x0,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        }

        [Flags]
        public enum INFO_PROCESSOR_ARCHITECTURE : ushort
        {
            PROCESSOR_ARCHITECTURE_INTEL = 0,
            PROCESSOR_ARCHITECTURE_ARM = 5,
            PROCESSOR_ARCHITECTURE_IA64 = 6,
            PROCESSOR_ARCHITECTURE_AMD64 = 9,
            PROCESSOR_ARCHITECTURE_ARM64 = 12,
            PROCESSOR_ARCHITECTURE_UNKNOWN = 0xffff
        }

        [Flags]
        public enum OPEN_MODE : uint
        {
            PIPE_ACCESS_INBOUND = 0x00000001,
            PIPE_ACCESS_OUTBOUND = 0x00000002,
            PIPE_ACCESS_DUPLEX = 0x00000003,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            FILE_FLAG_OVERLAPPED = 0x40000000,
            FILE_FLAG_WRITE_THROUGH = 0x80000000
        }

        [Flags]
        public enum PIPE_MODE : uint
        {
            PIPE_TYPE_BYTE = 0x00000000,
            PIPE_TYPE_MESSAGE = 0x00000004,
            PIPE_READMODE_BYTE = 0x00000000,
            PIPE_READMODE_MESSAGE = 0x00000002,
            PIPE_WAIT = 0x00000000,
            PIPE_NOWAIT = 0x00000001,
            PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000,
            PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
        }

        [Flags]
        public enum LOGON_FLAGS : uint
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }

        [Flags]
        public enum LOGON_PROVIDER
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }

        [Flags]
        public enum LOGON_TYPE
        {
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS = 9
        }

        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        public struct _PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public UInt32 dwProcessId;
            public UInt32 dwThreadId;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct _SECURITY_ATTRIBUTES
        {
            public DWORD nLength;
            public LPVOID lpSecurityDescriptor;
            public BOOL bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _STARTUPINFO
        {
            public UInt32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public UInt32 dwX;
            public UInt32 dwY;
            public UInt32 dwXSize;
            public UInt32 dwYSize;
            public UInt32 dwXCountChars;
            public UInt32 dwYCountChars;
            public UInt32 dwFillAttribute;
            public ProcessThreadsApi._STARTUPINFO_FLAGS dwFlags;
            public UInt16 wShowWindow;
            public UInt16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        };

        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        public struct _STARTUPINFOEX
        {
            public _STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
            // PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct _SYSTEM_INFO 
        {
            public INFO_PROCESSOR_ARCHITECTURE wProcessorArchitecture;
            public WORD wReserved;
            public DWORD dwPageSize;
            public LPVOID lpMinimumApplicationAddress;
            public LPVOID lpMaximumApplicationAddress;
            public DWORD_PTR dwActiveProcessorMask;
            public DWORD dwNumberOfProcessors;
            public DWORD dwProcessorType;
            public DWORD dwAllocationGranularity;
            public WORD wProcessorLevel;
            public WORD wProcessorRevision;
        }
    }
}