using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class ProcessThreadsApi
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _PROC_THREAD_ATTRIBUTE_ENTRY
        {
            public IntPtr Attribute;
            public uint cbSize;
            public IntPtr lpValue;
        }
        //PROC_THREAD_ATTRIBUTE_ENTRY, *LPPROC_THREAD_ATTRIBUTE_ENTRY;

        [StructLayout(LayoutKind.Sequential)]
        public struct _PROC_THREAD_ATTRIBUTE_LIST
        {
            public uint dwFlags;
            public ulong Size;
            public ulong Count;
            public ulong Reserved;
            public IntPtr Unknown;
            public _PROC_THREAD_ATTRIBUTE_ENTRY[] Entries;
        }

       [Flags]
       public enum ThreadSecurityRights : uint
        {
            THREAD_TERMINATE = 0x0001,
            THREAD_SUSPEND_RESUME = 0x0002,
            THREAD_GET_CONTEXT = 0x0008,
            THREAD_SET_CONTEXT = 0x0010,
            THREAD_SET_INFORMATION = 0x0020,
            THREAD_QUERY_INFORMATION = 0x0040,
            THREAD_SET_THREAD_TOKEN = 0x0080,
            THREAD_IMPERSONATE = 0x0100,
            THREAD_DIRECT_IMPERSONATION = 0x0200,                       
            THREAD_SET_LIMITED_INFORMATION = 0x0400,
            THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
            THREAD_ALL_ACCESS = 0x1FFFFF,
/*
            DELETE = 0x00010000L,
            READ_CONTROL = 0x00020000L,           
            WRITE_DAC = 0x00040000L,
            WRITE_OWNER = 0x00080000L,
            SYNCHRONIZE = 0x00100000L
*/
        }

        [Flags]
        public enum ProcessSecurityRights : ulong
        {
            PROCESS_TERMINATE = 0x0001,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
            PROCESS_ALL_ACCESS = 0x1f0fff,

            DELETE = 0x00010000L,
            READ_CONTROL = 0x00020000L,
            WRITE_DAC = 0x00040000L,
            WRITE_OWNER = 0x00080000L,
            SYNCHRONIZE = 0x00100000L
        }
        
        public enum _PROCESS_INFORMATION_CLASS : int
        {
            ProcessMemoryPriority,
            ProcessMemoryExhaustionInfo,
            ProcessAppMemoryInfo,
            ProcessInPrivateInfo,
            ProcessPowerThrottling,
            ProcessReservedValue1,
            ProcessTelemetryCoverageInfo,
            ProcessProtectionLevelInfo,
            ProcessLeapSecondInfo,
            ProcessInformationClassMax
        }

        [Flags]
        public enum _STARTUPINFO_FLAGS
        {
            STARTF_FORCEONFEEDBACK = 0x00000040,
            STARTF_FORCEOFFFEEDBACK = 0x00000080,
            STARTF_PREVENTPINNING = 0x00002000,
            STARTF_RUNFULLSCREEN = 0x00000020,
            STARTF_TITLEISAPPID = 0x00001000,
            STARTF_TITLEISLINKNAME = 0x00000800,
            STARTF_UNTRUSTEDSOURCE = 0x00008000,
            STARTF_USECOUNTCHARS = 0x00000008,
            STARTF_USEFILLATTRIBUTE = 0x00000010,
            STARTF_USEHOTKEY = 0x00000200,
            STARTF_USEPOSITION = 0x00000004,
            STARTF_USESHOWWINDOW = 0x00000001,
            STARTF_USESIZE = 0x00000002,
            STARTF_USESTDHANDLES = 0x00000100,
        }

        // Does not match processthreadsapi.h 
        //http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtSetInformationThread.html
        [Flags]
        public enum _THREAD_INFORMATION_CLASS
        {
            ThreadBasicInformation,
            ThreadTimes,
            ThreadPriority,
            ThreadBasePriority,
            ThreadAffinityMask,
            ThreadImpersonationToken,
            ThreadDescriptorTableEntry,
            ThreadEnableAlignmentFaultFixup,
            ThreadEventPair,
            ThreadQuerySetWin32StartAddress,
            ThreadZeroTlsCell,
            ThreadPerformanceCount,
            ThreadAmILastThread,
            ThreadIdealProcessor,
            ThreadPriorityBoost,
            ThreadSetTlsArrayAddress,
            ThreadIsIoPending,
            ThreadHideFromDebugger
        }
    }
}