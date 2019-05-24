using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class ntdll
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtCreateProcessEx(
            ref IntPtr ProcessHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr hInheritFromProcess,
            uint Flags,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            byte InJob
        );

        [DllImport("ntdll.dll", SetLastError = true)]
		public static extern uint NtCreateThreadEx(
			ref IntPtr hThread,
            uint DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr ProcessHandle,
			IntPtr lpStartAddress,
			IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
			IntPtr lpBytesBuffer
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtDuplicateToken(
            IntPtr ExistingTokenHandle,
            Winnt.ACCESS_MASK DesiredAccess,
            wudfwdm._OBJECT_ATTRIBUTES ObjectAttributes,
            bool EffectiveOnly,
            Winnt._TOKEN_TYPE TokenType,
            ref IntPtr NewTokenHandle
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtDuplicateToken(
            IntPtr ExistingTokenHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            bool EffectiveOnly,
            Winnt._TOKEN_TYPE TokenType,
            ref IntPtr NewTokenHandle
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtFilterToken(
            IntPtr TokenHandle,
            uint Flags,
            IntPtr SidsToDisable,
            IntPtr PrivilegesToDelete,
            IntPtr RestrictedSids,
            ref IntPtr hToken
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtGetContextThread(
            IntPtr ProcessHandle,
            IntPtr lpContext
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(
            IntPtr ProcessHandle,
            _PROCESS_INFORMATION_CLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            uint ProcessInformationLength,
            ref uint ReturnLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtSetInformationToken(
            IntPtr TokenHandle,
            int TokenInformationClass,
            ref Winnt._TOKEN_MANDATORY_LABEL TokenInformation,
            int TokenInformationLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtSetInformationProcess(
            IntPtr ProcessHandle,
            _PROCESS_INFORMATION_CLASS ProcessInformationClass,
            ref uint ProcessInformation,
            uint ProcessInformationLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtSetInformationProcess(
            IntPtr ProcessHandle,
            _PROCESS_INFORMATION_CLASS ProcessInformationClass,
            ref _PROCESS_ACCESS_TOKEN ProcessInformation,
            uint ProcessInformationLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtUnmapViewOfSection(
            IntPtr hProcess,
            IntPtr baseAddress
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint RtlNtStatusToDosError(
            uint Status
        );

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PROCESS_ACCESS_TOKEN
        {
            public IntPtr hToken;
            public IntPtr hThread;
        }

        [Flags]
        public enum _PROCESS_INFORMATION_CLASS
        {
            ProcessBasicInformation = 0,
            ProcessQuotaLimits,
            ProcessIoCounters,
            ProcessVmCounters,
            ProcessTimes,
            ProcessBasePriority,
            ProcessRaisePriority,
            ProcessDebugPort,
            ProcessExceptionPort,
            ProcessAccessToken,
            ProcessLdtInformation,
            ProcessLdtSize,
            ProcessDefaultHardErrorMode,
            ProcessIoPortHandlers,
            ProcessPooledUsageAndLimits,
            ProcessWorkingSetWatch,
            ProcessUserModeIOPL,
            ProcessEnableAlignmentFaultFixup,
            ProcessPriorityClass,
            ProcessWx86Information,
            ProcessHandleCount,
            ProcessAffinityMask,
            ProcessPriorityBoost,
            ProcessDeviceMap,
            ProcessSessionInformation,
            ProcessForegroundInformation,
            ProcessWow64Information,
            ProcessImageFileName,
            ProcessLUIDDeviceMapsEnabled,
            ProcessBreakOnTermination,
            ProcessDebugObjectHandle,
            ProcessDebugFlags,
            ProcessHandleTracing,
            ProcessIoPriority,
            ProcessExecuteFlags,
            ProcessTlsInformation,
            ProcessCookie,
            ProcessImageInformation,
            ProcessCycleTime,
            ProcessPagePriority,
            ProcessInstrumentationCallback,
            ProcessThreadStackAllocation,
            ProcessWorkingSetWatchEx,
            ProcessImageFileNameWin32,
            ProcessImageFileMapping,
            ProcessAffinityUpdateMode,
            ProcessMemoryAllocationMode,
            ProcessGroupInformation,
            ProcessTokenVirtualizationEnabled,
            ProcessConsoleHostProcess,
            ProcessWindowInformation,
            MaxProcessInfoClass,
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

    }
}