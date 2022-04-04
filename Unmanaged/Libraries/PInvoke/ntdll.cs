using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class ntdll
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtAllocateLocallyUniqueId( 
            ref Winnt._LUID LocallyUniqueID
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

        //This is the way
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtCreateToken(
            out IntPtr TokenHandle,
            uint DesiredAccess,
            ref wudfwdm._OBJECT_ATTRIBUTES ObjectAttributes,
            Winnt._TOKEN_TYPE TokenType,
            ref Winnt._LUID AuthenticationId, //From NtAllocateLocallyUniqueId
            ref long ExpirationTime,
            ref Ntifs._TOKEN_USER TokenUser,
            ref Ntifs._TOKEN_GROUPS TokenGroups,
            ref Winnt._TOKEN_PRIVILEGES_ARRAY TokenPrivileges,
            ref Ntifs._TOKEN_OWNER TokenOwner,
            ref Winnt._TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            ref Winnt._TOKEN_DEFAULT_DACL TokenDefaultDacl,
            ref Winnt._TOKEN_SOURCE TokenSource
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

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public ulong Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public ulong Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [DllImport("ntdll.dll")]//, SetLastError = true, EntryPoint = "NtOpenProcess")]
        public static extern uint NtOpenProcess(
            ref IntPtr ProcessHandle, 
            UInt32 AccessMask, 
            ref OBJECT_ATTRIBUTES ObjectAttributes, 
            ref CLIENT_ID ClientId
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
            ProcessProtectionInformation = 61
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