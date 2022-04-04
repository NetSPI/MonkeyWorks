using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    sealed class ntdll
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtAdjustGroupsToken(
            IntPtr TokenHandle,
            bool ResetToDefault,
            ref Ntifs._TOKEN_GROUPS TokenGroups,
            ulong PreviousGroupsLength,
            ref Ntifs._TOKEN_GROUPS PreviousGroups,
            ref ulong RequiredLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtAdjustPrivilegesToken(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref Winnt._TOKEN_PRIVILEGES TokenPrivileges,
            ulong PreviousPrivilegesLength,
            ref Winnt._TOKEN_PRIVILEGES PreviousPrivileges,
            ref ulong RequiredLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtAllocateLocallyUniqueId(ref Winnt._LUID LocallyUniqueID);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtClose(IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtCreateProcess(
            ref IntPtr ProcessHandle,
            uint DesiredAccess,
            ref wudfwdm._OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr ParentProcess,
            bool InheritObjectTable,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort
        );


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

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtCreateToken(
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

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtDuplicateToken(
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

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenProcess(
            ref IntPtr hProcess, 
            ProcessThreadsApi.ProcessSecurityRights processAccess, 
            ref OBJECT_ATTRIBUTES objectAttributes, 
            ref CLIENT_ID clientid
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenProcessToken(
            IntPtr ProcessHandle,
            [MarshalAs(UnmanagedType.U4)] uint DesiredAccess,
            ref IntPtr TokenHandle
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

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtSetInformationProcess(
            IntPtr ProcessHandle,
            _PROCESS_INFORMATION_CLASS ProcessInformationClass,
            ref uint ProcessInformation,
            [MarshalAs(UnmanagedType.U4)] uint ProcessInformationLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return:MarshalAs(UnmanagedType.U4)]
        public delegate uint NtSetInformationThread(
            IntPtr ThreadHandle,
            _THREAD_INFORMATION_CLASS ThreadInformationClass,
            ref IntPtr ThreadInformation,
            [MarshalAs(UnmanagedType.U4)] uint ThreadInformationLength 
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenThread(
            ref IntPtr ThreadHandle,
            ProcessThreadsApi.ThreadSecurityRights DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenThreadToken(
            IntPtr ProcessHandle,
            [MarshalAs(UnmanagedType.U4)] uint DesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool OpenAsSelf,
            ref IntPtr TokenHandle
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtPrivilegeCheck(
            IntPtr TokenHandle,
            ref Winnt._PRIVILEGE_SET RequiredPrivileges,
            ref bool Result
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtQueryInformationToken(
            IntPtr TokenHandle,
            Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            ulong TokenInformationLength,
            ref ulong ReturnLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtTerminateProcess(
            IntPtr ProcessHandle,
            [MarshalAs(UnmanagedType.U4)] uint ExitStatus
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtUnmapViewOfSection(
            IntPtr hProcess,
            IntPtr baseAddress
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint RtlNtStatusToDosError([MarshalAs(UnmanagedType.U4)] uint Status);

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