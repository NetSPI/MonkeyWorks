using System;
using System.Runtime.InteropServices;
using MonkeyWorks.Unmanaged.Headers;

#pragma warning disable 169

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    public sealed class ntdll
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtAdjustGroupsToken(
            IntPtr TokenIntPtr,
            bool ResetToDefault,
            ref Ntifs._TOKEN_GROUPS TokenGroups,
            ulong PreviousGroupsLength,
            ref Ntifs._TOKEN_GROUPS PreviousGroups,
            ref ulong RequiredLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtAdjustPrivilegesToken(
            IntPtr TokenIntPtr,
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
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessIntPtr,
            ref IntPtr BaseAddress,
            ulong ZeroBits,
            ref ulong RegionSize,
            ulong AllocationType,
            Winnt.MEMORY_PROTECTION_CONSTANTS Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtAlpcConnectPort(
            out IntPtr PortHandle,
            Ntddk._UNICODE_STRING PortName,
            Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
            ntlpcapi._ALPC_PORT_ATTRIBUTES PortAttributes,
            ntlpcapi.AlpcMessageFlags Flags,
            IntPtr RequiredServerSid,
            IntPtr ConnectionMessage,
            IntPtr BufferLength,
            IntPtr OutMessageAttributes,
            IntPtr InMessageAttributes,
            IntPtr Timeout
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtAlpcSendWaitReceivePort(
            IntPtr PortHandle,
            [MarshalAs(UnmanagedType.U4)]
            ntlpcapi.AlpcMessageFlags Flags,
            ref ntlpcapi.ReportExceptionWerAlpcMessage SendMessage,
            IntPtr SendMessageAttributes,
            ref ntlpcapi.ReportExceptionWerAlpcMessage ReceiveMessage,
            [MarshalAs(UnmanagedType.U4)]
            ref uint BufferLength,
            IntPtr ReceiveMessageAttributes,
            IntPtr Timeout
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtClose(IntPtr IntPtr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtCreateProcess(
            ref IntPtr ProcessIntPtr,
            uint DesiredAccess,
            ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr ParentProcess,
            bool InheritObjectTable,
            IntPtr SectionIntPtr,
            IntPtr DebugPort,
            IntPtr ExceptionPort
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtCreateProcessEx(
            ref IntPtr ProcessIntPtr,
            [MarshalAs(UnmanagedType.U4)]
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr hInheritFromProcess,
            [MarshalAs(UnmanagedType.U4)]
            uint Flags,
            IntPtr SectionIntPtr,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            [MarshalAs(UnmanagedType.Bool)]
            bool InJob
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtCreateSection(
            ref IntPtr SectionHandle,
            [MarshalAs(UnmanagedType.U4)]
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong MaximumSize,
            [MarshalAs(UnmanagedType.U8)]
            ulong SectionPageProtection,
            [MarshalAs(UnmanagedType.U8)]
            ulong AllocationAttributes,
            IntPtr FileHandle
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtCreateThread(
            ref IntPtr hThread,
            [MarshalAs(UnmanagedType.U4)] ProcessThreadsApi.ThreadSecurityRights DesiredAccess,
            ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr ProcessIntPtr,
            ref Winnt._LIST_ENTRY ClientId,
            ref Winnt.CONTEXT64 ThreadContext,
            ref Ntpsapi._INITIAL_TEB IntialTeb,
            bool CreateSuspended
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtCreateThreadEx(
            ref IntPtr hThread,
            [MarshalAs(UnmanagedType.U4)] ProcessThreadsApi.ThreadSecurityRights DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessIntPtr,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended,
            [MarshalAs(UnmanagedType.U4)] uint StackZeroBits,
            [MarshalAs(UnmanagedType.U4)] uint SizeOfStackCommit,
            [MarshalAs(UnmanagedType.U4)] uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtCreateToken(
            out IntPtr TokenIntPtr,
            uint DesiredAccess,
            ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
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
        public delegate uint NtDuplicateObject(
            IntPtr SourceProcessHandle,
            IntPtr SourceHandle,
            IntPtr TargetProcessHandle,
            ref IntPtr TargetHandle,
            [MarshalAs(UnmanagedType.U8)]
            ProcessThreadsApi.ProcessSecurityRights DesiredAccess,
            [MarshalAs(UnmanagedType.Bool)]
            bool InheritHandle,
            [MarshalAs(UnmanagedType.U8)]
            ulong Options
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtDuplicateToken(
            IntPtr ExistingTokenIntPtr,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            bool EffectiveOnly,
            Winnt._TOKEN_TYPE TokenType,
            ref IntPtr NewTokenIntPtr
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtFilterToken(
            IntPtr TokenIntPtr,
            uint Flags,
            IntPtr SidsToDisable,
            IntPtr PrivilegesToDelete,
            IntPtr RestrictedSids,
            ref IntPtr hToken
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtGetContextThread(
            IntPtr ProcessIntPtr,
            ref Winnt.CONTEXT64 lpContext
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            [MarshalAs(UnmanagedType.U8)]
            ulong  ZeroBits,
            [MarshalAs(UnmanagedType.U4)]
            uint CommitSize,
            ref Winnt.LARGE_INTEGER SectionOffset,
            [MarshalAs(UnmanagedType.U4)]
            ref uint ViewSize,
            [MarshalAs(UnmanagedType.U4)]
            uint InheritDisposition,
            [MarshalAs(UnmanagedType.U8)]
            ulong AllocationType,
            [MarshalAs(UnmanagedType.U4)]
            Winnt.MEMORY_PROTECTION_CONSTANTS Win32Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenEvent(
            out IntPtr EventHandle,
            [MarshalAs(UnmanagedType.U4)]
            Winnt.ACCESS_MASK DesiredAccess,
            ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes 
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenFile(
           ref IntPtr FileHandle,
           Winnt.ACCESS_MASK DesiredAccess,
           ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
           out Winternl._IO_STATUS_BLOCK IoStatusBlock,
           System.IO.FileShare ShareAccess,
           [MarshalAs(UnmanagedType.U8)]
           ulong OpenOptions
       );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenProcess(
            ref IntPtr hProcess, 
            ProcessThreadsApi.ProcessSecurityRights processAccess, 
            ref Ntddk.OBJECT_ATTRIBUTES objectAttributes, 
            ref Ntddk.CLIENT_ID clientid
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenProcessToken(
            IntPtr ProcessIntPtr,
            [MarshalAs(UnmanagedType.U4)] uint DesiredAccess,
            ref IntPtr TokenIntPtr
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenThread(
            ref IntPtr ThreadIntPtr,
            ProcessThreadsApi.ThreadSecurityRights DesiredAccess,
            ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
            ref Ntddk.CLIENT_ID ClientId
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtOpenThreadToken(
            IntPtr ProcessIntPtr,
            [MarshalAs(UnmanagedType.U4)] uint DesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool OpenAsSelf,
            ref IntPtr TokenIntPtr
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr ProcessIntPtr,
            ref IntPtr BaseAddress,
            ref ulong NumberOfBytesToProtect,
            Winnt.MEMORY_PROTECTION_CONSTANTS NewAccessProtection,
            ref Winnt.MEMORY_PROTECTION_CONSTANTS OldAccessProtection
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtQuerySystemInformation(
            Winternl._SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            [MarshalAs(UnmanagedType.U8)]
            ulong SystemInformationLength,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong ReturnLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtQueryVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            Ntmmapi._MEMORY_INFORMATION_CLASS MemoryInformationClass,
            IntPtr MemoryInformation,
            IntPtr MemoryInformationLength,
            ref IntPtr ReturnLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtSetContextThread(
            IntPtr ThreadIntPtr,
            ref Winnt.CONTEXT64 lpContext
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtSetInformationToken(
            IntPtr TokenIntPtr,
            int TokenInformationClass,
            ref Winnt._TOKEN_MANDATORY_LABEL TokenInformation,
            int TokenInformationLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtSetInformationProcess(
            IntPtr ProcessIntPtr,
            ProcessThreadsApi._PROCESS_INFORMATION_CLASS ProcessInformationClass,
            ref uint ProcessInformation,
            [MarshalAs(UnmanagedType.U4)] uint ProcessInformationLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return:MarshalAs(UnmanagedType.U4)]
        public delegate uint NtSetInformationThread(
            IntPtr ThreadIntPtr,
            ProcessThreadsApi._THREAD_INFORMATION_CLASS ThreadInformationClass,
            ref IntPtr ThreadInformation,
            [MarshalAs(UnmanagedType.U4)] uint ThreadInformationLength 
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtPrivilegeCheck(
            IntPtr TokenIntPtr,
            ref Winnt._PRIVILEGE_SET RequiredPrivileges,
            [MarshalAs(UnmanagedType.Bool)]
            ref bool Result
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtQueryInformationProcess(
            IntPtr ProcessHandle,
            [MarshalAs(UnmanagedType.U4)]
            Winternl.PROCESSINFOCLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            [MarshalAs(UnmanagedType.U4)] 
            uint ProcessInformationLength,
            [MarshalAs(UnmanagedType.U4)] 
            ref uint ReturnLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtQueryInformationThread(
            IntPtr ThreadHandle,
            [MarshalAs(UnmanagedType.U4)]
            ProcessThreadsApi._THREAD_INFORMATION_CLASS ThreadInformationClass,
            IntPtr ThreadInformation,
            [MarshalAs(UnmanagedType.U4)]
            uint ThreadInformationLength,
            [MarshalAs(UnmanagedType.U4)]
            ref uint ReturnLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtQueryInformationToken(
            IntPtr TokenIntPtr,
            Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            ulong TokenInformationLength,
            ref ulong ReturnLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtQueryObject(
            IntPtr Handle,
            Winternl._OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation,
            [MarshalAs(UnmanagedType.U8)]
            ulong ObjectInformationLength,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong ReturnLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtSetInformationFile(
            IntPtr FileHandle,
            ref Winternl._IO_STATUS_BLOCK IoStatusBlock,
            ref Ntddk._FILE_DISPOSITION_INFORMATION FileInformation,
            [MarshalAs(UnmanagedType.U8)]
            ulong Length,
            Winternl._FILE_INFORMATION_CLASS FileInformationClass
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtSuspendThread(
            IntPtr ThreadIntPtr,
            ref ulong PreviousSuspendCount
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtReadVirtualMemory(
            IntPtr ProcessIntPtr,
            IntPtr BaseAddress,
            IntPtr Buffer,
            ulong NumberOfBytesToRead,
            ref ulong NumberOfBytesReaded
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtTerminateProcess(
            IntPtr ProcessIntPtr,
            [MarshalAs(UnmanagedType.U4)] uint ExitStatus
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtUnmapViewOfSection(
            IntPtr hProcess,
            IntPtr baseAddress
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtUpdateWnfStateData(
            [MarshalAs(UnmanagedType.U8)]
            ref Wnf.WnfStateNames StateName,
            IntPtr Buffer,
            [MarshalAs(UnmanagedType.U4)]
            uint Length,
            Wnf._WNF_TYPE_ID TypeId,
            IntPtr ExplicitScope,
            [MarshalAs(UnmanagedType.U4)]
            int MatchingChangeStamp,
            [MarshalAs(UnmanagedType.Bool)]
            bool CheckChangeStamp
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtWaitForSingleObject(
            IntPtr Handle,
            [MarshalAs(UnmanagedType.Bool)]
            bool Alertable,
            [MarshalAs(UnmanagedType.U4)]
            uint Timeout
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            ref Winternl._IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer,
            [MarshalAs(UnmanagedType.U8)]
            ulong Length,
            ref Winnt.LARGE_INTEGER ByteOffset,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong Key
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr ProcessIntPtr,
            IntPtr BaseAddress,
            IntPtr Buffer,
            ulong NumberOfBytesToWrite,
            ref ulong NumberOfBytesWritten
        );
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint RtlCreateProcessReflection(
            IntPtr ProcessHandle,
            uint Flags,
            IntPtr StartRoutine,
            IntPtr StartContext,
            IntPtr EventHandle,
            out Ntrtl._RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint RtlNtStatusToDosError(
            [MarshalAs(UnmanagedType.U4)] uint Status
        );

        /*
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint RtlCreateProcessParametersEx(
            out IntPtr pProcessParameters,
            IntPtr ImagePathName,
            IntPtr DllPath,
            IntPtr CurrentDirectory,
            IntPtr CommandLine,
            IntPtr Environment,
            IntPtr WindowTitle,
            IntPtr DesktopInfo,
            IntPtr ShellInfo,
            IntPtr RuntimeData,
            [MarshalAs(UnmanagedType.U4)] uint Flags
        );
        */

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint RtlCreateProcessParametersEx(
            out IntPtr pProcessParameters,
            ref Ntddk._UNICODE_STRING ImagePathName,
            ref Ntddk._UNICODE_STRING DllPath,
            ref Ntddk._UNICODE_STRING CurrentDirectory,
            ref Ntddk._UNICODE_STRING CommandLine,
            IntPtr Environment,
            ref Ntddk._UNICODE_STRING WindowTitle,
            ref Ntddk._UNICODE_STRING DesktopInfo,
            ref Ntddk._UNICODE_STRING ShellInfo,
            ref Ntddk._UNICODE_STRING RuntimeData,
            [MarshalAs(UnmanagedType.U4)] uint Flags
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint RtlCreateUserThread(
            IntPtr processHandle, 
            IntPtr threadSecurity, 
            [MarshalAs(UnmanagedType.Bool)]
            bool createSuspended, 
            [MarshalAs(UnmanagedType.U8)]
            uint stackZeroBits, 
            [MarshalAs(UnmanagedType.U8)]
            ref ulong stackReserved,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong stackCommit,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong startAddress, 
            IntPtr parameter, 
            ref IntPtr threadHandle, 
            IntPtr clientId
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint RtlReportSilentProcessExit(
            IntPtr processHandle, 
            [MarshalAs(UnmanagedType.U4)]
            uint exitStatus
        );
    }
}