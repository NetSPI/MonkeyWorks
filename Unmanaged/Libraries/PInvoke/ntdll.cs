using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace MonkeyWorks.Unmanaged.Libraries
{
    public sealed class ntdll
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtAdjustPrivilegesToken(
            IntPtr TokenIntPtr,
            bool DisableAllPrivileges,
            ref Winnt._TOKEN_PRIVILEGES TokenPrivileges,
            ulong PreviousPrivilegesLength,
            ref Winnt._TOKEN_PRIVILEGES PreviousPrivileges,
            ref ulong RequiredLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtAlpcConnectPort(
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

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtAlpcSendWaitReceivePort(
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

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtAllocateVirtualMemory(
            IntPtr ProcessIntPtr,
            ref IntPtr BaseAddress,
            ulong ZeroBits,
            ref ulong RegionSize,
            ulong AllocationType,
            Winnt.MEMORY_PROTECTION_CONSTANTS Protect
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtAllocateLocallyUniqueId( 
            ref Winnt._LUID LocallyUniqueID
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtClose(IntPtr IntPtr);

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtCreateSection(
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

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtCreateThreadEx(
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

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern  uint NtCreateProcessEx(
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

        //This is the way
        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtCreateToken(
            out IntPtr TokenHandle,
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

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtDuplicateToken(
            IntPtr ExistingTokenHandle,
            Winnt.ACCESS_MASK DesiredAccess,
            Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
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

        [DllImport("ntdll.dll", SetLastError = true, EntryPoint = "NtGetContextThread")]
        public static extern uint NtGetContextThread32(
            IntPtr ProcessHandle,
            ref Winnt.CONTEXT lpContext
        );

        [DllImport("ntdll.dll", SetLastError = true, EntryPoint = "NtGetContextThread")]
        public static extern uint NtGetContextThread64(
            IntPtr ProcessHandle,
            ref Winnt.CONTEXT64 lpContext
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtOpenEvent(
            out IntPtr EventHandle,
            [MarshalAs(UnmanagedType.U4)]
            Winnt.ACCESS_MASK DesiredAccess,
            ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtOpenFile(
           ref IntPtr FileHandle,
           Winnt.ACCESS_MASK DesiredAccess,
           ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
           out Winternl._IO_STATUS_BLOCK IoStatusBlock,
           System.IO.FileShare ShareAccess,
           [MarshalAs(UnmanagedType.U8)]
           ulong OpenOptions
       );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtOpenProcess(
            ref IntPtr hProcess,
            ProcessThreadsApi.ProcessSecurityRights processAccess,
            ref Ntddk.OBJECT_ATTRIBUTES objectAttributes,
            ref Ntddk.CLIENT_ID clientid
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtOpenThread(
            ref IntPtr ThreadIntPtr,
            ProcessThreadsApi.ThreadSecurityRights DesiredAccess,
            ref Ntddk.OBJECT_ATTRIBUTES ObjectAttributes,
            ref Ntddk.CLIENT_ID ClientId
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtPrivilegeCheck(
            IntPtr TokenIntPtr,
            ref Winnt._PRIVILEGE_SET RequiredPrivileges,
            [MarshalAs(UnmanagedType.Bool)]
            ref bool Result
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtProtectVirtualMemory(
            IntPtr ProcessIntPtr,
            ref IntPtr BaseAddress,
            ref ulong NumberOfBytesToProtect,
            Winnt.MEMORY_PROTECTION_CONSTANTS NewAccessProtection,
            ref Winnt.MEMORY_PROTECTION_CONSTANTS OldAccessProtection
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtQueryInformationProcess(
            IntPtr ProcessHandle,
            Winternl.PROCESSINFOCLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            uint ProcessInformationLength,
            ref uint ReturnLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtQueryInformationToken(
            IntPtr TokenIntPtr,
            Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            ulong TokenInformationLength,
            ref ulong ReturnLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtQuerySystemInformation(
            Winternl._SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            [MarshalAs(UnmanagedType.U8)]
            ulong SystemInformationLength,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong ReturnLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtReadVirtualMemory(
            IntPtr ProcessIntPtr,
            IntPtr BaseAddress,
            IntPtr Buffer,
            ulong NumberOfBytesToRead,
            ref ulong NumberOfBytesReaded
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtSetInformationFile(
            IntPtr FileHandle,
            ref Winternl._IO_STATUS_BLOCK IoStatusBlock,
            ref Ntddk._FILE_DISPOSITION_INFORMATION FileInformation,
            [MarshalAs(UnmanagedType.U8)]
            ulong Length,
            Winternl._FILE_INFORMATION_CLASS FileInformationClass
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtSetInformationToken(
            IntPtr TokenHandle,
            int TokenInformationClass,
            ref Winnt._TOKEN_MANDATORY_LABEL TokenInformation,
            int TokenInformationLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtSetInformationProcess(
            IntPtr ProcessHandle,
            ProcessThreadsApi._PROCESS_INFORMATION_CLASS ProcessInformationClass,
            ref uint ProcessInformation,
            uint ProcessInformationLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtSetInformationProcess(
            IntPtr ProcessHandle,
            ProcessThreadsApi._PROCESS_INFORMATION_CLASS ProcessInformationClass,
            ref Ntpsapi._PROCESS_ACCESS_TOKEN ProcessInformation,
            uint ProcessInformationLength
        );

        [DllImport("ntdll.dll", SetLastError = true, EntryPoint = "NtSetContextThread")]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtSetContextThread32(
            IntPtr ThreadIntPtr,
            ref Winnt.CONTEXT lpContext
        );

        [DllImport("ntdll.dll", SetLastError = true, EntryPoint = "NtSetContextThread")]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtSetContextThread64(
            IntPtr ThreadIntPtr,
            ref Winnt.CONTEXT64 lpContext
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtSuspendThread(
            IntPtr ThreadIntPtr,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong PreviousSuspendCount
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtUnmapViewOfSection(
            IntPtr hProcess,
            IntPtr baseAddress
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtUpdateWnfStateData(
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

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtWaitForSingleObject(
            IntPtr Handle,
            [MarshalAs(UnmanagedType.Bool)]
            bool Alertable,
            [MarshalAs(UnmanagedType.U4)]
            uint Timeout
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtWriteFile(
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

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtWriteVirtualMemory(
            IntPtr ProcessIntPtr,
            IntPtr BaseAddress,
            IntPtr Buffer,
            ulong NumberOfBytesToWrite,
            ref ulong NumberOfBytesWritten
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint RtlCreateProcessParametersEx(
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

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint RtlCreateUserThread(
            IntPtr processHandle,
            IntPtr threadSecurity,
            [MarshalAs(UnmanagedType.Bool)]
            bool createSuspended,
            [MarshalAs(UnmanagedType.U4)]
            uint stackZeroBits,
            IntPtr stackReserved,
            IntPtr stackCommit,
            IntPtr startAddress,
            IntPtr parameter,
            ref IntPtr threadHandle,
            Ntddk.CLIENT_ID clientId
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint RtlNtStatusToDosError(
            uint Status
        );
    }
}