using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    sealed class advapi32
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenGroups(
            IntPtr TokenHandle,
            bool ResetToDefault,
            ref Ntifs._TOKEN_GROUPS NewState,
            uint BufferLength,
            ref Ntifs._TOKEN_GROUPS PreviousState,
            out uint ReturnLengthInBytes
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenGroups(
            IntPtr TokenHandle,
            bool ResetToDefault,
            ref Ntifs._TOKEN_GROUPS NewState,
            uint BufferLength,
            IntPtr PreviousState,
            out uint ReturnLengthInBytes
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref Winnt._TOKEN_PRIVILEGES NewState,
            uint BufferLengthInBytes,
            ref Winnt._TOKEN_PRIVILEGES PreviousState,
            out uint ReturnLengthInBytes
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool AllocateAndInitializeSid(
           ref Winnt._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
           byte nSubAuthorityCount,
           uint nSubAuthority0,
           uint nSubAuthority1,
           uint nSubAuthority2,
           uint nSubAuthority3,
           uint nSubAuthority4,
           uint nSubAuthority5,
           uint nSubAuthority6,
           uint nSubAuthority7,
           out IntPtr pSid
       );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool CloseServiceHandle(IntPtr hSCObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool ControlService(
            IntPtr hService,
            [MarshalAs(UnmanagedType.U4)] Winsvc.dwControl dwControl, 
            ref Winsvc._SERVICE_STATUS lpServiceStatus
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr ControlServiceEx(IntPtr hService, Winsvc.dwControl dwControl, int dwInfoLevel, out Winsvc._SERVICE_STATUS lpServiceStatus);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool ConvertSidToStringSidW(
            ref Ntifs._SID Sid, 
            ref IntPtr StringSid
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool ConvertStringSidToSidW(
            [MarshalAs(UnmanagedType.LPWStr)] string StringSid, 
            ref IntPtr Sid
        );

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorA(
            string StringSecurityDescriptor,
            uint StringSDRevision,
            ref IntPtr SecurityDescriptor,
            ref uint SecurityDescriptorSize
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool CreateProcessWithLogonW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpUsername,
            [MarshalAs(UnmanagedType.LPWStr)] string lpDomain,
            [MarshalAs(UnmanagedType.LPWStr)] string lpPassword,
            [MarshalAs(UnmanagedType.U4)] Winbase.LOGON_FLAGS dwLogonFlags,
            [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
            [MarshalAs(UnmanagedType.U4)] Winbase.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
            ref Winbase._STARTUPINFO lpStartupInfo,
            out Winbase._PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, ref Winbase._SECURITY_ATTRIBUTES lpProcessAttributes, ref Winbase._SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, Winbase.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Winbase._STARTUPINFO lpStartupInfo, out Winbase._PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateProcessAsUserW(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, Winbase.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Winbase._STARTUPINFO lpStartupInfo, out Winbase._PROCESS_INFORMATION lpProcessInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool CreateProcessWithTokenW(
            IntPtr hToken,
            [MarshalAs(UnmanagedType.U4)] Winbase.LOGON_FLAGS dwLogonFlags,
            [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
            [MarshalAs(UnmanagedType.U4)] Winbase.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
            ref Winbase._STARTUPINFO lpStartupInfo,
            out Winbase._PROCESS_INFORMATION lpProcessInfo
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateServiceW(
            IntPtr hSCManager,
            [MarshalAs(UnmanagedType.LPWStr)] string lpServiceName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpDisplayName,
            [MarshalAs(UnmanagedType.U4)] Winsvc.dwDesiredAccess dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)] Winsvc.dwServiceType dwServiceType,
            [MarshalAs(UnmanagedType.U4)] Winsvc.dwStartType dwStartType,
            [MarshalAs(UnmanagedType.U4)] Winsvc.dwErrorControl dwErrorControl,
            [MarshalAs(UnmanagedType.LPWStr)] string lpBinaryPathName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpLoadOrderGroup,
            [MarshalAs(UnmanagedType.LPWStr)] string lpdwTagId,
            [MarshalAs(UnmanagedType.LPWStr)] string lpDependencies,
            [MarshalAs(UnmanagedType.LPWStr)] string lpServiceStartName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpPassword
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool CreateWellKnownSid(
            Winnt.WELL_KNOWN_SID_TYPE WellKnownSidType,
            IntPtr DomainSid,
            IntPtr pSid,
            [MarshalAs(UnmanagedType.U4)] ref uint cbSid
        );

        [Flags]
        public enum CRED_TYPE : uint
        {
            Generic = 1,
            DomainPassword,
            DomainCertificate,
            DomainVisiblePassword,
            GenericCertificate,
            DomainExtended,
            Maximum,
            MaximumEx = Maximum + 1000,
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CredEnumerateW(string Filter, int Flags, out int Count, out IntPtr Credentials);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CredFree(IntPtr Buffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CredReadW(string target, CRED_TYPE type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CredWriteW(ref WinCred._CREDENTIAL userCredential, uint flags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool DeleteService(IntPtr hService);

        //[DllImport("advapi32.dll", SetLastError = true)]
        //public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, Winnt._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, Winnt._TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref Winbase._SECURITY_ATTRIBUTES lpTokenAttributes, Winnt._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, Winnt._TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool ImpersonateLoggedOnUser(IntPtr hToken);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateSelf(Winnt._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool InitializeSecurityDescriptor(Winnt._SECURITY_DESCRIPTOR pSecurityDescriptor, uint dwRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr FreeSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetSecurityDescriptorDacl(ref Winnt._SECURITY_DESCRIPTOR pSecurityDescriptor, ref bool lpbDaclPresent, ref Winnt._ACL pDacl, ref bool lpbDaclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, ref bool lpbDaclPresent, ref Winnt._ACL pDacl, ref bool lpbDaclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, ref bool lpbDaclPresent, IntPtr pDacl, ref bool lpbDaclDefaulted);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint GetSecurityInfo(
            IntPtr handle,
            Accctrl._SE_OBJECT_TYPE ObjectType,
            Winnt.SECURITY_INFORMATION SecurityInfo,
            ref IntPtr ppsidOwner,
            ref IntPtr ppsidGroup,
            ref IntPtr ppDacl,
            ref IntPtr ppSacl,
            ref IntPtr ppSecurityDescriptor
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool GetTokenInformation(
            IntPtr TokenHandle, 
            Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass, 
            IntPtr TokenInformation, 
            uint TokenInformationLength, 
            out uint ReturnLength
        );

        [Flags]
        public enum LOGON_FLAGS
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool LogonUserW(
            [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,
            [MarshalAs(UnmanagedType.LPWStr)] string pszDomain,
            [MarshalAs(UnmanagedType.LPWStr)] string pszPassword,
            Winbase.LOGON_TYPE dwLogonType,
            Winbase.LOGON_PROVIDER dwLogonProvider,
            out IntPtr phToken
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool LogonUserExExW(
            [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,
            [MarshalAs(UnmanagedType.LPWStr)] string pszDomain,
            [MarshalAs(UnmanagedType.LPWStr)] string pszPassword,
            Winbase.LOGON_TYPE dwLogonType,
            Winbase.LOGON_PROVIDER dwLogonProvider,
            ref Ntifs._TOKEN_GROUPS pTokenGroups,
            out IntPtr phToken,
            IntPtr ppLogonSid,
            IntPtr ppProfileBuffer,
            IntPtr pdwProfileLength,
            IntPtr QuotaLimits

        );


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool LookupAccountNameW(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpSystemName,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpAccountName,
            IntPtr Sid,
            ref uint cbSid,
            [MarshalAs(UnmanagedType.LPWStr)]StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out Winnt._SID_NAME_USE peUse
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupAccountSid(
            string lpSystemName, 
            IntPtr Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out Winnt._SID_NAME_USE peUse
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool LookupPrivilegeNameW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpSystemName, 
            IntPtr lpLuid,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpName,
            [MarshalAs(UnmanagedType.U4)] ref uint cchName
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool LookupPrivilegeValueW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpSystemName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpName, 
            ref Winnt._LUID luid
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint LsaEnumerateAccountRights(IntPtr PolicyHandle, IntPtr Sid, out IntPtr UserRights, out long CountOfRights);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint LsaNtStatusToWinError([MarshalAs(UnmanagedType.U4)] uint Status);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint LsaOpenPolicy(
            ref ntsecapi._LSA_UNICODE_STRING SystemName, 
            ref lsalookup._LSA_OBJECT_ATTRIBUTES ObjectAttributes, 
            uint DesiredAccess, 
            ref IntPtr PolicyHandle
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenSCManagerW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpMachineName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpDatabaseName,
            [MarshalAs(UnmanagedType.U4)] Winsvc.dwSCManagerDesiredAccess dwDesiredAccess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenServiceW(
            IntPtr hSCManager,
            [MarshalAs(UnmanagedType.LPWStr)] string lpServiceName,
            [MarshalAs(UnmanagedType.U4)] Winsvc.dwDesiredAccess dwDesiredAccess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate bool PrivilegeCheck(
            IntPtr ClientToken, 
            ref Winnt._PRIVILEGE_SET RequiredPrivileges, 
            out int pfResult
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint SetEntriesInAclW(
            ulong cCountOfExplicitEntries, 
            ref Accctrl._EXPLICIT_ACCESS_W pListOfExplicitEntries, 
            IntPtr OldAcl, 
            ref IntPtr NewAcl
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint SetSecurityInfo(
            IntPtr handle,
            [MarshalAs(UnmanagedType.I4)] Accctrl._SE_OBJECT_TYPE ObjectType,
            Winnt.SECURITY_INFORMATION SecurityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetSecurityDescriptorDacl(ref Winnt._SECURITY_DESCRIPTOR pSecurityDescriptor, bool bDaclPresent, ref Winnt._ACL pDacl, bool bDaclDefaulted);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool SetTokenInformation(
            IntPtr TokenHandle, 
            Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass, 
            IntPtr TokenInformation, 
            int TokenInformationLength
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool StartServiceW(
            IntPtr hService, 
            [MarshalAs(UnmanagedType.U4)] int dwNumServiceArgs, 
            string[] lpServiceArgVectors
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint RegQueryValueEx(UIntPtr hKey, string lpValueName, int lpReserved, ref RegistryValueKind lpType, IntPtr lpData, ref int lpcbData);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint RegQueryValueEx(
            UIntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref int lpType,
            IntPtr lpData,
            ref int lpcbData
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegQueryInfoKey(
            UIntPtr hKey,
            StringBuilder lpClass,
            ref uint lpcchClass,
            IntPtr lpReserved,
            out uint lpcSubkey,
            out uint lpcchMaxSubkeyLen,
            out uint lpcchMaxClassLen,
            out uint lpcValues,
            out uint lpcchMaxValueNameLen,
            out uint lpcbMaxValueLen,
            IntPtr lpSecurityDescriptor,
            IntPtr lpftLastWriteTime
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool RevertToSelf();
    }
} 