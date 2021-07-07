using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class advapi32
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AllocateAndInitializeSid(
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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AllocateAndInitializeSid(
            ref Winnt._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            byte nSubAuthorityCount,
            int dwSubAuthority0,
            int dwSubAuthority1,
            int dwSubAuthority2,
            int dwSubAuthority3,
            int dwSubAuthority4,
            int dwSubAuthority5,
            int dwSubAuthority6,
            int dwSubAuthority7,
            out IntPtr pSid
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr ControlService(IntPtr hService, Winsvc.dwControl dwControl, out Winsvc._SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr ControlServiceEx(IntPtr hService, Winsvc.dwControl dwControl, int dwInfoLevel, out Winsvc._SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr Sid, ref IntPtr StringSid);

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(ref Ntifs._SID Sid, ref IntPtr StringSid);

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertStringSidToSidW(string StringSid, ref IntPtr Sid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorA(
            string StringSecurityDescriptor,
            uint StringSDRevision,
            ref IntPtr SecurityDescriptor,
            ref uint SecurityDescriptorSize
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcessWithLogonW(
            string lpUsername,
            string lpDomain,
            string lpPassword,
            Winbase.LOGON_FLAGS dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            Winbase.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Winbase._STARTUPINFO lpStartupInfo,
            out Winbase._PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, ref Winbase._SECURITY_ATTRIBUTES lpProcessAttributes, ref Winbase._SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, Winbase.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Winbase._STARTUPINFO lpStartupInfo, out Winbase._PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateProcessAsUserW(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, Winbase.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Winbase._STARTUPINFO lpStartupInfo, out Winbase._PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, LOGON_FLAGS dwLogonFlags, IntPtr lpApplicationName, IntPtr lpCommandLine, Winbase.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Winbase._STARTUPINFO lpStartupInfo, out Winbase._PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            Winbase.LOGON_FLAGS dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            Winbase.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Winbase._STARTUPINFO lpStartupInfo,
            out Winbase._PROCESS_INFORMATION lpProcessInfo
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateService(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            Winsvc.dwDesiredAccess dwDesiredAccess,
            Winsvc.dwServiceType dwServiceType,
            Winsvc.dwStartType dwStartType,
            Winsvc.dwErrorControl dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            string lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword
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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, Winnt._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, Winnt._TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref Winbase._SECURITY_ATTRIBUTES lpTokenAttributes, Winnt._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, Winnt._TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass, ref Winnt._TOKEN_STATISTICS TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass, ref Winnt._TOKEN_DEFAULT_DACL_ACL TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [Flags]
        public enum LOGON_FLAGS
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        //http://pinvoke.net/default.aspx/advapi32.LogonUser
        [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LogonUser(
            [MarshalAs(UnmanagedType.LPStr)] string pszUserName,
            [MarshalAs(UnmanagedType.LPStr)] string pszDomain,
            [MarshalAs(UnmanagedType.LPStr)] string pszPassword,
            Winbase.LOGON_TYPE dwLogonType,
            Winbase.LOGON_PROVIDER dwLogonProvider,
            out IntPtr phToken
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupAccountName(
            StringBuilder lpSystemName,
            StringBuilder lpAccountName,
            ref Ntifs._SID Sid,
            ref uint cbSid,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out Winnt._SID_NAME_USE peUse
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupAccountName(
            StringBuilder lpSystemName,
            StringBuilder lpAccountName,
            System.IntPtr Sid,
            ref uint cbSid,
            StringBuilder ReferencedDomainName,
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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref Winnt._LUID luid);
        /*
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle, ref Ntifs._SID AccountSid, ref ntsecapi._LSA_UNICODE_STRING UserRights, ref long CountOfRights);
        */
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle, IntPtr Sid, out IntPtr UserRights, out long CountOfRights);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaNtStatusToWinError(uint Status);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaOpenPolicy(ref ntsecapi._LSA_UNICODE_STRING SystemName, ref lsalookup._LSA_OBJECT_ATTRIBUTES ObjectAttributes, uint DesiredAccess, out IntPtr PolicyHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaOpenPolicy(IntPtr SystemName, ref lsalookup._LSA_OBJECT_ATTRIBUTES ObjectAttributes, lsalookup.LSA_ACCESS_MASK DesiredAccess, out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, Winsvc.dwSCManagerDesiredAccess dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, Winsvc.dwDesiredAccess dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool PrivilegeCheck(IntPtr ClientToken, Winnt._PRIVILEGE_SET RequiredPrivileges, IntPtr pfResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool PrivilegeCheck(IntPtr ClientToken, ref Winnt._PRIVILEGE_SET RequiredPrivileges, out int pfResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint SetEntriesInAclW(ulong cCountOfExplicitEntries, ref Accctrl._EXPLICIT_ACCESS_W pListOfExplicitEntries, Winnt._ACL OldAcl, ref Winnt._ACL NewAcl);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint SetEntriesInAclW(ulong cCountOfExplicitEntries, ref Accctrl._EXPLICIT_ACCESS_W pListOfExplicitEntries, ref Winnt._ACL OldAcl, ref IntPtr NewAcl);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetSecurityDescriptorDacl(ref Winnt._SECURITY_DESCRIPTOR pSecurityDescriptor, bool bDaclPresent, ref Winnt._ACL pDacl, bool bDaclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetTokenInformation(
            IntPtr TokenHandle,
            Winnt._TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
    }
} 