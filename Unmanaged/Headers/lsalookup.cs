using System.Runtime.InteropServices;

using BOOLEAN = System.Boolean;
using WORD = System.UInt16;
using LONG = System.UInt32;
using ULONG = System.UInt32;
using DWORD = System.UInt32;
using QWORD = System.UInt64;
using ULONGLONG = System.UInt64;
using LARGE_INTEGER = System.UInt64;

using PSID = System.IntPtr;

using PVOID = System.IntPtr;
using HANDLE = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;
using SIZE_T = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class lsalookup
    {
        [System.Flags]
        public enum LSA_ACCESS_MASK : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L,

            POLICY_ALL_ACCESS = 
                POLICY_AUDIT_LOG_ADMIN |
                POLICY_CREATE_ACCOUNT |
                POLICY_CREATE_PRIVILEGE |
                POLICY_CREATE_SECRET |
                POLICY_GET_PRIVATE_INFORMATION |
                POLICY_LOOKUP_NAMES |
                POLICY_NOTIFICATION |
                POLICY_SERVER_ADMIN |
                POLICY_SET_AUDIT_REQUIREMENTS |
                POLICY_SET_DEFAULT_QUOTA_LIMITS |
                POLICY_TRUST_ADMIN |
                POLICY_VIEW_AUDIT_INFORMATION |
                POLICY_VIEW_LOCAL_INFORMATION
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LSA_OBJECT_ATTRIBUTES
        {
            public ULONG Length;
            public HANDLE RootDirectory;
            public ntsecapi._LSA_UNICODE_STRING ObjectName;
            public ULONG Attributes;
            public PVOID SecurityDescriptor;
            public PVOID SecurityQualityOfService;
        }
        /*
         * typedef struct _LSA_OBJECT_ATTRIBUTES {
         *   ULONG               Length;
         *   HANDLE              RootDirectory;
         *   PLSA_UNICODE_STRING ObjectName;
         *   ULONG               Attributes;
         *   PVOID               SecurityDescriptor;
         *   PVOID               SecurityQualityOfService;
         * } LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;
         */
    }
}
