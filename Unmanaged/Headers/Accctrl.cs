using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    public class Accctrl
    {
        [Flags]
        public enum _ACCESS_MODE
        {
            NOT_USED_ACCESS,
            GRANT_ACCESS,
            SET_ACCESS,
            DENY_ACCESS,
            REVOKE_ACCESS,
            SET_AUDIT_SUCCESS,
            SET_AUDIT_FAILURE
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _EXPLICIT_ACCESS_A
        {
            public uint grfAccessPermissions;
            public _ACCESS_MODE grfAccessMode;
            public uint grfInheritance;
            public _TRUSTEE_A Trustee;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct _EXPLICIT_ACCESS_W
        {
            public Winuser.WindowStationSecurity grfAccessPermissions;
            public _ACCESS_MODE grfAccessMode;
            public Inheritance grfInheritance;
            public _TRUSTEE_W Trustee;
        }
        //FILTER_AGGREGATE_BASIC_INFORMATION, *PFILTER_AGGREGATE_BASIC_INFORMATION;

        [Flags]
        public enum Inheritance : uint
        {
            NO_INHERITANCE = 0x0,
            SUB_OBJECTS_ONLY_INHERIT = 0x1,
            SUB_CONTAINERS_ONLY_INHERIT = 0x2,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3,
            INHERIT_NO_PROPAGATE = 0x4,
            INHERIT_ONLY = 0x8,
            INHERITED_ACCESS_ENTRY = 0x10,
            INHERITED_PARENT = 0x10000000,
            INHERITED_GRANDPARENT = 0x20000000
        }

        [Flags]
        public enum _MULTIPLE_TRUSTEE_OPERATION
        {
            NO_MULTIPLE_TRUSTEE,
            TRUSTEE_IS_IMPERSONATE
        }

        [Flags]
        public enum _SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY,
            SE_REGISTRY_WOW64_64KEY
        }


        [Flags]
        public enum _TRUSTEE_FORM
        {
            TRUSTEE_IS_SID,
            TRUSTEE_IS_NAME,
            TRUSTEE_BAD_FORM,
            TRUSTEE_IS_OBJECTS_AND_SID,
            TRUSTEE_IS_OBJECTS_AND_NAME
        }

        [Flags]
        public enum _TRUSTEE_TYPE
        {
            TRUSTEE_IS_UNKNOWN,
            TRUSTEE_IS_USER,
            TRUSTEE_IS_GROUP,
            TRUSTEE_IS_DOMAIN,
            TRUSTEE_IS_ALIAS,
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            TRUSTEE_IS_DELETED,
            TRUSTEE_IS_INVALID,
            TRUSTEE_IS_COMPUTER
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct _TRUSTEE_A
        {
            public IntPtr pMultipleTrustee;
            public _MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            public _TRUSTEE_FORM TrusteeForm;
            public _TRUSTEE_TYPE TrusteeType;
            public IntPtr ptstrName;
        }

        //From PInvoke.net
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct _TRUSTEE_W : IDisposable
        {
            public IntPtr pMultipleTrustee;
            public _MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            public _TRUSTEE_FORM TrusteeForm;
            public _TRUSTEE_TYPE TrusteeType;
            public IntPtr ptstrName;

            void IDisposable.Dispose()
            {
                if (ptstrName != IntPtr.Zero) Marshal.Release(ptstrName);
            }

            public string Name { get { return Marshal.PtrToStringAuto(ptstrName); } }
        }

    }
}
