using System.Runtime.InteropServices;

using PSID = System.IntPtr;

using UCHAR = System.Byte;
using ULONG = System.Int32;
using DWORD = System.UInt32;

//https://blogs.technet.microsoft.com/fabricem_blogs/2009/07/21/active-directory-maximum-limits-scalability/

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class Ntifs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _SID
        {
            public byte Revision;
            public byte SubAuthorityCount;
            public Winnt._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public DWORD[] SubAuthority;
        }
        //SID, *PISID

        [StructLayout(LayoutKind.Sequential)]
        public struct _PSID
        {
            byte Revision;
            byte SubAuthorityCount;
            Winnt._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            System.IntPtr SubAuthority;
        }
        //SID, *PISID

        //Also defined in Winnt
        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_GROUPS
        {
            public ULONG GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 230)]
            public Winnt._SID_AND_ATTRIBUTES[] Groups;
            public void Initialize()
            {
                Groups = new Winnt._SID_AND_ATTRIBUTES[230];
                
                for (int i = 0; i < 230; i++)
                {
                    Groups[i].Sid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(System.IntPtr)));
                }
            }
        }
        /*
         * typedef struct _TOKEN_GROUPS {
         * ULONG              GroupCount;
         * #if ...
         *   SID_AND_ATTRIBUTES *Groups[];
         * #else
         *   SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
         * #endif
         * } TOKEN_GROUPS, *PTOKEN_GROUPS;
         */

        //Also defined in Winnt
        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_GROUPS_DYNAMIC
        {
            public ULONG GroupCount;
            public Winnt._SID_AND_ATTRIBUTES[] Groups;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_OWNER
        {
            public PSID Owner;
        }
        //TOKEN_OWNER, *PTOKEN_OWNER

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct _TOKEN_USER_U
        {
            public Winnt._SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_USER
        {
            public Winnt._SID_AND_ATTRIBUTES User;
        }
        /*
         * typedef struct _TOKEN_USER {
         *  SID_AND_ATTRIBUTES User;
         * } TOKEN_USER, *PTOKEN_USER;
         */
}
}