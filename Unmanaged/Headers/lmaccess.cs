using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class lmaccess
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct _LOCALGROUP_USERS_INFO_0
        {
            public string lgrui0_name;
        }
        /*
         * typedef struct _LOCALGROUP_USERS_INFO_0 {
         *   LPWSTR lgrui0_name;
         * } LOCALGROUP_USERS_INFO_0, *PLOCALGROUP_USERS_INFO_0, *LPLOCALGROUP_USERS_INFO_0;
         */

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct _GROUP_USERS_INFO_0
        {
            public string grui0_name;
        }
        /*
         * typedef struct _GROUP_USERS_INFO_0 {
         *   LPWSTR grui0_name;
         * } GROUP_USERS_INFO_0, *PGROUP_USERS_INFO_0, *LPGROUP_USERS_INFO_0;
         */
    }
}
