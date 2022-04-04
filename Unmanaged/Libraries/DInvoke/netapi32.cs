using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    sealed class netapi32
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NetUserGetLocalGroups(
            [MarshalAs(UnmanagedType.LPWStr)] ref string servername,
            [MarshalAs(UnmanagedType.LPWStr)] ref string username,
            uint level,
            uint flags,
            out IntPtr bufptr,
            int prefmaxlen,
            ref uint entriesread,
            ref uint totalentries
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NetUserGetGroups(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string username,
            uint level,
            out IntPtr bufptr,
            int prefmaxlen,
            ref uint entriesread,
            ref uint totalentries
        );

        /// <summary>
        /// https://www.pinvoke.net/default.aspx/Enums/NET_API_STATUS.html
        /// </summary>
        [Flags]
        public enum NET_API_STATUS : uint
        {
            NERR_Success = 0,
            /// <summary>
            /// This computer name is invalid.
            /// </summary>
            NERR_InvalidComputer = 2351,
            /// <summary>
            /// This operation is only allowed on the primary domain controller of the domain.
            /// </summary>
            NERR_NotPrimary = 2226,
            /// <summary>
            /// This operation is not allowed on this special group.
            /// </summary>
            NERR_SpeGroupOp = 2234,
            /// <summary>
            /// This operation is not allowed on the last administrative account.
            /// </summary>
            NERR_LastAdmin = 2452,
            /// <summary>
            /// The password parameter is invalid.
            /// </summary>
            NERR_BadPassword = 2203,
            /// <summary>
            /// The password does not meet the password policy requirements. 
            /// Check the minimum password length, password complexity and password history requirements.
            /// </summary>
            NERR_PasswordTooShort = 2245,
            /// <summary>
            /// The user name could not be found.
            /// </summary>
            NERR_UserNotFound = 2221,
            ERROR_ACCESS_DENIED = 5,
            ERROR_NOT_ENOUGH_MEMORY = 8,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_INVALID_NAME = 123,
            ERROR_INVALID_LEVEL = 124,
            ERROR_MORE_DATA = 234,
            ERROR_SESSION_CREDENTIAL_CONFLICT = 1219,
            /// <summary>
            /// The RPC server is not available. This error is returned if a remote computer was specified in
            /// the lpServer parameter and the RPC server is not available.
            /// </summary>
            RPC_S_SERVER_UNAVAILABLE = 2147944122, // 0x800706BA
            /// <summary>
            /// Remote calls are not allowed for this process. This error is returned if a remote computer was 
            /// specified in the lpServer parameter and remote calls are not allowed for this process.
            /// </summary>
            RPC_E_REMOTE_DISABLED = 2147549468 // 0x8001011C
        }
    }
}
