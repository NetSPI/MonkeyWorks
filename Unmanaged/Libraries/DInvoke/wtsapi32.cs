﻿using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    class wtsapi32
    {
        [Flags]
        public enum _WTS_INFO_CLASS : int
        {
            WTSInitialProgram = 0,
            WTSApplicationName = 1,
            WTSWorkingDirectory = 2,
            WTSOEMId = 3,
            WTSSessionId = 4,
            WTSUserName = 5,
            WTSWinStationName = 6,
            WTSDomainName = 7,
            WTSConnectState = 8,
            WTSClientBuildNumber = 9,
            WTSClientName = 10,
            WTSClientDirectory = 11,
            WTSClientProductId = 12,
            WTSClientHardwareId = 13,
            WTSClientAddress = 14,
            WTSClientDisplay = 15,
            WTSClientProtocolType = 16,
            WTSIdleTime = 17,
            WTSLogonTime = 18,
            WTSIncomingBytes = 19,
            WTSOutgoingBytes = 20,
            WTSIncomingFrames = 21,
            WTSOutgoingFrames = 22,
            WTSClientInfo = 23,
            WTSSessionInfo = 24,
            WTSSessionInfoEx = 25,
            WTSConfigInfo = 26,
            WTSValidationInfo = 27,
            WTSSessionAddressV4 = 28,
            WTSIsRemoteSession = 29
        }

        [Flags]
        public enum _WTS_CONNECTSTATE_CLASS : int
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _WTS_SESSION_INFO
        {
            public uint SessionId;
            public string pWinStationName;
            public _WTS_CONNECTSTATE_CLASS State;
        }

        //https://social.msdn.microsoft.com/Forums/vstudio/en-US/aeff7e41-a4ba-4bf0-8677-81162040984d/retrieving-username-of-a-running-process?forum=netfxbcl
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool WTSQuerySessionInformationW(
            IntPtr hServer,
            [MarshalAs(UnmanagedType.U4)] uint SessionId,
            _WTS_INFO_CLASS WTSInfoClass,
            ref IntPtr ppBuffer,
            ref IntPtr pBytesReturned);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool WTSEnumerateSessionsW(
            IntPtr hServer,
            [MarshalAs(UnmanagedType.U4)] uint Reserved,
            [MarshalAs(UnmanagedType.U4)] uint Version,
            ref IntPtr ppSessionInfo,
            [MarshalAs(UnmanagedType.U4)] ref uint pCount);
    }
}