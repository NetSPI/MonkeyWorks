using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class ntlpcapi
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _ALPC_PORT_ATTRIBUTES
        {
            public AlpcMessageFlags Flags;
            public Winnt._SECURITY_QUALITY_OF_SERVICE SecurityQos;
            public uint MaxMessageLength;
            public IntPtr MemoryBandwidth;
            public IntPtr MaxPoolUsage;
            public IntPtr MaxSectionSize;
            public IntPtr MaxViewSize;
            public IntPtr MaxTotalSectionSize;
            public uint DupObjectTypes;
            public uint Reserved;
        }

        //Referenced from sandbox-attacksurface-analysis-tools
        [StructLayout(LayoutKind.Sequential)]
        public class _PORT_MESSAGE
        {
            [StructLayout(LayoutKind.Explicit)]
            public struct Union1
            {
                [FieldOffset(0)]
                public ushort DataLength;
                [FieldOffset(2)]
                public ushort TotalLength;
                [FieldOffset(0)]
                public uint Length;
            }
            public Union1 u1;

            [StructLayout(LayoutKind.Explicit)]
            public struct Union2
            {
                [FieldOffset(0)]
                public ushort Type;
                [FieldOffset(2)]
                public ushort DataInfoOffset;
                [FieldOffset(0)]
                public uint ZeroInit;
            }
            public Union2 u2;

            public Winnt._LIST_ENTRY ClientId;
            public uint MessageId;

            [StructLayout(LayoutKind.Explicit)]
            public struct Union3
            {
                [FieldOffset(0)]
                public IntPtr ClientViewSize;
                [FieldOffset(0)]
                public uint CallbackId;
            }
            public Union3 u3;

            public _PORT_MESSAGE(ushort length)
            {
                u1.DataLength = (ushort)(length - (ushort)Marshal.SizeOf(typeof(_PORT_MESSAGE)));
                u1.TotalLength = length;
            }

            internal _PORT_MESSAGE Clone()
            {
                return (_PORT_MESSAGE)MemberwiseClone();
            }
        }

        // Instance type of _ALPC_MESSAGE
        [StructLayout(LayoutKind.Sequential)]
        public struct ReportExceptionWerAlpcMessage
        {
            public ntlpcapi._PORT_MESSAGE PortMessage;
            public WerSvcMessageId MessageType;
            public uint NtStatusErrorCode;
            public uint Flags;
            public uint TargetProcessId;
            public IntPtr hFileMapping;
            //public uint Filler0;
            public IntPtr hRecoveryEvent;
            //public uint Filler1;
            public IntPtr hCompletionEvent;
            //public uint Filler2;
            public IntPtr hFileMapping2;
            //public uint Filler3;
            public IntPtr hTargetProcess;
            //public uint Filler4;
            public IntPtr hTargetThread;
            //public uint Filler5;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 324)]
            public uint[] Filler6;
        };

        [Flags]
        public enum AlpcHandleObjectType : uint
        {
            None = 0,
            File = 0x0001,
            Invalid0002 = 0x0002,
            Thread = 0x0004,
            Semaphore = 0x0008,
            Event = 0x0010,
            Process = 0x0020,
            Mutex = 0x0040,
            Section = 0x0080,
            RegKey = 0x0100,
            Token = 0x0200,
            Composition = 0x0400,
            Job = 0x0800,
            AllObjects = File | Thread | Semaphore | Event
                | Process | Mutex | Section | RegKey | Token
                | Composition | Job
        }

        [Flags]
        public enum AlpcMessageFlags : uint
        {
            None = 0,
            ReplyMessage = 0x1,
            LpcMode = 0x2,
            ReleaseMessage = 0x10000,
            SyncRequest = 0x20000,
            TrackPortReferences = 0x40000,
            WaitUserMode = 0x100000,
            WaitAlertable = 0x200000,
            WaitChargePolicy = 0x400000,
            Unknown1000000 = 0x1000000,
            /// <summary>
            /// When used all structures passed to kernel need to be 64 bit versions.
            /// </summary>
            Wow64Call = 0x40000000,
        }

        [Flags]
        public enum WerSvcMessageId : uint
        {
            RequestReportUnhandledException = 0x20000000,
            ReplyReportUnhandledExceptionSuccess = 0x20000001,
            ReplyReportUnhandledExceptionFailure = 0x20000002,
            Something = 0x20000004,
            RequestSilentProcessExit = 0x30000000,
            ResponseSilentProcessExitSuccess = 0x30000001,
            ResponseSilentProcessExitFailure = 0x30000002
        };
    }
}
