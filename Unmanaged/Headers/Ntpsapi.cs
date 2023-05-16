using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    // So this is a non-public file that we guess these items came from, so yeah, sorry
    // https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html
    // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/source/inc/ntpsapi.htm
    // If I can't find another place for structs used by ntdll, they are going here

    public sealed class Ntpsapi
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _INITIAL_TEB
        {
            public IntPtr StackBase;
            public IntPtr StackLimit;
            public IntPtr StackCommit;
            public IntPtr StackCommitMax;
            public IntPtr StackReserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PROCESS_ACCESS_TOKEN
        {
            public IntPtr hToken;
            public IntPtr hThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_HANDLE_INFORMATION
        {
            [MarshalAs(UnmanagedType.U8)]
            public ulong NumberOfHandles;
            public SYSTEM_HANDLE_TABLE_ENTRY_INFO[] Handles;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
        { // Information Class 16
            public int ProcessID;
            public byte ObjectTypeNumber;
            public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
            public ushort Handle;
            public int Object_Pointer;
            public uint GrantedAccess;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
        {
            public ushort UniqueProcessId;
            public ushort CreatorBackTraceIndex;
            public byte ObjectTypeIndex;
            public byte HandleAttributes;
            public ushort HandleValue;
            public IntPtr Object;
            public ulong GrantedAccess;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _THREAD_BASIC_INFORMATION
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint ExitStatus;
            public IntPtr TebBaseAddress;
            public Winnt._LIST_ENTRY ClientId;
            public IntPtr AffinityMask;
            [MarshalAs(UnmanagedType.I4)]
            public int Priority;
            [MarshalAs(UnmanagedType.I4)]
            public int BasePriority;
        }
    }
}