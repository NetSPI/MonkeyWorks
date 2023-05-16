using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    // So this is a non-public file that we guess these items came from, so yeah, sorry
    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html#ae5fbb4213ce766164eeee1cb04d5a84f

    public sealed class Ntrtl
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CURDIR
        {
            public Ntddk._UNICODE_STRING DosPath;
            public IntPtr Handle;

        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct _CURDIR
        {
            public Ntddk._UNICODE_STRING DosPath;
            public IntPtr Handle;

        }

        [StructLayout(LayoutKind.Explicit, Size = 0x18)]
        public struct _RTL_DRIVE_LETTER_CURDIR
        {
            [FieldOffset(0x000)] public ushort Flags;
            [FieldOffset(0x002)] public ushort Length;
            [FieldOffset(0x004)] public uint TimeStamp;
            [FieldOffset(0x008)] public Winternl._STRING DosPath;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
        {
            public IntPtr ReflectionProcessHandle;
            public IntPtr ReflectionThreadHandle;
            public Winternl._CLIENT_ID ReflectionClientId;
        }

        public const uint RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED = 0x00000001;
        public const uint RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES = 0x00000002;
        public const uint RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE = 0x00000004;

    }
}