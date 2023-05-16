using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

    public sealed class Fileapi
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _BY_HANDLE_FILE_INFORMATION
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint dwFileAttributes;
            public FILETIME ftCreationTime;
            public FILETIME ftLastAccessTime;
            public FILETIME ftLastWriteTime;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwVolumeSerialNumber;
            [MarshalAs(UnmanagedType.U4)]
            public uint nFileSizeHigh;
            [MarshalAs(UnmanagedType.U4)]
            public uint nFileSizeLow;
            [MarshalAs(UnmanagedType.U4)]
            public uint nNumberOfLinks;
            [MarshalAs(UnmanagedType.U4)]
            public uint nFileIndexHigh;
            [MarshalAs(UnmanagedType.U4)]
            public uint nFileIndexLow;
        }
    }
}
