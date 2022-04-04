using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    class fltlib
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint FilterDetach(string lpFilterName, string lpVolumeName, string lpInstanceName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint FilterInstanceFindClose(IntPtr hFilterInstanceFind);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint FilterInstanceFindFirst(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFilterName,
            [MarshalAs(UnmanagedType.U4)] FltUserStructures._INSTANCE_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            [MarshalAs(UnmanagedType.U4)] uint dwBufferSize,
            [MarshalAs(UnmanagedType.U4)] ref uint lpBytesReturned,
            ref IntPtr lpFilterInstanceFind
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint FilterInstanceFindNext(
            IntPtr hFilterInstanceFind,
            [MarshalAs(UnmanagedType.U4)] FltUserStructures._INSTANCE_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            [MarshalAs(UnmanagedType.U4)] uint dwBufferSize,
            [MarshalAs(UnmanagedType.U4)] ref uint lpBytesReturned
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint FilterFindClose(IntPtr hFilterFind);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint FilterFindFirst(
            [MarshalAs(UnmanagedType.U4)] FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            [MarshalAs(UnmanagedType.U4)] uint dwBufferSize,
            [MarshalAs(UnmanagedType.U4)] ref uint lpBytesReturned,
            ref IntPtr lpFilterFind
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint FilterFindNext(
            IntPtr hFilterFind,
            [MarshalAs(UnmanagedType.U4)] FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            [MarshalAs(UnmanagedType.U4)] uint dwBufferSize,
            [MarshalAs(UnmanagedType.U4)] ref uint lpBytesReturned
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate uint FilterUnload(string lpFilterName);
    }
}
