using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace MonkeyWorks.Unmanaged.Libraries
{
    class fltlib
    {
        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint FilterDetach(string lpFilterName, string lpVolumeName, string lpInstanceName);

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern uint FilterInstanceFindClose(IntPtr hFilterInstanceFind);

        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint FilterInstanceFindFirst(
            string lpFilterName,
            FltUserStructures._INSTANCE_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            uint dwBufferSize,
            ref uint lpBytesReturned,
            ref IntPtr lpFilterInstanceFind
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern uint FilterInstanceFindNext(
            IntPtr hFilterInstanceFind,
            FltUserStructures._INSTANCE_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            uint dwBufferSize,
            ref uint lpBytesReturned
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern uint FilterFindClose(IntPtr hFilterFind);

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern uint FilterFindFirst(
            FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            uint dwBufferSize,
            ref uint lpBytesReturned,
            ref IntPtr lpFilterFind
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern uint FilterFindNext(
            IntPtr hFilterFind,
            FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            uint dwBufferSize,
            out uint lpBytesReturned
        );

        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint FilterUnload(string lpFilterName);
    }
}
