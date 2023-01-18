using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class ntbasic
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        [SecurityCritical]
        public struct _UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public _UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            [HandleProcessCorruptedStateExceptions]
            public override string ToString()
            {
                string strBuffer = string.Empty;

                try
                {
                    strBuffer = Marshal.PtrToStringUni(buffer);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }

                return strBuffer;
            }

            public void FromString(string s)
            {
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public IntPtr Address()
            {
                return buffer;
            }
        }

    }
}
