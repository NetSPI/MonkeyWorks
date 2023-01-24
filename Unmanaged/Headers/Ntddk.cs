using System;
using System.Runtime.InteropServices;

using HANDLE = System.IntPtr;
using WORD = System.UInt16;
using LONG = System.UInt32;
using ULONG = System.UInt32;
using DWORD = System.UInt32;
using QWORD = System.UInt64;
using ULONGLONG = System.UInt64;
using LARGE_INTEGER = System.UInt64;

using PSID = System.IntPtr;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;
using SIZE_T = System.IntPtr;
using System.Runtime.ExceptionServices;
using System.Security;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class Ntddk
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }
        
        //Dont add pack
        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES : IDisposable
        {
            public int Length;
            public IntPtr RootDirectory;
            private IntPtr objectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

            public OBJECT_ATTRIBUTES(string name, uint attrs)
            {
                Length = 0;
                RootDirectory = IntPtr.Zero;
                objectName = IntPtr.Zero;
                Attributes = attrs;
                SecurityDescriptor = IntPtr.Zero;
                SecurityQualityOfService = IntPtr.Zero;

                Length = Marshal.SizeOf(this);
                ObjectName = new _UNICODE_STRING(name);
            }

            public _UNICODE_STRING ObjectName
            {
                get
                {
                    return (_UNICODE_STRING)Marshal.PtrToStructure(
                        objectName, typeof(_UNICODE_STRING)
                    );
                }

                set
                {
                    bool fDeleteOld = objectName != IntPtr.Zero;
                    if (!fDeleteOld)
                    {
                        objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                    }
                    Marshal.StructureToPtr(value, objectName, fDeleteOld);
                }
            }

            public void Dispose()
            {
                if (objectName != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(objectName, typeof(_UNICODE_STRING));
                    Marshal.FreeHGlobal(objectName);
                    objectName = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public Winnt._SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
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
        /*
         * typedef struct _OBJECT_ATTRIBUTES {
         *   ULONG Length;
         *   HANDLE RootDirectory;
         *   PUNICODE_STRING ObjectName;
         *   ULONG Attributes;
         *   PVOID SecurityDescriptor;
         *   PVOID SecurityQualityOfService;
         * } OBJECT_ATTRIBUTES;
         */
    }
}
