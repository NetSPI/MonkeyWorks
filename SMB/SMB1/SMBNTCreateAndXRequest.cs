using System;
using System.Linq;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBNTCreateAndXRequest
    {
        private readonly Byte[] WordCount = { 0x18 };
        private readonly Byte[] AndXCommand = { 0xff };
        private readonly Byte[] Reserved = { 0x00 };
        private readonly Byte[] AndXOffset = { 0x00, 0x00 };
        private readonly Byte[] Reserved2 = { 0x00 };
        private Byte[] FileNameLen;
        private readonly Byte[] CreateFlags = { 0x16, 0x00, 0x00, 0x00 };
        private readonly Byte[] RootFID = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] AccessMask = { 0x00, 0x00, 0x00, 0x02 };
        private readonly Byte[] AllocationSize = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] FileAttributes = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] ShareAccess = { 0x07, 0x00, 0x00, 0x00 };
        private readonly Byte[] Disposition = { 0x01, 0x00, 0x00, 0x00 };
        private readonly Byte[] CreateOptions = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] Impersonation = { 0x02, 0x00, 0x00, 0x00 };
        private readonly Byte[] SecurityFlags = { 0x00 };
        private Byte[] ByteCount;
        private Byte[] Filename;

        internal SMBNTCreateAndXRequest()
        {

        }

        internal void SetFileName(Byte[] Filename)
        {
            this.Filename = Filename;
            FileNameLen = BitConverter.GetBytes(Filename.Length - 1).Take(2).ToArray();
            ByteCount = BitConverter.GetBytes(Filename.Length).Take(2).ToArray();
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(WordCount, AndXCommand);
            request = Combine.combine(request, Reserved);
            request = Combine.combine(request, AndXOffset);
            request = Combine.combine(request, Reserved2);
            request = Combine.combine(request, FileNameLen);
            request = Combine.combine(request, CreateFlags);
            request = Combine.combine(request, RootFID);
            request = Combine.combine(request, AccessMask);
            request = Combine.combine(request, AllocationSize);
            request = Combine.combine(request, FileAttributes);
            request = Combine.combine(request, ShareAccess);
            request = Combine.combine(request, Disposition);
            request = Combine.combine(request, CreateOptions);
            request = Combine.combine(request, Impersonation);
            request = Combine.combine(request, SecurityFlags);
            request = Combine.combine(request, ByteCount);
            return  Combine.combine(request, Filename);
        }
    }
}
