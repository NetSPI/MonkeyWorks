using System;
using System.Linq;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBSessionSetupAndXRequest
    {
        private readonly Byte[] WordCount = { 0x0c };
        private readonly Byte[] AndXCommand = { 0xff };
        private readonly Byte[] Reserved = { 0x00 };
        private readonly Byte[] AndXOffset = { 0x00, 0x00 };
        private readonly Byte[] MaxBuffer = { 0xff, 0xff };
        private readonly Byte[] MaxMpxCount = { 0x02, 0x00 };
        private readonly Byte[] VCNumber = { 0x01, 0x00 };
        private readonly Byte[] SessionKey = { 0x00, 0x00, 0x00, 0x00 };
        private Byte[] SecurityBlobLength;
        private readonly Byte[] Reserved2 = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] Capabilities = { 0x44, 0x00, 0x00, 0x80 };
        private Byte[] ByteCount;
        private Byte[] SecurityBlob;
        private readonly Byte[] NativeOS = { 0x00, 0x00, 0x00 };
        private readonly Byte[] NativeLANManage = { 0x00, 0x00 };

        internal SMBSessionSetupAndXRequest()
        {

        }

        internal void SetSecurityBlog(Byte[] SecurityBlob)
        {
            this.SecurityBlob = SecurityBlob;
            ByteCount = BitConverter.GetBytes(SecurityBlob.Length).Take(2).ToArray();
            SecurityBlobLength = BitConverter.GetBytes(SecurityBlob.Length).Take(2).ToArray();
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(WordCount, AndXCommand);
            request = Combine.combine(request, Reserved);
            request = Combine.combine(request, AndXOffset);
            request = Combine.combine(request, MaxBuffer);
            request = Combine.combine(request, MaxMpxCount);
            request = Combine.combine(request, VCNumber);
            request = Combine.combine(request, SessionKey);
            request = Combine.combine(request, SecurityBlobLength);
            request = Combine.combine(request, Reserved2);
            request = Combine.combine(request, Capabilities);
            request = Combine.combine(request, ByteCount);
            request = Combine.combine(request, SecurityBlob);
            request = Combine.combine(request, NativeOS);
            return Combine.combine(request, NativeLANManage);
        }
    }
}
