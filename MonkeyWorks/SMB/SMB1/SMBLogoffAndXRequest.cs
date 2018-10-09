using System;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBLogoffAndXRequest
    {
        private readonly Byte[] WordCount = { 0x02 };
        private readonly Byte[] AndXCommand = { 0xff };
        private readonly Byte[] Reserved = { 0x00 };
        private readonly Byte[] AndXOffset = { 0x00, 0x00 };
        private readonly Byte[] ByteCount = { 0x00, 0x00 };

        internal SMBLogoffAndXRequest()
        {

        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(WordCount, AndXCommand);
            request = Combine.combine(request, Reserved);
            request = Combine.combine(request, AndXOffset);
            return Combine.combine(request, ByteCount);
        }
    }
}
