using System;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBReadAndXRequest
    {
        private readonly Byte[] WordCount = { 0x0a };
        private readonly Byte[] AndXCommand = { 0xff };
        private readonly Byte[] Reserved = { 0x00 };
        private readonly Byte[] AndXOffset = { 0x00, 0x00 };
        private readonly Byte[] FID = { 0x00, 0x40 };
        private readonly Byte[] Offset = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] MaxCountLow = { 0x58, 0x02 };
        private readonly Byte[] MinCount = { 0x58, 0x02 };
        private readonly Byte[] Unknown = { 0xff, 0xff, 0xff, 0xff };
        private readonly Byte[] Remaining = { 0x00, 0x00 };
        private readonly Byte[] ByteCount = { 0x00, 0x00 };

        internal SMBReadAndXRequest()
        {

        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(WordCount, AndXCommand);
            request = Combine.combine(request, Reserved);
            request = Combine.combine(request, AndXOffset);
            request = Combine.combine(request, FID);
            request = Combine.combine(request, Offset);
            request = Combine.combine(request, MaxCountLow);
            request = Combine.combine(request, MinCount);
            request = Combine.combine(request, Unknown);
            request = Combine.combine(request, Remaining);
            return Combine.combine(request, ByteCount);
        }
    }
}
