using System;
using System.Linq;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBWriteAndXRequest
    {
        private readonly Byte[] WordCount = { 0x0e };
        private readonly Byte[] AndXCommand = { 0xff };
        private readonly Byte[] Reserved = { 0x00 };
        private readonly Byte[] AndXOffset = { 0x00, 0x00 };
        private Byte[] FID;
        private readonly Byte[] Offset = { 0xea, 0x03, 0x00, 0x00 };
        private readonly Byte[] Reserved2 = { 0xff, 0xff, 0xff, 0xff };
        private readonly Byte[] WriteMode = { 0x08, 0x00 };
        private Byte[] Remaining;
        private readonly Byte[] DataLengthHigh = { 0x00, 0x00 };
        private Byte[] DataLengthLow;
        private readonly Byte[] DataOffset = { 0x3f, 0x00 };
        private readonly Byte[] HighOffset = { 0x00, 0x00, 0x00, 0x00 };
        private Byte[] ByteCount;

        internal SMBWriteAndXRequest()
        {

        }

        internal void SetFID(Byte[] FID)
        {
            this.FID = FID;
        }

        internal void SetLength(Int32 dwLength)
        {
            Byte[] bLength = BitConverter.GetBytes(dwLength).Take(2).ToArray();
            Remaining = bLength;
            DataLengthLow = bLength;
            ByteCount = bLength;
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(WordCount, AndXCommand);
            request = Combine.combine(request, Reserved);
            request = Combine.combine(request, AndXOffset);
            request = Combine.combine(request, FID);
            request = Combine.combine(request, Offset);
            request = Combine.combine(request, Reserved2);
            request = Combine.combine(request, WriteMode);
            request = Combine.combine(request, Remaining);
            request = Combine.combine(request, DataLengthHigh);
            request = Combine.combine(request, DataLengthLow);
            request = Combine.combine(request, DataOffset);
            request = Combine.combine(request, HighOffset);
            return Combine.combine(request, ByteCount);
        }
    }
}
