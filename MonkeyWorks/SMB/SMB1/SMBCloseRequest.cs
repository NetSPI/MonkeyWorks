using System;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBCloseRequest
    {
        private readonly Byte[] WordCount = { 0x03 };
        private Byte[] FID;
        private readonly Byte[] LastWrite = { 0xff, 0xff, 0xff, 0xff };
        private readonly Byte[] ByteCount = { 0x00, 0x00 };

        internal SMBCloseRequest()
        {

        }

        internal void SetFID(Byte[] FID)
        {
            this.FID = FID;
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(WordCount, FID);
            request = Combine.combine(request, LastWrite);
            return Combine.combine(request, ByteCount);
        }
    }
}
