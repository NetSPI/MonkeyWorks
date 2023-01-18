using System;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBTreeDisconnectRequest
    {
        private readonly Byte[] WordCount = { 0x00 };
        private readonly Byte[] ByteCount = { 0x00, 0x00 };

        internal SMBTreeDisconnectRequest()
        {

        }

        internal Byte[] GetRequest()
        {
            return Combine.combine(WordCount, ByteCount);
        }
    }
}
