using System;

namespace MonkeyWorks.SMB.SMB2
{
    sealed class SMB2TreeDisconnectRequest
    {
        private readonly Byte[] StructureSize = { 0x04, 0x00 };
        private readonly Byte[] Reserved = { 0x00, 0x00 };

        internal SMB2TreeDisconnectRequest()
        {

        }

        internal Byte[] GetRequest()
        {
            return Combine.combine(StructureSize, Reserved);
        }
    }
}
