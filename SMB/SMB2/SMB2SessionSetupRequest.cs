using System;
using System.Linq;

namespace MonkeyWorks.SMB.SMB2
{
    sealed class SMB2SessionSetupRequest
    {
        private readonly Byte[] StructureSize = { 0x19, 0x00 };
        private readonly Byte[] Flags = { 0x00 };
        private readonly Byte[] SecurityMode = { 0x01 };
        private readonly Byte[] Capabilities = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] Channel = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] BlobOffset = { 0x58, 0x00 };
        private Byte[] BlobLength = new Byte[2];
        private readonly Byte[] PreviousSessionID = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        private Byte[] SecurityBlob;

        internal SMB2SessionSetupRequest()
        {
        }

        internal void SetSecurityBlob(Byte[] securityBlob)
        {
            BlobLength = BitConverter.GetBytes(securityBlob.Length).Take(2).ToArray();
            this.SecurityBlob = securityBlob;
        }

        internal Byte[] GetSMB2SessionSetupRequest()
        {
            Byte[] request = Combine.combine(StructureSize, Flags);
            request = Combine.combine(request, SecurityMode);
            request = Combine.combine(request, Capabilities);
            request = Combine.combine(request, Channel);
            request = Combine.combine(request, BlobOffset);
            request = Combine.combine(request, BlobLength);
            request = Combine.combine(request, PreviousSessionID);
            request = Combine.combine(request, SecurityBlob);
            return request;
        }
    }
}