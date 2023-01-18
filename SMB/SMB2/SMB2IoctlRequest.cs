using System;

namespace MonkeyWorks.SMB.SMB2
{
    sealed class SMB2IoctlRequest
    {
        private readonly Byte[] StructureSize = { 0x39, 0x00 };
        private readonly Byte[] Reserved = { 0x00, 0x00 };
        private readonly Byte[] Function = { 0x94, 0x01, 0x06, 0x00 };
        private readonly Byte[] GUIDHandle = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        private readonly Byte[] InDataBlobOffset = { 0x78, 0x00, 0x00, 0x00 };
        private Byte[] InDataBlobLength;
        private readonly Byte[] MaxIoctlInSize = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] OutDataBlobOffset = { 0x78, 0x00, 0x00, 0x00 };
        private readonly Byte[] OutDataBlobLength = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] MaxIoctlOutSize = { 0x00, 0x10, 0x00, 0x00 };
        private readonly Byte[] Flags = { 0x01, 0x00, 0x00, 0x00 };
        private readonly Byte[] Reserved2 = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] InDataMaxReferralLevel = { 0x04, 0x00 };
        private Byte[] InDataFileName;


        internal void SetFileName(String fileName)
        {
            this.InDataFileName = System.Text.Encoding.Unicode.GetBytes(fileName);
            this.InDataBlobLength = BitConverter.GetBytes(InDataFileName.Length + 2);
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(StructureSize, Reserved);
            request = Combine.combine(request, Function);
            request = Combine.combine(request, GUIDHandle);
            request = Combine.combine(request, InDataBlobOffset);
            request = Combine.combine(request, InDataBlobLength);
            request = Combine.combine(request, MaxIoctlInSize);
            request = Combine.combine(request, OutDataBlobOffset);
            request = Combine.combine(request, OutDataBlobLength);
            request = Combine.combine(request, MaxIoctlOutSize);
            request = Combine.combine(request, Flags);
            request = Combine.combine(request, Reserved2);
            request = Combine.combine(request, InDataMaxReferralLevel);
            request = Combine.combine(request, InDataFileName);
            return request;
        }
    }
}