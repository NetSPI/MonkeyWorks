using System;

namespace MonkeyWorks.SMB.SMB2
{
    sealed class SMB2ReadRequest
    {
        private readonly Byte[] StructureSize = { 0x31, 0x00 };
        private readonly Byte[] Padding = { 0x50 };
        private readonly Byte[] Flags = { 0x00 };
        private Byte[] Length = { 0x00, 0x10, 0x00, 0x00 };
        private Byte[] Offset = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        private Byte[] GuidHandleFile;
        private readonly Byte[] MinimumCount = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] Channel = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] RemainingBytes = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] ReadChannelInfoOffset = { 0x00, 0x00 };
        private readonly Byte[] ReadChannelInfoLength = { 0x00, 0x00 };
        private readonly Byte[] Buffer = { 0x30 };

        internal SMB2ReadRequest()
        {

        }

        internal void SetLength(Byte[] Length)
        {
            if (this.Length.Length == Length.Length)
            {
                this.Length = Length;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal void SetOffset(Byte[] Offset)
        {
            if (this.Offset.Length == Offset.Length)
            {
                this.Offset = Offset;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal void SetGuidHandleFile(Byte[] GuidHandleFile)
        {
            this.GuidHandleFile = GuidHandleFile;
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(StructureSize, Padding);
            request = Combine.combine(request, Flags);
            request = Combine.combine(request, Length);
            request = Combine.combine(request, Offset);
            request = Combine.combine(request, GuidHandleFile);
            request = Combine.combine(request, MinimumCount);
            request = Combine.combine(request, Channel);
            request = Combine.combine(request, RemainingBytes);
            request = Combine.combine(request, ReadChannelInfoOffset);
            request = Combine.combine(request, ReadChannelInfoLength);
            return Combine.combine(request, Buffer);
        }
    }
}
