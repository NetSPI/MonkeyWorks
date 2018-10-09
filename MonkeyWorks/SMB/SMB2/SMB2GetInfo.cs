using System;

namespace MonkeyWorks.SMB.SMB2
{
    sealed class SMB2GetInfo
    {
        private readonly Byte[] StructureSize = { 0x29, 0x00 };
        private Byte[] Class = new Byte[1];
        private Byte[] InfoLevel = new Byte[1];
        private Byte[] MaxResponseSize = new Byte[4];
        private Byte[] GetInfoInputOffset = new Byte[2];
        private readonly Byte[] Reserved = { 0x00, 0x00 };
        private readonly Byte[] GetInfoInputSize = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] AdditionalInformation = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] Flags = { 0x00, 0x00, 0x00, 0x00 };
        private Byte[] GUIDHandleFile;
        private Byte[] Buffer = new Byte[0];


        internal SMB2GetInfo()
        {
        }

        internal void SetClass(Byte[] Class)
        {
            this.Class = Class;
        }

        internal void SetInfoLevel(Byte[] infoLevel)
        {
            this.InfoLevel = infoLevel;
        }

        internal void SetMaxResponseSize(Byte[] maxResponseSize)
        {
            this.MaxResponseSize = maxResponseSize;
        }

        internal void SetGetInfoInputOffset(Byte[] getInfoInputOffset)
        {
            this.GetInfoInputOffset = getInfoInputOffset;
        }

        internal void SetGUIDHandleFile(Byte[] guidHandleFile)
        {
            this.GUIDHandleFile = guidHandleFile;
        }

        internal void SetBuffer(Int32 bufferSize)
        {
            Buffer = new Byte[bufferSize];
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(StructureSize, Class);
            request = Combine.combine(request, InfoLevel);
            request = Combine.combine(request, MaxResponseSize);
            request = Combine.combine(request, GetInfoInputOffset);
            request = Combine.combine(request, Reserved);
            request = Combine.combine(request, GetInfoInputSize);
            request = Combine.combine(request, AdditionalInformation);
            request = Combine.combine(request, Flags);
            request = Combine.combine(request, GUIDHandleFile);
            request = Combine.combine(request, Buffer);
            return request;
        }

    }
}