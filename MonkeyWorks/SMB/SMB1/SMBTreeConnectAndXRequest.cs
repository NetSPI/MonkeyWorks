using System;
using System.Linq;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBTreeConnectAndXRequest
    {
        private readonly Byte[] WordCount = { 0x04 };
        private readonly Byte[] AndXCommand = { 0xff };
        private readonly Byte[] Reserved = { 0x00 };
        private readonly Byte[] AndXOffset = { 0x00, 0x00 };
        private readonly Byte[] Flags = { 0x00, 0x00 };
        private readonly Byte[] PasswordLength = { 0x01, 0x00 };
        private Byte[] ByteCount;
        private readonly Byte[] Password = { 0x00 };
        private Byte[] Tree;
        private readonly Byte[] Service = { 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x00 };

        internal SMBTreeConnectAndXRequest()
        {

        }

        internal void SetTree(Byte[] Tree)
        {
            this.Tree = Tree;
            ByteCount = BitConverter.GetBytes(Tree.Length + 7).Take(2).ToArray();
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(WordCount, AndXCommand);
            request = Combine.combine(request, Reserved);
            request = Combine.combine(request, AndXOffset);
            request = Combine.combine(request, Flags);
            request = Combine.combine(request, PasswordLength);
            request = Combine.combine(request, ByteCount);
            request = Combine.combine(request, Password);
            request = Combine.combine(request, Tree);
            return Combine.combine(request, Service);
        }
    }
}
