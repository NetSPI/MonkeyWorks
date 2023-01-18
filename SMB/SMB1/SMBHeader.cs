using System;

namespace MonkeyWorks.SMB.SMB1
{
    class SMBHeader
    {
        private readonly Byte[] ServerComponent = { 0xff, 0x53, 0x4d, 0x42 };
        private Byte[] Command = new Byte[1];
        private readonly Byte[] NtStatus = { 0x00, 0x00, 0x00, 0x00 };
        private Byte[] Flags = new Byte[1];
        private Byte[] Flags2 = new Byte[2];
        private readonly Byte[] ProcessIDHigh = { 0x00, 0x00 };
        private readonly Byte[] Signature = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] Reserved2 = { 0x00, 0x00 };
        private Byte[] TreeID = new Byte[2];
        private Byte[] ProcessID = new Byte[2];
        private Byte[] UserID = new Byte[2];
        private readonly Byte[] MultiplexID = { 0x00, 0x00 };

        internal SMBHeader()
        {
        }

        internal void SetCommand(Byte[] command)
        {
            if (command.Length == this.Command.Length)
            {
                this.Command = command;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal void SetFlags(Byte[] flags)
        {
            if (flags.Length == this.Flags.Length)
            {
                this.Flags = flags;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal void SetFlags2(Byte[] flags2)
        {
            if (flags2.Length == this.Flags2.Length)
            {
                this.Flags2 = flags2;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal void SetTreeID(Byte[] treeId)
        {
            if (treeId.Length == this.TreeID.Length)
            {
                this.TreeID = treeId;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal void SetProcessID(Byte[] processId)
        {
            if (processId.Length == this.ProcessID.Length)
            {
                this.ProcessID = processId;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal void SetTreeId(Byte[] treeId)
        {
            if (treeId.Length == this.TreeID.Length)
            {
                this.TreeID = treeId;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal void SetUserID(Byte[] userId)
        {
            if (userId.Length == this.UserID.Length)
            {
                this.UserID = userId;
                return;
            }
            throw new IndexOutOfRangeException();
        }

        internal Byte[] GetHeader()
        {
            Byte[] header = Combine.combine(ServerComponent, Command);
            header = Combine.combine(header, NtStatus);
            header = Combine.combine(header, Flags);
            header = Combine.combine(header, Flags2);
            header = Combine.combine(header, ProcessIDHigh);
            header = Combine.combine(header, Signature);
            header = Combine.combine(header, Reserved2);
            header = Combine.combine(header, TreeID);
            header = Combine.combine(header, ProcessID);
            header = Combine.combine(header, UserID);
            header = Combine.combine(header, MultiplexID);
            return header;
        }
    }
}