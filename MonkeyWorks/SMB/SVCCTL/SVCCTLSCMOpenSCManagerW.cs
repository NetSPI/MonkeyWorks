using System;
using System.Text;

namespace MonkeyWorks.SMB.SVCCTL
{
    sealed class SVCCTLSCMOpenSCManagerW
    {
        private Byte[] MachineName_ReferentID;
        private Byte[] MachineName_MaxCount;
        private readonly Byte[] MachineName_Offset = { 0x00, 0x00, 0x00, 0x00 };
        private Byte[] MachineName_ActualCount;
        private Byte[] MachineName;
        private Byte[] Database_ReferentID;
        private readonly Byte[] Database_NameMaxCount = { 0x0f, 0x00, 0x00, 0x00 };
        private readonly Byte[] Database_NameOffset = { 0x00, 0x00, 0x00, 0x00 };
        private readonly Byte[] Database_NameActualCount = { 0x0f, 0x00, 0x00, 0x00 };
        private readonly Byte[] Database = { 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x41, 0x00, 0x63, 0x00, 0x74, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x00, 0x00 };
        private readonly Byte[] Unknown = { 0xbf, 0xbf };
        private readonly Byte[] AccessMask = { 0x3f, 0x00, 0x00, 0x00 };

        internal SVCCTLSCMOpenSCManagerW()
        {
            String strMachineName = SVCCTLSCMCreateServiceW.GenerateUuidAlpha(20);
            MachineName = Encoding.Unicode.GetBytes(strMachineName);
            /*
            if (0 == MachineName.Length % 2)
                MachineName = Combine.combine(MachineName, new Byte[] { 0x00, 0x00 });
            else
                MachineName = Combine.combine(MachineName, new Byte[] { 0x00, 0x00, 0x00, 0x00 });
            */
            MachineName = Combine.combine(MachineName, new Byte[] { 0x00, 0x00, 0x00, 0x00 });
            MachineName_ActualCount = MachineName_MaxCount = BitConverter.GetBytes(strMachineName.Length + 1);

            MachineName_ReferentID = Combine.combine(BitConverter.GetBytes((short)SVCCTLSCMCreateServiceW.GenerateUuidNumeric(2)), new Byte[] { 0x00, 0x00 });
            Database_ReferentID = Combine.combine(BitConverter.GetBytes((short)SVCCTLSCMCreateServiceW.GenerateUuidNumeric(2)), new Byte[] { 0x00, 0x00 });
        }

        internal Byte[] GetRequest()
        {
            Byte[] request = Combine.combine(MachineName_ReferentID, MachineName_MaxCount);
            request = Combine.combine(request, MachineName_Offset);
            request = Combine.combine(request, MachineName_ActualCount);
            request = Combine.combine(request, MachineName);
            request = Combine.combine(request, Database_ReferentID);
            request = Combine.combine(request, Database_NameMaxCount);
            request = Combine.combine(request, Database_NameOffset);
            request = Combine.combine(request, Database_NameActualCount);
            request = Combine.combine(request, Database);
            request = Combine.combine(request, Unknown);
            return Combine.combine(request, AccessMask);
        }
    }
}
