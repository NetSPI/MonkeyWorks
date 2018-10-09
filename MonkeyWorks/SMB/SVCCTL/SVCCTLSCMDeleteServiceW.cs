using System;

namespace MonkeyWorks.SMB.SVCCTL
{
    sealed class SVCCTLSCMDeleteServiceW
    {
        private Byte[] ContextHandle;

        internal SVCCTLSCMDeleteServiceW()
        {

        }

        internal void SetContextHandle(Byte[] ContextHandle)
        {
            this.ContextHandle = ContextHandle;
        }

        internal Byte[] GetRequest()
        {
            return ContextHandle;
        }
    }
}
