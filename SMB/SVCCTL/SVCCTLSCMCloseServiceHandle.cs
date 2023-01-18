using System;

namespace MonkeyWorks.SMB.SVCCTL
{
    sealed class SVCCTLSCMCloseServiceHandle
    {
        private Byte[] ContextHandle;

        internal SVCCTLSCMCloseServiceHandle()
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
