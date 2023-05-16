using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    //https://processhacker.sourceforge.io/doc/ntmmapi_8h_source.html

    public sealed class Ntmmapi
    {
        public enum _MEMORY_INFORMATION_CLASS
        {
            MemoryBasicInformation,
            MemoryWorkingSetInformation,
            MemoryMappedFilenameInformation,
            MemoryRegionInformation,
            MemoryWorkingSetExInformation,
            MemorySharedCommitInformation,
            MemoryImageInformation,
            MemoryRegionInformationEx,
            MemoryPrivilegedBasicInformation,
            MemoryEnclaveImageInformation,
            MemoryBasicInformationCapped,
            MemoryPhysicalContiguityInformation,
        }
    }
}