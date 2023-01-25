using System;
using System.Runtime.InteropServices;

using BYTE = System.Byte;
using BOOL = System.Boolean;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using ULONG = System.UInt32;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    public sealed class Winternl
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [Flags]
        public enum _FILE_INFORMATION_CLASS
        {
            FileDirectoryInformation = 1,
            FileFullDirectoryInformation,                   // 2
            FileBothDirectoryInformation,                   // 3
            FileBasicInformation,                           // 4
            FileStandardInformation,                        // 5
            FileInternalInformation,                        // 6
            FileEaInformation,                              // 7
            FileAccessInformation,                          // 8
            FileNameInformation,                            // 9
            FileRenameInformation,                          // 10
            FileLinkInformation,                            // 11
            FileNamesInformation,                           // 12
            FileDispositionInformation,                     // 13
            FilePositionInformation,                        // 14
            FileFullEaInformation,                          // 15
            FileModeInformation,                            // 16
            FileAlignmentInformation,                       // 17
            FileAllInformation,                             // 18
            FileAllocationInformation,                      // 19
            FileEndOfFileInformation,                       // 20
            FileAlternateNameInformation,                   // 21
            FileStreamInformation,                          // 22
            FilePipeInformation,                            // 23
            FilePipeLocalInformation,                       // 24
            FilePipeRemoteInformation,                      // 25
            FileMailslotQueryInformation,                   // 26
            FileMailslotSetInformation,                     // 27
            FileCompressionInformation,                     // 28
            FileObjectIdInformation,                        // 29
            FileCompletionInformation,                      // 30
            FileMoveClusterInformation,                     // 31
            FileQuotaInformation,                           // 32
            FileReparsePointInformation,                    // 33
            FileNetworkOpenInformation,                     // 34
            FileAttributeTagInformation,                    // 35
            FileTrackingInformation,                        // 36
            FileIdBothDirectoryInformation,                 // 37
            FileIdFullDirectoryInformation,                 // 38
            FileValidDataLengthInformation,                 // 39
            FileShortNameInformation,                       // 40
            FileIoCompletionNotificationInformation,        // 41
            FileIoStatusBlockRangeInformation,              // 42
            FileIoPriorityHintInformation,                  // 43
            FileSfioReserveInformation,                     // 44
            FileSfioVolumeInformation,                      // 45
            FileHardLinkInformation,                        // 46
            FileProcessIdsUsingFileInformation,             // 47
            FileNormalizedNameInformation,                  // 48
            FileNetworkPhysicalNameInformation,             // 49
            FileIdGlobalTxDirectoryInformation,             // 50
            FileIsRemoteDeviceInformation,                  // 51
            FileUnusedInformation,                          // 52
            FileNumaNodeInformation,                        // 53
            FileStandardLinkInformation,                    // 54
            FileRemoteProtocolInformation,                  // 55

            //
            //  These are special versions of these operations (defined earlier)
            //  which can be used by kernel mode drivers only to bypass security
            //  access checks for Rename and HardLink operations.  These operations
            //  are only recognized by the IOManager, a file system should never
            //  receive these.
            //

            FileRenameInformationBypassAccessCheck,         // 56
            FileLinkInformationBypassAccessCheck,           // 57

            //
            // End of special information classes reserved for IOManager.
            //

            FileVolumeNameInformation,                      // 58
            FileIdInformation,                              // 59
            FileIdExtdDirectoryInformation,                 // 60
            FileReplaceCompletionInformation,               // 61
            FileHardLinkFullIdInformation,                  // 62
            FileIdExtdBothDirectoryInformation,             // 63
            FileDispositionInformationEx,                   // 64
            FileRenameInformationEx,                        // 65
            FileRenameInformationExBypassAccessCheck,       // 66
            FileDesiredStorageClassInformation,             // 67
            FileStatInformation,                            // 68
            FileMemoryPartitionInformation,                 // 69
            FileStatLxInformation,                          // 70
            FileCaseSensitiveInformation,                   // 71
            FileLinkInformationEx,                          // 72
            FileLinkInformationExBypassAccessCheck,         // 73
            FileStorageReserveIdInformation,                // 74
            FileCaseSensitiveInformationForceAccessCheck,   // 75
            FileKnownFolderInformation,   // 76

            FileMaximumInformation
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IO_STATUS_BLOCK
        {
            public uint Status;
            public IntPtr Information;
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)]
            public long QuadPart;
            [FieldOffset(0)]
            public UInt32 LowPart;
            [FieldOffset(4)]
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack=1)]
        public struct _LDR_DATA_TABLE_ENTRY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            PVOID Reserved1;
            _LIST_ENTRY InMemoryOrderLinks;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            PVOID Reserved2;
            PVOID DllBase;
            PVOID EntryPoint;
            PVOID Reserved3;
            Subauth._LSA_UNICODE_STRING FullDllName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            BYTE Reserved4;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            PVOID Reserved5;
            ULONG CheckSum;
            PVOID Reserved6;
            ULONG TimeDateStamp;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _LIST_ENTRY
        {
            IntPtr Flink;
            IntPtr Blink;
        }

        [Flags]
        public enum _OBJECT_INFORMATION_CLASS : int
        {
            ObjectBasicInformation,
            ObjectNameInformation,
            ObjectTypeInformation,
            ObjectTypesInformation,
            ObjectHandleFlagInformation,
            ObjectSessionInformation,
            ObjectSessionObjectInformation,
            MaxObjectInfoClass
        }

        /*
        public struct _PEB
        {
            public bool InheritedAddressSpace;      // These four fields cannot change unless the
            public bool ReadImageFileExecOptions;   //
            public bool BeingDebugged;              //
            public bool SpareBool;                  //
            public IntPtr Mutant;                   // INITIAL_PEB structure is also updated.

            public IntPtr ImageBaseAddress;
            public IntPtr Ldr;
            public _RTL_USER_PROCESS_PARAMETERS ProcessParameters;
            public IntPtr SubSystemData;
            public IntPtr ProcessHeap;
            public IntPtr FastPebLock;
            public IntPtr FastPebLockRoutine;
            public IntPtr FastPebUnlockRoutine;
            public ulong EnvironmentUpdateCount;
            public IntPtr KernelCallbackTable;
            public IntPtr SystemReserved;
            public IntPtr AtlThunkSListPtr32;
            public IntPtr FreeList;
            public ulong TlsExpansionCounter;
            public IntPtr TlsBitmap;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ulong[] TlsBitmapBits; // relates to TLS_MINIMUM_AVAILABLE
            public IntPtr ReadOnlySharedMemoryBase;
            public IntPtr ReadOnlySharedMemoryHeap;
            public IntPtr ReadOnlyStaticServerData; //ref //IntPtr* ReadOnlyStaticServerData
            public IntPtr AnsiCodePageData;
            public IntPtr OemCodePageData;
            public IntPtr UnicodeCaseTableData;

            //
            // Useful information for LdrpInitialize

            public ulong NumberOfProcessors;
            public ulong NtGlobalFlag;

            //
            // Passed up from MmCreatePeb from Session Manager registry key
            //

            public ulong CriticalSectionTimeout; //LARGE_INTEGER
            public ulong HeapSegmentReserve;
            public ulong HeapSegmentCommit;
            public ulong HeapDeCommitTotalFreeThreshold;
            public ulong HeapDeCommitFreeBlockThreshold;

            //
            // Where heap manager keeps track of all heaps created for a process
            // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
            // to point to the first free byte after the PEB and MaximumNumberOfHeaps
            // is computed from the page size used to hold the PEB, less the fixed
            // size of this data structure.
            //

            public ulong NumberOfHeaps;
            public ulong MaximumNumberOfHeaps;
            public IntPtr ProcessHeaps; //ref //IntPtr* ProcessHeaps

            //
            //
            public IntPtr GdiSharedIntPtrTable;
            public IntPtr ProcessStarterHelper;
            public IntPtr GdiDCAttributeList;
            public IntPtr LoaderLock;

            //
            // Following fields filled in by MmCreatePeb from system values and/or
            // image header. These fields have changed since Windows NT 4.0,
            // so use with caution
            //

            public ulong OSMajorVersion;
            public ulong OSMinorVersion;
            public ushort OSBuildNumber;
            public ushort OSCSDVersion;
            public ulong OSPlatformId;
            public ulong ImageSubsystem;
            public ulong ImageSubsystemMajorVersion;
            public ulong ImageSubsystemMinorVersion;
            public ulong ImageProcessAffinityMask;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 34)]
            public ulong[] GdiIntPtrBuffer;

        }
        */


        [StructLayout(LayoutKind.Explicit, Size = 0x7a0)]
        public struct PEB
        {
            [FieldOffset(0x000)] public byte InheritedAddressSpace;
            [FieldOffset(0x001)] public byte ReadImageFileExecOptions;
            [FieldOffset(0x002)] public byte BeingDebugged;
            [FieldOffset(0x003)] public byte BitField;
            [FieldOffset(0x004)] public /*fixed*/ byte Padding0;//[4];
            [FieldOffset(0x008)] public IntPtr Mutant;
            [FieldOffset(0x010)] public IntPtr ImageBaseAddress;
            [FieldOffset(0x018)] public IntPtr Ldr;
            [FieldOffset(0x020)] public IntPtr ProcessParameters;
            [FieldOffset(0x028)] public IntPtr SubSystemData;
            [FieldOffset(0x030)] public IntPtr ProcessHeap;
            [FieldOffset(0x038)] public IntPtr FastPebLock;
            [FieldOffset(0x040)] public IntPtr AtlThunkSListPtr;
            [FieldOffset(0x048)] public IntPtr IFEOKey;
            [FieldOffset(0x050)] public uint CrossProcessFlags;
            [FieldOffset(0x054)] public /*fixed*/ byte Padding1;//[4];
            [FieldOffset(0x058)] public IntPtr KernelCallbackTable;
            [FieldOffset(0x058)] public IntPtr UserSharedInfoPtr;
            [FieldOffset(0x060)] public /*fixed*/ uint SystemReserved;//[1];
            [FieldOffset(0x064)] public uint AtlThunkSListPtr32;
            [FieldOffset(0x068)] public IntPtr ApiSetMap;
            [FieldOffset(0x070)] public uint TlsExpansionCounter;
            [FieldOffset(0x074)] public /*fixed*/ byte Padding2;//[4];
            [FieldOffset(0x078)] public IntPtr TlsBitmap;
            [FieldOffset(0x080)] public /*fixed*/ uint TlsBitmapBits;//[2];
            [FieldOffset(0x088)] public IntPtr ReadOnlySharedMemoryBase;
            [FieldOffset(0x090)] public IntPtr SparePvoid0;
            [FieldOffset(0x098)] public IntPtr ReadOnlyStaticServerData;
            [FieldOffset(0x0a0)] public IntPtr AnsiCodePageData;
            [FieldOffset(0x0a8)] public IntPtr OemCodePageData;
            [FieldOffset(0x0b0)] public IntPtr UnicodeCaseTableData;
            [FieldOffset(0x0b8)] public uint NumberOfProcessors;
            [FieldOffset(0x0bc)] public uint NtGlobalFlag;
            [FieldOffset(0x0c0)] public long CriticalSectionTimeout;
            [FieldOffset(0x0c8)] public ulong HeapSegmentReserve;
            [FieldOffset(0x0d0)] public ulong HeapSegmentCommit;
            [FieldOffset(0x0d8)] public ulong HeapDeCommitTotalFreeThreshold;
            [FieldOffset(0x0e0)] public ulong HeapDeCommitFreeBlockThreshold;
            [FieldOffset(0x0e8)] public uint NumberOfHeaps;
            [FieldOffset(0x0ec)] public uint MaximumNumberOfHeaps;
            [FieldOffset(0x0f0)] public IntPtr ProcessHeaps;
            [FieldOffset(0x0f8)] public IntPtr GdiSharedHandleTable;
            [FieldOffset(0x100)] public IntPtr ProcessStarterHelper;
            [FieldOffset(0x108)] public uint GdiDCAttributeList;
            [FieldOffset(0x10c)] public /*fixed*/ byte Padding3;//[4];
            [FieldOffset(0x110)] public IntPtr LoaderLock;
            [FieldOffset(0x118)] public uint OSMajorVersion;
            [FieldOffset(0x11c)] public uint OSMinorVersion;
            [FieldOffset(0x120)] public ushort OSBuildNumber;
            [FieldOffset(0x122)] public ushort OSCSDVersion;
            [FieldOffset(0x124)] public uint OSPlatformId;
            [FieldOffset(0x128)] public uint ImageSubsystem;
            [FieldOffset(0x12c)] public uint ImageSubsystemMajorVersion;
            [FieldOffset(0x130)] public uint ImageSubsystemMinorVersion;
            [FieldOffset(0x134)] public /*fixed*/ byte Padding4;//[4];
            [FieldOffset(0x138)] public ulong ActiveProcessAffinityMask;
            [FieldOffset(0x140)] public /*fixed*/ uint GdiHandleBuffer;//[60];
            [FieldOffset(0x230)] public IntPtr PostProcessInitRoutine;
            [FieldOffset(0x238)] public IntPtr TlsExpansionBitmap;
            [FieldOffset(0x240)] public /*fixed*/ uint TlsExpansionBitmapBits;//[32];
            [FieldOffset(0x2c0)] public uint SessionId;
            [FieldOffset(0x2c4)] public /*fixed*/ byte Padding5;//[4];
            [FieldOffset(0x2c8)] public ulong AppCompatFlags;
            [FieldOffset(0x2d0)] public ulong AppCompatFlagsUser;
            [FieldOffset(0x2d8)] public IntPtr pShimData;
            [FieldOffset(0x2e0)] public IntPtr AppCompatInfo;
            [FieldOffset(0x2e8)] public Ntddk._UNICODE_STRING CSDVersion;
            [FieldOffset(0x2f8)] public IntPtr ActivationContextData;
            [FieldOffset(0x300)] public IntPtr ProcessAssemblyStorageMap;
            [FieldOffset(0x308)] public IntPtr SystemDefaultActivationContextData;
            [FieldOffset(0x310)] public IntPtr SystemAssemblyStorageMap;
            [FieldOffset(0x318)] public ulong MinimumStackCommit;
            [FieldOffset(0x320)] public IntPtr FlsCallback;
            [FieldOffset(0x328)] public Winnt._LIST_ENTRY FlsListHead;
            [FieldOffset(0x338)] public IntPtr FlsBitmap;
            [FieldOffset(0x340)] public /*fixed*/ uint FlsBitmapBits;//[4];
            [FieldOffset(0x350)] public uint FlsHighIndex;
            [FieldOffset(0x358)] public IntPtr WerRegistrationData;
            [FieldOffset(0x360)] public IntPtr WerShipAssertPtr;
            [FieldOffset(0x368)] public IntPtr pUnused;
            [FieldOffset(0x370)] public IntPtr pImageHeaderHash;
            [FieldOffset(0x378)] public uint TracingFlags;
            [FieldOffset(0x37c)] public /*fixed*/ byte Padding6;//[4];
            [FieldOffset(0x380)] public ulong CsrServerReadOnlySharedMemoryBase;
            [FieldOffset(0x388)] public ulong TppWorkerpListLock;
            [FieldOffset(0x390)] public Winnt._LIST_ENTRY TppWorkerpList;
            [FieldOffset(0x3a0)] public IntPtr WaitOnAddressHashTable;


            public bool ImageUsesLargePages => (BitField & 0x0001) >> 0 == 1;
            public bool IsProtectedProcess => (BitField & 0x0002) >> 1 == 1;
            public bool IsImageDynamicallyRelocated => (BitField & 0x0004) >> 2 == 1;
            public bool SkipPatchingUser32Forwarders => (BitField & 0x0008) >> 3 == 1;
            public bool IsPackagedProcess => (BitField & 0x0010) >> 4 == 1;
            public bool IsAppContainer => (BitField & 0x0020) >> 5 == 1;
            public bool IsProtectedProcessLight => (BitField & 0x0040) >> 6 == 1;
            public bool SpareBits => (BitField & 0x0080) >> 7 == 1;

            public bool ProcessInJob => (CrossProcessFlags & 0x0001) >> 0 == 1;
            public bool ProcessInitializing => (CrossProcessFlags & 0x0002) >> 1 == 1;
            public bool ProcessUsingVEH => (CrossProcessFlags & 0x0004) >> 2 == 1;
            public bool ProcessUsingVCH => (CrossProcessFlags & 0x0008) >> 3 == 1;
            public bool ProcessUsingFTH => (CrossProcessFlags & 0x0010) >> 4 == 1;
            public uint ReservedBits0 => ((CrossProcessFlags & 0xFFFFFFE0) >> 5);

            public bool HeapTracingEnabled => (TracingFlags & 0x0001) >> 0 == 1;
            public bool CritSecTracingEnabled => (TracingFlags & 0x0002) >> 1 == 1;
            public bool LibLoaderTracingEnabled => (TracingFlags & 0x0004) >> 2 == 1;
            public uint SpareTracingBits => ((TracingFlags & 0xFFFFFFF8) >> 3);

        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PEB32
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte Reserved1;
            public Byte BeingDebugged;
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 1)]
            public Byte Reserved2;
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 2)]
            public IntPtr Reserved3;
            public IntPtr Ldr; /*_PEB_LDR_DATA*/
            public IntPtr ProcessParameters; /*_RTL_USER_PROCESS_PARAMETERS*/
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 104)]
            public Byte Reserved4;
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 52)]
            public IntPtr Reserved5;
            public IntPtr PostProcessInitRoutine; /*_PS_POST_PROCESS_INIT_ROUTINE*/
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 128)]
            public Byte Reserved6;
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 1)]
            public IntPtr Reserved7;
            public UInt32 SessionId;
        }

        //http://bytepointer.com/resources/peb64.htm
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PEB64
        {
            public BYTE InheritedAddressSpace;
            public BYTE ReadImageFileExecOptions;
            public BYTE BeingDebugged;
            public BYTE BitField;

            public UInt32 Reserved3;
            public IntPtr Mutant;
            public IntPtr ImageBaseAddress;
            public IntPtr Ldr;
            public IntPtr ProcessParameters;
            public IntPtr SubSystemData;
            public IntPtr ProcessHeap;
            public IntPtr FastPebLock;

            public IntPtr AtlThunkSListPtr;
            public IntPtr IFEOKey;
            public UInt64 CrossProcessFlags;
            public IntPtr KernelCallbackTable;

            //public  QWORD UserSharedInfoPtr;
            public UInt32 SystemReserved;
            public UInt32 AtlThunkSListPtr32;
            public IntPtr ApiSetMap;
            public UInt32 TlsExpansionCounter;
            public IntPtr TlsBitmap;
            [MarshalAs(UnmanagedType.U4, SizeConst = 2)]
            public UInt32 TlsBitmapBits;
            public IntPtr ReadOnlySharedMemoryBase;
            public IntPtr HotpatchInformation;
            public IntPtr ReadOnlyStaticServerData;
            public IntPtr AnsiCodePageData;
            public IntPtr OemCodePageData;
            public IntPtr UnicodeCaseTableData;
            public UInt32 NumberOfProcessors;
            public UInt32 NtGlobalFlag;
            //public  DWORD dummy02;
            public long /*LARGE_INTEGER*/ CriticalSectionTimeout;
            public QWORD HeapSegmentReserve;
            public QWORD HeapSegmentCommit;
            public QWORD HeapDeCommitTotalFreeThreshold;
            public QWORD HeapDeCommitFreeBlockThreshold;
            public DWORD NumberOfHeaps;
            public DWORD MaximumNumberOfHeaps;
            public QWORD ProcessHeaps;
            public QWORD GdiSharedHandleTable;
            public QWORD ProcessStarterHelper;
            public QWORD GdiDCAttributeList;
            public QWORD LoaderLock;
            public DWORD OSMajorVersion;
            public DWORD OSMinorVersion;
            public WORD OSBuildNumber;
            public WORD OSCSDVersion;
            public DWORD OSPlatformId;
            public DWORD ImageSubsystem;
            public DWORD ImageSubsystemMajorVersion;
            public QWORD ImageSubsystemMinorVersion;
            public QWORD ImageProcessAffinityMask;
            public QWORD ActiveProcessAffinityMask;
            [MarshalAs(UnmanagedType.U8, SizeConst = 30)]
            public QWORD GdiHandleBuffer;
            public QWORD PostProcessInitRoutine;
            public QWORD TlsExpansionBitmap;
            [MarshalAs(UnmanagedType.U4, SizeConst = 32)]
            public DWORD TlsExpansionBitmapBits;
            public QWORD SessionId;
            public UInt64 /*ULARGE_INTEGER*/ AppCompatFlags;
            public UInt64 /*ULARGE_INTEGER*/ AppCompatFlagsUser;
            public QWORD pShimData;
            public QWORD AppCompatInfo;
            public Subauth._LSA_UNICODE_STRING CSDVersion;
            public QWORD ActivationContextData;
            public QWORD ProcessAssemblyStorageMap;
            public QWORD SystemDefaultActivationContextData;
            public QWORD SystemAssemblyStorageMap;
            public QWORD MinimumStackCommit;
        }

        /*
        struct _PEB_LDR_DATA
        {
            ulong Length;
            bool Initialized;
            IntPtr SsHandle;
            Winnt._LIST_ENTRY InLoadOrderModuleList;               // Points to the loaded modules (main EXE usually)
            Winnt._LIST_ENTRY InMemoryOrderModuleList;             // Points to all modules (EXE and all DLLs)
            Winnt._LIST_ENTRY InInitializationOrderModuleList;
            IntPtr EntryInProgress;

        }
        */

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PEB_LDR_DATA
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            Byte Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            IntPtr Reserved2;
            _LIST_ENTRY InMemoryOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct _PROCESS_BASIC_INFORMATION
        {
            public readonly IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public readonly IntPtr AffinityMask;
            public readonly IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public readonly IntPtr Reserved3;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _PUBLIC_OBJECT_TYPE_INFORMATION
        {
            public Ntddk._UNICODE_STRING TypeName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
            ulong[] Reserved;
        }

        /*
        [StructLayout(LayoutKind.Explicit, Size = 0x410)]
        public struct RTL_USER_PROCESS_PARAMETERS
        {
            [FieldOffset(0x000)] public uint MaximumLength;
            [FieldOffset(0x004)] public uint Length;
            [FieldOffset(0x008)] public uint Flags;
            [FieldOffset(0x00c)] public uint DebugFlags;
            [FieldOffset(0x010)] public IntPtr ConsoleHandle;
            [FieldOffset(0x018)] public uint ConsoleFlags;
            [FieldOffset(0x020)] public IntPtr StandardInput;
            [FieldOffset(0x028)] public IntPtr StandardOutput;
            [FieldOffset(0x030)] public IntPtr StandardError;
            [FieldOffset(0x038)] public _CURDIR CurrentDirectory;
            [FieldOffset(0x050)] public Ntddk._UNICODE_STRING DllPath;
            [FieldOffset(0x060)] public Ntddk._UNICODE_STRING ImagePathName;
            [FieldOffset(0x070)] public Ntddk._UNICODE_STRING CommandLine;
            [FieldOffset(0x080)] public IntPtr Environment;
            [FieldOffset(0x088)] public uint StartingX;
            [FieldOffset(0x08c)] public uint StartingY;
            [FieldOffset(0x090)] public uint CountX;
            [FieldOffset(0x094)] public uint CountY;
            [FieldOffset(0x098)] public uint CountCharsX;
            [FieldOffset(0x09c)] public uint CountCharsY;
            [FieldOffset(0x0a0)] public uint FillAttribute;
            [FieldOffset(0x0a4)] public uint WindowFlags;
            [FieldOffset(0x0a8)] public uint ShowWindowFlags;
            [FieldOffset(0x0b0)] public Ntddk._UNICODE_STRING WindowTitle;
            [FieldOffset(0x0c0)] public Ntddk._UNICODE_STRING DesktopInfo;
            [FieldOffset(0x0d0)] public Ntddk._UNICODE_STRING ShellInfo;
            [FieldOffset(0x0e0)] public Ntddk._UNICODE_STRING RuntimeData;
            [FieldOffset(0x0f0)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores0;
            [FieldOffset(0x108)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores1;
            [FieldOffset(0x120)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores2;
            [FieldOffset(0x138)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores3;
            [FieldOffset(0x150)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores4;
            [FieldOffset(0x168)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores5;
            [FieldOffset(0x180)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores6;
            [FieldOffset(0x198)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores7;
            [FieldOffset(0x1b0)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores8;
            [FieldOffset(0x1c8)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores9;
            [FieldOffset(0x1e0)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores10;
            [FieldOffset(0x1f8)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores11;
            [FieldOffset(0x210)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores12;
            [FieldOffset(0x228)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores13;
            [FieldOffset(0x240)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores14;
            [FieldOffset(0x258)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores15;
            [FieldOffset(0x270)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores16;
            [FieldOffset(0x288)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores17;
            [FieldOffset(0x2a0)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores18;
            [FieldOffset(0x2b8)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores19;
            [FieldOffset(0x2d0)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores20;
            [FieldOffset(0x2e8)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores21;
            [FieldOffset(0x300)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores22;
            [FieldOffset(0x318)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores23;
            [FieldOffset(0x330)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores24;
            [FieldOffset(0x348)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores25;
            [FieldOffset(0x360)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores26;
            [FieldOffset(0x378)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores27;
            [FieldOffset(0x390)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores28;
            [FieldOffset(0x3a8)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores29;
            [FieldOffset(0x3c0)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores30;
            [FieldOffset(0x3d8)] public RTL_DRIVE_LETTER_CURDIR CurrentDirectores31;
            [FieldOffset(0x3f0)] public ulong EnvironmentSize;
            [FieldOffset(0x3f8)] public ulong EnvironmentVersion;
            [FieldOffset(0x400)] public IntPtr PackageDependencyData;
            [FieldOffset(0x408)] public uint ProcessGroupId;
            [FieldOffset(0x40c)] public uint LoaderThreads;

        }
        */

        /*
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct _RTL_USER_PROCESS_PARAMETERS
        {
            public uint MaximumLength;
            public uint Length;
            public uint Flags;
            public uint DebugFlags;
            public IntPtr ConsoleHandle;
            public ulong ConsoleFlags;
            public IntPtr StandardInput;
            public IntPtr StandardOutput;
            public IntPtr StandardError;
            public _CURDIR CurrentDirectory;
            public Ntddk._UNICODE_STRING DllPath;
            public Ntddk._UNICODE_STRING ImagePathName;
            public Ntddk._UNICODE_STRING CommandLine;
            public IntPtr Environment;
            public uint StartingPositionLeft;
            public uint StartingPositionTop;
            public uint Width;
            public uint Height;
            public uint CharWidth;
            public uint CharHeight;
            public uint ConsoleTextAttributes;
            public uint WindowFlags;
            public uint ShowWindowFlags;
            public uint Reserved;
            public Ntddk._UNICODE_STRING WindowTitle;
            public Ntddk._UNICODE_STRING DesktopName;
            public Ntddk._UNICODE_STRING ShellInfo;
            public Ntddk._UNICODE_STRING RuntimeData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
            public _RTL_DRIVE_LETTER_CURDIR[] CurrentDirectories;//[0x20];
            public ulong EnvironmentSize;
        }
        */

        [StructLayout(LayoutKind.Sequential, Pack=1)]
        public struct _RTL_USER_PROCESS_PARAMETERS
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            BYTE Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            PVOID Reserved2;
            Ntddk._UNICODE_STRING ImagePathName;
            Ntddk._UNICODE_STRING CommandLine;
        }

        [StructLayout(LayoutKind.Explicit, Size = 0x10)]
        public struct _STRING
        {
            [FieldOffset(0x000)] public ushort Length;
            [FieldOffset(0x002)] public ushort MaximumLength;
            [FieldOffset(0x008)] public IntPtr Buffer; //ref IntPtr*
        }

        [Flags]
        public enum _SYSTEM_INFORMATION_CLASS : int
        {
            SystemBasicInformation = 0x00,
            SystemProcessorInformation = 0x01,
            SystemPerformanceInformation = 0x02,
            SystemTimeOfDayInformation = 0x03,
            SystemPathInformation = 0x04,
            SystemProcessInformation = 0x05,
            SystemCallCountInformation = 0x06,
            SystemDeviceInformation = 0x07,
            SystemProcessorPerformanceInformation = 0x08,
            SystemFlagsInformation = 0x09,
            SystemCallTimeInformation = 0x0A,
            SystemModuleInformation = 0x0B,
            SystemLocksInformation = 0x0C,
            SystemStackTraceInformation = 0x0D,
            SystemPagedPoolInformation = 0x0E,
            SystemNonPagedPoolInformation = 0x0F,
            SystemHandleInformation = 0x10,
            SystemObjectInformation = 0x11,
            SystemPageFileInformation = 0x12,
            SystemVdmInstemulInformation = 0x13,
            SystemVdmBopInformation = 0x14,
            SystemFileCacheInformation = 0x15,
            SystemPoolTagInformation = 0x16,
            SystemSpare1Information = 0x17,
            SystemInterruptInformation = 0x17,
            SystemSpare2Informationbelow = 0x18,
            SystemDpcBehaviorInformation = 0x18,
            SystemSpare3Information = 0x19,
            SystemFullMemoryInformation = 0x19,
            SystemSpare4Informationbelow = 0x1A,
            SystemLoadGdiDriverInformation = 0x1A,
            SystemSpare5Informationbelow = 0x1B,
            SystemUnloadGdiDriverInformation = 0x1B,
            SystemTimeAdjustmentInformation = 0x1C,
            SystemSpare6Information = 0x1D,
            SystemSummaryMemoryInformation = 0x1D,
            SystemNextEventIdInformation = 0x1E,
            SystemMirrorMemoryInformation = 0x1E,
            SystemEventIdsInformation = 0x1F,
            SystemPerformanceTraceInformation = 0x1F,
            SystemCrashDumpInformation = 0x20,
            SystemObsolete0 = 0x20,
            SystemExceptionInformation = 0x21,
            SystemCrashDumpStateInformation = 0x22,
            SystemKernelDebuggerInformation = 0x23,
            SystemContextSwitchInformation = 0x24,
            SystemRegistryQuotaInformation = 0x25,
            SystemExtendServiceTableInformation = 0x26,
            SystemPrioritySeperation = 0x27,
            SystemPlugPlayBusInformation = 0x28,
            SystemVerifierAddDriverInformation = 0x28,
            SystemDockInformation = 0x29,
            SystemVerifierRemoveDriverInformation = 0x29,
            SystemPowerInformation = 0x2A,
            SystemProcessorIdleInformation = 0x2A,
            SystemProcessorSpeedInformation = 0x2B,
            SystemLegacyDriverInformation = 0x2B,
            SystemCurrentTimeZoneInformation = 0x2C,
            SystemLookasideInformation = 0x2D,
            SystemTimeSlipNotification = 0x2E,
            SystemSessionCreate = 0x2F,
            SystemSessionDetach = 0x30,
            SystemSessionInformation = 0x31,
            SystemRangeStartInformation = 0x32,
            SystemVerifierInformation = 0x33,
            SystemVerifierThunkExtend = 0x34,
            SystemSessionProcessInformation = 0x35,
            SystemObjectSecurityMode = 0x36,
            SystemLoadGdiDriverInSystemSpace = 0x36,
            SystemNumaProcessorMap = 0x37,
            SystemPrefetcherInformation = 0x38,
            SystemExtendedProcessInformation = 0x39,
            SystemRecommendedSharedDataAlignment = 0x3A,
            SystemComPlusPackage = 0x3B,
            SystemNumaAvailableMemory = 0x3C,
            SystemProcessorPowerInformation = 0x3D,
            SystemEmulationBasicInformation = 0x3E,
            SystemEmulationProcessorInformation = 0x3F,
            SystemExtendedHandleInformation = 0x40,
            SystemLostDelayedWriteInformation = 0x41,
            SystemBigPoolInformation = 0x42,
            SystemSessionPoolTagInformation = 0x43,
            SystemSessionMappedViewInformation = 0x44,
            SystemHotpatchInformation = 0x45,
            SystemObjectSecurityMode2 = 0x46,
            SystemWatchdogTimerHandler = 0x47,
            SystemWatchdogTimerInformation = 0x48,
            SystemLogicalProcessorInformation = 0x49,
            SystemWow64SharedInformationObsolete = 0x4A,
            SystemRegisterFirmwareTableInformationHandler = 0x4B,
            SystemFirmwareTableInformation = 0x4C,
            SystemModuleInformationEx = 0x4D,
            SystemVerifierTriageInformation = 0x4E,
            SystemSuperfetchInformation = 0x4F,
            SystemMemoryListInformation = 0x50,
            SystemFileCacheInformationEx = 0x51,
            SystemThreadPriorityClientIdInformation = 0x52,
            SystemProcessorIdleCycleTimeInformation = 0x53,
            SystemVerifierCancellationInformation = 0x54,
            SystemProcessorPowerInformationEx = 0x55,
            SystemRefTraceInformation = 0x56,
            SystemSpecialPoolInformation = 0x57,
            SystemProcessIdInformation = 0x58,
            SystemErrorPortInformation = 0x59,
            SystemBootEnvironmentInformation = 0x5A,
            SystemHypervisorInformation = 0x5B,
            SystemVerifierInformationEx = 0x5C,
            SystemTimeZoneInformation = 0x5D,
            SystemImageFileExecutionOptionsInformation = 0x5E,
            SystemCoverageInformation = 0x5F,
            SystemPrefetchPatchInformation = 0x60,
            SystemVerifierFaultsInformation = 0x61,
            SystemSystemPartitionInformation = 0x62,
            SystemSystemDiskInformation = 0x63,
            SystemProcessorPerformanceDistribution = 0x64,
            SystemNumaProximityNodeInformation = 0x65,
            SystemDynamicTimeZoneInformation = 0x66,
            SystemCodeIntegrityInformation = 0x67,
            SystemProcessorMicrocodeUpdateInformation = 0x68,
            SystemProcessorBrandString = 0x69,
            SystemVirtualAddressInformation = 0x6A,
            SystemLogicalProcessorAndGroupInformation = 0x6B,
            SystemProcessorCycleTimeInformation = 0x6C,
            SystemStoreInformation = 0x6D,
            SystemRegistryAppendString = 0x6E,
            SystemAitSamplingValue = 0x6F,
            SystemVhdBootInformation = 0x70,
            SystemCpuQuotaInformation = 0x71,
            SystemNativeBasicInformation = 0x72,
            SystemErrorPortTimeouts = 0x73,
            SystemLowPriorityIoInformation = 0x74,
            SystemBootEntropyInformation = 0x75,
            SystemVerifierCountersInformation = 0x76,
            SystemPagedPoolInformationEx = 0x77,
            SystemSystemPtesInformationEx = 0x78,
            SystemNodeDistanceInformation = 0x79,
            SystemAcpiAuditInformation = 0x7A,
            SystemBasicPerformanceInformation = 0x7B,
            SystemQueryPerformanceCounterInformation = 0x7C,
            SystemSessionBigPoolInformation = 0x7D,
            SystemBootGraphicsInformation = 0x7E,
            SystemScrubPhysicalMemoryInformation = 0x7F,
            SystemBadPageInformation = 0x80,
            SystemProcessorProfileControlArea = 0x81,
            SystemCombinePhysicalMemoryInformation = 0x82,
            SystemEntropyInterruptTimingInformation = 0x83,
            SystemConsoleInformation = 0x84,
            SystemPlatformBinaryInformation = 0x85,
            SystemThrottleNotificationInformation = 0x86,
            SystemPolicyInformation = 0x86,
            SystemHypervisorProcessorCountInformation = 0x87,
            SystemDeviceDataInformation = 0x88,
            SystemDeviceDataEnumerationInformation = 0x89,
            SystemMemoryTopologyInformation = 0x8A,
            SystemMemoryChannelInformation = 0x8B,
            SystemBootLogoInformation = 0x8C,
            SystemProcessorPerformanceInformationEx = 0x8D,
            SystemSpare0 = 0x8E,
            SystemCriticalProcessErrorLogInformation = 0x8E,
            SystemSecureBootPolicyInformation = 0x8F,
            SystemPageFileInformationEx = 0x90,
            SystemSecureBootInformation = 0x91,
            SystemEntropyInterruptTimingRawInformation = 0x92,
            SystemPortableWorkspaceEfiLauncherInformation = 0x93,
            SystemFullProcessInformation = 0x94,
            SystemKernelDebuggerInformationEx = 0x95,
            SystemBootMetadataInformation = 0x96,
            SystemSoftRebootInformation = 0x97,
            SystemElamCertificateInformation = 0x98,
            SystemOfflineDumpConfigInformation = 0x99,
            SystemProcessorFeaturesInformation = 0x9A,
            SystemRegistryReconciliationInformation = 0x9B,
            SystemEdidInformation = 0x9C,
            SystemManufacturingInformation = 0x9D,
            SystemEnergyEstimationConfigInformation = 0x9E,
            SystemHypervisorDetailInformation = 0x9F,
            SystemProcessorCycleStatsInformation = 0xA0,
            SystemVmGenerationCountInformation = 0xA1,
            SystemTrustedPlatformModuleInformation = 0xA2,
            SystemKernelDebuggerFlags = 0xA3,
            SystemCodeIntegrityPolicyInformation = 0xA4,
            SystemIsolatedUserModeInformation = 0xA5,
            SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
            SystemSingleModuleInformation = 0xA7,
            SystemAllowedCpuSetsInformation = 0xA8,
            SystemDmaProtectionInformation = 0xA9,
            SystemInterruptCpuSetsInformation = 0xAA,
            SystemSecureBootPolicyFullInformation = 0xAB,
            SystemCodeIntegrityPolicyFullInformation = 0xAC,
            SystemAffinitizedInterruptProcessorInformation = 0xAD,
            SystemRootSiloInformation = 0xAE,
            SystemCpuSetInformation = 0xAF,
            SystemCpuSetTagInformation = 0xB0,
            SystemWin32WerStartCallout = 0xB1,
            SystemSecureKernelProfileInformation = 0xB2,
            SystemCodeIntegrityPlatformManifestInformation = 0xB3,
            SystemInterruptSteeringInformation = 0xB4,
            SystemSuppportedProcessorArchitectures = 0xB5,
            SystemMemoryUsageInformation = 0xB6,
            SystemCodeIntegrityCertificateInformation = 0xB7,
            SystemPhysicalMemoryInformation = 0xB8,
            SystemControlFlowTransition = 0xB9,
            SystemKernelDebuggingAllowed = 0xBA,
            SystemActivityModerationExeState = 0xBB,
            SystemActivityModerationUserSettings = 0xBC,
            SystemCodeIntegrityPoliciesFullInformation = 0xBD,
            SystemCodeIntegrityUnlockInformation = 0xBE,
            SystemIntegrityQuotaInformation = 0xBF,
            SystemFlushInformation = 0xC0,
            SystemProcessorIdleMaskInformation = 0xC1,
            SystemSecureDumpEncryptionInformation = 0xC2,
            SystemWriteConstraintInformation = 0xC3,
            SystemKernelVaShadowInformation = 0xC4,
            SystemHypervisorSharedPageInformation = 0xC5,
            SystemFirmwareBootPerformanceInformation = 0xC6,
            SystemCodeIntegrityVerificationInformation = 0xC7,
            SystemFirmwarePartitionInformation = 0xC8,
            SystemSpeculationControlInformation = 0xC9,
            SystemDmaGuardPolicyInformation = 0xCA,
            SystemEnclaveLaunchControlInformation = 0xCB
        }

    }
}