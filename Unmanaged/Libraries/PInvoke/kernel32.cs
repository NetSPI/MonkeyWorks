using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.Win32.SafeHandles;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace MonkeyWorks.Unmanaged.Libraries
{
    public sealed class kernel32
    {
        public const uint PROCESS_CREATE_THREAD = 0x0002;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint MEM_FREE = 0x00010000;
        public const uint MEM_PRIVATE = 0x00020000;

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(SafeFileHandle hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ConnectNamedPipe(
            IntPtr hNamedPipe,
            MinWinBase._OVERLAPPED lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ConnectNamedPipe(
            IntPtr hNamedPipe,
            IntPtr lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateEventW(
            ref Winbase._SECURITY_ATTRIBUTES lpEventAttributes,
            [MarshalAs(UnmanagedType.Bool)]
            bool bManualReset,
            [MarshalAs(UnmanagedType.Bool)]
            bool bInitialState,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpName
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileMappingW(
            IntPtr hFile,
            Winbase._SECURITY_ATTRIBUTES lpSecurityAttributes,
            [MarshalAs(UnmanagedType.U4)]
            Winnt.MEMORY_PROTECTION_CONSTANTS flProtect,
            [MarshalAs(UnmanagedType.U4)]
            uint dwMaximumSizeHigh,
            [MarshalAs(UnmanagedType.U4)]
            uint dwMaximumSizeLow,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpFileName
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpFileName,
            Winnt.ACCESS_MASK dwDesiredAccess,
            System.IO.FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            [MarshalAs(UnmanagedType.U4)]
            uint dwCreationDisposition,
            [MarshalAs(UnmanagedType.U4)]
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine, 
            ref Winbase._SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Winbase._SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            Winbase.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Winbase._STARTUPINFO lpStartupInfo,
            out Winbase._PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateNamedPipeA(
            string lpName,
            Winbase.OPEN_MODE dwOpenMode,
            Winbase.PIPE_MODE dwPipeMode,
            uint nMaxInstances,
            uint nOutBufferSize,
            uint nInBufferSize,
            uint nDefaultTimeOut,
            Winbase._SECURITY_ATTRIBUTES lpSecurityAttributes
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateNamedPipeA(
            string lpName,
            Winbase.OPEN_MODE dwOpenMode,
            Winbase.PIPE_MODE dwPipeMode,
            uint nMaxInstances,
            uint nOutBufferSize,
            uint nInBufferSize,
            uint nDefaultTimeOut,
            IntPtr lpSecurityAttributes
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
            ref Winbase._SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Winbase._SECURITY_ATTRIBUTES lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            Winbase.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
            ref Winbase._STARTUPINFO lpStartupInfo,
            out Winbase._PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
            ref Winbase._SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Winbase._SECURITY_ATTRIBUTES lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            Winbase.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
            ref Winbase._STARTUPINFOEX lpStartupInfo,
            out Winbase._PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hHandle, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateSymbolicLinkW(
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpSymlinkFileName,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpTargetFileName,
            [MarshalAs(UnmanagedType.U4)]
            uint dwFlags
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DisconnectNamedPipe(IntPtr hNamedPipe);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushFileBuffers(IntPtr hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileInformationByHandle(
            IntPtr hFile,
            ref Fileapi._BY_HANDLE_FILE_INFORMATION lpFileInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileSizeEx(
            IntPtr hFile,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong lpFileSize
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void GetNativeSystemInfo(out Winbase._SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetPrivateProfileStringW(
            [MarshalAs(UnmanagedType.LPWStr)] string Section,
            [MarshalAs(UnmanagedType.LPWStr)] string Key,
            [MarshalAs(UnmanagedType.LPWStr)] string Default,
            StringBuilder RetVal,
            [MarshalAs(UnmanagedType.U4)] uint Size,
            [MarshalAs(UnmanagedType.LPWStr)] string FilePath
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)]string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetProcessId(IntPtr Process);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetShortPathName(string lpszLongPath, StringBuilder lpszShortPath, uint cchBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void GetSystemInfo(out Winbase._SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetTempFileNameW(
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpPathName,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpPrefixString,
            [MarshalAs(UnmanagedType.U4)]
            uint uUnique,
            [MarshalAs(UnmanagedType.LPWStr)]
            StringBuilder lpTempFileName
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetTempPathW(
            [MarshalAs(UnmanagedType.U4)]
            uint nBufferLength,
            [MarshalAs(UnmanagedType.LPWStr)]
            StringBuilder lpBuffer
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext(IntPtr hThread, ref Winnt.CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadTimes(
            IntPtr hThread,
            ref FILETIME lpCreationTime,
            ref FILETIME lpExitTime,
            ref FILETIME lpKernelTime,
            ref FILETIME lpUserTime
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GlobalSize(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            [MarshalAs(UnmanagedType.U4)]
            uint dwAttributeCount,
            [MarshalAs(UnmanagedType.U4)]
            uint dwFlags,
            ref IntPtr lpSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsProcessCritical(IntPtr hProcess, ref bool Critical);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Module32First(IntPtr hSnapshot, ref TiHelp32.tagMODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Module32Next(IntPtr hSnapshot, ref TiHelp32.tagMODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            [MarshalAs(UnmanagedType.U4)]
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)]
            uint dwFileOffsetHigh,
            [MarshalAs(UnmanagedType.U4)]
            uint dwFileOffsetLow,
            [MarshalAs(UnmanagedType.U4)]
            uint dwNumberOfBytesToMap
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Process32First(IntPtr hSnapshot, ref TiHelp32.tagPROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Process32Next(IntPtr hSnapshot, ref TiHelp32.tagPROCESSENTRY32 lppe);

        /*
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            [MarshalAs(UnmanagedType.U8)] uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            [MarshalAs(UnmanagedType.U4)] uint dwProcessId
        );
        */

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            [MarshalAs(UnmanagedType.U8)] ProcessThreadsApi.ProcessSecurityRights dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            [MarshalAs(UnmanagedType.U4)] uint dwProcessId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr hProcess,
            [MarshalAs(UnmanagedType.U8)] ulong dwDesiredAccess, 
            out IntPtr hToken
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ProcessThreadsApi.ThreadSecurityRights dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, ref IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            ref uint lpNumberOfBytesRead,
            IntPtr lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            ref uint lpNumberOfBytesRead,
            ref MinWinBase._OVERLAPPED lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            ref uint lpNumberOfBytesRead,
            ref System.Threading.NativeOverlapped lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "ReadProcessMemory")]
        public static extern bool ReadProcessMemory64(IntPtr hProcess, ulong lpBaseAddress, IntPtr lpBuffer, ulong nSize, ref uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint SearchPath(string lpPath, string lpFileName, string lpExtension, uint nBufferLength, StringBuilder lpBuffer, ref IntPtr lpFilePart);

        public delegate bool HandlerRoutine(Wincon.CtrlType CtrlType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetConsoleCtrlHandler(HandlerRoutine HandlerRoutine, bool Add);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetEndOfFile(IntPtr hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetFilePointerEx(
            IntPtr hThread,
            [MarshalAs(UnmanagedType.U8)]
            ulong liDistanceToMove,
            [MarshalAs(UnmanagedType.U8)]
            ref ulong lpNewFilePointer,
            [MarshalAs(UnmanagedType.U4)]
            uint dwMoveMethod
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFileTime(
            IntPtr hFile,
            ref System.Runtime.InteropServices.ComTypes.FILETIME lpCreationTime,
            ref System.Runtime.InteropServices.ComTypes.FILETIME lpLastAccessTime,
            ref System.Runtime.InteropServices.ComTypes.FILETIME lpLastWriteTime
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext(IntPtr hThread, ref Winnt.CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Thread32First(IntPtr hSnapshot, ref TiHelp32.tagTHREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Thread32Next(IntPtr hSnapshot, ref TiHelp32.tagTHREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            [MarshalAs(UnmanagedType.U4)]
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, Winnt.MEMORY_PROTECTION_CONSTANTS flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hHandle, IntPtr lpAddress, uint dwSize, uint flAllocationType, Winnt.MEMORY_PROTECTION_CONSTANTS flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, Winnt.MEMORY_PROTECTION_CONSTANTS flNewProtect, ref Winnt.MEMORY_PROTECTION_CONSTANTS lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtectEx(IntPtr hHandle, IntPtr lpAddress, uint dwSize, Winnt.MEMORY_PROTECTION_CONSTANTS flNewProtect, ref Winnt.MEMORY_PROTECTION_CONSTANTS lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQuery")]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint VirtualQuery64(IntPtr lpAddress, ref Winnt._MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="VirtualQueryEx")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out Winnt._MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="VirtualQueryEx")]
        public static extern int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out Winnt._MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint WaitForSingleObject(
            IntPtr hHandle,
            [MarshalAs(UnmanagedType.U4)]
            uint nSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint WaitForSingleObjectEx(
            IntPtr hProcess, 
            IntPtr hHandle,
            [MarshalAs(UnmanagedType.U4)]
            uint dwMilliseconds
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint WaitForSingleObjectEx(
            IntPtr hHandle,
            [MarshalAs(UnmanagedType.U4)] 
            uint dwMilliseconds,
            [MarshalAs(UnmanagedType.Bool)] 
            bool bAlertable
        );


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64GetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64SetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteFile(
            IntPtr hFile,
            byte[] lpBuffer,
            [MarshalAs(UnmanagedType.U4)]
            uint nNumberOfBytesToWrite,
            [MarshalAs(UnmanagedType.U4)]
            out uint lpNumberOfBytesWritten,
            [In] ref System.Threading.NativeOverlapped lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            [MarshalAs(UnmanagedType.U4)] uint nNumberOfBytesToWrite,
            [MarshalAs(UnmanagedType.U4)] out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped
        );

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WritePrivateProfileStringW(
            [MarshalAs(UnmanagedType.LPWStr)] string Section,
            [MarshalAs(UnmanagedType.LPWStr)] string Key,
            [MarshalAs(UnmanagedType.LPWStr)] string Value,
            [MarshalAs(UnmanagedType.LPWStr)] string FilePath
        );


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref uint lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref ulong lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);
    }
}