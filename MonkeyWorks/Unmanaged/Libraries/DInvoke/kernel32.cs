using System;
using System.Runtime.InteropServices;
using System.Text;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    sealed class kernel32
    {
        public const uint PROCESS_CREATE_THREAD = 0x0002;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;

        ////////////////////////////////////////////////////////////////////////////////
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CloseHandle(IntPtr hProcess);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ConnectNamedPipe(
            IntPtr hNamedPipe,
            MinWinBase._OVERLAPPED lpOverlapped
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcess(
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

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateNamedPipeA(
            string lpName,
            Winbase.OPEN_MODE dwOpenMode,
            Winbase.PIPE_MODE dwPipeMode,
            uint nMaxInstances,
            uint nOutBufferSize,
            uint nInBufferSize,
            uint nDefaultTimeOut,
            Winbase._SECURITY_ATTRIBUTES lpSecurityAttributes
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread(IntPtr hHandle, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DisconnectNamedPipe(IntPtr hNamedPipe);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetCurrentThread();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return:MarshalAs(UnmanagedType.U4)]
        public delegate uint GetCurrentThreadId();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetCurrentProcess();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetModuleHandleA([MarshalAs(UnmanagedType.LPStr)] string lpModuleName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void GetNativeSystemInfo(out Winbase._SYSTEM_INFO lpSystemInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int GetPrivateProfileStringA(
            [MarshalAs(UnmanagedType.LPStr)] string lpAppName,
            [MarshalAs(UnmanagedType.LPStr)] string lpKeyName,
            [MarshalAs(UnmanagedType.LPStr)] string lpDefault,
            StringBuilder lpReturnedString,
            uint nSize,
            [MarshalAs(UnmanagedType.LPStr)] string lpFileName
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int GetPrivateProfileStringW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpAppName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpKeyName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpDefault,
            StringBuilder lpReturnedString,
            uint nSize,
            [MarshalAs(UnmanagedType.LPWStr)] string lpFileName
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string procName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void GetSystemInfo(out Winbase._SYSTEM_INFO lpSystemInfo);

        //Winnt.CONTEXT
        //Winnt.CONTEXT64
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool GetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint GlobalSize(IntPtr hMem);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool IsProcessCritical(IntPtr hProcess, ref bool Critical);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool Wow64Process);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool Module32First(IntPtr hSnapshot, ref TiHelp32.tagMODULEENTRY32 lpme);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool Module32Next(IntPtr hSnapshot, ref TiHelp32.tagMODULEENTRY32 lpme);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr LocalFree(IntPtr hMem);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool Process32First(IntPtr hSnapshot, ref TiHelp32.tagPROCESSENTRY32 lppe);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool Process32Next(IntPtr hSnapshot, ref TiHelp32.tagPROCESSENTRY32 lppe);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenProcess(
            [MarshalAs(UnmanagedType.U8)] ProcessThreadsApi.ProcessSecurityRights dwDesiredAccess, 
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            [MarshalAs(UnmanagedType.U4)] uint dwProcessId
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool OpenProcessToken(
            IntPtr hProcess,
            uint dwDesiredAccess, 
            ref IntPtr hToken
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenThread(ProcessThreadsApi.ThreadSecurityRights dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, ref IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ReadFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            ref uint lpNumberOfBytesRead,
            ref System.Threading.NativeOverlapped lpOverlapped
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref uint lpNumberOfBytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint ResumeThread(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        internal delegate uint SearchPathW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpPath,
            [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpExtension,
            [MarshalAs(UnmanagedType.U4)] uint nBufferLength,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpBuffer, 
            ref IntPtr lpFilePart
        );

        public delegate bool HandlerRoutine(Wincon.CtrlType CtrlType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool SetConsoleCtrlHandler(HandlerRoutine HandlerRoutine, bool Add);

        //Winnt.CONTEXT
        //Winnt.CONTEXT64
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool SetThreadContext(IntPtr hThread, IntPtr lpContext);
        
        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate bool SetThreadContext(IntPtr hThread, ref object lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int SuspendThread(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool Thread32First(IntPtr hSnapshot, ref TiHelp32.tagTHREADENTRY32 lpte);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool Thread32Next(IntPtr hSnapshot, ref TiHelp32.tagTHREADENTRY32 lpte);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, Winnt.MEMORY_PROTECTION_CONSTANTS flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocEx(IntPtr hHandle, IntPtr lpAddress, uint dwSize, uint flAllocationType, Winnt.MEMORY_PROTECTION_CONSTANTS flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtect(IntPtr lpAddress, uint dwSize, Winnt.MEMORY_PROTECTION_CONSTANTS flNewProtect, ref Winnt.MEMORY_PROTECTION_CONSTANTS lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtectEx(IntPtr hHandle, IntPtr lpAddress, uint dwSize, Winnt.MEMORY_PROTECTION_CONSTANTS flNewProtect, ref Winnt.MEMORY_PROTECTION_CONSTANTS lpflOldProtect);

        //Winnt._MEMORY_BASIC_INFORMATION
        //Winnt._MEMORY_BASIC_INFORMATION64
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out Winnt._MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WaitForSingleObject(IntPtr hProcess, uint nSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForSingleObjectEx(IntPtr hProcess, IntPtr hHandle, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool Wow64GetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool Wow64SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);
    }
}