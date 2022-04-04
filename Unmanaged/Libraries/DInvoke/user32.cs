using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace MonkeyWorks.Unmanaged.Libraries.DInvoke
{
    sealed class user32
    {
        //PInvoke.net
        [Flags]
        public enum IdHook : int
        {
            /// <summary>
            /// Installs a hook procedure that monitors messages generated as a result of an input event in a dialog box, 
            /// message box, menu, or scroll bar. For more information, see the MessageProc hook procedure.
            /// </summary>
            WH_MSGFILTER = -1,
            /// <summary>
            /// Installs a hook procedure that records input messages posted to the system message queue. This hook is 
            /// useful for recording macros. For more information, see the JournalRecordProc hook procedure.
            /// </summary>
            WH_JOURNALRECORD = 0,
            /// <summary>
            /// Installs a hook procedure that posts messages previously recorded by a WH_JOURNALRECORD hook procedure. 
            /// For more information, see the JournalPlaybackProc hook procedure.
            /// </summary>
            WH_JOURNALPLAYBACK = 1,
            /// <summary>
            /// Installs a hook procedure that monitors keystroke messages. For more information, see the KeyboardProc 
            /// hook procedure.
            /// </summary>
            WH_KEYBOARD = 2,
            /// <summary>
            /// Installs a hook procedure that monitors messages posted to a message queue. For more information, see the 
            /// GetMsgProc hook procedure.
            /// </summary>
            WH_GETMESSAGE = 3,
            /// <summary>
            /// Installs a hook procedure that monitors messages before the system sends them to the destination window 
            /// procedure. For more information, see the CallWndProc hook procedure.
            /// </summary>
            WH_CALLWNDPROC = 4,
            /// <summary>
            /// Installs a hook procedure that receives notifications useful to a CBT application. For more information, 
            /// see the CBTProc hook procedure.
            /// </summary>
            WH_CBT = 5,
            /// <summary>
            /// Installs a hook procedure that monitors messages generated as a result of an input event in a dialog box, 
            /// message box, menu, or scroll bar. The hook procedure monitors these messages for all applications in the 
            /// same desktop as the calling thread. For more information, see the SysMsgProc hook procedure.
            /// </summary>
            WH_SYSMSGFILTER = 6,
            /// <summary>
            /// Installs a hook procedure that monitors mouse messages. For more information, see the MouseProc hook 
            /// procedure.
            /// </summary>
            WH_MOUSE = 7,
            /// <summary>
            /// 
            /// </summary>
            WH_HARDWARE = 8,
            /// <summary>
            /// Installs a hook procedure useful for debugging other hook procedures. For more information, see the 
            /// DebugProc hook procedure.
            /// </summary>
            WH_DEBUG = 9,
            /// <summary>
            /// Installs a hook procedure that receives notifications useful to shell applications. For more information, 
            /// see the ShellProc hook procedure.
            /// </summary>
            WH_SHELL = 10,
            /// <summary>
            /// Installs a hook procedure that will be called when the application's foreground thread is about to become 
            /// idle. This hook is useful for performing low priority tasks during idle time. For more information, see the
            /// ForegroundIdleProc hook procedure.
            /// </summary>
            WH_FOREGROUNDIDLE = 11,
            /// <summary>
            /// Installs a hook procedure that monitors messages after they have been processed by the destination window 
            /// procedure. For more information, see the CallWndRetProc hook procedure.
            /// </summary>
            WH_CALLWNDPROCRET = 12,
            /// <summary>
            /// Installs a hook procedure that monitors low-level keyboard input events. For more information, see the 
            /// LowLevelKeyboardProc hook procedure.
            /// </summary>
            WH_KEYBOARD_LL = 13,
            /// <summary>
            /// Installs a hook procedure that monitors low-level mouse input events. For more information, see the 
            /// LowLevelMouseProc hook procedure.
            /// </summary>
            WH_MOUSE_LL = 14
        }



        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool AddClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll")]
        public static extern bool ChangeClipboardChain(IntPtr hWndRemove, IntPtr hWndNewNext);

        [DllImport("user32.dll")]
        public static extern bool CloseClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr CreateWindowEx(
           Winuser.WindowStylesEx dwExStyle,
           [MarshalAs(UnmanagedType.LPStr)]
           string lpClassName,
           [MarshalAs(UnmanagedType.LPStr)] string lpWindowName, 
           Winuser.WindowStyles dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr CreateWindowEx(
           Winuser.WindowStylesEx dwExStyle,
           IntPtr lpClassName,
           [MarshalAs(UnmanagedType.LPStr)] string lpWindowName,
           Winuser.WindowStyles dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr DefWindowProcW(IntPtr hWnd, uint Msg, IntPtr wParam, [MarshalAs(UnmanagedType.LPWStr)] string lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool DestroyWindow(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr DispatchMessage(ref Winuser.tagMSG lpMsg);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint EnumClipboardFormats(uint format);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return:MarshalAs(UnmanagedType.Bool)]
        public delegate bool EnumWindows(
            WindowCallBack callback,
            object lParam
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool EnumChildWindows(
            IntPtr window,
            WindowCallBack callback,
            IntPtr lParam
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.U4)]
        public delegate int EnumPropsW(
            IntPtr hwnd,
            PropEnumPropCallBack lpEnumFunc
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern ushort GetAsyncKeyState(uint vKey);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return:MarshalAs(UnmanagedType.I4)]
        public delegate int GetClassNameW(
           IntPtr hWnd,
           [MarshalAs(UnmanagedType.LPWStr)]
           System.Text.StringBuilder lpClassName,
           [MarshalAs(UnmanagedType.I4)]
           int nMaxCount
       );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetClipboardData(uint uFormat);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetClipboardSequenceNumber();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetMessage(ref Winuser.tagMSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetParent(
            IntPtr hWnd
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetPropW(
            IntPtr hWnd, 
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpString
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectSecurity(IntPtr hObj, ref Winnt.SECURITY_INFORMATION pSIRequested, Winnt.SECURITY_DESCRIPTOR_CONTROL pSID, uint nLength, ref uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectSecurity(IntPtr hObj, ref Winnt.SECURITY_INFORMATION pSIRequested, IntPtr pSID, uint nLength, ref uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, uint nMaxCount);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowTextLength(IntPtr hWnd);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return:MarshalAs(UnmanagedType.U4)]
        public delegate uint GetWindowThreadProcessId(
            IntPtr hWnd,
            out uint lpdwProcessId
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenDesktopA(
            [MarshalAs(UnmanagedType.LPStr)] string lpszDesktop,
            [MarshalAs(UnmanagedType.U4)] uint dwFlags,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            Winuser.DesktopSecurity dwDesiredAccess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenDesktopW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpszDesktop,
            [MarshalAs(UnmanagedType.U4)] uint dwFlags,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            Winuser.DesktopSecurity dwDesiredAccess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenWindowStationA(
            [MarshalAs(UnmanagedType.LPStr)] string lpszWinSta,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            Winuser.WindowStationSecurity dwDesiredAccess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenWindowStationW(
            IntPtr lpszWinSta,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            Winuser.WindowStationSecurity dwDesiredAccess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool PostMessageW(
            IntPtr hWnd,
            [MarshalAs(UnmanagedType.U4)]
            uint Msg, 
            IntPtr wParam, 
            IntPtr lParam
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern ushort RegisterClassEx(ref Winuser.WNDCLASSEX lpwcx);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, [MarshalAs(UnmanagedType.LPWStr)] string lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetClipboardViewer(IntPtr hWndNewViewer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool SetPropW(
            IntPtr hWnd,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpString,
            IntPtr hData
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetUserObjectSecurity(IntPtr hObj, Winnt.SECURITY_INFORMATION pSIRequested, Winnt._SECURITY_DESCRIPTOR pSID);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr SetWindowsHookExW(
            [MarshalAs(UnmanagedType.I4)] IdHook idHook,
            IntPtr lpfn,
            IntPtr hmod,
            [MarshalAs(UnmanagedType.U4)] uint dwThreadId
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool TranslateMessage(ref Winuser.tagMSG lpMsg);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnregisterClass(string lpClassName, IntPtr hInstance);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool UnhookWindowsHookEx(IntPtr hhk);

        public delegate bool WindowCallBack(IntPtr hwnd, IntPtr lParam);
        public delegate bool PropEnumPropCallBack(IntPtr hwnd, IntPtr lpszString, IntPtr hData);

        
        //https://modexp.wordpress.com/2018/08/23/process-injection-propagate/
        [StructLayout(LayoutKind.Sequential)]
        public struct _SUBCLASS_CALL
        {
            public IntPtr pfnSubclass;    // subclass procedure
            public IntPtr uIdSubclass;    // unique subclass identifier
            public IntPtr dwRefData;      // optional ref data
        }
        //SUBCLASS_CALL, PSUBCLASS_CALL;

        
        [StructLayout(LayoutKind.Sequential)]
        public struct _SUBCLASS_FRAME
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint uCallIndex;
            [MarshalAs(UnmanagedType.U4)]
            public uint uDeepestCall;
            public IntPtr  pFramePrev;
            public _SUBCLASS_HEADER pHeader;
        }
        //SUBCLASS_FRAME, PSUBCLASS_FRAME;


        [StructLayout(LayoutKind.Sequential)]
        public struct _SUBCLASS_HEADER
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint uRefs;        // subclass count
            [MarshalAs(UnmanagedType.U4)]
            public uint uAlloc;       // allocated subclass call nodes
            [MarshalAs(UnmanagedType.U4)]
            public uint uCleanup;     // index of call node to clean up
            [MarshalAs(UnmanagedType.U4)]
            public uint dwThreadId;   // thread id of window we are hooking
            public IntPtr pFrameCur;   // current subclass frame pointer
            public _SUBCLASS_CALL CallArray; // base of packed call node array
        }
        //SUBCLASS_HEADER, *PSUBCLASS_HEADER;
    }
}