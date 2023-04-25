using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace MonkeyWorks.Unmanaged.Libraries
{
    public sealed class user32
    {
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
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumChildWindows(IntPtr window, WindowCallBack callback, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint EnumClipboardFormats(uint format);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern int EnumPropsW(IntPtr hwnd, PropEnumPropCallBack lpEnumFunc);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumWindows(WindowCallBack callback, object lParam);

        [DllImport("User32.dll", EntryPoint = "FindWindowW", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindowW(
            //[MarshalAs(UnmanagedType.LPWStr)]
            IntPtr lpClassName,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpWindowName
        );

        [DllImport("User32.dll", EntryPoint = "FindWindowExW", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindowExW(
            IntPtr hWndParent,
            IntPtr hWndChildAfter,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpszClass,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpszWindow
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern ushort GetAsyncKeyState(uint vKey);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetClipboardData(uint uFormat);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetMessage(ref Winuser.tagMSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int GetClassNameW(
           IntPtr hWnd,
           [MarshalAs(UnmanagedType.LPWStr)]
           System.Text.StringBuilder lpClassName,
           [MarshalAs(UnmanagedType.I4)]
           int nMaxCount
       );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetClipboardSequenceNumber();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectSecurity(IntPtr hObj, ref Winnt.SECURITY_INFORMATION pSIRequested, Winnt.SECURITY_DESCRIPTOR_CONTROL pSID, uint nLength, ref uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectSecurity(IntPtr hObj, ref Winnt.SECURITY_INFORMATION pSIRequested, IntPtr pSID, uint nLength, ref uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetParent(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetPropW(
            IntPtr hWnd,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpString
        );

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetWindowText(
            IntPtr hWnd, 
            System.Text.StringBuilder lpString, 
            uint nMaxCount
        );

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint GetWindowThreadProcessId(
            IntPtr hWnd,
            [MarshalAs(UnmanagedType.U4)]
            out uint lpdwProcessId
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenDesktopA(
            [MarshalAs(UnmanagedType.LPStr)] string lpszDesktop,
            [MarshalAs(UnmanagedType.U4)] uint dwFlags,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            Winuser.DesktopSecurity dwDesiredAccess
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenDesktopW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpszDesktop,
            [MarshalAs(UnmanagedType.U4)] uint dwFlags,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            Winuser.DesktopSecurity dwDesiredAccess
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenWindowStationA(
            [MarshalAs(UnmanagedType.LPStr)] string lpszWinSta,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            Winuser.WindowStationSecurity dwDesiredAccess
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenWindowStationW(
            IntPtr lpszWinSta,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            Winuser.WindowStationSecurity dwDesiredAccess
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool PostMessage(IntPtr hWnd, uint Msg, uint wParam, uint lParam);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PostMessageW(
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
        public static extern IntPtr SendMessage(
            IntPtr hWnd,
            [MarshalAs(UnmanagedType.U4)]
            uint Msg, 
            IntPtr wParam, 
            [MarshalAs(UnmanagedType.LPWStr)] 
            string lParam
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint SendMessage(
            IntPtr hWnd,
            [MarshalAs(UnmanagedType.U4)]
            uint Msg,
            [MarshalAs(UnmanagedType.U4)]
            uint wParam,
            IntPtr lParam
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetClipboardViewer(IntPtr hWndNewViewer);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetPropW(
            IntPtr hWnd,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpString,
            IntPtr hData
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetUserObjectSecurity(IntPtr hObj, Winnt.SECURITY_INFORMATION pSIRequested, Winnt._SECURITY_DESCRIPTOR pSID);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool TranslateMessage(ref Winuser.tagMSG lpMsg);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnregisterClass(string lpClassName, IntPtr hInstance);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

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
            public IntPtr pFramePrev;
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