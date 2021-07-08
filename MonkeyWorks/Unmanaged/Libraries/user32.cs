using System;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class user32
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
        public static extern uint EnumClipboardFormats(uint format);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern ushort GetAsyncKeyState(uint vKey);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern ushort GetAsyncKeyState(System.Windows.Forms.Keys vKey);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetClipboardData(uint uFormat);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetMessage(ref Winuser.tagMSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetClipboardSequenceNumber();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectSecurity(IntPtr hObj, ref Winnt.SECURITY_INFORMATION pSIRequested, Winnt.SECURITY_DESCRIPTOR_CONTROL pSID, uint nLength, ref uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectSecurity(IntPtr hObj, ref Winnt.SECURITY_INFORMATION pSIRequested, IntPtr pSID, uint nLength, ref uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, uint nMaxCount);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool PostMessage(IntPtr hWnd, uint Msg, uint wParam, uint lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern ushort RegisterClassEx(ref Winuser.WNDCLASSEX lpwcx);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, [MarshalAs(UnmanagedType.LPWStr)] string lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetClipboardViewer(IntPtr hWndNewViewer);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetUserObjectSecurity(IntPtr hObj, Winnt.SECURITY_INFORMATION pSIRequested, Winnt._SECURITY_DESCRIPTOR pSID);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool TranslateMessage(ref Winuser.tagMSG lpMsg);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnregisterClass(string lpClassName, IntPtr hInstance);
    }
}