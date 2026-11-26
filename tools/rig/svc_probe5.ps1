# Probe only (never merged): three things measured before ADR-0013's next ruling, on a throwaway machine - a
# folder made closed in the one call that makes it; a folder read and held by one handle on its name; what the
# system says of a service that refuses. It makes folders, services and one local user of its own and removes them.
$ErrorActionPreference = "Continue"
$py = (Get-Command python).Source
$script = Join-Path $PSScriptRoot "svc_probe.py"
$pd = "C:\ProgramData"
$pub = "C:\raqib-pub"
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null; "a plain user made" } catch { "a plain user NOT made: $($_.Exception.Message)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
function As-User($tag, $lines) {
  $cmd = "$pub\t5-$tag.cmd"; $out = "$pub\o5-$tag.txt"
  ("@echo off`r`n" + ($lines -replace "OUT", $out)) | Set-Content -Encoding ascii $cmd
  try {
    Start-Process cmd.exe -ArgumentList "/c", $cmd -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
    "as the plain user ($tag):"
    Get-Content $out -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | ForEach-Object { "    " + ($_ -replace "\s+", " ") }
  } catch { "as the plain user ($tag): NOT MEASURED: $($_.Exception.Message)" }
}
function Tries($d) {
  "echo x > $d\by-user.txt 2>nul && (echo write into it: DONE > OUT) || (echo write into it: REFUSED > OUT)`r`n" +
  "dir /b $d > nul 2>&1 && (echo list it: DONE >> OUT) || (echo list it: REFUSED >> OUT)`r`n" +
  "ren $d $(Split-Path $d -Leaf)-renamed > nul 2>&1 && (echo give it another name: DONE >> OUT) || (echo give it another name: REFUSED >> OUT)`r`n" +
  "rmdir $d > nul 2>&1 && (echo remove it: DONE >> OUT) || (echo remove it: REFUSED >> OUT)"
}

"=== a folder made closed in the one call that makes it (as an administrator)"
$a = "$pd\RaqibProbe5a"
Mask ((python $script --make $a) -join " | ")
"made again where it is: $((python $script --make $a | Select-Object -First 1))"
As-User "made-closed" (Tries $a)
"it is still there: $(Test-Path $a)"

"=== the same by the system's own account (a service)"
New-Service -Name RaqibProbeM -BinaryPathName "`"$py`" `"$script`" --service RaqibProbeM make" -StartupType Manual | Out-Null
try { Start-Service RaqibProbeM -ErrorAction Stop } catch { "start: $(Cut $_.Exception.Message 120)" }
Start-Sleep 3
Get-Content "$pd\RaqibProbe\make\svc.log" -ErrorAction SilentlyContinue | Select-String "as the system" | ForEach-Object { "    " + (Mask (Cut $_.Line 220)) }
sc.exe delete RaqibProbeM | Out-Null

"=== read through one handle on the name itself: a folder, a junction, a link to a folder, a file, nothing"
$t = "$pd\RaqibProbe5t"; New-Item -ItemType Directory -Force "$t\real" | Out-Null
cmd /c mklink /J "$t\junction" "$t\real" | Out-Null
cmd /c mklink /D "$t\link" "$t\real" | Out-Null
"x" | Set-Content "$t\file.txt"
foreach ($n in "real", "junction", "link", "file.txt", "absent") { "{0}: {1}" -f $n, (Mask ((python $script --read "$t\$n") -join " ")) }

"=== a folder a plain user made, held by one handle: can he take its name away?"
$u = "$pd\RaqibProbe5u"
As-User "make-his" "mkdir $u 2>nul && (echo make his folder: DONE > OUT) || (echo make his folder: REFUSED > OUT)"
$hold = Start-Process python -ArgumentList "`"$script`"", "--hold", $u, "25" -PassThru -WindowStyle Hidden -RedirectStandardOutput "$pub\hold.txt"
Start-Sleep 4
"the holder says: $(Get-Content "$pub\hold.txt" -ErrorAction SilentlyContinue)"
As-User "held" (Tries $u)
"its maker's folder is still there under its name: $(Test-Path $u)"
try { Rename-Item $u "$u-by-admin" -ErrorAction Stop; "an administrator gave it another name: DONE"; Rename-Item "$u-by-admin" $u } catch { "an administrator gave it another name: REFUSED ($(Cut $_.Exception.Message 90))" }
try { "y" | Set-Content "$u\made-while-held.txt" -ErrorAction Stop; "a file made in it while it is held: DONE" } catch { "a file made in it while it is held: REFUSED" }
$hold.WaitForExit(40000) | Out-Null
Remove-Item "$u\made-while-held.txt", "$u\by-user.txt" -ErrorAction SilentlyContinue
As-User "let-go" (Tries $u)

"=== what the system says of a service that refuses"
foreach ($n in 14, 20014, 536870926) {
  foreach ($mode in "running", "pending") {
    New-Service -Name RaqibProbeR -BinaryPathName "`"$py`" `"$script`" --service RaqibProbeR refuse $n $mode" -StartupType Manual | Out-Null
    $said = "ok"
    try { Start-Service RaqibProbeR -ErrorAction Stop } catch { $said = "FAILED: " + (Cut ($_.Exception.Message -replace "\s+", " ") 150) }
    Start-Sleep 2
    $s = Get-CimInstance Win32_Service -Filter "Name='RaqibProbeR'"
    "number $n, refused from $mode : the start command says: $said"
    "    state $($s.State); exit $($s.ExitCode); the service's own exit $($s.ServiceSpecificExitCode)"
    "    sc: $(Cut (((sc.exe start RaqibProbeR) -join ' ') -replace '\s+', ' ') 170)"
    Start-Sleep 1
    $e = Get-WinEvent -FilterHashtable @{LogName = "System"; ProviderName = "Service Control Manager"; Id = 7024} -MaxEvents 1 -ErrorAction SilentlyContinue
    "    the system's log: $(Cut ($e.Message -replace '\s+', ' ') 190)"
    sc.exe delete RaqibProbeR | Out-Null
    Start-Sleep 1
  }
}

"=== removed"
foreach ($d in $a, "$pd\RaqibProbe5s", $t, $u, "$pd\RaqibProbe") { cmd /c rmdir /s /q $d 2>$null }
"left: $((Get-ChildItem $pd -Filter 'RaqibProbe*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')"
try { Remove-LocalUser -Name raqibprobe -ErrorAction Stop; "the user removed" } catch { "the user NOT removed: $($_.Exception.Message)" }
exit 0
