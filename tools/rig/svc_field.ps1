# Probe only (never merged): the field's word for ADR-0013 AE-5 - a branch's `raqib service run` as a real
# service of Windows on a throwaway machine. It makes one service, one local user and the service's place, reads
# what they did, and removes all three.
# usage: svc_field.ps1 PACKED_EXE
param([string]$Packed)
$ErrorActionPreference = "Continue"
$py = (Get-Command python).Source
$place = "C:\ProgramData\Raqib"
$pub = "C:\raqib-pub"
$name = "RaqibWatch"

function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Sddl($p) { try { (Get-Acl -LiteralPath $p -ErrorAction Stop).GetSecurityDescriptorSddlForm("Owner, Access") -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" } catch { "not read: $($_.Exception.Message)" } }
function State { $s = Get-CimInstance Win32_Service -Filter "Name='$name'"; "state $($s.State); pid $($s.ProcessId); exit $($s.ExitCode); the service's own exit $($s.ServiceSpecificExitCode)" }
function Show-Place {
  "the place: $(if (Test-Path $place) { Sddl $place } else { 'absent' })"
  Get-ChildItem $place -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object { "    {0} ({1} bytes)" -f $_.FullName.Replace($place, "PLACE"), $_.Length }
  $t = "$place\service.txt"
  "service.txt: $((Get-Content $t -ErrorAction SilentlyContinue).Count) line(s)"
  Get-Content $t -ErrorAction SilentlyContinue | Select-String -Pattern "^raqib watch --host: sources|round \d+: \d+ records|stopped|RESULT|HOLES \(|BLIND SPOTS|Traceback|Error|raqib:|refus" | Select-Object -First 9 | ForEach-Object { "    " + (Cut $_.Line 190) }
}
function Events-Tail { "the system's own log of the service:"; Get-WinEvent -FilterHashtable @{LogName = "System"; ProviderName = "Service Control Manager"} -MaxEvents 8 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match $name } | Select-Object -First 3 | ForEach-Object { "    event {0}: {1}" -f $_.Id, (Cut ($_.Message -replace "\s+", " ") 200) } }
function Try-Start($why) {
  $t = Get-Date
  try { Start-Service $name -ErrorAction Stop; "start ($why): ok in {0:n2} s" -f ((Get-Date) - $t).TotalSeconds } catch { "start ($why): NOT started: $(Cut $_.Exception.Message 160)" }
  Start-Sleep 2
  State
}
function Try-Stop {
  $t = Get-Date
  try { Stop-Service $name -ErrorAction Stop; "stop: ok in {0:n2} s" -f ((Get-Date) - $t).TotalSeconds } catch { "stop: FAILED: $(Cut $_.Exception.Message 160)" }
  State
}
function Clear-Place { if (Test-Path $place) { Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue }; "the place removed: $(-not (Test-Path $place))" }

"=== run by hand, with no service manager"
$o = & python -I -m raqib service run 2>&1
"exit $LASTEXITCODE; said: $(Cut (($o | Out-String) -replace '\s+', ' ') 220)"
"the place after it: $(if (Test-Path $place) { 'present' } else { 'absent' })"

New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null; "a plain user made" } catch { "a plain user NOT made: $($_.Exception.Message)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
function As-User($tag, $lines) {
  $cmd = "$pub\try-$tag.cmd"; $out = "$pub\out-$tag.txt"
  ("@echo off`r`n" + ($lines -replace "OUT", $out)) | Set-Content -Encoding ascii $cmd
  try {
    Start-Process cmd.exe -ArgumentList "/c", $cmd -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
    "as the plain user ($tag):"
    Get-Content $out -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | ForEach-Object { "    " + ($_ -replace "\s+", " ") }
  } catch { "as the plain user ($tag): NOT MEASURED: $($_.Exception.Message)" }
}

"=== plain: the service, the place absent before it"
Clear-Place
New-Service -Name $name -BinaryPathName "`"$py`" -I -m raqib service run" -StartupType Manual | Out-Null
Try-Start "the place absent"
Start-Sleep 12
Show-Place
$svcpid = (Get-CimInstance Win32_Service -Filter "Name='$name'").ProcessId
As-User "running" ("echo x > $place\by-user.txt 2>nul && (echo write into the place: DONE > OUT) || (echo write into the place: REFUSED > OUT)`r`n" +
  "type $place\service.txt > nul 2>&1 && (echo read its text: DONE >> OUT) || (echo read its text: REFUSED >> OUT)`r`n" +
  "dir /b $place > nul 2>&1 && (echo list the place: DONE >> OUT) || (echo list the place: REFUSED >> OUT)`r`n" +
  "sc.exe stop $name > nul 2>&1 && (echo stop the service: DONE >> OUT) || (echo stop the service: REFUSED >> OUT)`r`n" +
  "taskkill /f /pid $svcpid > nul 2>&1 && (echo end its process: DONE >> OUT) || (echo end its process: REFUSED >> OUT)")
State
Try-Stop
Show-Place
"raqib's own reading of the service's events:"
& python -I -m raqib events "$place\.raqib\host\events.jsonl" 2>&1 | Select-Object -First 6 | ForEach-Object { "    " + (Cut "$_" 200) }

"=== started again on its own closed place (the text before kept once)"
Try-Start "the place closed and its own"
Start-Sleep 5
Try-Stop
"texts in the place: $((Get-ChildItem $place -Filter 'service*.txt' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')"

"=== the place made first by a plain user"
Clear-Place
As-User "make" "mkdir $place 2>nul && (echo make the place first: DONE > OUT) || (echo make the place first: REFUSED > OUT)"
"the place: $(Sddl $place)"
Try-Start "the place a plain user's"
Events-Tail
"the place after it: $(Sddl $place); files in it: $((Get-ChildItem $place -Recurse -File -ErrorAction SilentlyContinue).Count)"

"=== the place an administrator made, open, with a file in it"
Clear-Place
New-Item -ItemType Directory -Force $place | Out-Null
"x" | Set-Content "$place\left-here.txt"
"the place: $(Sddl $place)"
Try-Start "open and not empty"
Events-Tail
"the place after it: $(Sddl $place); files in it: $((Get-ChildItem $place -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')"

"=== a place closed after it existed (the list set on it): refused"
Clear-Place
New-Item -ItemType Directory -Force $place | Out-Null
icacls $place /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
"the place: $(Sddl $place)"
Try-Start "closed after it existed"
"the place after it: $(Sddl $place)"

"=== the place an administrator made, open and empty"
Clear-Place
New-Item -ItemType Directory -Force $place | Out-Null
"the place: $(Sddl $place)"
Try-Start "open and empty"
Start-Sleep 5
"the place: $(Sddl $place)"
Try-Stop

"=== the place a junction to another folder, then a link to it"
New-Item -ItemType Directory -Force "C:\ProgramData\RaqibElsewhere" | Out-Null
foreach ($how in "/J", "/D") {
  Clear-Place
  cmd /c mklink $how $place "C:\ProgramData\RaqibElsewhere" | Out-Null
  Try-Start "mklink $how"
  Events-Tail
  "files in the folder it points to: $((Get-ChildItem 'C:\ProgramData\RaqibElsewhere' -Recurse -File -ErrorAction SilentlyContinue).Count); its list: $(Sddl 'C:\ProgramData\RaqibElsewhere')"
  cmd /c rmdir $place | Out-Null
}
Remove-Item -Recurse -Force "C:\ProgramData\RaqibElsewhere" -ErrorAction SilentlyContinue

"=== a file where the place would be"
Clear-Place
"x" | Set-Content $place
Try-Start "a file at the name"
Events-Tail
"the file is as it was: $((Get-Content $place -ErrorAction SilentlyContinue) -eq 'x')"
Remove-Item -Force $place -ErrorAction SilentlyContinue

"=== refused twice in a row: the place a plain user made, started again"
Clear-Place
As-User "make2" "mkdir $place 2>nul && (echo make the place first: DONE > OUT) || (echo make the place first: REFUSED > OUT)"
Try-Start "a plain user's, the first time"
Try-Start "a plain user's, the second time"
"the place after both: $(Sddl $place); files in it: $((Get-ChildItem $place -Recurse -File -ErrorAction SilentlyContinue).Count)"
sc.exe delete $name | Select-Object -First 1

if ($Packed) {
  "=== packed: the service, the place absent before it"
  Clear-Place
  New-Service -Name $name -BinaryPathName "`"$Packed`" service run" -StartupType Manual | Out-Null
  Try-Start "packed, the place absent"
  Start-Sleep 10
  Show-Place
  Try-Stop
  sc.exe delete $name | Select-Object -First 1
}

"=== removed"
Clear-Place
try { Remove-LocalUser -Name raqibprobe -ErrorAction Stop; "the user removed" } catch { "the user NOT removed: $($_.Exception.Message)" }
exit 0
