# Probe only (never merged): the thirteenth measurement - a branch's `raqib service status` on real Windows
# (ADR-0013 Amendment V), asked by the job's administrator and by a plain user it makes, of the name RaqibWatch at
# each moment of a service's life: not there, made without Raqib's mark, with it and never started, running,
# stopped, refused at its start (its own number 15), made otherwise than Raqib's install would. It makes one
# folder under Program Files, one under the public folder, one local user and one service at a time, and removes
# them. The command itself changes nothing.
$ErrorActionPreference = "Continue"
function Flat($lines) { ((($lines -join " | ") -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>") -replace "[ \t]+", " ").Trim() }
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
$name = "RaqibWatch"
$place = Join-Path $env:ProgramData "Raqib"
$hold = "C:\Program Files\RaqibFieldStatus"
$pub = "C:\Users\Public\raqib-status"
$own = (Get-Command python).Source
$copy = "$hold\Py\python.exe"
New-Item -ItemType Directory -Force $hold, $pub | Out-Null
Copy-Item (Split-Path $own) "$hold\Py" -Recurse
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
$plain = $true
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null } catch { $plain = $false; "a plain user NOT made: $(Cut $_.Exception.Message 200)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
"@echo off`r`nwhoami /groups | findstr /c:`"S-1-5-32-544`" > `"$pub\groups.txt`"`r`n`"$own`" -m raqib service status > `"$pub\plain.txt`" 2>&1`r`necho exit %errorlevel% >> `"$pub\plain.txt`"" | Set-Content -Encoding ascii "$pub\plain.cmd"
function Ask($moment) {
  "--- $moment"
  $said = & $own -m raqib service status 2>&1 | ForEach-Object { "$_" }
  "the administrator: exit $LASTEXITCODE; $(Cut (Flat $said) 1500)"
  if ($plain) {
    Remove-Item -Force "$pub\plain.txt" -ErrorAction SilentlyContinue
    try {
      Start-Process cmd.exe -ArgumentList "/c", "$pub\plain.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
      "a plain user: $(Cut (Flat (Get-Content "$pub\plain.txt" -ErrorAction SilentlyContinue)) 1500)"
    } catch { "a plain user: NOT MEASURED: $(Cut $_.Exception.Message 200)" }
  }
}
function Gone { sc.exe delete $name | Out-Null; Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue; Start-Sleep 1 }
function WaitRound { $t = Get-Date; while (((Get-Date) - $t).TotalSeconds -lt 60) { if (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue) { break }; Start-Sleep -Milliseconds 500 } }
$mark = "raqib-service/1 Raqib's watch of this host (ADR-0013)"
if (Get-CimInstance Win32_Service -Filter "Name='$name'") { "a service of the name was there before the probe: NOT MEASURED"; exit 0 }
Ask "no service of the name"
if ($plain) { "the plain user is in the administrators' group: $([bool](Get-Content "$pub\groups.txt" -ErrorAction SilentlyContinue))" }
New-Service -Name $name -BinaryPathName "`"$copy`" -I -m raqib service run" -StartupType Manual | Out-Null
Ask "made from the copy under Program Files, without Raqib's mark, never started"
sc.exe description $name $mark | Out-Null
Ask "the mark set as its description, never started"
Start-Service $name; WaitRound
Ask "running"
Stop-Service $name
Ask "stopped by a Stop"
sc.exe config $name start= auto | Out-Null
Ask "its start set to automatic"
sc.exe config $name obj= "NT AUTHORITY\LocalService" password= "" | Out-Null
Ask "its account set to another than the system's (not started)"
Gone
New-Service -Name $name -BinaryPathName "`"$own`" -I -m raqib service run" -StartupType Manual | Out-Null
sc.exe description $name $mark | Out-Null
try { Start-Service $name -ErrorAction Stop } catch { "the start failed, as the system says it: $(Cut $_.Exception.Message 160)" }
Ask "made with the mark from the job's own Python, refused at its start"
Gone
New-Service -Name $name -BinaryPathName "`"$copy`" -m raqib service run" -StartupType Manual | Out-Null
sc.exe description $name $mark | Out-Null
Ask "made with the mark and a command that is not one of the two forms (no -I), never started"
Gone
New-Service -Name $name -BinaryPathName "`"$copy`" -I -m raqib service run" -StartupType Manual -DisplayName "Raqib watch" | Out-Null
sc.exe description $name "raqib-service/10 not this mark" | Out-Null
Ask "made with a description that only begins like the mark"
Gone
"=== removed"
if ($plain) { Remove-LocalUser -Name raqibprobe -ErrorAction SilentlyContinue }
Remove-Item -Recurse -Force $hold, $pub -ErrorAction SilentlyContinue
"left: the service $([bool](Get-CimInstance Win32_Service -Filter "Name='$name'")), the folders $(Test-Path $hold) $(Test-Path $pub), the user $([bool](Get-LocalUser -Name raqibprobe -ErrorAction SilentlyContinue))"
exit 0
