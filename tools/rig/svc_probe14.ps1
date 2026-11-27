# Probe only (never merged): the fourteenth measurement (see svc_probe14.py). On a throwaway Windows machine it
# makes the service RaqibWatch as Raqib's install would, from a copy of the job's Python under Program Files and
# then from the job's own Python (refused at its start), reads it back as an administrator and as a user it makes
# outside the administrators' group, watches the system start a refused service again, and removes everything.
$ErrorActionPreference = "Continue"
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
$name = "RaqibWatch"
$place = Join-Path $env:ProgramData "Raqib"
$hold = "C:\Program Files\RaqibField14"
$pub = "C:\Users\Public\raqib-probe14"
$own = (Get-Command python).Source
$copy = "$hold\Py\python.exe"
$probe = Join-Path $PSScriptRoot "svc_probe14.py"
New-Item -ItemType Directory -Force $hold, $pub | Out-Null
Copy-Item (Split-Path $own) "$hold\Py" -Recurse
Copy-Item $probe "$pub\p14.py"
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null } catch { "a plain user NOT made: $(Cut $_.Exception.Message 200)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
"@echo off`r`n`"$own`" `"$pub\p14.py`" read $name > `"$pub\plain.txt`" 2>&1`r`n`"$own`" -m raqib service status >> `"$pub\plain.txt`" 2>&1" | Set-Content -Encoding ascii "$pub\plain.cmd"
function Plain {
  Remove-Item -Force "$pub\plain.txt" -ErrorAction SilentlyContinue
  try {
    Start-Process cmd.exe -ArgumentList "/c", "$pub\plain.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
    Get-Content "$pub\plain.txt" | ForEach-Object { "    " + (Cut (Mask $_) 400) }
  } catch { "as the plain user: NOT MEASURED: $(Cut $_.Exception.Message 200)" }
}
"=== made as the install would, from the copy under Program Files"
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
python $probe make $name "`"$copy`" -I -m raqib service run" | ForEach-Object { Cut (Mask $_) 500 }
"--- read by a user with no rights (the probe's reader, then `raqib service status`)"
Plain
"--- the runner's first lines"
Get-Content "$place\service.txt" -TotalCount 2 -ErrorAction SilentlyContinue | ForEach-Object { "    " + (Cut (Mask $_) 300) }
"--- removed by the system's own calls"
python $probe remove $name
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
"=== made the same way from the job's own Python: refused at every start, and the system told to start it again"
$t = Get-Date
python $probe make $name "`"$own`" -I -m raqib service run" | ForEach-Object { Cut (Mask $_) 300 }
"--- 50 s of what the system does with it"
$last = ""
while (((Get-Date) - $t).TotalSeconds -lt 55) {
  $s = Get-CimInstance Win32_Service -Filter "Name='$name'"
  $now = "state $($s.State), pid $($s.ProcessId), exit $($s.ExitCode), its own $($s.ServiceSpecificExitCode)"
  if ($now -ne $last) { "{0,6:n1} s: {1}" -f ((Get-Date) - $t).TotalSeconds, $now; $last = $now }
  Start-Sleep -Milliseconds 300
}
"--- the system's log of it, with the seconds since it was made"
Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Service Control Manager"; StartTime = $t } -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match "Raqib watch|$name" } | Sort-Object TimeCreated |
  ForEach-Object { "{0,6:n1} s: {1}: {2}" -f ($_.TimeCreated - $t).TotalSeconds, $_.Id, (Cut (($_.Message -replace "\s+", " ").Trim()) 230) }
"--- how many times the runner began its text file"
"service.txt: $(@(Get-Content "$place\service.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match 'its own code, checked at this start' }).Count) check line(s); the files there: $((Get-ChildItem $place -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')"
"--- read by a user with no rights while the system holds it for its next start"
Plain
"--- removed"
python $probe remove $name
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
"=== cleaned"
Remove-LocalUser -Name raqibprobe -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $hold, $pub -ErrorAction SilentlyContinue
"left: the service $([bool](Get-CimInstance Win32_Service -Filter "Name='$name'")), the folders $(Test-Path $hold) $(Test-Path $pub), the user $([bool](Get-LocalUser -Name raqibprobe -ErrorAction SilentlyContinue))"
exit 0
