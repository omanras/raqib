# Probe only (never merged): measured before ADR-0013's ruling on install, remove and status for Windows - the
# system's numbers for each service call made at the wrong moment, what a caller with no rights may open and read,
# and whether the system starts a service again after an exit of the service's own when it is told to. It makes
# one service, the service's place and one local user of its own, and removes them.
$ErrorActionPreference = "Continue"
$probe = Join-Path $PSScriptRoot "svc_probe10.py"
$py = (Get-Command python).Source
$name = "RaqibProbeP10"
$place = "C:\ProgramData\Raqib"
$pub = "C:\raqib-pub"
$command = "`"$py`" -I -m raqib service run"
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
"=== the system's numbers, call by call (the service: main's runner)"
python $probe numbers $name $command
"left after it: $((Get-CimInstance Win32_Service -Filter "Name='$name'" | Measure-Object).Count) service(s) of the name"
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
"=== what a plain user may open and read of a service"
python $probe make $name $command | Select-Object -First 1
New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null } catch { "a plain user NOT made: $($_.Exception.Message)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
Copy-Item $probe "$pub\p10.py"
"@echo off`r`n`"$py`" $pub\p10.py plain $name > $pub\plain.txt 2>&1" | Set-Content -Encoding ascii "$pub\plain.cmd"
try {
  Start-Process cmd.exe -ArgumentList "/c", "$pub\plain.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
  Get-Content "$pub\plain.txt" | ForEach-Object { "    " + (Mask $_) }
} catch { "as the plain user: NOT MEASURED: $($_.Exception.Message)" }
"--- the same asks by the administrator, for comparison"
python $probe plain $name | Select-Object -First 6
python $probe remove $name
Start-Sleep 3
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
"=== an exit of the service's own, with the failure flag set: is it started again"
New-Item -ItemType Directory -Force $place | Out-Null    # an open place: the runner refuses it with its own number
$before = Get-Date
python $probe flag $name $command
Start-Sleep 2
"what the system's log says of it since: $((Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=$before} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match $name -or $_.Message -match 'Raqib probe 10' } | Group-Object Id | ForEach-Object { "$($_.Count) of event $($_.Name)" }) -join '; ')"
python $probe remove $name
Start-Sleep 3
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
"=== the same exit, without the flag"
New-Item -ItemType Directory -Force $place | Out-Null
$before = Get-Date
python $probe noflag $name $command
Start-Sleep 2
"what the system's log says of it since: $((Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=$before} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match $name -or $_.Message -match 'Raqib probe 10' } | Group-Object Id | ForEach-Object { "$($_.Count) of event $($_.Name)" }) -join '; ')"
python $probe remove $name
"=== removed"
Start-Sleep 3
Remove-Item -Recurse -Force $place, $pub -ErrorAction SilentlyContinue
"left: $((Get-CimInstance Win32_Service -Filter "Name='$name'" | Measure-Object).Count) service(s), place $(Test-Path $place)"
try { Remove-LocalUser -Name raqibprobe -ErrorAction Stop; "the user removed" } catch { "the user NOT removed: $($_.Exception.Message)" }
exit 0
