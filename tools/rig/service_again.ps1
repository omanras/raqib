# The rig's service of Windows, ended from outside (ADR-0013 AH-3, AI-5; X48). On GitHub's throwaway Windows
# machine it makes the service RaqibWatch from the Raqib this job installed (`python -I -m raqib service run`),
# tells the system to start it again 5 s after an end that was not a Stop, ends its process once, waits for the
# service to read a round again, and keeps what tools/rig/check.py reads:
#
#     tools\rig\service_again.ps1 -Out FOLDER
#
#   FOLDER\service-run.txt        killed-pid, again-pid, again-seconds, state (one `key: value` a line)
#   FOLDER\service-events.jsonl   the place's events file, both runs in it
#   FOLDER\service.txt, service.before.txt   the two runs' own text, for a person
#
# Then it stops the service, removes it and removes its place (C:\ProgramData\Raqib). It judges nothing: a step
# that fails leaves a file unwritten, and the check says X48 MISSED with the words of what is missing. It ends no
# process but the service's own, which it made.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$name = "RaqibWatch"
$place = Join-Path $env:ProgramData "Raqib"
$py = (Get-Command python).Source
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }
New-Item -ItemType Directory -Force $Out | Out-Null
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
New-Service -Name $name -BinaryPathName "`"$py`" -I -m raqib service run" -StartupType Manual | Out-Null
sc.exe failure $name reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
Start-Service $name
$t = Get-Date
while (((Get-Date) - $t).TotalSeconds -lt 60) {   # its first round read, so that the run has a record to leave
  if (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue) { break }
  Start-Sleep -Milliseconds 500
}
$killed = (Svc).ProcessId
"the service runs: state $((Svc).State), pid $killed"
$t = Get-Date
taskkill /f /pid $killed | Out-Null
$again = 0; $state = ""
while (((Get-Date) - $t).TotalSeconds -lt 120) {
  $s = Svc; $state = $s.State; $again = $s.ProcessId
  if ($state -eq "Running" -and $again -and $again -ne $killed) {
    if (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue) { break }
  }
  Start-Sleep -Milliseconds 500
}
$seconds = [int]((Get-Date) - $t).TotalSeconds
"after its process was ended: state $state, pid $again, a round read again after $seconds s"
@("killed-pid: $killed", "again-pid: $again", "again-seconds: $seconds", "state: $state") | Set-Content -Encoding ascii (Join-Path $Out "service-run.txt")
try { Stop-Service $name -ErrorAction Stop; "stopped" } catch { "the stop failed: $($_.Exception.Message)" }
Copy-Item "$place\.raqib\host\events.jsonl" (Join-Path $Out "service-events.jsonl") -ErrorAction SilentlyContinue
Copy-Item "$place\service.txt", "$place\service.before.txt" $Out -ErrorAction SilentlyContinue
sc.exe delete $name | Out-Null
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
"removed: the service $(-not (Svc)), its place $(-not (Test-Path $place))"
exit 0
