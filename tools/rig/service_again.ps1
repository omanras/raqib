# The rig's service of Windows, ended from outside (ADR-0013 AH-3, AI-5; X48). On GitHub's throwaway Windows
# machine it makes the service RaqibWatch from a copy of this job's Python, Raqib in it, that it puts under Program
# Files as an administrator would, one folder deeper (`python -I -m raqib service run`; ADR-0013 T-3: the service
# asks the check of its own code at every start, and the job's own Python is a tree a user may write),
# tells the system to start it again 5 s after an end that was not a Stop, ends its process once, waits for the
# service to read a round again, and keeps what tools/rig/check.py reads:
#
#     tools\rig\service_again.ps1 -Out FOLDER
#
#   FOLDER\service-run.txt        killed-pid, again-pid, again-seconds, state (one `key: value` a line)
#   FOLDER\service-events.jsonl   the place's events file, both runs in it
#   FOLDER\service.txt, service.before.txt   the two runs' own text, for a person
#
# Then it stops the service, removes it and removes its place (C:\ProgramData\Raqib) and the copy. It judges
# nothing: a step that fails leaves a file unwritten, and the check says X48 MISSED with the words of what is
# missing. It ends no process but the service's own, which it made.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$name = "RaqibWatch"
$place = Join-Path $env:ProgramData "Raqib"
$holder = Join-Path $env:ProgramFiles "RaqibRigService"   # N-1: the interpreter two folders below Program Files
$py = Join-Path $holder "Py\python.exe"
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }
New-Item -ItemType Directory -Force $Out, $holder | Out-Null
Copy-Item (Split-Path (Get-Command python).Source) (Join-Path $holder "Py") -Recurse
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
Remove-Item -Recurse -Force $place, $holder -ErrorAction SilentlyContinue
"removed: the service $(-not (Svc)), its place $(-not (Test-Path $place)), the copy $(-not (Test-Path $holder))"
exit 0
