# Probe only (never merged): the field's word for ADR-0013 Amendment H - a branch's `raqib service run` as a real
# service of Windows, its process ended from outside, the system told to start it again. It makes one service and
# its place, reads what they did, and removes both. The same steps the rig's job will keep for X48.
$ErrorActionPreference = "Continue"
$py = (Get-Command python).Source
$place = "C:\ProgramData\Raqib"
$name = "RaqibWatch"
$out = "$env:RUNNER_TEMP\service-run.txt"
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
New-Service -Name $name -BinaryPathName "`"$py`" -I -m raqib service run" -StartupType Manual | Out-Null
sc.exe failure $name reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Select-Object -First 1
Start-Service $name
Start-Sleep 14
$killed = (Svc).ProcessId
"before: state $((Svc).State), pid $killed"
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
"after: state $state, pid $again, $seconds s after its process was ended (its first round read)"
@("killed-pid: $killed", "again-pid: $again", "again-seconds: $seconds", "state: $state") | Set-Content -Encoding ascii $out
Start-Sleep 8
"--- the text of the service started again (service.txt):"
Get-Content "$place\service.txt" -ErrorAction SilentlyContinue | Select-String -Pattern "raqib service run:|hole:|watch-unended|ended without its end|round \d+: \d+ records" | Select-Object -First 10 | ForEach-Object { "    " + (Cut $_.Line 330) }
"--- the text of the one that was ended (service.before.txt), its last lines:"
Get-Content "$place\service.before.txt" -ErrorAction SilentlyContinue | Select-Object -Last 3 | ForEach-Object { "    " + (Cut $_ 200) }
$t = Get-Date
try { Stop-Service $name -ErrorAction Stop; "stop: ok in {0:n2} s" -f ((Get-Date) - $t).TotalSeconds } catch { "stop: FAILED: $(Cut $_.Exception.Message 150)" }
"state $((Svc).State); exit $((Svc).ExitCode); the service's own exit $((Svc).ServiceSpecificExitCode)"
Copy-Item "$place\.raqib\host\events.jsonl" "$env:RUNNER_TEMP\service-events.jsonl" -ErrorAction SilentlyContinue
"--- raqib's own reading of the place's events:"
& python -I -m raqib events "$env:RUNNER_TEMP\service-events.jsonl" 2>&1 | Select-Object -First 12 | ForEach-Object { "    " + (Cut "$_" 220) }
"--- the system's own log:"
Get-WinEvent -FilterHashtable @{LogName = "System"; ProviderName = "Service Control Manager"} -MaxEvents 12 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match $name } | Select-Object -First 5 | ForEach-Object { "    event {0}: {1}" -f $_.Id, (Cut ($_.Message -replace "\s+", " ") 190) }
"--- the rig's own check of what was kept (X48):"
$code = @"
import sys
sys.path.insert(0, r'$env:GITHUB_WORKSPACE\tools\rig')
import check
run = open(r'$out', encoding='ascii').read()
events = open(r'$env:RUNNER_TEMP\service-events.jsonl', encoding='utf-8').read()
for row in check.read_service_again(run, events):
    print(row[1], row[0][:60], '::', str(row[2])[:400])
"@
$code | python -I -
"=== started once more after a clean stop: no such hole"
Start-Service $name; Start-Sleep 8; Stop-Service $name
"holes of the kind in the events now: $((Select-String -Path "$place\.raqib\host\events.jsonl" -Pattern 'watch-unended').Count) (one, from the run after the ended one)"
sc.exe delete $name | Select-Object -First 1
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
"the place removed: $(-not (Test-Path $place))"
exit 0
