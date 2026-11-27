# The rig's service of Windows, made from two trees (ADR-0013 T-1, T-3; X52). On GitHub's throwaway Windows
# machine it makes a service that runs `python -I -m raqib service run` twice: once from this job's own Python, a
# tree a user may write, and once from a copy of it that it puts under Program Files as an administrator would,
# one folder deeper. The runner asks the check of its own code at every start: the first is to fail to start with
# the service's own number 15 and say in its text file what was refused; the second is to run with the pass in its
# text file. It keeps what tools/rig/check.py reads:
#
#     tools\rig\service_refused.ps1 -Out FOLDER
#
#   FOLDER\service-refused.txt   refused-exit, refused-own, refused-text (the first service: the exit the system
#                                gives, its own number, the runner's line of the check in its text file),
#                                taken-state, taken-text (the second), one `key: value` a line
#   FOLDER\refused.service.txt, FOLDER\taken.service.txt   the two text files, for a person
#
# Then it stops the second service, removes both, their place (C:\ProgramData\Raqib) and the copy. It judges
# nothing: a step that fails leaves a key unwritten or with what it read, and the check says X52 MISSED with the
# words of what is missing. It ends no process.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$name = "RaqibWatchAsked"
$place = Join-Path $env:ProgramData "Raqib"
$own = (Get-Command python).Source
$holder = Join-Path $env:ProgramFiles "RaqibRigAsked"   # N-1: the interpreter two folders below Program Files
$copy = Join-Path $holder "Py\python.exe"
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }
function Line {   # the runner's one line of the check, user SIDs masked, on one line
  $l = Get-Content "$place\service.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "its own code, checked at this start" } | Select-Object -First 1
  ((("$l" -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>") -replace "\s+", " ").Trim())
}
function Made($python, $keep) {
  if (Test-Path $place) { Remove-Item -Recurse -Force $place }
  New-Service -Name $name -BinaryPathName "`"$python`" -I -m raqib service run" -StartupType Manual | Out-Null
  try { Start-Service $name -ErrorAction Stop; "the start was taken" } catch { "the start failed, as the system says it: $($_.Exception.Message)" }
  $t = Get-Date
  while (((Get-Date) - $t).TotalSeconds -lt 60) {   # a round read, or stopped
    if ((Svc).State -eq "Stopped") { break }
    if (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Milliseconds 500
  }
  Copy-Item "$place\service.txt" (Join-Path $Out $keep) -ErrorAction SilentlyContinue
}
function Unmade {
  if ((Svc).State -ne "Stopped") { try { Stop-Service $name -ErrorAction Stop } catch { "the stop failed: $($_.Exception.Message)" } }
  sc.exe delete $name | Out-Null
  Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force $Out, $holder | Out-Null
Copy-Item (Split-Path $own) (Join-Path $holder "Py") -Recurse
$lines = @()
Made $own "refused.service.txt"
$s = Svc
"from the job's own Python: state $($s.State), exit $($s.ExitCode), its own $($s.ServiceSpecificExitCode)"
$lines += "refused-exit: $($s.ExitCode)", "refused-own: $($s.ServiceSpecificExitCode)", "refused-text: $(Line)"
Unmade
Made $copy "taken.service.txt"
$s = Svc
"from the copy under Program Files: state $($s.State), exit $($s.ExitCode)"
$lines += "taken-state: $($s.State)", "taken-text: $(Line)"
Unmade
$lines | Set-Content -Encoding ascii (Join-Path $Out "service-refused.txt")
Remove-Item -Recurse -Force $holder -ErrorAction SilentlyContinue
"removed: the service $(-not (Svc)), its place $(-not (Test-Path $place)), the copy $(-not (Test-Path $holder))"
exit 0
