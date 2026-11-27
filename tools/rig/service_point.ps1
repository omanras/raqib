# The rig's service of Windows, started over a long check (ADR-0013 ZB; X55). On GitHub's throwaway Windows
# machine it copies this job's Python under Program Files as an administrator would, one folder deeper, adds
# 150000 empty files to the copy so that the check of its own code walks for several seconds, and makes a service
# that runs `python -I -m raqib service run` from it. It starts the service twice: once by the system's own call,
# asking the system every 200 ms what it says of the service while it starts (the highest check-point read); and
# once by `net start`, a command that waits for the start by the check-point. It keeps what tools/rig/check.py
# reads:
#
#     tools\rig\service_point.ps1 -Out FOLDER
#
#   FOLDER\service-point.txt   names-added, point-highest, point-wait (the wait the system said with it),
#                              point-state, point-text (the first start: the highest check-point read while it
#                              started, the state after, the runner's line of the check in its text file),
#                              net-exit, net-seconds, net-state, net-text (the second), one `key: value` a line
#   FOLDER\point.service.txt, FOLDER\net.service.txt   the two text files, for a person
#
# Then it stops the service, removes it, its place (C:\ProgramData\Raqib) and the copy. It judges nothing: a step
# that fails leaves a key unwritten or with what it read, and the check says X55 MISSED with the words of what is
# missing. It ends no process.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$name = "RaqibWatchPoint"
$place = Join-Path $env:ProgramData "Raqib"
$own = (Get-Command python).Source
$holder = Join-Path $env:ProgramFiles "RaqibRigPoint"   # N-1: the interpreter two folders below Program Files
$copy = Join-Path $holder "Py\python.exe"
$added = 150000
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }
function Line {   # the runner's one line of the check, user SIDs masked, on one line
  $l = Get-Content "$place\service.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "its own code, checked at this start" } | Select-Object -First 1
  ((("$l" -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>") -replace "\s+", " ").Trim())
}
function Asked {   # what the system says of the service now: its state's number, its check-point, its wait
  $o = ((sc.exe queryex $name) -join " ")
  $m = [regex]::Match($o, "STATE\s+:\s+(\d+).*?CHECKPOINT\s+:\s+0x([0-9a-fA-F]+)\s+WAIT_HINT\s+:\s+0x([0-9a-fA-F]+)")
  if ($m.Success) { @([int]$m.Groups[1].Value, [Convert]::ToInt32($m.Groups[2].Value, 16), [Convert]::ToInt32($m.Groups[3].Value, 16)) } else { @(-1, 0, 0) }
}
function Stopped {
  if ((Svc).State -ne "Stopped") { try { Stop-Service $name -ErrorAction Stop } catch { "the stop failed: $($_.Exception.Message)" } }
  $t = Get-Date
  while (((Get-Date) - $t).TotalSeconds -lt 60 -and (Svc).State -ne "Stopped") { Start-Sleep -Milliseconds 300 }
}
New-Item -ItemType Directory -Force $Out, $holder | Out-Null
Copy-Item (Split-Path $own) (Join-Path $holder "Py") -Recurse
$t = Get-Date
python -c "import os, sys`nroot, n = sys.argv[1], int(sys.argv[2])`nfor i in range(n // 500):`n    d = os.path.join(root, 'd%03d' % i)`n    os.makedirs(d)`n    for j in range(500):`n        open(os.path.join(d, 'f%03d' % j), 'w').close()" (Join-Path $holder "Py\Lib\site-packages\raqib_rig_many") $added
"$added empty files added to the copy in $([int]((Get-Date) - $t).TotalSeconds) s"
$lines = @("names-added: $added")
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
New-Service -Name $name -BinaryPathName "`"$copy`" -I -m raqib service run" -StartupType Manual | Out-Null
# the first start: by the system's own call, which does not wait; the system asked while it starts
sc.exe start $name | Out-Null
$t = Get-Date
$high = 0; $wait = 0; $state = -1
while (((Get-Date) - $t).TotalSeconds -lt 180) {
  $a = Asked
  $state = $a[0]
  if ($state -eq 2 -and $a[1] -gt $high) { $high = $a[1]; $wait = $a[2] }
  if ($state -eq 4 -or $state -eq 1) { break }
  Start-Sleep -Milliseconds 200
}
"started by the system's call: after $([int]((Get-Date) - $t).TotalSeconds) s state $state, the highest check-point read while it started $high (its wait $wait ms)"
$lines += "point-highest: $high", "point-wait: $wait", "point-state: $((Svc).State)", "point-text: $(Line)"
Copy-Item "$place\service.txt" (Join-Path $Out "point.service.txt") -ErrorAction SilentlyContinue
Stopped
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
# the second start: by a command that waits for it
$t = Get-Date
$said = net start $name 2>&1
$code = $LASTEXITCODE
$secs = ((Get-Date) - $t).TotalSeconds.ToString("n1")
"net start: exit $code after $secs s: $((($said -join ' ') -replace '\s+', ' ').Trim())"
$lines += "net-exit: $code", "net-seconds: $secs", "net-state: $((Svc).State)"
$t = Get-Date
while (((Get-Date) - $t).TotalSeconds -lt 120 -and (Svc).State -eq "Start Pending") { Start-Sleep -Milliseconds 500 }   # for its text file's line
$lines += "net-text: $(Line)"
Copy-Item "$place\service.txt" (Join-Path $Out "net.service.txt") -ErrorAction SilentlyContinue
Stopped
sc.exe delete $name | Out-Null
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
$lines | Set-Content -Encoding ascii (Join-Path $Out "service-point.txt")
Remove-Item -Recurse -Force $holder -ErrorAction SilentlyContinue
"removed: the service $(-not (Svc)), its place $(-not (Test-Path $place)), the copy $(-not (Test-Path $holder))"
exit 0
