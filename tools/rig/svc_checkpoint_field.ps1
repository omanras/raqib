# Probe only (never merged): the seventeenth measurement - a command that waits for a start, against a service
# whose check of its own code walks a tree made large with empty files: Raqib as it is (the check-point stays 0),
# and a candidate that raises its check-point every 2 s while the check walks (ADR-0013 U-4). What the system
# says of the service through the walk, and what Start-Service and net start say and when. It makes one folder
# under Program Files and one service of its own at a time, and removes them. It ends no process.
# Asked a third time of the builder's branch after the review's fixes (ADR-0013 ZC).
# Asked a fourth time, of the commit to be merged (ADR-0013 ZD); it prints the runner's own line of its raisings too.
$ErrorActionPreference = "Continue"
function Flat($lines) { ((($lines -join " ") -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>") -replace "\s+", " ").Trim() }
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
$name = "RaqibFieldPoint"
$place = Join-Path $env:ProgramData "Raqib"
$hold = "C:\Program Files\RaqibFieldPoint"
$py = "$hold\Py\python.exe"
New-Item -ItemType Directory -Force $hold | Out-Null
Copy-Item (Split-Path (Get-Command python).Source) "$hold\Py" -Recurse
$t = Get-Date
python -c "import os, sys`nroot = sys.argv[1]`nfor i in range(300):`n    d = os.path.join(root, 'd%03d' % i)`n    os.makedirs(d)`n    for j in range(500):`n        open(os.path.join(d, 'f%03d' % j), 'w').close()" "$hold\Py\Lib\site-packages\raqib_field_many"
"150000 empty files made in $([int]((Get-Date) - $t).TotalSeconds) s"
function Q {
  $o = Flat (sc.exe queryex $name)
  $m = [regex]::Match($o, "STATE\s+:\s+(\d+)\s+(\w+).*?WIN32_EXIT_CODE\s+:\s+(\d+).*?SERVICE_EXIT_CODE\s+:\s+(\d+).*?CHECKPOINT\s+:\s+(\S+)\s+WAIT_HINT\s+:\s+(\S+)")
  if ($m.Success) {
    $g = $m.Groups
    "state " + $g[1].Value + " " + $g[2].Value + ", exit " + $g[3].Value + ", its own " + $g[4].Value + ", check-point " + $g[5].Value + ", wait " + $g[6].Value
  } else { "not read: " + (Cut $o 200) }
}
function Secs($t) { ((Get-Date) - $t).TotalSeconds.ToString("n1") }
function Make { if (Test-Path $place) { Remove-Item -Recurse -Force $place }; New-Service -Name $name -BinaryPathName "`"$py`" -I -m raqib service run" -StartupType Manual | Out-Null }
function Unmake {
  $q = Q
  if ($q -notmatch "^state 1 ") { "a Stop at the end: " + (Cut (Flat (sc.exe stop $name | Select-String "STATE|FAILED|\d+:")) 200); $t = Get-Date; while (((Get-Date) - $t).TotalSeconds -lt 60 -and (Q) -notmatch "^state 1 ") { Start-Sleep -Milliseconds 300 } }
  "at the end: " + (Q) + "; its text file's last line: " + (Cut (Flat (Get-Content "$place\service.txt" -Tail 1 -ErrorAction SilentlyContinue)) 300)
  "the raisings' line: " + (Cut (Flat (Get-Content "$place\service.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "check-point" })) 400)
  "the check's line: " + (Cut (Flat (Get-Content "$place\service.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "its own code" } | Select-Object -First 1)) 240)
  sc.exe delete $name | Out-Null
  Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
  "removed: the service $(-not (Get-CimInstance Win32_Service -Filter "Name='$name'")), its place $(-not (Test-Path $place))"
}
"=== started by the system's own call: what the system says while the check walks"
Make
$t = Get-Date
"sc start said: " + (Cut (Flat (sc.exe start $name | Select-String "STATE|FAILED|CHECKPOINT|WAIT_HINT|\d+:")) 300)
$last = ""; $seen = 0
while (((Get-Date) - $t).TotalSeconds -lt 120) {
  $q = Q
  if ($q -ne $last) { $seen += 1; if ($seen -le 8 -or $q -notmatch "^state 2 ") { (Secs $t) + " s: " + $q }; $last = $q }
  if ($q -match "^state 1 ") { break }
  if ($q -match "^state 4 ") { break }
  Start-Sleep -Milliseconds 250
}
"different answers read while it started: $seen; after " + (Secs $t) + " s: " + (Q)
Unmake
"=== started by a command that waits (Start-Service)"
Make
$t = Get-Date
try { Start-Service $name -ErrorAction Stop; "Start-Service returned after " + (Secs $t) + " s: taken; " + (Q) }
catch { "Start-Service returned after " + (Secs $t) + " s: " + (Cut (Flat $_.Exception.Message) 300) + "; " + (Q) }
$t2 = Get-Date
while (((Get-Date) - $t2).TotalSeconds -lt 90 -and (Q) -notmatch "^state [14] ") { Start-Sleep -Milliseconds 500 }
"then, after " + (Secs $t) + " s from the start: " + (Q)
Unmake
"=== started by net start, which waits too"
Make
$t = Get-Date
$said = net start $name 2>&1
"net start returned after " + (Secs $t) + " s with exit $LASTEXITCODE" + ": " + (Cut (Flat $said) 300) + "; " + (Q)
$t2 = Get-Date
while (((Get-Date) - $t2).TotalSeconds -lt 90 -and (Q) -notmatch "^state [14] ") { Start-Sleep -Milliseconds 500 }
"then, after " + (Secs $t) + " s from the start: " + (Q)
Unmake
"=== removed"
Remove-Item -Recurse -Force $hold -ErrorAction SilentlyContinue
"left: $(Test-Path $hold)"
exit 0
