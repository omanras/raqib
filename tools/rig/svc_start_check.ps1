# Probe only (never merged): the twelfth measurement - a branch's runner asking the check of its own code at its
# start (ADR-0013 Amendment T), on real Windows: a service made from a tree a user may write and from copies
# under Program Files; what the system says while the check walks (state, check-point, wait) and of a Stop sent
# then; a tree made large with empty files (near WALK_MAX, and past it). It makes one folder under Program Files
# and one service of its own at a time, and removes them. It ends no process.
param([string]$PackedDir, [string]$Out)
$ErrorActionPreference = "Continue"
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Flat($lines) { Mask ((($lines -join " ") -replace "\s+", " ").Trim()) }
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
$name = "RaqibFieldStart"
$place = Join-Path $env:ProgramData "Raqib"
$hold = "C:\Program Files\RaqibFieldStart"
$own = (Get-Command python).Source
New-Item -ItemType Directory -Force $hold, $Out | Out-Null
Copy-Item $PackedDir "$hold\packed" -Recurse
Copy-Item (Split-Path $own) "$hold\Py" -Recurse
function Q {
  $o = (sc.exe queryex $name) -join " "
  $m = [regex]::Match($o, "STATE\s+:\s+(\d+)\s+(\w+).*?WIN32_EXIT_CODE\s+:\s+(\d+).*?SERVICE_EXIT_CODE\s+:\s+(-?\d+).*?CHECKPOINT\s+:\s+(\S+)\s+WAIT_HINT\s+:\s+(\S+)")
  if ($m.Success) { "state {0} {1}, exit {2}, its own {3}, check-point {4}, wait {5}" -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value, $m.Groups[4].Value, $m.Groups[5].Value }
  else { "not read: $(Cut (Flat $o) 200)" }
}
function Serve($label, $bin, $stopDuring) {
  "--- $label"
  if (Test-Path $place) { Remove-Item -Recurse -Force $place }
  New-Service -Name $name -BinaryPathName $bin -StartupType Manual | Out-Null
  $t = Get-Date
  $said = sc.exe start $name
  "sc start returned after {0:n1} s: {1}" -f ((Get-Date) - $t).TotalSeconds, (Cut (Flat ($said | Select-String "STATE|FAILED|CHECKPOINT|WAIT_HINT|EXIT_CODE|\d+:")) 400)
  $last = ""; $stopped = $false
  while (((Get-Date) - $t).TotalSeconds -lt 150) {
    $q = Q
    if ($q -ne $last) { "{0,6:n1} s: {1}" -f ((Get-Date) - $t).TotalSeconds, $q; $last = $q }
    if ($stopDuring -and -not $stopped -and $q -match "^state 2 ") {
      $stopped = $true
      "{0,6:n1} s: a Stop sent while it starts: {1}" -f ((Get-Date) - $t).TotalSeconds, (Cut (Flat (sc.exe stop $name)) 300)
    }
    if ($q -match "^state 1 ") { break }
    if ($q -match "^state 4 " -and (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 200
  }
  $s = Get-CimInstance Win32_Service -Filter "Name='$name'"
  $text = Get-Content "$place\service.txt" -ErrorAction SilentlyContinue
  $line = $text | Where-Object { $_ -match "its own code" } | Select-Object -First 1
  "ended reading after {0:n1} s: state {1}, exit {2}, its own {3}" -f ((Get-Date) - $t).TotalSeconds, $s.State, $s.ExitCode, $s.ServiceSpecificExitCode
  "the check's line in its text file: $(Cut (Flat $line) 900)"
  "its text file has $(@($text).Count) lines; the watch began: $([bool]($text | Where-Object { $_ -match 'raqib watch --host: the host' }))"
  $events = Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Service Control Manager"; StartTime = $t } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $name } | ForEach-Object { "$($_.Id): $(Cut (Flat $_.Message) 260)" }
  "the system's log: $(if ($events) { $events -join ' || ' } else { 'no line of this service' })"
  if ($s.State -ne "Stopped") {
    $t2 = Get-Date
    "a Stop when it runs: $(Cut (Flat (sc.exe stop $name | Select-String 'STATE|FAILED|\d+:')) 200)"
    while (((Get-Date) - $t2).TotalSeconds -lt 40 -and (Q) -notmatch "^state 1 ") { Start-Sleep -Milliseconds 300 }
    "after the Stop ({0:n1} s): {1}; its last line: {2}" -f ((Get-Date) - $t2).TotalSeconds, (Q), (Cut (Flat (Get-Content "$place\service.txt" -Tail 1 -ErrorAction SilentlyContinue)) 300)
  }
  $got = @{ state = $s.State; exit = $s.ExitCode; own = $s.ServiceSpecificExitCode; line = (Flat $line) }
  sc.exe delete $name | Out-Null
  Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
  "removed: the service $(-not (Get-CimInstance Win32_Service -Filter "Name='$name'")), its place $(-not (Test-Path $place))"
  $got
}
function Show($r) { $r | Where-Object { $_ -is [string] }; $r | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1 | Set-Variable -Name got -Scope Script }
"=== a service from each tree"
Show (Serve "from the job's own Python with -I (a tree a user may write)" "`"$own`" -I -m raqib service run" $false)
$refused = $script:got
Show (Serve "from the job's own packed folder" "`"$PackedDir\raqib.exe`" service run" $false)
Show (Serve "from the Python copied under Program Files, without -I" "`"$hold\Py\python.exe`" -m raqib service run" $false)
Show (Serve "from the packed copy under Program Files" "`"$hold\packed\raqib.exe`" service run" $false)
Show (Serve "from the Python copied under Program Files, with -I" "`"$hold\Py\python.exe`" -I -m raqib service run" $false)
$taken = $script:got
"=== what X52 reads of the first and the last"
@("refused-exit: $($refused.exit)", "refused-own: $($refused.own)", "refused-text: $($refused.line)", "taken-state: $($taken.state)", "taken-text: $($taken.line)") |
  Set-Content -Encoding ascii (Join-Path $Out "service-refused.txt")
python tools\rig\check.py --service-refused (Join-Path $Out "service-refused.txt") 2>&1 | Select-String "X52" | ForEach-Object { Cut (Mask "$_") 700 }
"=== the copied Python made large with empty files an administrator adds (150000 in 300 folders): the check near WALK_MAX"
$many = "$hold\Py\Lib\site-packages\raqib_field_many"
$t = Get-Date
python -c "import os, sys`nroot = sys.argv[1]`nfor i in range(int(sys.argv[2]), int(sys.argv[3])):`n    d = os.path.join(root, 'd%03d' % i)`n    os.makedirs(d)`n    for j in range(500):`n        open(os.path.join(d, 'f%03d' % j), 'w').close()" $many 0 300
"made in {0:n0} s" -f ((Get-Date) - $t).TotalSeconds
$t = Get-Date
$said = & "$hold\Py\python.exe" -I -m raqib service check 2>&1 | ForEach-Object { "$_" }
"asked by the job's user: exit {0} in {1:n1} s; {2}" -f $LASTEXITCODE, ((Get-Date) - $t).TotalSeconds, (Cut (Flat $said) 260)
Show (Serve "the large tree as a service, a Stop sent while it starts" "`"$hold\Py\python.exe`" -I -m raqib service run" $true)
Show (Serve "the large tree as a service, left to start" "`"$hold\Py\python.exe`" -I -m raqib service run" $false)
"=== 45000 more (past WALK_MAX)"
python -c "import os, sys`nroot = sys.argv[1]`nfor i in range(int(sys.argv[2]), int(sys.argv[3])):`n    d = os.path.join(root, 'd%03d' % i)`n    os.makedirs(d)`n    for j in range(500):`n        open(os.path.join(d, 'f%03d' % j), 'w').close()" $many 300 390
Show (Serve "the tree past WALK_MAX as a service" "`"$hold\Py\python.exe`" -I -m raqib service run" $false)
"=== removed"
Remove-Item -Recurse -Force $hold -ErrorAction SilentlyContinue
"left: $(Test-Path $hold)"
exit 0
