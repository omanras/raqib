# Probe only (never merged): the eleventh measurement - what `raqib service check` says asked by the system's own
# account (a task of the scheduler run as SYSTEM once, then removed) of the same trees it is asked of as the job's
# user (ADR-0013 N-2, Q, R: the check is a reading of the session that asks), and whether the runner of 0.13.0
# serves from a copy under Program Files (packed, and a plain Python with -I). It makes one folder under Program
# Files, one under ProgramData, one task, one letter and one service of its own, and removes them. The check
# itself changes nothing.
param([string]$PackedDir)
$ErrorActionPreference = "Continue"
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Flat($lines) { Mask ((($lines -join " ") -replace "\s+", " ").Trim()) }
$hold = "C:\Program Files\RaqibFieldSys"
$work = "C:\ProgramData\RaqibFieldSys"
$task = "RaqibFieldSys"
New-Item -ItemType Directory -Force $hold, $work | Out-Null
Copy-Item $PackedDir "$hold\packed" -Recurse
$own = (Get-Command python).Source
Copy-Item (Split-Path $own) "$hold\Py" -Recurse
function AsUser($label, $line) {
  $t = Get-Date
  $said = cmd /c "$line 2>&1"
  "{0} | the job's user: exit {1} in {2:n1} s; {3}" -f $label, $LASTEXITCODE, ((Get-Date) - $t).TotalSeconds, (Flat $said)
}
function AsSystem($label, $line) {
  $out = "$work\out.txt"
  Remove-Item -Force $out -ErrorAction SilentlyContinue
  @("@echo off", "whoami > `"$out`"", "echo began %time% >> `"$out`"", "$line >> `"$out`" 2>&1", "echo exit %errorlevel% at %time% >> `"$out`"") |
    Set-Content -Encoding ascii "$work\ask.cmd"
  schtasks /Create /TN $task /TR "$work\ask.cmd" /SC ONCE /ST 23:59 /RU SYSTEM /F | Out-Null
  schtasks /Run /TN $task | Out-Null
  $t = Get-Date
  while (((Get-Date) - $t).TotalSeconds -lt 180) {
    if (Select-String -Path $out -Pattern "^exit " -Quiet -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Milliseconds 500
  }
  $said = Get-Content $out -ErrorAction SilentlyContinue
  "{0} | the system: {1}" -f $label, (Flat $said)
  schtasks /Delete /TN $task /F | Out-Null
}
function Both($label, $line) { AsUser $label $line; AsSystem $label $line }
"=== the same question, by the job's user and by the system"
Both "the packed copy under Program Files" "`"$hold\packed\raqib.exe`" service check"
Both "a Python copied under Program Files, one folder deeper, with -I" "`"$hold\Py\python.exe`" -I -m raqib service check"
Both "the job's own Python with -I" "`"$own`" -I -m raqib service check"
Both "the job's own packed folder" "`"$PackedDir\raqib.exe`" service check"
"=== a letter the job's session gave to the packed copy's folder: what the system sees of it"
subst R: "$hold\packed"
Both "by R:, given by the job's session" "R:\raqib.exe service check"
AsSystem "is R:\ there for the system" "if exist R:\ (echo R: is there) else (echo R: is not there)"
subst R: /D | Out-Null
"=== the runner of this version as a service from each copy (made, started, read, stopped, removed)"
$place = Join-Path $env:ProgramData "Raqib"
function Serve($label, $bin) {
  $name = "RaqibFieldSys"
  if (Test-Path $place) { Remove-Item -Recurse -Force $place }
  New-Service -Name $name -BinaryPathName $bin -StartupType Manual | Out-Null
  $why = ""
  try { Start-Service $name -ErrorAction Stop } catch { $why = $_.Exception.Message }
  $t = Get-Date
  while (((Get-Date) - $t).TotalSeconds -lt 60) {
    if (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Milliseconds 500
  }
  $s = Get-CimInstance Win32_Service -Filter "Name='$name'"
  "{0}: state {1}, exit {2}, its own {3}, a round read after {4:n0} s; start said: {5}" -f $label, $s.State, $s.ExitCode, $s.ServiceSpecificExitCode, ((Get-Date) - $t).TotalSeconds, (Flat $why)
  "its text file's first lines: $(Flat (Get-Content "$place\service.txt" -TotalCount 6 -ErrorAction SilentlyContinue))"
  try { Stop-Service $name -ErrorAction Stop } catch { "the stop: $(Flat $_.Exception.Message)" }
  sc.exe delete $name | Out-Null
  Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
  "removed: the service $(-not (Get-CimInstance Win32_Service -Filter "Name='$name'")), its place $(-not (Test-Path $place))"
}
Serve "from the packed copy" "`"$hold\packed\raqib.exe`" service run"
Serve "from the Python copied under Program Files, with -I" "`"$hold\Py\python.exe`" -I -m raqib service run"
"=== removed"
Remove-Item -Recurse -Force $hold, $work -ErrorAction SilentlyContinue
"left: $(Test-Path $hold), $(Test-Path $work), $(Test-Path 'R:\')"
exit 0
