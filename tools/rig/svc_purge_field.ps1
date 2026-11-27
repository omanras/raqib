# Probe only (never merged): the nineteenth measurement - the place of Raqib's Windows service after
# `raqib service remove`, on real Windows: what an administrator reads of it and whether an administrator's
# process removes it; and what the runner's own reader says of a name there that is not the service's place - a
# folder an administrator's shell made, and a link to another folder (the link alone removed afterwards, its
# target left and checked). It makes one folder under Program Files, one service by Raqib's own install, and names
# under ProgramData\Raqib, and removes them all. It ends no process.
$ErrorActionPreference = "Continue"
function Flat($lines) { ((($lines -join " ") -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>") -replace "\s+", " ").Trim() }
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
$place = Join-Path $env:ProgramData "Raqib"
$hold = "C:\Program Files\RaqibFieldPurge"
$py = "$hold\Py\python.exe"
$tool = "$env:GITHUB_WORKSPACE\tools\rig\svc_purge_field.py"
New-Item -ItemType Directory -Force $hold | Out-Null
Copy-Item (Split-Path (Get-Command python).Source) "$hold\Py" -Recurse
"=== the service installed by Raqib's own install, watched a round, removed by Raqib's own remove"
"install: exit " + $(& $py -I -m raqib service install | Out-Null; $LASTEXITCODE)
$t = Get-Date
while (((Get-Date) - $t).TotalSeconds -lt 90 -and -not (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue)) { Start-Sleep -Milliseconds 500 }
"a round was read after $([int]((Get-Date) - $t).TotalSeconds) s: " + [bool](Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue)
$said = & $py -I -m raqib service remove 2>&1
"remove: exit $LASTEXITCODE; " + (Cut (Flat ($said | Select-String "RESULT|record")) 400)
"=== the place after the remove, as this administrator reads it"
& $py -I $tool read $place
"=== removed by this administrator's process"
& $py -I $tool remove $place
"=== a folder of that name made by this administrator's shell, as the runner's reader says it"
New-Item -ItemType Directory $place | Out-Null
Set-Content "$place\a-file.txt" "x"
& $py -I $tool read $place
Remove-Item -Recurse -Force $place
"=== a link of that name to another folder, as the runner's reader says it"
$target = Join-Path $env:RUNNER_TEMP "raqib_purge_target"
New-Item -ItemType Directory -Force $target | Out-Null
Set-Content "$target\kept.txt" "kept"
cmd /c mklink /J "$place" "$target" | Out-Null
& $py -I $tool read $place
cmd /c rmdir "$place"
"the link removed: $(-not (Test-Path $place)); its target's file still there: $(Test-Path "$target\kept.txt")"
Remove-Item -Recurse -Force $target
"=== removed"
Remove-Item -Recurse -Force $hold -ErrorAction SilentlyContinue
"left: the copy $(Test-Path $hold), the place $(Test-Path $place), the service $([bool](Get-CimInstance Win32_Service -Filter "Name='RaqibWatch'"))"
exit 0
