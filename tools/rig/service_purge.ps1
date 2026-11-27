# The rig's `raqib service remove --purge` on Windows (ADR-0013 ZE; X56). On GitHub's throwaway Windows machine it
# copies this job's Python under Program Files as an administrator would, one folder deeper, asks Raqib's own
# install from it, waits for the service's first round, and asks `raqib service remove --purge`: the service and
# its record - the place, Raqib under ProgramData - are to be gone. Then, with nothing installed, it makes a folder
# of that name as a shell makes one (ProgramData's own list, a file in it) and asks the same command: the folder
# is not the place as Raqib's service makes it, and is to be left exactly as it is. It keeps what
# tools/rig/check.py reads:
#
#     tools\rig\service_purge.ps1 -Out FOLDER
#
#   FOLDER\service-purge.txt   purge-exit, purge-result, purge-place (the first ask: its exit, its RESULT line,
#                              whether the place is there after it), kept-exit, kept-result, kept-place, kept-file
#                              (the second: and whether the folder and its file are there after it), one
#                              `key: value` a line
#   FOLDER\purge.txt, FOLDER\kept.txt   what each ask said, for a person
#
# Then it removes the folder it made and the copy. It judges nothing: a step that fails leaves a key unwritten or
# with what it read, and the check says X56 MISSED with the words of what is missing. It ends no process.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$place = Join-Path $env:ProgramData "Raqib"
$own = (Get-Command python).Source
$holder = Join-Path $env:ProgramFiles "RaqibRigPurge"   # N-1: the interpreter two folders below Program Files
$copy = Join-Path $holder "Py\python.exe"
function Asked($keep) {   # (the exit, the RESULT line) of `raqib service remove --purge`, users' SIDs masked
  $said = @(& $copy -I -m raqib service remove --purge 2>&1 | ForEach-Object { "$_" -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" })
  $code = $LASTEXITCODE
  $said | Set-Content -Encoding ascii (Join-Path $Out $keep)
  $said | ForEach-Object { "  $_" } | Out-Host
  @{ exit = $code; result = "$($said | Where-Object { $_ -like 'RESULT:*' } | Select-Object -Last 1)" }
}
New-Item -ItemType Directory -Force $Out, $holder | Out-Null
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
Copy-Item (Split-Path $own) (Join-Path $holder "Py") -Recurse
$lines = @()
& $copy -I -m raqib service install | Out-Null
$t = Get-Date
while (((Get-Date) - $t).TotalSeconds -lt 90 -and -not (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue)) { Start-Sleep -Milliseconds 500 }
"installed; a round read: $([bool](Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue))"
$a = Asked "purge.txt"
$lines += "purge-exit: $($a.exit)", "purge-result: $($a.result)", "purge-place: $(Test-Path $place)"
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
New-Item -ItemType Directory $place | Out-Null
Set-Content "$place\a-file.txt" "x"
$a = Asked "kept.txt"
$lines += "kept-exit: $($a.exit)", "kept-result: $($a.result)", "kept-place: $(Test-Path $place)", "kept-file: $(Test-Path "$place\a-file.txt")"
$lines | Set-Content -Encoding ascii (Join-Path $Out "service-purge.txt")
Remove-Item -Recurse -Force $place, $holder -ErrorAction SilentlyContinue
"removed: the folder $(-not (Test-Path $place)), the copy $(-not (Test-Path $holder)), the service $(-not (Get-CimInstance Win32_Service -Filter "Name='RaqibWatch'"))"
exit 0
