# The rig's question of `raqib service check` for a plain interpreter (ADR-0013 M-6, N-5; X50). On GitHub's
# throwaway Windows machine it copies the Python this job runs, the Raqib the job installed in it, into a folder
# of its own under Program Files as an administrator would (two folders below Program Files: ADR-0013 N-1), asks
# the copy and the job's own Python - each started with -I, as a service would run it - whether the code a service
# would run is the system's alone, and keeps what tools/rig/check.py reads:
#
#     tools\rig\service_check_plain.ps1 -Out FOLDER
#
#   FOLDER\service-check-plain.txt   system-exit, system-words (the copy in Program Files), open-exit, open-words
#                                    (the job's own Python); one `key: value` a line
#
# Then it removes the copy. It judges nothing: a step that fails leaves a key unwritten, and the check says X50
# MISSED with the words of what is missing. The check itself changes nothing and starts nothing.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$holder = Join-Path $env:ProgramFiles "RaqibRig"   # N-1: the interpreter two folders below Program Files, not one
$system = Join-Path $holder "Py"
New-Item -ItemType Directory -Force $Out | Out-Null
$kept = Join-Path $Out "service-check-plain.txt"
Set-Content -Encoding ascii $kept ""
$own = (Get-Command python).Source
if (Test-Path $holder) { Remove-Item -Recurse -Force $holder }
New-Item -ItemType Directory -Force $holder | Out-Null
Copy-Item (Split-Path $own) $system -Recurse
if (-not (Test-Path "$system\python.exe")) { "no interpreter at $system\python.exe: nothing asked"; exit 0 }
function Ask($label, $exe) {
  $said = & $exe -I -m raqib service check 2>&1 | ForEach-Object { "$_" }
  $code = $LASTEXITCODE
  $words = (($said -join " ") -replace "\s+", " ").Trim()
  Add-Content -Encoding ascii $kept "$label-exit: $code"
  Add-Content -Encoding ascii $kept "$label-words: $words"
  "${label}: exit $code; $words"
}
Ask "system" "$system\python.exe"
Ask "open" $own
Remove-Item -Recurse -Force $holder -ErrorAction SilentlyContinue
"the copy in Program Files left: $(Test-Path $holder)"
exit 0
