# The rig's question of `raqib service check` (ADR-0013 K-8; X49). On GitHub's throwaway Windows machine it packs
# the Raqib this job installed into one folder with its own runtime (PyInstaller 6.11.1, installed by the job's
# step, never a dependency of Raqib; the arguments are tools/rig/pack.sh's), copies that folder into Program Files
# as an administrator would, asks each copy whether the code a service would run is the system's alone, and keeps
# what tools/rig/check.py reads:
#
#     tools\rig\service_check.ps1 -Out FOLDER
#
#   FOLDER\service-check.txt   system-exit, system-words (the copy in Program Files), open-exit, open-words (the
#                              copy in the job's own folder); one `key: value` a line
#
# Then it removes the copy in Program Files. It judges nothing: a step that fails leaves a key unwritten, and the
# check says X49 MISSED with the words of what is missing. The check itself changes nothing and starts nothing.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$system = Join-Path $env:ProgramFiles "RaqibRigCheck"
$work = Join-Path $Out "pack"
New-Item -ItemType Directory -Force $work | Out-Null
$kept = Join-Path $Out "service-check.txt"
Set-Content -Encoding ascii $kept ""
Push-Location $work
"import sys`nfrom raqib.cli import main`nsys.exit(main())" | Set-Content -Encoding ascii entry.py
python -m PyInstaller --noconfirm --onedir --name raqib --collect-all raqib --exclude-module tkinter --log-level WARN --distpath "$work\dist" --workpath "$work\build" --specpath $work entry.py 2>&1 | Select-Object -Last 3
Pop-Location
$open = Join-Path $work "dist\raqib"
if (-not (Test-Path "$open\raqib.exe")) { "no packed program at $open\raqib.exe: nothing asked"; exit 0 }
if (Test-Path $system) { Remove-Item -Recurse -Force $system }
Copy-Item $open $system -Recurse
function Ask($label, $exe) {
  $said = & $exe service check 2>&1 | ForEach-Object { "$_" }
  $code = $LASTEXITCODE
  $words = (($said -join " ") -replace "\s+", " ").Trim()
  Add-Content -Encoding ascii $kept "$label-exit: $code"
  Add-Content -Encoding ascii $kept "$label-words: $words"
  "${label}: exit $code; $words"
}
Ask "system" "$system\raqib.exe"
Ask "open" "$open\raqib.exe"
Remove-Item -Recurse -Force $system -ErrorAction SilentlyContinue
"the copy in Program Files left: $(Test-Path $system)"
exit 0
