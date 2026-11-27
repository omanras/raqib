# The rig's question of `raqib service check` through a letter given to a folder (ADR-0013 P-3; X51). On GitHub's
# throwaway Windows machine it copies the packed Raqib tools\rig\service_check.ps1 made into Program Files, gives a
# free letter to that folder (subst), asks the copy through the letter whether the code a service would run is the
# system's alone, and keeps what tools/rig/check.py reads:
#
#     tools\rig\service_check_drive.ps1 -Packed FOLDER -Out FOLDER
#
#   FOLDER\service-check-drive.txt   letter-exit, letter-words; one `key: value` a line
#
# Then it takes the letter back and removes the copy. It judges nothing: a step that fails leaves a key unwritten,
# and the check says X51 MISSED with the words of what is missing. The check itself changes nothing.
param([Parameter(Mandatory = $true)][string]$Packed, [Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$system = Join-Path $env:ProgramFiles "RaqibRigDrive"
New-Item -ItemType Directory -Force $Out | Out-Null
$kept = Join-Path $Out "service-check-drive.txt"
Set-Content -Encoding ascii $kept ""
if (-not (Test-Path "$Packed\raqib.exe")) { "no packed program at $Packed\raqib.exe: nothing asked"; exit 0 }
$letter = "R", "S", "T", "U", "V", "W" | Where-Object { -not (Test-Path "${_}:\") } | Select-Object -First 1
if (-not $letter) { "no free letter: nothing asked"; exit 0 }
if (Test-Path $system) { Remove-Item -Recurse -Force $system }
Copy-Item $Packed $system -Recurse
subst "${letter}:" $system
if (-not (Test-Path "${letter}:\raqib.exe")) { "the letter ${letter}: was not given to the folder: nothing asked" } else {
  $said = & "${letter}:\raqib.exe" service check 2>&1 | ForEach-Object { "$_" }
  $code = $LASTEXITCODE
  $words = (($said -join " ") -replace "\s+", " ").Trim()
  Add-Content -Encoding ascii $kept "letter-exit: $code"
  Add-Content -Encoding ascii $kept "letter-words: $words"
  "through ${letter}: exit $code; $words"
}
subst "${letter}:" /D | Out-Null
Remove-Item -Recurse -Force $system -ErrorAction SilentlyContinue
"the letter left: $(Test-Path "${letter}:\"); the copy in Program Files left: $(Test-Path $system)"
exit 0
