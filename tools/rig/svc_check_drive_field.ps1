# Probe only (never merged): the field's word on `raqib service check` and the drive a path is on (ADR-0013
# Amendment P) - what the branch's own reader says of real drives, and what the check says asked through a disk's
# letter, a letter given to a folder, a small disk image with and without access lists, and a letter that is not
# there. It makes one folder under Program Files, one disk image and letters of its own, and removes them.
param([string]$PackedDir)
$ErrorActionPreference = "Continue"
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Ask($label, $exe) {
  $said = & $exe service check 2>&1 | ForEach-Object { "$_" }
  $code = $LASTEXITCODE
  "{0}: exit {1}; {2}" -f $label, $code, (Mask ((($said -join " ") -replace "\s+", " ").Trim()))
}
$read = "import sys; from raqib import winservice; s = winservice.System()`nfor r in sys.argv[1:]:`n    try:`n        print(r, s.read_drive(r))`n    except Exception as e:`n        print(r, type(e).__name__, e.args)"
"=== the branch's reader of a drive, on this machine"
python -c $read "C:\" "D:\" "Q:\"
"=== a packed copy in Program Files, asked by its disk's letter"
$pf = "C:\Program Files\RaqibFieldDrive"
Copy-Item $PackedDir $pf -Recurse
Ask "by C:" "$pf\raqib.exe"
"=== a letter given to that folder"
subst R: $pf
python -c $read "R:\"
Ask "by R: (a letter given to the folder)" "R:\raqib.exe"
subst R: /D | Out-Null
"=== a letter given to Program Files itself, the copy one folder below the letter"
subst R: "C:\Program Files"
Ask "by R: (a letter given to Program Files)" "R:\RaqibFieldDrive\raqib.exe"
subst R: /D | Out-Null
"=== a disk image, with access lists (NTFS) and without (FAT32)"
$vhd = "$env:RUNNER_TEMP\pd.vhd"
foreach ($fs in "ntfs", "fat32") {
  if (Test-Path $vhd) { Remove-Item -Force $vhd }
  $dp = "$env:RUNNER_TEMP\dpd.txt"
  "create vdisk file=`"$vhd`" maximum=400 type=expandable", "select vdisk file=`"$vhd`"", "attach vdisk", "create partition primary", "format fs=$fs quick", "assign letter=V" | Set-Content -Encoding ascii $dp
  diskpart /s $dp | Out-Null
  if (Test-Path "V:\") {
    python -c $read "V:\"
    Copy-Item $PackedDir "V:\raqib" -Recurse
    Ask "by V: (a disk image, $fs)" "V:\raqib\raqib.exe"
  } else { "V: is not there ($fs): NOT MEASURED" }
  "select vdisk file=`"$vhd`"", "detach vdisk" | Set-Content -Encoding ascii $dp
  diskpart /s $dp | Out-Null
}
Remove-Item -Force $vhd -ErrorAction SilentlyContinue
"=== removed"
Remove-Item -Recurse -Force $pf -ErrorAction SilentlyContinue
"left: $(Test-Path $pf), $(Test-Path 'R:\'), $(Test-Path 'V:\')"
exit 0
