# Probe only (never merged): the field's word on `raqib service check` (ADR-0013 Amendment K) - the branch's
# Raqib packed, asked on real Windows of copies an administrator made in several places and changed in several
# harmless ways, by an administrator and by a plain user. It makes folders under Program Files, ProgramData and the
# drive's root and one local user of its own, and removes them. The check itself changes nothing.
param([string]$PackedDir, [string]$OneFile)
$ErrorActionPreference = "Continue"
$pub = "C:\raqib-pub"
$pf = "C:\Program Files\RaqibField"
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Ask($label, $exe) {
  $t = Get-Date
  $said = & $exe service check 2>&1 | ForEach-Object { "$_" }
  $code = $LASTEXITCODE
  "{0}: exit {1} in {2:n1} s; {3}" -f $label, $code, ((Get-Date) - $t).TotalSeconds, (Mask ((($said -join " ") -replace "\s+", " ").Trim()))
}
"=== a copy in Program Files, as an administrator made it"
Copy-Item $PackedDir $pf -Recurse
Ask "taken?" "$pf\raqib.exe"
"=== the same, asked by a plain user"
New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null } catch { "a plain user NOT made: $($_.Exception.Message)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
"@echo off`r`n`"$pf\raqib.exe`" service check > $pub\u.txt 2>&1`r`necho exit %errorlevel% >> $pub\u.txt" | Set-Content -Encoding ascii "$pub\u.cmd"
try {
  Start-Process cmd.exe -ArgumentList "/c", "$pub\u.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
  "by the plain user: $(Mask (((Get-Content "$pub\u.txt") -join ' ') -replace '\s+', ' '))"
} catch { "by the plain user: NOT MEASURED: $($_.Exception.Message)" }

"=== one thing changed in that copy at a time, by an administrator, each undone"
$deep = (Get-ChildItem "$pf\_internal\raqib" -File -Filter "*.py*" -Recurse | Select-Object -First 1).FullName
if (-not $deep) { $deep = (Get-ChildItem "$pf\_internal" -File | Select-Object -First 1).FullName }
"the file changed: $($deep.Substring($pf.Length))"
icacls $deep /grant "*S-1-5-32-545:(M)" | Out-Null
Ask "a file users may modify" "$pf\raqib.exe"
icacls $deep /remove:g "*S-1-5-32-545" | Out-Null
icacls $deep /grant "*S-1-5-32-545:(RX)" | Out-Null
Ask "the same file, users given read and execute by an entry of its own" "$pf\raqib.exe"
icacls $deep /remove:g "*S-1-5-32-545" | Out-Null
icacls $deep /setowner "$env:COMPUTERNAME\$env:USERNAME" | Out-Null
Ask "a file owned by the administrator's own account" "$pf\raqib.exe"
icacls $deep /setowner "*S-1-5-32-544" | Out-Null
icacls $deep /deny "*S-1-5-32-545:(W)" | Out-Null
Ask "a file with a denying entry for users" "$pf\raqib.exe"
icacls $deep /remove:d "*S-1-5-32-545" | Out-Null
cmd /c mklink /J "$pf\_internal\joined" "C:\Windows\Temp" | Out-Null
Ask "a junction inside it" "$pf\raqib.exe"
cmd /c rmdir "$pf\_internal\joined"
New-Item -ItemType Directory "$pf\_internal\added-by-admin" | Out-Null; "x" | Set-Content "$pf\_internal\added-by-admin\new.txt"
Ask "a folder and a file an administrator added" "$pf\raqib.exe"
Remove-Item -Recurse -Force "$pf\_internal\added-by-admin"
Ask "after every change was undone" "$pf\raqib.exe"

"=== copies in other places"
Copy-Item $PackedDir "C:\RaqibFieldRoot" -Recurse
Ask "a folder an administrator made at the drive's root" "C:\RaqibFieldRoot\raqib.exe"
Copy-Item $PackedDir "C:\ProgramData\RaqibField" -Recurse
Ask "under ProgramData" "C:\ProgramData\RaqibField\raqib.exe"
Ask "in the job's own folder" "$PackedDir\raqib.exe"
New-Item -ItemType Directory "C:\Program Files\RaqibField Deep\a\b" -Force | Out-Null
Copy-Item $PackedDir "C:\Program Files\RaqibField Deep\a\b\raqib" -Recurse
Ask "three folders deep under Program Files, a space in a name" "C:\Program Files\RaqibField Deep\a\b\raqib\raqib.exe"
if ($OneFile -and (Test-Path $OneFile)) {
  New-Item -ItemType Directory "C:\Program Files\RaqibFieldOne" | Out-Null
  Copy-Item $OneFile "C:\Program Files\RaqibFieldOne\raqib.exe"
  Ask "packed as one file that unpacks itself at each start" "C:\Program Files\RaqibFieldOne\raqib.exe"
} else { "packed as one file: NOT MEASURED (no such packing was made)" }
"=== not packed"
$said = python -m raqib service check 2>&1 | ForEach-Object { "$_" }
"a plain interpreter: exit $LASTEXITCODE; $(Mask ((($said -join ' ') -replace '\s+', ' ').Trim()))"

"=== removed"
Remove-Item -Recurse -Force $pf, "C:\RaqibFieldRoot", "C:\ProgramData\RaqibField", "C:\Program Files\RaqibField Deep", "C:\Program Files\RaqibFieldOne" -ErrorAction SilentlyContinue
"left: $(Test-Path $pf), $(Test-Path 'C:\RaqibFieldRoot'), $(Test-Path 'C:\ProgramData\RaqibField'), $(Test-Path 'C:\Program Files\RaqibField Deep'), $(Test-Path 'C:\Program Files\RaqibFieldOne')"
try { Remove-LocalUser -Name raqibprobe -ErrorAction Stop; "the user removed" } catch { "the user NOT removed: $($_.Exception.Message)" }
exit 0
