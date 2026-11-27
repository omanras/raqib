# Probe only (never merged): measured before ADR-0013's ruling on "the code is the system's alone" for Windows -
# a Raqib packed with its own runtime and copied into Program Files: who owns it, who may write it, the folders
# above it up to the drive, and whether it runs as the service from there. It makes that folder, one service, the
# service's place and one local user of its own and removes them.
param([string]$PackedDir)
$ErrorActionPreference = "Continue"
$script = Join-Path $PSScriptRoot "svc_probe.py"
$pub = "C:\raqib-pub"
$name = "RaqibProbeP8"
$home8 = "C:\Program Files\RaqibProbe8"
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }

"=== a packed Raqib copied into Program Files"
Copy-Item $PackedDir $home8 -Recurse
$exe = "$home8\raqib.exe"
"it says: $(& $exe --version)"
$inner = (Get-ChildItem "$home8\_internal" -File | Select-Object -First 1).FullName
$deep = (Get-ChildItem "$home8\_internal" -Directory | Select-Object -First 1).FullName
python $script --survey "C:\" "C:\Program Files" $home8 $exe "$home8\_internal" $inner $deep "D:\" "C:\Users" $env:USERPROFILE | ForEach-Object { Mask (Cut $_ 420) }
"reparse points under it: $((Get-ChildItem $home8 -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue).Count); files and folders under it: $((Get-ChildItem $home8 -Recurse -Force).Count)"

New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null; "a plain user made" } catch { "a plain user NOT made: $($_.Exception.Message)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
$cmd = "$pub\t8.cmd"; $out = "$pub\o8.txt"
@"
@echo off
echo x > "$home8\by-user.txt" 2>nul && (echo write beside the program: DONE > $out) || (echo write beside the program: REFUSED > $out)
echo x > "$home8\_internal\by-user.py" 2>nul && (echo write into its own folder of modules: DONE >> $out) || (echo write into its own folder of modules: REFUSED >> $out)
echo x >> "$exe" 2>nul && (echo write to the program itself: DONE >> $out) || (echo write to the program itself: REFUSED >> $out)
ren "$home8" RaqibProbe8-renamed > nul 2>&1 && (echo give its folder another name: DONE >> $out) || (echo give its folder another name: REFUSED >> $out)
mkdir "C:\RaqibProbe8-at-root" > nul 2>&1 && (echo make a folder at the drive's root: DONE >> $out) || (echo make a folder at the drive's root: REFUSED >> $out)
ren "C:\Program Files" "Program Files-renamed" > nul 2>&1 && (echo give Program Files another name: DONE >> $out) || (echo give Program Files another name: REFUSED >> $out)
"$exe" --version > nul 2>&1 && (echo run it: DONE >> $out) || (echo run it: REFUSED >> $out)
"@ | Set-Content -Encoding ascii $cmd
try {
  Start-Process cmd.exe -ArgumentList "/c", $cmd -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
  "as the plain user:"; Get-Content $out -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | ForEach-Object { "    " + ($_ -replace "\s+", " ") }
} catch { "as the plain user: NOT MEASURED: $($_.Exception.Message)" }
if (Test-Path "C:\RaqibProbe8-at-root") { "the folder a plain user made at the root: $(Mask ((python $script --read 'C:\RaqibProbe8-at-root') -join ' '))"; Remove-Item -Recurse -Force "C:\RaqibProbe8-at-root" }

"=== the service from there, by the system's own calls"
python $script --svc install $name "`"$exe`" service run"
python $script --svc start $name
Start-Sleep 12
python $script --svc query $name | ForEach-Object { Cut $_ 200 }
"its text: $((Get-Content 'C:\ProgramData\Raqib\service.txt' -ErrorAction SilentlyContinue | Select-String 'round \d+: \d+ records' | Select-Object -First 1).Line)"
python $script --svc stop $name
Start-Sleep 3
python $script --svc query $name | Select-Object -Last 1
python $script --svc remove $name

"=== removed"
Remove-Item -Recurse -Force "C:\ProgramData\Raqib", $home8 -ErrorAction SilentlyContinue
"left: $(Test-Path $home8), $(Test-Path 'C:\ProgramData\Raqib')"
try { Remove-LocalUser -Name raqibprobe -ErrorAction Stop; "the user removed" } catch { "the user NOT removed: $($_.Exception.Message)" }
exit 0
