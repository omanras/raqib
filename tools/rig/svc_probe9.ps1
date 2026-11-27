# Probe only (never merged): measured before ADR-0013's ruling on a plain interpreter's road and on the kind of
# the drive - what the system says of a drive (a fixed disk, a letter given to a folder, a volume that keeps no
# lists), and a Python put under Program Files for all users: who owns it, who may write it, a venv made from
# it, Raqib installed into it, and the watch as a service from it. It makes two folders under Program Files, one
# small disk image, one service, the service's place and one local user of its own and removes them.
$ErrorActionPreference = "Continue"
$script = Join-Path $PSScriptRoot "svc_probe.py"
$pub = "C:\raqib-pub"
$name = "RaqibProbeP9"
$home9 = "C:\Program Files\RaqibProbe9Py"
$venv9 = "C:\Program Files\RaqibProbe9Venv"
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Whole { process { "WHOLE " + (Mask $_) } }

"=== the kind of a drive"
python $script --drive "C:\" "D:\" | Whole
subst R: C:\ProgramData
python $script --drive "R:\" | Whole
python $script --survey "R:\" | Whole
subst R: /D
$vhd = "$env:RUNNER_TEMP\p9.vhd"
foreach ($fs in "fat32", "exfat") {
  if (Test-Path $vhd) { Remove-Item -Force $vhd }
  $dp = "$env:RUNNER_TEMP\dp9.txt"
  "create vdisk file=`"$vhd`" maximum=300 type=expandable", "select vdisk file=`"$vhd`"", "attach vdisk", "create partition primary", "format fs=$fs quick", "assign letter=V" | Set-Content -Encoding ascii $dp
  $said = (diskpart /s $dp | Where-Object { $_ -match "succe|error|fail|not" }) -join " | "
  "a disk image formatted ${fs}: $(Cut $said 300)"
  if (Test-Path "V:\") {
    "x" | Set-Content "V:\file.txt"; New-Item -ItemType Directory "V:\folder" | Out-Null
    python $script --drive "V:\" | Whole
    python $script --survey "V:\" "V:\file.txt" "V:\folder" | Whole
  } else { "V: is not there: NOT MEASURED" }
  "select vdisk file=`"$vhd`"", "detach vdisk" | Set-Content -Encoding ascii $dp
  diskpart /s $dp | Out-Null
}
Remove-Item -Force $vhd -ErrorAction SilentlyContinue

"=== a Python for all users under Program Files"
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$ver = "3.13.9"
$inst = "$env:RUNNER_TEMP\python-inst.exe"
$how = "the installer of python.org ($ver, $arch), InstallAllUsers=1"
try {
  Invoke-WebRequest "https://www.python.org/ftp/python/$ver/python-$ver-$arch.exe" -OutFile $inst -ErrorAction Stop
  $p = Start-Process $inst -ArgumentList "/quiet", "InstallAllUsers=1", "TargetDir=`"$home9`"", "PrependPath=0", "Include_test=0", "Include_launcher=0", "Shortcuts=0", "AssociateFiles=0", "Include_doc=0", "Include_tcltk=0" -Wait -PassThru
  "the installer ended with $($p.ExitCode)"
} catch { "the installer was NOT run: $(Cut $_.Exception.Message 200)" }
if (-not (Test-Path "$home9\python.exe")) {
  $pydir = Split-Path (Get-Command python).Source
  Copy-Item $pydir $home9 -Recurse
  $how = "no install: GitHub's Python copied there by an administrator"
}
$py = "$home9\python.exe"
"how it came there: $how; it says: $(& $py --version 2>&1)"
$dll = (Get-ChildItem $home9 -Filter "python3*.dll" | Select-Object -First 1).FullName
python $script --survey $home9 $py $dll "$home9\Lib" "$home9\Lib\os.py" "$home9\Lib\site-packages" "$home9\DLLs" "$home9\Scripts" | Whole
"reparse points under it: $((Get-ChildItem $home9 -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue).Count); files and folders under it: $((Get-ChildItem $home9 -Recurse -Force).Count)"

"=== Raqib installed into it by an administrator, and a venv made from it"
& $py -m pip install --disable-pip-version-check -q --no-warn-script-location "$env:GITHUB_WORKSPACE" 2>&1 | Select-Object -Last 2
python $script --survey "$home9\Lib\site-packages\raqib" "$home9\Lib\site-packages\raqib\cli.py" "$home9\Scripts\raqib.exe" | Whole
$ask = "import sys, site; print('executable', sys.executable); print('base executable', sys._base_executable); print('prefix', sys.prefix, '| base', sys.base_prefix); print('flags: isolated', sys.flags.isolated, 'no_site', sys.flags.no_site, 'ignore_environment', sys.flags.ignore_environment, 'safe_path', sys.flags.safe_path); print('site folders', site.getsitepackages()); print('user site', site.ENABLE_USER_SITE); [print('path', repr(p)) for p in sys.path]"
"--- as it is started plainly, from the job's folder:"; & $py -c $ask
"--- with -I:"; & $py -I -c $ask
"--- by the raqib.exe beside it (what sys.path begins with):"; & "$home9\Scripts\raqib.exe" --version
& $py -m venv $venv9
"--- the venv's own, with -I:"; & "$venv9\Scripts\python.exe" -I -c $ask
"pyvenv.cfg: $((Get-Content "$venv9\pyvenv.cfg") -join ' ; ')"
python $script --survey $venv9 "$venv9\pyvenv.cfg" "$venv9\Scripts" "$venv9\Scripts\python.exe" "$venv9\Lib\site-packages" | Whole
"*.pth files in the two site folders: $((Get-ChildItem "$home9\Lib\site-packages", "$venv9\Lib\site-packages" -Filter *.pth | ForEach-Object { $_.Name }) -join ', ')"

New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null; "a plain user made" } catch { "a plain user NOT made: $($_.Exception.Message)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
$cmd = "$pub\t9.cmd"; $out = "$pub\o9.txt"
@"
@echo off
echo x > "$home9\by-user.txt" 2>nul && (echo write beside the interpreter: DONE > $out) || (echo write beside the interpreter: REFUSED > $out)
echo x > "$home9\Lib\site-packages\by-user.py" 2>nul && (echo write into its site folder: DONE >> $out) || (echo write into its site folder: REFUSED >> $out)
echo x > "$home9\Lib\site-packages\raqib\by-user.py" 2>nul && (echo write into the raqib package: DONE >> $out) || (echo write into the raqib package: REFUSED >> $out)
echo x >> "$home9\Lib\os.py" 2>nul && (echo write to a module of the library: DONE >> $out) || (echo write to a module of the library: REFUSED >> $out)
echo x > "$venv9\Lib\site-packages\by-user.py" 2>nul && (echo write into the venv's site folder: DONE >> $out) || (echo write into the venv's site folder: REFUSED >> $out)
echo x >> "$venv9\pyvenv.cfg" 2>nul && (echo write to the venv's pyvenv.cfg: DONE >> $out) || (echo write to the venv's pyvenv.cfg: REFUSED >> $out)
ren "$home9" RaqibProbe9Py-renamed > nul 2>&1 && (echo give its folder another name: DONE >> $out) || (echo give its folder another name: REFUSED >> $out)
"$py" -I -c "print(1)" > nul 2>&1 && (echo run it: DONE >> $out) || (echo run it: REFUSED >> $out)
"@ | Set-Content -Encoding ascii $cmd
try {
  Start-Process cmd.exe -ArgumentList "/c", $cmd -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
  "as the plain user:"; Get-Content $out -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | ForEach-Object { "    " + ($_ -replace "\s+", " ") }
} catch { "as the plain user: NOT MEASURED: $($_.Exception.Message)" }

"=== the watch as a service from that interpreter, with -I, by the system's own calls"
python $script --svc install $name "`"$py`" -I -m raqib service run"
python $script --svc start $name
Start-Sleep 12
python $script --svc query $name | ForEach-Object { Cut $_ 200 }
"its text: $((Get-Content 'C:\ProgramData\Raqib\service.txt' -ErrorAction SilentlyContinue | Select-String 'round \d+: \d+ records' | Select-Object -First 1).Line)"
python $script --svc stop $name
Start-Sleep 3
python $script --svc query $name | Select-Object -Last 1
python $script --svc remove $name

"=== removed"
if ($how -like "the installer*") { $p = Start-Process $inst -ArgumentList "/quiet", "/uninstall" -Wait -PassThru; "the installer's removal ended with $($p.ExitCode)" }
Remove-Item -Recurse -Force "C:\ProgramData\Raqib", $home9, $venv9 -ErrorAction SilentlyContinue
"left: $(Test-Path $home9), $(Test-Path $venv9), $(Test-Path 'C:\ProgramData\Raqib')"
try { Remove-LocalUser -Name raqibprobe -ErrorAction Stop; "the user removed" } catch { "the user NOT removed: $($_.Exception.Message)" }
exit 0
