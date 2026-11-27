# Probe only (never merged): the field's word on `raqib service check` for a plain interpreter (ADR-0013
# Amendment M) - python.org's installer for all users, the branch's Raqib installed into it, a venv from it, asked
# with -I and without, a few harmless changes made by an administrator one at a time and undone, and whether -I
# reads a path from the registry. It installs one Python under Program Files, makes one venv, a few empty folders
# and two registry keys of its own, and removes them. The check itself changes nothing.
$ErrorActionPreference = "Continue"
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Ask($label, $exe, $more) {
  $t = Get-Date
  $said = & $exe @more -m raqib service check 2>&1 | ForEach-Object { "$_" }
  $code = $LASTEXITCODE
  "{0}: exit {1} in {2:n1} s; {3}" -f $label, $code, ((Get-Date) - $t).TotalSeconds, (Mask ((($said -join " ") -replace "\s+", " ").Trim()))
}
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$ver = "3.11.9"
"Pythons the machine already holds: $((Get-ChildItem 'C:\hostedtoolcache\windows\Python' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')"
"=== python.org's installer, $ver $arch, for all users"
$inst = "$env:RUNNER_TEMP\python-$ver.exe"
$how = "python.org's installer for all users"
try {
  Invoke-WebRequest "https://www.python.org/ftp/python/$ver/python-$ver-$arch.exe" -OutFile $inst -ErrorAction Stop
  $p = Start-Process $inst -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=0", "Include_test=0", "Include_launcher=0", "Shortcuts=0", "AssociateFiles=0", "Include_doc=0", "Include_tcltk=0" -Wait -PassThru
  "the installer ended with $($p.ExitCode)"
} catch { "the installer was NOT run: $(Cut $_.Exception.Message 200)" }
$home9 = (Get-ChildItem "C:\Program Files" -Directory -Filter "Python311*" | Select-Object -First 1).FullName
if (-not $home9) {
  $home9 = "C:\Program Files\RaqibFieldPy"
  Copy-Item (Split-Path (Get-Command python).Source) $home9 -Recurse
  Remove-Item -Recurse -Force "$home9\Lib\site-packages\raqib*" -ErrorAction SilentlyContinue
  $how = "no install: GitHub's Python copied there by an administrator, the job's Raqib taken out of the copy"
}
$py = "$home9\python.exe"
"how it came there: $how; at $home9; it says: $(& $py --version 2>&1)"
& $py -m pip install --disable-pip-version-check -q --no-warn-script-location "$env:GITHUB_WORKSPACE" 2>&1 | Select-Object -Last 1
"its path with -I -m: $((& $py -I -c "import sys; print(' | '.join(sys.path))") -join ' ')"

"=== asked"
Ask "with -I" $py @("-I")
Ask "without -I" $py @()
Ask "with -I and -S" $py @("-I", "-S")
$said = & "$home9\Scripts\raqib.exe" service check 2>&1 | ForEach-Object { "$_" }
"by the raqib.exe beside it: exit $LASTEXITCODE; $(Cut (Mask ((($said -join ' ') -replace '\s+', ' ').Trim())) 400)"
$said = python -I -m raqib service check 2>&1 | ForEach-Object { "$_" }
"the job's own Python with -I: exit $LASTEXITCODE; $(Cut (Mask ((($said -join ' ') -replace '\s+', ' ').Trim())) 500)"

"=== a venv from it under Program Files, the branch's Raqib installed into the venv"
$venv = "C:\Program Files\RaqibFieldVenv"
& $py -m venv $venv
& "$venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q --no-warn-script-location "$env:GITHUB_WORKSPACE" 2>&1 | Select-Object -Last 1
"its path with -I: $((& "$venv\Scripts\python.exe" -I -c "import sys; print(' | '.join(sys.path))") -join ' ')"
Ask "the venv's interpreter with -I" "$venv\Scripts\python.exe" @("-I")

"=== one thing changed at a time by an administrator, each undone"
$site = "$home9\Lib\site-packages"
"C:\RaqibFieldLater\lib" | Set-Content -Encoding ascii "$site\field.pth"
Ask "a *.pth line naming a folder that is not there, under the drive's root" $py @("-I")
New-Item -ItemType Directory -Force "C:\Program Files\RaqibFieldExtra" | Out-Null
"C:\Program Files\RaqibFieldExtra" | Set-Content -Encoding ascii "$site\field.pth"
Ask "a *.pth line naming a folder an administrator made under Program Files" $py @("-I")
"    is that folder on the interpreter's path: $((& $py -I -c "import sys; print(any(p.lower().endswith('raqibfieldextra') for p in sys.path))") -join ' ')"
New-Item -ItemType Directory -Force "C:\ProgramData\RaqibFieldPth" | Out-Null
"C:\ProgramData\RaqibFieldPth" | Set-Content -Encoding ascii "$site\field.pth"
Ask "a *.pth line naming a folder under ProgramData" $py @("-I")
"import os", "# a comment", "" | Set-Content -Encoding ascii "$site\field.pth"
Ask "a *.pth file of an import line, a comment and a blank line" $py @("-I")
Remove-Item -Force "$site\field.pth"
$deep = "$site\raqib\__init__.py"
icacls $deep /grant "*S-1-5-32-545:(M)" | Out-Null
Ask "one file of the package users may modify" $py @("-I")
icacls $deep /remove:g "*S-1-5-32-545" | Out-Null
Ask "after every change was undone" $py @("-I")

"=== does -I read a path from the registry"
$tag = (Get-ChildItem "HKLM:\Software\Python\PythonCore" -ErrorAction SilentlyContinue | Where-Object { (Get-ItemProperty "$($_.PSPath)\InstallPath" -ErrorAction SilentlyContinue).'(default)' -like "$home9*" } | Select-Object -First 1).PSChildName
if (-not $tag) { "no key of this interpreter under HKLM\Software\Python\PythonCore: NOT MEASURED" } else {
  "the interpreter's key: PythonCore\$tag"
  $see = "import sys; print(any('raqibfieldreg' in p.lower() for p in sys.path))"
  foreach ($hive in "HKCU", "HKLM") {
    $key = "${hive}:\Software\Python\PythonCore\$tag\PythonPath\RaqibField"
    New-Item -Path $key -Force | Out-Null
    Set-Item -Path $key -Value "C:\RaqibFieldReg"
    "a path under ${hive}'s key: on the path without -I: $((& $py -c $see) -join ' '); with -I: $((& $py -I -c $see) -join ' ')"
    Ask "    asked with -I while that key is there" $py @("-I")
    Remove-Item -Path $key -Force
  }
  if (-not (Get-ChildItem "HKCU:\Software\Python\PythonCore\$tag\PythonPath" -ErrorAction SilentlyContinue) -and (Test-Path "HKCU:\Software\Python\PythonCore\$tag\PythonPath")) { Remove-Item "HKCU:\Software\Python\PythonCore\$tag\PythonPath" -Force }
}

"=== removed"
Remove-Item -Recurse -Force $venv, "C:\Program Files\RaqibFieldExtra", "C:\ProgramData\RaqibFieldPth" -ErrorAction SilentlyContinue
if ($how -like "python.org*") { $p = Start-Process $inst -ArgumentList "/quiet", "/uninstall" -Wait -PassThru; "the installer's removal ended with $($p.ExitCode)" }
Remove-Item -Recurse -Force $home9 -ErrorAction SilentlyContinue
"left: $(Test-Path $home9), $(Test-Path $venv), $(Test-Path 'C:\Program Files\RaqibFieldExtra'), $(Test-Path 'C:\ProgramData\RaqibFieldPth')"
exit 0
