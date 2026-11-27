# Probe only (never merged): python.org's own installer for all users, which ended with 1603 in probe 9 - once
# more with its log read, an older version of a line GitHub's machines may already hold, and the owners and lists
# of what it installs. It installs one Python under Program Files and removes it.
$ErrorActionPreference = "Continue"
$script = Join-Path $PSScriptRoot "svc_probe.py"
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Whole { process { "WHOLE " + (Mask $_) } }
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
"Pythons the machine already holds: $((Get-ChildItem 'C:\hostedtoolcache\windows\Python' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')"
# a line of versions the machine does not already hold (a newer one of the same line stopped the two before)
$vers = if ($arch -eq "arm64") { @("3.11.9") } else { @("3.10.11") }
foreach ($ver in $vers) {
  "=== python.org's installer, $ver $arch, for all users, to its own default folder"
  $inst = "$env:RUNNER_TEMP\python-$ver.exe"; $log = "$env:RUNNER_TEMP\python-$ver.log"
  try { Invoke-WebRequest "https://www.python.org/ftp/python/$ver/python-$ver-$arch.exe" -OutFile $inst -ErrorAction Stop } catch { "NOT fetched: $(Cut $_.Exception.Message 200)"; continue }
  $p = Start-Process $inst -ArgumentList "/quiet", "/log", "`"$log`"", "InstallAllUsers=1", "PrependPath=0", "Include_test=0", "Include_launcher=0", "Shortcuts=0", "AssociateFiles=0", "Include_doc=0", "Include_tcltk=0" -Wait -PassThru
  "the installer ended with $($p.ExitCode)"
  $home9 = (Get-ChildItem "C:\Program Files" -Directory -Filter "Python3*" | Select-Object -First 1).FullName
  if (-not $home9) {
    "nothing under Program Files; the log's lines that say why:"
    Get-Content $log -ErrorAction SilentlyContinue | Select-String "rror|ail|lready|newer|locked" | Select-Object -Last 12 | ForEach-Object { "    " + (Cut (Mask $_.Line) 260) }
    continue
  }
  $py = "$home9\python.exe"
  "installed at $home9; it says: $(& $py --version 2>&1)"
  $dll = (Get-ChildItem $home9 -Filter "python3*.dll" | Select-Object -First 1).FullName
  python $script --survey $home9 $py $dll "$home9\Lib" "$home9\Lib\os.py" "$home9\Lib\site-packages" "$home9\DLLs" "$home9\Scripts" "$home9\Scripts\pip.exe" | Whole
  "reparse points under it: $((Get-ChildItem $home9 -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue).Count); files and folders under it: $((Get-ChildItem $home9 -Recurse -Force).Count)"
  "owners under it, by count: $((Get-ChildItem $home9 -Recurse -Force | ForEach-Object { (Get-Acl -LiteralPath $_.FullName).Owner } | Group-Object | ForEach-Object { "$($_.Count) $($_.Name -replace '^.*\\','')" }) -join '; ')"
  "--- with -I:"; & $py -I -c "import sys, site; print('site folders', site.getsitepackages()); [print('path', repr(p)) for p in sys.path]"
  "*.pth files in its site folder: $((Get-ChildItem "$home9\Lib\site-packages" -Filter *.pth | ForEach-Object { $_.Name }) -join ', ')"
  $p = Start-Process $inst -ArgumentList "/quiet", "/uninstall" -Wait -PassThru
  "the installer's removal ended with $($p.ExitCode); left: $(Test-Path $home9)"
  break
}
exit 0
