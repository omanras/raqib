# Probe only (never merged): the fifteenth measurement - a branch's `raqib service install | remove` on real
# Windows (ADR-0013 Amendment X): asked by the job's administrator and by a plain user it makes, from the job's
# own Python (a tree the check refuses), from a copy of it under Program Files (with -I and without) and from a
# packed copy there; over a service that is there, over one that is not Raqib's, with a place that is there and
# not the runner's; and what `raqib service status` then says to a user with no rights. It makes one folder under
# Program Files, one under the public folder, one local user and the service RaqibWatch, and removes them.
param([string]$PackedDir)
$ErrorActionPreference = "Continue"
function Flat($lines) {
  $t = ((($lines -join " | ") -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>") -replace "[ \t]+", " ").Trim()
  $t = $t -replace "raqib service check: the code a service would run is the system's alone: checked (\d+) names.*?HarddiskVolume\d+`"", '<the check passed: $1 names>'
  $t -replace "a service named RaqibWatch is there \(opened with the rights 0x5.*?\| (RESULT: [A-Z, ]+)", '<status''s lines> | $1'
}
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
$name = "RaqibWatch"
$place = Join-Path $env:ProgramData "Raqib"
$hold = "C:\Program Files\RaqibFieldInstall"
$pub = "C:\Users\Public\raqib-install"
$own = (Get-Command python).Source
$copy = "$hold\Py\python.exe"
New-Item -ItemType Directory -Force $hold, $pub | Out-Null
Copy-Item (Split-Path $own) "$hold\Py" -Recurse
if ($PackedDir) { Copy-Item $PackedDir "$hold\packed" -Recurse }
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null } catch { "a plain user NOT made: $(Cut $_.Exception.Message 200)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
function Admin($label, $exe, $more, $cut = 1700) {
  $t = Get-Date
  $said = & $exe @more 2>&1 | ForEach-Object { "$_" }
  "{0} | the administrator: exit {1} in {2:n1} s; {3}" -f $label, $LASTEXITCODE, ((Get-Date) - $t).TotalSeconds, (Cut (Flat $said) $cut)
}
function Plain($label, $line, $cut = 900) {
  Remove-Item -Force "$pub\plain.txt" -ErrorAction SilentlyContinue
  "@echo off`r`n$line > `"$pub\plain.txt`" 2>&1`r`necho exit %errorlevel% >> `"$pub\plain.txt`"" | Set-Content -Encoding ascii "$pub\plain.cmd"
  try {
    Start-Process cmd.exe -ArgumentList "/c", "$pub\plain.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
    "{0} | a plain user: {1}" -f $label, (Cut (Flat (Get-Content "$pub\plain.txt" -ErrorAction SilentlyContinue)) $cut)
  } catch { "$label | a plain user: NOT MEASURED: $(Cut $_.Exception.Message 200)" }
}
function Status($label) { Plain "status, $label" "`"$own`" -m raqib service status" 2000 | ForEach-Object { $_ -replace "^(.*? \| a plain user: ).*(RESULT: [^|]*\| exit \d+)$", '$1... $2' } }
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }
function There { $s = Svc; if ($s) { "the service is there: state $($s.State), start $($s.StartMode), account $($s.StartName), command $($s.PathName)" } else { "no service of the name" } }
if (Svc) { "a service of the name was there before the probe: NOT MEASURED"; exit 0 }
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
"=== from the job's own Python, a tree the check refuses"
Admin "install" $own @("-I", "-m", "raqib", "service", "install") 900
There
"=== from the copy under Program Files, without -I"
Admin "install" $copy @("-m", "raqib", "service", "install") 900
There
"=== from the copy under Program Files, with -I, by a plain user"
Plain "install" "`"$copy`" -I -m raqib service install"
There
"=== from the copy under Program Files, with -I, by the administrator"
Admin "install" $copy @("-I", "-m", "raqib", "service", "install") 3600
There
Status "after the install"
"the system's log: $((Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7045 } -MaxEvents 1 -ErrorAction SilentlyContinue | ForEach-Object { Cut (($_.Message -replace '\s+', ' ').Trim()) 300 }))"
"the place: $(Cut (Flat (Get-Content "$place\service.txt" -TotalCount 1 -ErrorAction SilentlyContinue)) 260)"
"=== a second install over it"
Admin "install" $copy @("-I", "-m", "raqib", "service", "install") 900
There
"=== remove, by a plain user; then --purge; then by the administrator"
Plain "remove" "`"$copy`" -I -m raqib service remove"
There
Admin "remove --purge" $copy @("-I", "-m", "raqib", "service", "remove", "--purge") 600
There
Admin "remove" $copy @("-I", "-m", "raqib", "service", "remove") 1500
There
"the place after the remove: there $(Test-Path $place), its events file $(Test-Path "$place\.raqib\host\events.jsonl")"
Status "after the remove"
"=== remove with nothing installed"
Admin "remove" $copy @("-I", "-m", "raqib", "service", "remove") 700
"=== install again, the place there as the runner left it; then --no-start; each removed"
Admin "install" $copy @("-I", "-m", "raqib", "service", "install") 1100
Admin "remove" $copy @("-I", "-m", "raqib", "service", "remove") 500
Admin "install --no-start" $copy @("-I", "-m", "raqib", "service", "install", "--no-start") 2200
There
Status "after --no-start"
Admin "remove (of one never started)" $copy @("-I", "-m", "raqib", "service", "remove") 1200
There
"=== a place that is there and is not the runner's (a folder an administrator made, with the list it inherits)"
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $place | Out-Null
Admin "install" $copy @("-I", "-m", "raqib", "service", "install") 1300
There
Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
"=== a service of the name that is not Raqib's (made by hand, no mark)"
New-Service -Name $name -BinaryPathName "`"$copy`" -I -m raqib service run" -StartupType Manual | Out-Null
Admin "install" $copy @("-I", "-m", "raqib", "service", "install") 1100
Admin "remove" $copy @("-I", "-m", "raqib", "service", "remove") 900
There
sc.exe delete $name | Out-Null
Start-Sleep 1
if ($PackedDir) {
  "=== from the packed copy under Program Files"
  Admin "install" "$hold\packed\raqib.exe" @("service", "install") 2600
  There
  Status "of the packed service"
  Admin "remove" "$hold\packed\raqib.exe" @("service", "remove") 900
  There
}
"=== cleaned"
sc.exe delete $name 2>$null | Out-Null
Remove-LocalUser -Name raqibprobe -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $hold, $pub, $place -ErrorAction SilentlyContinue
"left: the service $([bool](Svc)), the folders $(Test-Path $hold) $(Test-Path $pub), the place $(Test-Path $place), the user $([bool](Get-LocalUser -Name raqibprobe -ErrorAction SilentlyContinue))"
exit 0
