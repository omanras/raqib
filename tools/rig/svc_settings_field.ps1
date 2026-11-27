# Probe only (never merged): the sixteenth measurement - a branch's `raqib service status` reading what Raqib's
# install sets (ADR-0013 Amendment Z), on real Windows: a service Raqib's own install made, asked by a user with
# no rights; then each setting changed alone by the system's own tool (sc.exe), as an administrator may, and
# asked again; then put back. It makes one folder under Program Files, one under the public folder, one local
# user and the service RaqibWatch (by Raqib's install), and removes them.
$ErrorActionPreference = "Continue"
function Flat($lines) { ((($lines -join " | ") -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>") -replace "[ \t]+", " ").Trim() }
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
$name = "RaqibWatch"
$place = Join-Path $env:ProgramData "Raqib"
$hold = "C:\Program Files\RaqibFieldSettings"
$pub = "C:\Users\Public\raqib-settings"
$own = (Get-Command python).Source
$copy = "$hold\Py\python.exe"
New-Item -ItemType Directory -Force $hold, $pub | Out-Null
Copy-Item (Split-Path $own) "$hold\Py" -Recurse
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null } catch { "a plain user NOT made: $(Cut $_.Exception.Message 200)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
"@echo off`r`n`"$own`" -m raqib service status > `"$pub\plain.txt`" 2>&1`r`necho exit %errorlevel% >> `"$pub\plain.txt`"" | Set-Content -Encoding ascii "$pub\plain.cmd"
function Status($label) {
  Remove-Item -Force "$pub\plain.txt" -ErrorAction SilentlyContinue
  try {
    Start-Process cmd.exe -ArgumentList "/c", "$pub\plain.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
    $lines = @(Get-Content "$pub\plain.txt" -ErrorAction SilentlyContinue | ForEach-Object { "$_".Trim() })
    $kept = $lines | Where-Object { $_ -match "^(start:|after an end|the failure flag|delayed start|the message kept|the command kept|NOT AS INSTALLED|RESULT:|exit |its .* failed|state:)" }
    "$label | a plain user: $(Cut (Flat $kept) 1500)"
  } catch { "$label | a plain user: NOT MEASURED: $(Cut $_.Exception.Message 200)" }
}
if (Get-CimInstance Win32_Service -Filter "Name='$name'") { "a service of the name was there before the probe: NOT MEASURED"; exit 0 }
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
"=== made by Raqib's own install"
$said = & $copy -I -m raqib service install 2>&1 | ForEach-Object { "$_" }
"install: exit $LASTEXITCODE; $(Cut ($said | Select-Object -Last 1) 200)"
Status "as the install made it"
"=== each setting changed alone by the system's own tool, asked, and put back"
sc.exe config $name start= demand | Out-Null
Status "its start set to on demand"
sc.exe config $name start= delayed-auto | Out-Null
Status "its start set to automatic, delayed"
sc.exe config $name start= auto | Out-Null
Status "its start put back"
sc.exe failureflag $name 0 | Out-Null
Status "its failure flag taken away"
sc.exe failureflag $name 1 | Out-Null
sc.exe failure $name reset= 60 actions= restart/5000/restart/30000/restart/300000 | Out-Null
Status "the count forgotten after 60 s"
sc.exe failure $name reset= 3600 actions= restart/5000 | Out-Null
Status "one action only"
sc.exe failure $name reset= 3600 actions= restart/5000/restart/30000/run/300000 command= "C:\Windows\System32\whoami.exe" | Out-Null
Status "a third action that runs a command, with a command kept"
sc.exe failure $name reset= 0 actions= `"`" | Out-Null
Status "its actions taken away"
sc.exe failure $name reset= 3600 actions= restart/5000/restart/30000/restart/300000 command= `"`" | Out-Null
Status "its actions put back"
"=== removed by Raqib's own remove"
$said = & $copy -I -m raqib service remove 2>&1 | ForEach-Object { "$_" }
"remove: exit $LASTEXITCODE; $(Cut ($said | Select-Object -Last 1) 200)"
Status "after the remove"
"=== cleaned"
sc.exe delete $name 2>$null | Out-Null
Remove-LocalUser -Name raqibprobe -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $hold, $pub, $place -ErrorAction SilentlyContinue
"left: the service $([bool](Get-CimInstance Win32_Service -Filter "Name='$name'")), the folders $(Test-Path $hold) $(Test-Path $pub), the place $(Test-Path $place), the user $([bool](Get-LocalUser -Name raqibprobe -ErrorAction SilentlyContinue))"
exit 0
