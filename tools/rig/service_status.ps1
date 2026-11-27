# The rig's `raqib service status` on Windows, asked with no rights (ADR-0013 V-5, W-6; X53). On GitHub's throwaway
# Windows machine it makes a local user of its own, outside the administrators' group, and has that user ask
# `python -m raqib service status` at three moments: with no service named RaqibWatch; with one that Raqib's own
# install made from a copy of this job's Python under Program Files (ADR-0013 Z-3: only a service made as the
# install makes it reads as installed), running; and with one made by hand with the mark from the job's own Python,
# a tree a user may write, which the install refuses and the runner's own check refuses at its start. It keeps
# what tools/rig/check.py reads:
#
#     tools\rig\service_status.ps1 -Out FOLDER
#
#   FOLDER\service-status.txt   asked-by-administrator (no: the asker's groups hold no administrators' group),
#                               none-exit, none-result, active-exit, active-result, active-command, refused-exit,
#                               refused-result, refused-words (status's own lines), one `key: value` a line
#   FOLDER\none.txt, active.txt, refused.txt   what status wrote at each moment, for a person
#
# Then it stops and removes the services, their place (C:\ProgramData\Raqib), the copy, its folder under the
# public folder and the user. It judges nothing: a step that fails leaves a key unwritten, and the check says X53
# MISSED with the words of what is missing. The command it asks changes nothing; it ends no process.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$name = "RaqibWatch"
$user = "raqibrig"
$place = Join-Path $env:ProgramData "Raqib"
$own = (Get-Command python).Source
$holder = Join-Path $env:ProgramFiles "RaqibRigStatus"   # N-1: the interpreter two folders below Program Files
$copy = Join-Path $holder "Py\python.exe"
$pub = Join-Path $env:PUBLIC "raqib-rig-status"
$mark = "raqib-service/1 Raqib's watch of this host, made by the rig"
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }
function Made($python) {
  if (Test-Path $place) { Remove-Item -Recurse -Force $place }
  New-Service -Name $name -BinaryPathName "`"$python`" -I -m raqib service run" -StartupType Manual | Out-Null
  sc.exe description $name $mark | Out-Null
  try { Start-Service $name -ErrorAction Stop; "the start was taken" } catch { "the start failed, as the system says it: $($_.Exception.Message)" }
  $t = Get-Date
  while (((Get-Date) - $t).TotalSeconds -lt 60) {   # a round read, or stopped
    if ((Svc).State -eq "Stopped") { break }
    if (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Milliseconds 500
  }
}
function Unmade {
  if ((Svc).State -ne "Stopped") { try { Stop-Service $name -ErrorAction Stop } catch { "the stop failed: $($_.Exception.Message)" } }
  sc.exe delete $name | Out-Null
  Remove-Item -Recurse -Force $place -ErrorAction SilentlyContinue
  Start-Sleep 1
}
function Asked($keep) {   # the plain user asks; what it was answered, or nothing where the ask could not be made
  Remove-Item -Force "$pub\said.txt", "$pub\exit.txt", "$pub\groups.txt" -ErrorAction SilentlyContinue
  try { Start-Process cmd.exe -ArgumentList "/c", "$pub\ask.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop }
  catch { "the plain user could not ask: $($_.Exception.Message)"; return @{} }
  Copy-Item "$pub\said.txt" (Join-Path $Out $keep) -ErrorAction SilentlyContinue
  $lines = @(Get-Content "$pub\said.txt" -ErrorAction SilentlyContinue | ForEach-Object { "$_".Trim() })
  @{ exit = "$(Get-Content "$pub\exit.txt" -ErrorAction SilentlyContinue)".Trim(); lines = $lines
     result = "$($lines | Where-Object { $_ -like 'RESULT:*' } | Select-Object -Last 1)"
     groups = (Test-Path "$pub\groups.txt") -and -not "$(Get-Content "$pub\groups.txt" -ErrorAction SilentlyContinue)".Trim() }
}
New-Item -ItemType Directory -Force $Out, $holder, $pub | Out-Null
Copy-Item (Split-Path $own) (Join-Path $holder "Py") -Recurse
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name $user -Password $pw -ErrorAction Stop | Out-Null } catch { "the plain user was not made: $($_.Exception.Message)" }
net localgroup Users $user /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", $pw)
"@echo off`r`nwhoami /groups | findstr /c:`"S-1-5-32-544`" > `"$pub\groups.txt`"`r`n`"$own`" -m raqib service status > `"$pub\said.txt`" 2>&1`r`necho %errorlevel% > `"$pub\exit.txt`"" |
  Set-Content -Encoding ascii "$pub\ask.cmd"
$kept = @()
$none = Asked "none.txt"
if ($none.Count) {
  $kept += "asked-by-administrator: $(if ($none.groups) { 'no' } else { 'yes, or not read' })"
  $kept += "none-exit: $($none.exit)", "none-result: $($none.result)"
}
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
"Raqib's own install from the copy: exit $(& $copy -I -m raqib service install | Out-Null; $LASTEXITCODE)"
$active = Asked "active.txt"
if ($active.Count) {
  $kept += "active-exit: $($active.exit)", "active-result: $($active.result)"
  $kept += "active-command: $($active.lines | Where-Object { $_ -like 'command: *' } | Select-Object -First 1)"
}
"Raqib's own remove: exit $(& $copy -I -m raqib service remove | Out-Null; $LASTEXITCODE)"
if (Svc) { Unmade }
Made $own
$refused = Asked "refused.txt"
if ($refused.Count) {
  $kept += "refused-exit: $($refused.exit)", "refused-result: $($refused.result)"
  $kept += "refused-words: $(($refused.lines | Where-Object { $_ -notlike 'RESULT:*' -and $_ -ne 'raqib service status' }) -join ' ')"
}
Unmade
$kept | Set-Content -Encoding ascii (Join-Path $Out "service-status.txt")
$kept | ForEach-Object { if ($_.Length -gt 300) { $_.Substring(0, 300) } else { $_ } }
Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $holder, $pub -ErrorAction SilentlyContinue
"removed: the service $(-not (Svc)), its place $(-not (Test-Path $place)), the copy $(-not (Test-Path $holder)), the user $(-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue))"
exit 0
