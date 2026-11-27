# The rig's `raqib service install | remove` on Windows (ADR-0013 X-7, Y-6; X54). On GitHub's throwaway Windows
# machine, as the job's administrator, it asks Raqib's own install three things: to install from this job's own
# Python, a tree a user may write, which the check refuses - nothing is to be made; to install from a copy of that
# Python it puts under Program Files as an administrator would, one folder deeper, asked with -I - the service is
# to be made, started and running; and to remove it - nothing is to be left. After each, a local user it makes
# outside the administrators' group asks `raqib service status`. It keeps what tools/rig/check.py reads:
#
#     tools\rig\service_install.ps1 -Out FOLDER
#
#   FOLDER\service-install.txt   asked-by-administrator (no: the asker of status), refused-exit, refused-words,
#                                refused-status, install-exit, install-result, installed-status,
#                                installed-command, remove-exit, remove-result, removed-status, one `key: value` a
#                                line
#   FOLDER\refused.txt, install.txt, remove.txt   what each command wrote, for a person
#
# Then it removes the place (C:\ProgramData\Raqib), the copy, its folder under the public folder and the user; a
# service of the name still there then is said and removed by the system's own tool. It judges nothing: a step
# that fails leaves a key unwritten or with what it read, and the check says X54 MISSED with the words of what is
# missing. It ends no process.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Continue"
$name = "RaqibWatch"
$user = "raqibrig"
$place = Join-Path $env:ProgramData "Raqib"
$own = (Get-Command python).Source
$holder = Join-Path $env:ProgramFiles "RaqibRigInstall"   # N-1: the interpreter two folders below Program Files
$copy = Join-Path $holder "Py\python.exe"
$pub = Join-Path $env:PUBLIC "raqib-rig-install"
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }
function Asked($python, $action, $keep) {   # the administrator asks; (the exit, its lines)
  $said = @(& $python -I -m raqib service $action 2>&1 | ForEach-Object { "$_" })
  $code = $LASTEXITCODE
  $said | Set-Content -Encoding ascii (Join-Path $Out $keep)
  @{ exit = $code; lines = $said; last = "$($said | Select-Object -Last 1)" }
}
function Status {   # the plain user asks status; its lines, or nothing where the ask could not be made
  Remove-Item -Force "$pub\said.txt", "$pub\groups.txt" -ErrorAction SilentlyContinue
  try { Start-Process cmd.exe -ArgumentList "/c", "$pub\ask.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop }
  catch { "the plain user could not ask: $($_.Exception.Message)" | Out-Host; return @{} }
  $lines = @(Get-Content "$pub\said.txt" -ErrorAction SilentlyContinue | ForEach-Object { "$_".Trim() })
  @{ lines = $lines; result = "$($lines | Where-Object { $_ -like 'RESULT:*' } | Select-Object -Last 1)"
     plain = (Test-Path "$pub\groups.txt") -and -not "$(Get-Content "$pub\groups.txt" -ErrorAction SilentlyContinue)".Trim() }
}
New-Item -ItemType Directory -Force $Out, $holder, $pub | Out-Null
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
Copy-Item (Split-Path $own) (Join-Path $holder "Py") -Recurse
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name $user -Password $pw -ErrorAction Stop | Out-Null } catch { "the plain user was not made: $($_.Exception.Message)" }
net localgroup Users $user /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", $pw)
"@echo off`r`nwhoami /groups | findstr /c:`"S-1-5-32-544`" > `"$pub\groups.txt`"`r`n`"$own`" -m raqib service status > `"$pub\said.txt`" 2>&1" |
  Set-Content -Encoding ascii "$pub\ask.cmd"
$kept = @()
$refused = Asked $own "install" "refused.txt"
$after = Status
$kept += "refused-exit: $($refused.exit)"
$kept += "refused-words: $(($refused.lines | Where-Object { $_ -like '*raqib service check:*' } | ForEach-Object { $_.Trim() }) -join ' ')"
if ($after.Count) { $kept += "asked-by-administrator: $(if ($after.plain) { 'no' } else { 'yes, or not read' })", "refused-status: $($after.result)" }
$made = Asked $copy "install" "install.txt"
$after = Status
$kept += "install-exit: $($made.exit)", "install-result: $($made.last)"
if ($after.Count) {
  $kept += "installed-status: $($after.result)"
  $kept += "installed-command: $($after.lines | Where-Object { $_ -like 'command: *' } | Select-Object -First 1)"
}
$gone = Asked $copy "remove" "remove.txt"
$after = Status
$kept += "remove-exit: $($gone.exit)", "remove-result: $($gone.last)"
if ($after.Count) { $kept += "removed-status: $($after.result)" }
$kept | Set-Content -Encoding ascii (Join-Path $Out "service-install.txt")
$kept | ForEach-Object { if ($_.Length -gt 300) { $_.Substring(0, 300) } else { $_ } }
if (Svc) { "a service of the name is still there after the remove (said; removed by the system's own tool)"; sc.exe stop $name | Out-Null; sc.exe delete $name | Out-Null }
Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $place, $holder, $pub -ErrorAction SilentlyContinue
"removed: the service $(-not (Svc)), its place $(-not (Test-Path $place)), the copy $(-not (Test-Path $holder)), the user $(-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue))"
exit 0
