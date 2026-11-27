# Probe only (never merged): the nineteenth measurement asked of the builder's branch - `raqib service remove
# --purge` itself, on real Windows: the place as the service leaves it; a folder of the name made by a shell; a link
# of the name; a link inside the place; a read-only file and a file held open inside it; and the command asked by
# a user outside the administrators' group (made for the run, removed after it). Each link points at a folder of
# this probe's own, whose one file is checked afterwards. It makes one folder under Program Files, one service by
# Raqib's own install, and names under ProgramData\Raqib, and removes them all. It ends no process.
$ErrorActionPreference = "Continue"
function Flat($lines) { ((($lines -join " | ") -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>") -replace "\s+", " ").Trim() }
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
$place = Join-Path $env:ProgramData "Raqib"
$hold = "C:\Program Files\RaqibFieldPurge"
$py = "$hold\Py\python.exe"
$target = Join-Path $env:RUNNER_TEMP "raqib_purge_target"
$pub = Join-Path $env:PUBLIC "raqib-field-purge"
$user = "raqibfield"
function Purge($label) {
  $said = @(& $py -I -m raqib service remove --purge 2>&1 | ForEach-Object { "$_" })
  "$label -> exit $LASTEXITCODE; " + (Cut (Flat ($said | Where-Object { $_ -match "record|RESULT" })) 900)
}
function Lived {   # the place as the service leaves it: installed, a round read, removed without --purge
  & $py -I -m raqib service install | Out-Null
  $t = Get-Date
  while (((Get-Date) - $t).TotalSeconds -lt 90 -and -not (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue)) { Start-Sleep -Milliseconds 500 }
  & $py -I -m raqib service remove | Out-Null
  "the place left by a service that watched a round: there $(Test-Path $place), names in it $(@(Get-ChildItem -Recurse -Force $place -ErrorAction SilentlyContinue).Count)"
}
New-Item -ItemType Directory -Force $hold, $target, $pub | Out-Null
Set-Content "$target\kept.txt" "kept"
Copy-Item (Split-Path (Get-Command python).Source) "$hold\Py" -Recurse
"=== 1. installed, a round, then remove --purge in one command"
& $py -I -m raqib service install | Out-Null
$t = Get-Date
while (((Get-Date) - $t).TotalSeconds -lt 90 -and -not (Select-String -Path "$place\service.txt" -Pattern "round \d+: \d+ records" -Quiet -ErrorAction SilentlyContinue)) { Start-Sleep -Milliseconds 500 }
Purge "remove --purge of a running service"
"after it: the place there $(Test-Path $place); the service there $([bool](Get-CimInstance Win32_Service -Filter "Name='RaqibWatch'"))"
"=== 2. nothing installed, no place"
Purge "remove --purge"
"=== 3. a folder of the name made by this administrator's shell, a file in it"
New-Item -ItemType Directory $place | Out-Null
Set-Content "$place\a-file.txt" "x"
Purge "remove --purge"
"after it: the folder there $(Test-Path $place), its file there $(Test-Path "$place\a-file.txt")"
Remove-Item -Recurse -Force $place
"=== 4. a link of the name to another folder"
cmd /c mklink /J "$place" "$target" | Out-Null
Purge "remove --purge"
"after it: the link there $(Test-Path $place), its target's file there $(Test-Path "$target\kept.txt")"
cmd /c rmdir "$place"
"=== 5. the place as the service leaves it, with a link inside it to another folder"
Lived
cmd /c mklink /J "$place\inner" "$target" | Out-Null
Purge "remove --purge"
"after it: the place there $(Test-Path $place), the link inside there $(Test-Path "$place\inner"), its target's file there $(Test-Path "$target\kept.txt"), names left in the place $(@(Get-ChildItem -Force $place -ErrorAction SilentlyContinue).Count)"
cmd /c rmdir "$place\inner"
Purge "remove --purge again, the link taken away"
"after it: the place there $(Test-Path $place)"
"=== 6. the place as the service leaves it, a read-only file in it"
Lived
Set-Content "$place\read-only.txt" "x"
Set-ItemProperty "$place\read-only.txt" -Name IsReadOnly -Value $true
Purge "remove --purge"
"after it: the place there $(Test-Path $place), the read-only file there $(Test-Path "$place\read-only.txt")"
if (Test-Path "$place\read-only.txt") { Set-ItemProperty "$place\read-only.txt" -Name IsReadOnly -Value $false }
"=== 7. a file in the place held open by this shell"
if (-not (Test-Path $place)) { Lived }
Set-Content "$place\held.txt" "x"
$h = [System.IO.File]::Open("$place\held.txt", "Open", "Read", "None")
Purge "remove --purge"
"after it: the place there $(Test-Path $place), the held file there $(Test-Path "$place\held.txt")"
$h.Close()
Purge "remove --purge again, the file let go"
"after it: the place there $(Test-Path $place)"
"=== 8. asked by a user outside the administrators' group, the place as the service leaves it"
Lived
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name $user -Password $pw -ErrorAction Stop | Out-Null } catch { "the plain user was not made: $($_.Exception.Message)" }
net localgroup Users $user /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", $pw)
"@echo off`r`nwhoami /groups | findstr /c:`"S-1-5-32-544`" > `"$pub\groups.txt`"`r`n`"$py`" -I -m raqib service remove --purge > `"$pub\said.txt`" 2>&1`r`necho exit %errorlevel% >> `"$pub\said.txt`"" | Set-Content -Encoding ascii "$pub\ask.cmd"
try { Start-Process cmd.exe -ArgumentList "/c", "$pub\ask.cmd" -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop } catch { "the plain user could not ask: $($_.Exception.Message)" }
"asked by an administrator: " + [bool]("$(Get-Content "$pub\groups.txt" -ErrorAction SilentlyContinue)".Trim())
"the plain user was told: " + (Cut (Flat (Get-Content "$pub\said.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "record|RESULT|exit|raqib service" })) 900)
"after it: the place there $(Test-Path $place), names in it $(@(Get-ChildItem -Recurse -Force $place -ErrorAction SilentlyContinue).Count)"
Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
Purge "remove --purge by the administrator, at the end"
"=== removed"
Remove-Item -Recurse -Force $hold, $target, $pub -ErrorAction SilentlyContinue
if (Test-Path $place) { Remove-Item -Recurse -Force $place }
"left: the copy $(Test-Path $hold), the place $(Test-Path $place), the service $([bool](Get-CimInstance Win32_Service -Filter "Name='RaqibWatch'")), the user $([bool](Get-LocalUser -Name $user -ErrorAction SilentlyContinue))"
exit 0
