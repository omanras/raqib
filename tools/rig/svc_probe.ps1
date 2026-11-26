# Probe only (never merged): svc_probe.py as a real service of Windows on a throwaway machine (M12.4). It makes
# two services of its own and one local user of its own, reads what they did, and removes all three.
# usage: svc_probe.ps1 PACKED_EXE
param([string]$Packed)
$ErrorActionPreference = "Continue"
$py = (Get-Command python).Source
$script = Join-Path $PSScriptRoot "svc_probe.py"
$root = "C:\ProgramData\RaqibProbe"
$pub = "C:\raqib-pub"

function Show-Log($label) {
  "--- svc.log ($label)"
  Get-Content "$root\$label\svc.log" -ErrorAction SilentlyContinue | ForEach-Object { "    " + $_.Substring(0, [Math]::Min(230, $_.Length)) }
}
function Show-Watch($label) {
  $f = "$root\$label\watch.out"
  "--- watch.out ($label): $((Get-Content $f -ErrorAction SilentlyContinue).Count) line(s); watch.err: $((Get-Content "$root\$label\watch.err" -ErrorAction SilentlyContinue).Count) line(s)"
  Get-Content $f -ErrorAction SilentlyContinue | Select-String -Pattern "^raqib watch --host: sources|RESULT|round \d+:|stopped|Stop|HOLES \(|BLIND SPOTS|Traceback|Error" | Select-Object -First 14 | ForEach-Object { "    " + $_.Line.Substring(0, [Math]::Min(200, $_.Line.Length)) }
  Get-Content "$root\$label\watch.err" -ErrorAction SilentlyContinue | Select-Object -First 6 | ForEach-Object { "    err: " + $_.Substring(0, [Math]::Min(200, $_.Length)) }
  "--- the record's place ($label):"
  Get-ChildItem "$root\$label\home" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 12 | ForEach-Object { "    {0} ({1} bytes)" -f $_.FullName.Replace($root, "ROOT"), $_.Length }
}
function Svc-Pid($name) { (Get-CimInstance Win32_Service -Filter "Name='$name'").ProcessId }
function Run-Once($name, $bin, $label) {
  "=== $label : the service $name"
  New-Service -Name $name -BinaryPathName $bin -StartupType Manual | Out-Null
  $t = Get-Date
  try { Start-Service $name -ErrorAction Stop; "start: ok in {0:n2} s" -f ((Get-Date) - $t).TotalSeconds } catch { "start: FAILED: $($_.Exception.Message)" }
  "state: $((Get-Service $name).Status); pid $(Svc-Pid $name)"
  Start-Sleep 14
  $t = Get-Date
  try { Stop-Service $name -ErrorAction Stop; "stop: ok in {0:n2} s" -f ((Get-Date) - $t).TotalSeconds } catch { "stop: FAILED: $($_.Exception.Message)" }
  "state: $((Get-Service $name).Status); exit code $((Get-CimInstance Win32_Service -Filter "Name='$name'").ExitCode)"
  Show-Log $label
  Show-Watch $label
}

"=== with no service manager (a console)"
python $script --service RaqibProbeNone console 2 | Out-Null
"exit $LASTEXITCODE"
Show-Log "console"

$plain = "`"$py`" `"$script`" --service RaqibProbe plain"
Run-Once "RaqibProbe" $plain "plain"
if ($Packed) { Run-Once "RaqibProbeP" "`"$Packed`" --service RaqibProbeP packed" "packed" }

"=== killed, with the system told to start it again"
sc.exe failure RaqibProbe reset= 86400 actions= restart/2000/restart/2000/restart/2000 | Select-Object -First 1
Start-Service RaqibProbe
$p1 = Svc-Pid "RaqibProbe"
Start-Sleep 5
$t = Get-Date
taskkill /f /pid $p1 | Out-Null
$p2 = 0
while (((Get-Date) - $t).TotalSeconds -lt 40) {
  $p2 = Svc-Pid "RaqibProbe"
  if ($p2 -and $p2 -ne $p1 -and (Get-Service RaqibProbe).Status -eq "Running") { break }
  Start-Sleep -Milliseconds 500
}
"killed pid $p1; state $((Get-Service RaqibProbe).Status) with pid $p2 after {0:n1} s" -f ((Get-Date) - $t).TotalSeconds
Get-WinEvent -FilterHashtable @{LogName = "System"; ProviderName = "Service Control Manager"} -MaxEvents 12 -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match "RaqibProbe" } | Select-Object -First 5 | ForEach-Object { "    event {0}: {1}" -f $_.Id, ($_.Message -replace "\s+", " ").Substring(0, [Math]::Min(170, ($_.Message -replace "\s+", " ").Length)) }

"=== who may touch it: the folder, the service, the process"
"the folder as the service made it:"
icacls $root | Select-Object -First 8 | ForEach-Object { "    $_" }
"the service's own rights (sdshow):"
sc.exe sdshow RaqibProbe | Where-Object { $_ } | ForEach-Object { "    $_" }
New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!"
net user raqibprobe $pw /add | Out-Null
"a plain user made: exit $LASTEXITCODE; in Administrators: $([bool](net localgroup Administrators | Select-String raqibprobe))"
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", (ConvertTo-SecureString $pw -AsPlainText -Force))
function As-User($tag) {
  $svcpid = Svc-Pid "RaqibProbe"
  $cmd = "$pub\try-$tag.cmd"
  $o = "$pub\out-$tag.txt"
  @"
@echo off
whoami > $o 2>&1
echo x > $root\plain\by-user.txt 2>nul && (echo write into the folder: DONE >> $o) || (echo write into the folder: REFUSED >> $o)
type $root\plain\svc.log > nul 2>&1 && (echo read its log: DONE >> $o) || (echo read its log: REFUSED >> $o)
dir /b $root\plain\home > nul 2>&1 && (echo list its record: DONE >> $o) || (echo list its record: REFUSED >> $o)
sc.exe stop RaqibProbe >> $o 2>&1
taskkill /f /pid $svcpid >> $o 2>&1
"@ | Set-Content -Encoding ascii $cmd
  try {
    Start-Process cmd.exe -ArgumentList "/c", $cmd -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
    "as the plain user ($tag):"
    Get-Content $o -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | ForEach-Object { "    " + ($_ -replace "\s+", " ") }
  } catch { "as the plain user ($tag): NOT MEASURED - a process could not be started as that user: $($_.Exception.Message)" }
  "after it: state $((Get-Service RaqibProbe).Status), pid $(Svc-Pid 'RaqibProbe') (was $svcpid)"
}
As-User "default"
icacls $root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Select-Object -Last 1
"the folder with the system and the administrators alone:"
icacls $root | Select-Object -First 5 | ForEach-Object { "    $_" }
As-User "closed"

"=== removed"
Stop-Service RaqibProbe -ErrorAction SilentlyContinue
sc.exe delete RaqibProbe | Select-Object -First 1
if ($Packed) { sc.exe delete RaqibProbeP | Select-Object -First 1 }
net user raqibprobe /delete | Out-Null
"the user removed: exit $LASTEXITCODE"
