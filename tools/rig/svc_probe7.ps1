# Probe only (never merged): measured before ADR-0013's ruling on the install (M12.4c), on a throwaway machine -
# the service made, read, started, stopped and removed by the system's own calls; whether the name it is made
# under matters; who owns and who may write the Python it would run. It makes one service, the service's place
# and one local user of its own and removes them.
$ErrorActionPreference = "Continue"
$py = (Get-Command python).Source
$script = Join-Path $PSScriptRoot "svc_probe.py"
$pub = "C:\raqib-pub"
$name = "RaqibProbeI"
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
function Svc { Get-CimInstance Win32_Service -Filter "Name='$name'" }

"=== the service made by the system's own calls, under a name that is not the one its own table says"
python $script --svc install $name "`"$py`" -I -m raqib service run"
python $script --svc query $name | ForEach-Object { Cut $_ 240 }
"as the system's own tools read it: start mode $((Svc).StartMode), delayed $((Svc).DelayedAutoStart), account $((Svc).StartName)"
sc.exe qfailure $name | Select-String "RESET_PERIOD|FAILURE_ACTIONS|RESTART" | ForEach-Object { "    " + ($_.Line -replace "\s+", " ") }
sc.exe qdescription $name | Select-String "DESCRIPTION" | ForEach-Object { "    " + ($_.Line -replace "\s+", " ") }
python $script --svc start $name
Start-Sleep 12
python $script --svc query $name | Select-Object -Last 1
"its text: $((Get-Content 'C:\ProgramData\Raqib\service.txt' -ErrorAction SilentlyContinue | Select-String 'round \d+: \d+ records' | Select-Object -First 1).Line)"
$killed = (Svc).ProcessId
$t = Get-Date
taskkill /f /pid $killed | Out-Null
$again = 0
while (((Get-Date) - $t).TotalSeconds -lt 30) { $again = (Svc).ProcessId; if ($again -and $again -ne $killed) { break }; Start-Sleep -Milliseconds 500 }
"its process ended from outside: pid $killed; started again by the system: pid $again after $([int]((Get-Date) - $t).TotalSeconds) s"
python $script --svc stop $name
Start-Sleep 3
python $script --svc query $name | Select-Object -Last 1
python $script --svc remove $name
Start-Sleep 1
python $script --svc query $name
Remove-Item -Recurse -Force "C:\ProgramData\Raqib" -ErrorAction SilentlyContinue

"=== who owns the Python the service would run, and who may write it"
$exe = $py
$dir = Split-Path $exe
$site = (python -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")
$pkg = (python -c "import raqib, os; print(os.path.dirname(raqib.__file__))")
$paths = @($exe, $dir, (Split-Path $dir), (Split-Path (Split-Path $dir)), $site, $pkg, "$pkg\cli.py",
           "C:\Program Files", "C:\Windows\System32", "C:\Windows\System32\sc.exe", "C:\ProgramData", $env:LOCALAPPDATA)
python $script --survey @paths | ForEach-Object { Mask (Cut $_ 300) }

New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null; "a plain user made" } catch { "a plain user NOT made: $($_.Exception.Message)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
$cmd = "$pub\t7.cmd"; $out = "$pub\o7.txt"
@"
@echo off
echo x > "$dir\by-user.txt" 2>nul && (echo write beside the interpreter: DONE > $out) || (echo write beside the interpreter: REFUSED > $out)
echo x > "$site\by-user.pth" 2>nul && (echo write into its site folder: DONE >> $out) || (echo write into its site folder: REFUSED >> $out)
echo x > "$pkg\by-user.py" 2>nul && (echo write into Raqib's own folder: DONE >> $out) || (echo write into Raqib's own folder: REFUSED >> $out)
echo x > "C:\Program Files\by-user.txt" 2>nul && (echo write into Program Files: DONE >> $out) || (echo write into Program Files: REFUSED >> $out)
"@ | Set-Content -Encoding ascii $cmd
try {
  Start-Process cmd.exe -ArgumentList "/c", $cmd -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
  "as the plain user:"; Get-Content $out -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | ForEach-Object { "    " + ($_ -replace "\s+", " ") }
} catch { "as the plain user: NOT MEASURED: $($_.Exception.Message)" }
Remove-Item "$dir\by-user.txt", "$site\by-user.pth", "$pkg\by-user.py" -ErrorAction SilentlyContinue
try { Remove-LocalUser -Name raqibprobe -ErrorAction Stop; "the user removed" } catch { "the user NOT removed: $($_.Exception.Message)" }
exit 0
