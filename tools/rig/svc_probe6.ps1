# Probe only (never merged): two things measured before ADR-0013's ruling on the review of M12.4a REDO, on a
# throwaway machine - what the call that makes a folder does where the name is a link or a junction, its target
# there or not; and what a plain user can do to a file of his own inside a folder closed after he put it there.
$ErrorActionPreference = "Continue"
$script = Join-Path $PSScriptRoot "svc_probe.py"
$pd = "C:\ProgramData"
$pub = "C:\raqib-pub"
function Cut($s, $n) { if ($null -eq $s) { "" } else { $s.Substring(0, [Math]::Min($n, $s.Length)) } }
function Mask($s) { $s -replace "S-1-5-21-[0-9-]+", "S-1-5-21-<a user>" }
New-Item -ItemType Directory -Force $pub | Out-Null
icacls $pub /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
$pw = ConvertTo-SecureString ((-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 22 | ForEach-Object { [char]$_ })) + "aA1!") -AsPlainText -Force
try { New-LocalUser -Name raqibprobe -Password $pw -ErrorAction Stop | Out-Null; "a plain user made" } catch { "a plain user NOT made: $($_.Exception.Message)" }
net localgroup Users raqibprobe /add 2>$null | Out-Null
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\raqibprobe", $pw)
function As-User($tag, $lines) {
  $cmd = "$pub\t6-$tag.cmd"; $out = "$pub\o6-$tag.txt"
  ("@echo off`r`n" + ($lines -replace "OUT", $out)) | Set-Content -Encoding ascii $cmd
  try {
    Start-Process cmd.exe -ArgumentList "/c", $cmd -Credential $cred -WorkingDirectory $pub -WindowStyle Hidden -Wait -ErrorAction Stop
    "as the plain user ($tag):"
    Get-Content $out -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | ForEach-Object { "    " + ($_ -replace "\s+", " ") }
  } catch { "as the plain user ($tag): NOT MEASURED: $($_.Exception.Message)" }
}

$r = "$pd\RaqibProbe6"
New-Item -ItemType Directory -Force "$r\there" | Out-Null
foreach ($way in "--make", "--make2") {
  "=== the making call ($way) where the name is taken"
  foreach ($case in @(@("a junction, its target there", "/J", "$r\there"), @("a link, its target there", "/D", "$r\there"),
                      @("a junction, its target absent", "/J", "$r\absent-j$way"), @("a link, its target absent", "/D", "$r\absent-d$way"))) {
    $name = "$r\name"
    cmd /c rmdir $name 2>$null | Out-Null
    cmd /c mklink $case[1] $name $case[2] | Out-Null
    if ($case[2] -match "absent") { cmd /c rmdir $case[2] 2>$null | Out-Null }
    $said = Mask ((python $script $way $name) -join " | ")
    "{0}: {1}" -f $case[0], (Cut $said 230)
    "    where it points exists after the call: $(Test-Path -LiteralPath $case[2]); files in it: $((Get-ChildItem $case[2] -ErrorAction SilentlyContinue).Count)"
    cmd /c rmdir $name 2>$null | Out-Null
  }
  "x" | Set-Content "$r\name"
  "a file: $(Cut (Mask ((python $script $way "$r\name") -join ' | ')) 200)"
  Remove-Item -Force "$r\name"
  "nothing there: $(Cut (Mask ((python $script $way "$r\name") -join ' | ')) 200)"
  cmd /c rmdir "$r\name" 2>$null | Out-Null
}

"=== a plain user's file inside a folder closed after he put it there"
$c = "$pd\RaqibProbe6c"
As-User "plant" ("mkdir $c 2>nul`r`necho his > $c\his.txt 2>nul && (echo make a folder and a file of his own: DONE > OUT) || (echo make a folder and a file of his own: REFUSED > OUT)")
python $script --give $c | Select-Object -Last 1 | ForEach-Object { Mask $_ }
python $script --close $c | Select-String "as asked|inside" | ForEach-Object { "    " + (Mask (Cut $_.Line 200)) }
"the file's owner and list now: $(Mask ((Get-Acl "$c\his.txt").GetSecurityDescriptorSddlForm('Owner, Access')))"
As-User "after" ("type $c\his.txt > nul 2>&1 && (echo read his file by its whole path: DONE > OUT) || (echo read his file by its whole path: REFUSED > OUT)`r`n" +
  "icacls $c\his.txt /grant *S-1-5-32-545:F > nul 2>&1 && (echo give the users his file again: DONE >> OUT) || (echo give the users his file again: REFUSED >> OUT)`r`n" +
  "echo more >> $c\his.txt 2>nul && (echo write to his file: DONE >> OUT) || (echo write to his file: REFUSED >> OUT)`r`n" +
  "dir /b $c > nul 2>&1 && (echo list the folder: DONE >> OUT) || (echo list the folder: REFUSED >> OUT)")
"the file now holds: $((Get-Content "$c\his.txt" -ErrorAction SilentlyContinue) -join ' / '); its list: $(Mask ((Get-Acl "$c\his.txt").GetSecurityDescriptorSddlForm('Access')))"

"=== removed"
foreach ($d in $r, $c) { cmd /c rmdir /s /q $d 2>$null }
try { Remove-LocalUser -Name raqibprobe -ErrorAction Stop; "the user removed" } catch { "the user NOT removed: $($_.Exception.Message)" }
exit 0
