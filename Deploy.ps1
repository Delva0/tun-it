[CmdletBinding()]
param([string]$StatePath="$env:LOCALAPPDATA\tun-it")
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -lt 7){
  $pwsh=Get-Command pwsh.exe -ErrorAction SilentlyContinue
  if(-not $pwsh){
    Write-Host 'Installing PowerShell 7 using winget...'
    & winget.exe install --id Microsoft.PowerShell --exact --source winget --accept-package-agreements --accept-source-agreements
    if($LASTEXITCODE -ne 0){throw 'Install PowerShell 7 and run Deploy.ps1 again'}
    $pwsh=Get-Command "$env:ProgramFiles\PowerShell\7\pwsh.exe"
  }
  & $pwsh.Source -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -StatePath $StatePath
  exit $LASTEXITCODE
}
function Prompt-Default([string]$Label,[string]$Default){$answer=Read-Host "$Label [$Default]";if($answer){$answer}else{$Default}}
function Invoke-Deployment([string]$Action,[hashtable]$Options=@{}){
  $report="$StatePath\reports\operation.json"
  Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue
  & "$PSScriptRoot\TunIt.ps1" -Action $Action -StatePath $StatePath @Options
  $deadline=(Get-Date).AddMinutes(8)
  while(-not(Test-Path -LiteralPath $report)){
    if((Get-Date) -gt $deadline){throw "Operation timed out: $Action. Check $StatePath\reports before retrying."}
    Start-Sleep -Milliseconds 500
  }
  $result=Get-Content -LiteralPath $report -Raw|ConvertFrom-Json
  if(-not $result.Success){throw "Deployment failed: $($result.Error)"}
}
Write-Host 'tun-it: route selected environments through one v2rayN GUI node.'
New-Item -ItemType Directory -Path $StatePath,"$StatePath\reports" -Force|Out-Null
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $StatePath /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
if($LASTEXITCODE -ne 0){throw 'Could not protect the private configuration directory'}
if(Test-Path -LiteralPath "$StatePath\config.json"){
  $c=Get-Content -LiteralPath "$StatePath\config.json" -Raw|ConvertFrom-Json
}else{$c=Get-Content -LiteralPath "$PSScriptRoot\config.example.json" -Raw|ConvertFrom-Json}
if(-not $c.v2rayn_home){
  $running=Get-Process v2rayN -ErrorAction SilentlyContinue|Select-Object -First 1
  $detected=if($running -and $running.Path){Split-Path $running.Path}else{''}
  $c.v2rayn_home=Prompt-Default 'v2rayN folder (start v2rayN once first)' $detected
}
if(-not(Test-Path -LiteralPath "$($c.v2rayn_home)\guiConfigs\guiNDB.db")){throw 'v2rayN database missing. Start v2rayN once, select a working ordinary node, then run deployment again.'}
if(-not(Test-Path -LiteralPath "$($c.v2rayn_home)\bin\sing_box\sing-box.exe")){throw 'v2rayN sing-box core missing; install it using v2rayN core updates.'}
$python=Get-Command python.exe -ErrorAction SilentlyContinue
if($c.python -eq 'python' -or -not $c.python){
  $candidate=if($python){$python.Source}else{''}
  $c.python=Prompt-Default 'Python 3.10+ executable (install Python first if missing)' $candidate
}
& $c.python -c 'import sys; assert sys.version_info >= (3,10)'
if($LASTEXITCODE -ne 0){throw 'Python 3.10 or later is required'}
$c.local_port=[int](Prompt-Default 'v2rayN ordinary local SOCKS/mixed port' ([string]$c.local_port))
$c|ConvertTo-Json -Depth 50|Set-Content -LiteralPath "$StatePath\config.json" -Encoding utf8
Import-Module "$PSScriptRoot\lib\Common.psm1" -Force -DisableNameChecking
Initialize-TunIt $StatePath
$profiles=@(Invoke-TunItEngine profiles|ConvertFrom-Json)
Write-Host 'Available GUI targets:'
for($i=0;$i -lt $profiles.Count;$i++){Write-Host "$($i+1): $($profiles[$i].remarks)"}
$selection=Read-Host 'Choose a number, or press Enter to import server configuration'
if($selection){
  $index=0
  if(-not[int]::TryParse($selection,[ref]$index) -or $index -lt 1 -or $index -gt $profiles.Count){throw 'Invalid target selection'}
  $c.profile_id=$profiles[$index-1].indexId
  $c|ConvertTo-Json -Depth 50|Set-Content -LiteralPath "$StatePath\config.json" -Encoding utf8
}else{
  Write-Host 'Paste a VLESS, VMess, Trojan or SIP002 Shadowsocks share URI. Input is hidden.'
  $secret=Read-Host 'Server configuration' -AsSecureString
  $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
  $input="$StatePath\import.json"
  try{
    @{uri=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)}|ConvertTo-Json|Set-Content -LiteralPath $input -Encoding utf8
    Invoke-Deployment ImportNode @{InputFile=$input}
  }finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);Remove-Item -LiteralPath $input -Force -ErrorAction SilentlyContinue}
  $c=Get-Content -LiteralPath "$StatePath\config.json" -Raw|ConvertFrom-Json
}
$c.expected_exit=Prompt-Default 'Optional expected public IPv4 (Enter accepts current value)' $c.expected_exit
$android=(Prompt-Default 'Attach an installed Android SDK emulator? y/n' $(if($c.android.enabled){'y'}else{'n'})) -eq 'y'
if($android){
  $c.android.sdk=Prompt-Default 'Android SDK folder' $c.android.sdk
  $c.android.avd_home=Prompt-Default 'AVD folder' $(if($c.android.avd_home){$c.android.avd_home}else{"$env:USERPROFILE\.android\avd"})
  $c.android.avd=Prompt-Default 'Existing AVD name' $c.android.avd
}
$c.android.enabled=$false
$answer=Read-Host 'WSL2 distributions to install tun into (comma separated; Enter skips)'
$distributions=if($answer){@($answer.Split(',')|ForEach-Object {$_.Trim()}|Where-Object {$_})}else{@()}
$c|ConvertTo-Json -Depth 50|Set-Content -LiteralPath "$StatePath\config.json" -Encoding utf8
# First capture a native baseline. Then only the TUN template receives owned routes.
Invoke-Deployment Bootstrap
if($android){Invoke-Deployment AndroidInstall @{EnableTun=$true}}else{Invoke-Deployment Sync @{EnableTun=$true}}
foreach($distribution in $distributions){Invoke-Deployment WslInstall @{Distribution=$distribution;EnableTun=$true;InstallDependencies=$true}}
Invoke-Deployment Verify
Write-Host "Deployment complete. Private settings: $StatePath\config.json"
Write-Host 'WSL usage: tun COMMAND [ARGUMENTS...]. Manage the target in v2rayN, then run .\TunIt.ps1 -Action Sync.'
