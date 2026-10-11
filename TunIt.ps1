#Requires -Version 7.2
[CmdletBinding()]
param(
  [ValidateSet('Status','Plan','Bootstrap','ImportNode','Sync','AndroidInstall','AndroidRemove','StartAndroid','WslInstall','WslRemove','Verify','Remove')][string]$Action='Status',
  [string]$StatePath="$env:LOCALAPPDATA\tun-it",[string]$Distribution,[string]$InputFile,
  [switch]$EnableTun,[switch]$InstallDependencies,
  [string]$Sdk,[string]$AvdHome,[string]$Avd
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\lib\Common.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot\adapters\Android.psm1" -Force -DisableNameChecking
if($Action -in @('Bootstrap','ImportNode','Sync','AndroidInstall','AndroidRemove','WslInstall','WslRemove','Remove') -and -not(Test-TunItAdmin)){
  $arguments=@('-NoProfile','-File',('"'+$PSCommandPath+'"'),'-Action',$Action,'-StatePath',('"'+$StatePath+'"'))
  if($Distribution){$arguments+=@('-Distribution',('"'+$Distribution+'"'))}
  if($InputFile){$arguments+=@('-InputFile',('"'+$InputFile+'"'))}
  if($EnableTun){$arguments+='-EnableTun'}
  if($InstallDependencies){$arguments+='-InstallDependencies'}
  foreach($item in @(@('Sdk',$Sdk),@('AvdHome',$AvdHome),@('Avd',$Avd))){if($item[1]){$arguments+=@('-'+$item[0],('"'+$item[1]+'"'))}}
  $process=Start-Process pwsh.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments -PassThru
  Write-Output "Administrator operation PID $($process.Id). Result: $StatePath\reports\operation.json"
  exit
}
Initialize-TunIt $StatePath
$c=Get-TunItConfig
$mutex=[Threading.Mutex]::new($false,'Local\tun-it-'+[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($StatePath)))).Substring(0,16))
$locked=$false;$configBefore=Get-Content -LiteralPath "$StatePath\config.json" -Raw
try{
  $locked=$mutex.WaitOne(0)
  if(-not $locked){throw 'Another tun-it operation is active'}
  switch($Action){
    'Status' {Invoke-TunItEngine status; Get-NetFirewallRule -Group 'tun-it' -ErrorAction SilentlyContinue|Select-Object Name,Enabled,Direction,Action|ConvertTo-Json}
    'Plan' {
      $args=@();if($c.wsl.enabled){$network=Get-TunItWslNetwork;$args=@('--host',$network.Host,'--prefix',$network.Prefix)}
      Invoke-TunItEngine build -Arguments $args
      & (Get-TunItCore) check -c "$StatePath\validation.json"
      if($LASTEXITCODE -ne 0){throw 'Candidate validation failed'}
    }
    'Bootstrap' {
      Invoke-TunItEngine snapshot|Out-Null
      $gui="$($c.v2rayn_home)\guiConfigs\guiNConfig.json"
      if(-not(Test-Path "$StatePath\original-gui.json")){Copy-Item -LiteralPath $gui -Destination "$StatePath\original-gui.json"}
      Copy-Item -LiteralPath $gui -Destination "$StatePath\bootstrap-gui.json" -Force
      Stop-TunItV2
      try{
        $saved=Get-Content -LiteralPath $gui -Raw|ConvertFrom-Json
        $saved.TunModeItem.EnableTun=$true
        $saved|ConvertTo-Json -Depth 60|Set-Content -LiteralPath $gui -Encoding utf8
      }finally{Start-TunItV2}
      $healthy=$false
      for($i=0;$i -lt 6;$i++){Start-Sleep -Seconds 2;if(Test-TunItWindows -RequireTun){$healthy=$true;break}}
      if(-not $healthy){
        Stop-TunItV2
        try{Copy-Item -LiteralPath "$StatePath\bootstrap-gui.json" -Destination $gui -Force}finally{Start-TunItV2}
        throw 'Native TUN bootstrap failed; previous GUI settings restored'
      }
      Invoke-TunItEngine capture
    }
    'ImportNode' {
      if(-not $InputFile){throw 'Private input file required'}
      Stop-TunItV2
      try{Invoke-TunItEngine import-node -Arguments @('--input',$InputFile)}finally{Start-TunItV2;Remove-Item -LiteralPath $InputFile -Force -ErrorAction SilentlyContinue}
    }
    'Sync' {Invoke-TunItSync -EnableTun:$EnableTun}
    'AndroidInstall' {
      if($Sdk){$c.android.sdk=[IO.Path]::GetFullPath($Sdk)}
      if($AvdHome){$c.android.avd_home=[IO.Path]::GetFullPath($AvdHome)}
      if($Avd){$c.android.avd=$Avd}
      $c.android.enabled=$true;Save-TunItConfig;Invoke-TunItSync -EnableTun:$EnableTun
    }
    'AndroidRemove' {Assert-TunItAndroidClosed;$c.android.enabled=$false;Save-TunItConfig;Invoke-TunItSync}
    'StartAndroid' {Start-TunItAndroid}
    'WslInstall' {
      if(-not $Distribution){throw 'Distribution required'}
      if($InstallDependencies){Invoke-TunItWslDependencies $Distribution}
      Get-TunItWslIdentity $Distribution|Out-Null
      $c.wsl.enabled=$true;$c.wsl.distributions=@(@($c.wsl.distributions)+$Distribution|Select-Object -Unique)
      Save-TunItConfig;Invoke-TunItSync -EnableTun:$EnableTun
      Install-TunItWsl $Distribution
    }
    'WslRemove' {
      if(-not $Distribution){throw 'Distribution required'}
      Remove-TunItWsl $Distribution
      $c.wsl.distributions=@($c.wsl.distributions|Where-Object {$_ -ne $Distribution})
      $c.wsl.enabled=$c.wsl.distributions.Count -gt 0
      Save-TunItConfig;Invoke-TunItSync
    }
    'Verify' {
      Invoke-TunItEngine status
      if(-not(Test-TunItWindows -RequireTun)){throw 'Windows TUN/connectivity check failed'}
      foreach($distro in $c.wsl.distributions){& wsl.exe -d $distro --exec /usr/local/bin/tun --check;if($LASTEXITCODE -ne 0){throw "WSL check failed: $distro"}}
    }
    'Remove' {
      if($c.android.enabled){Assert-TunItAndroidClosed}
      foreach($distro in $c.wsl.distributions){Remove-TunItWsl $distro}
      # Guards stay installed until consumers have closed and original template is restored.
      Stop-TunItV2
      try{Invoke-TunItEngine restore|Out-Null}finally{Start-TunItV2}
      if(-not(Test-TunItWindows)){Start-Sleep -Seconds 3}
      if(-not(Test-TunItWindows)){throw 'Original template restored; firewall guards retained because connectivity check failed'}
      Get-NetFirewallRule -Group 'tun-it' -ErrorAction SilentlyContinue|Remove-NetFirewallRule
      $c.android.enabled=$false;$c.wsl.enabled=$false;$c.wsl.distributions=@();$c.process_adapters=@();Save-TunItConfig
      Write-Output 'Removed owned routes, guards and command entries. Private backups were retained.'
    }
  }
  [pscustomobject]@{Success=$true;Action=$Action;Time=(Get-Date -Format o)}|ConvertTo-Json|Set-Content -LiteralPath "$StatePath\reports\operation.json" -Encoding utf8
}catch{
  if($Action -in @('AndroidInstall','AndroidRemove','WslInstall','WslRemove')){$configBefore|Set-Content -LiteralPath "$StatePath\config.json" -Encoding utf8}
  if($locked){[pscustomobject]@{Success=$false;Action=$Action;Error=$_.Exception.Message;Time=(Get-Date -Format o)}|ConvertTo-Json|Set-Content -LiteralPath "$StatePath\reports\operation.json" -Encoding utf8}
  throw
}finally{if($locked){$mutex.ReleaseMutex()};$mutex.Dispose()}
