$ErrorActionPreference='Stop'
$script:Root=Split-Path $PSScriptRoot
function Initialize-TunIt {
  param([string]$StatePath)
  $script:State=[IO.Path]::GetFullPath($StatePath)
  New-Item -ItemType Directory -Path $script:State,"$script:State\reports" -Force|Out-Null
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & icacls.exe $script:State /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Could not restrict private state directory'}
  $script:Config=Get-Content -LiteralPath "$script:State\config.json" -Raw|ConvertFrom-Json
}
function Get-TunItConfig { $script:Config }
function Get-TunItState { $script:State }
function Save-TunItConfig { $script:Config|ConvertTo-Json -Depth 50|Set-Content -LiteralPath "$script:State\config.json" -Encoding utf8 }
function Test-TunItAdmin {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Invoke-TunItEngine {
  param([string]$Action,[string[]]$Arguments=@())
  $output=& $script:Config.python "$script:Root\lib\engine.py" $Action --state $script:State @Arguments 2>"$script:State\reports\engine-error.log"
  if($LASTEXITCODE -ne 0){throw "Configuration operation failed ($Action): $output"}
  $output
}
function Get-TunItCore { Join-Path $script:Config.v2rayn_home 'bin\sing_box\sing-box.exe' }
function Get-TunItWslNetwork {
  $adapter=@(Get-NetAdapter|Where-Object {$_.Name -like 'vEthernet (WSL*' -and $_.Status -eq 'Up'})
  if($adapter.Count -ne 1){throw 'WSL2 NAT adapter missing or ambiguous. Start the selected distribution; mirrored networking is not supported.'}
  $address=@(Get-NetIPAddress -InterfaceIndex $adapter[0].ifIndex -AddressFamily IPv4|Where-Object {$_.IPAddress -notlike '169.254.*'})
  if($address.Count -ne 1){throw 'WSL2 NAT host address missing or ambiguous'}
  $prefix=& $script:Config.python -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1],strict=False))' "$($address[0].IPAddress)/$($address[0].PrefixLength)"
  if($LASTEXITCODE -ne 0){throw 'Invalid WSL2 NAT prefix'}
  [pscustomobject]@{Host=$address[0].IPAddress;Prefix=[string]$prefix;Alias=$adapter[0].Name}
}
function Stop-TunItV2 {
  Get-CimInstance Win32_Process|Where-Object {$_.Name -eq 'v2rayN.exe' -and $_.ExecutablePath -eq "$($script:Config.v2rayn_home)\v2rayN.exe"}|ForEach-Object{Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
  Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -like "$($script:Config.v2rayn_home)\bin\*" -and $_.Name -in @('xray.exe','sing-box.exe')}|ForEach-Object{Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
}
function Start-TunItV2 {
  $running=Get-CimInstance Win32_Process|Where-Object {$_.Name -eq 'v2rayN.exe' -and $_.ExecutablePath -eq "$($script:Config.v2rayn_home)\v2rayN.exe"}
  if(-not $running){Start-Process -FilePath "$($script:Config.v2rayn_home)\v2rayN.exe" -WorkingDirectory $script:Config.v2rayn_home -WindowStyle Hidden|Out-Null}
}
function Test-TunItWindows {
  param([switch]$RequireTun)
  $code=& curl.exe --silent --max-time 10 --connect-timeout 4 --proxy "socks5h://127.0.0.1:$($script:Config.local_port)" --output NUL --write-out '%{http_code}' $script:Config.health_url 2>$null
  if($LASTEXITCODE -ne 0 -or $code -notmatch '^2\d\d$'){return $false}
  if($RequireTun){
    $candidate=Get-Content -LiteralPath "$script:State\candidate-tun.json" -Raw -ErrorAction SilentlyContinue|ConvertFrom-Json
    $tun=@($candidate.inbounds|Where-Object {$_.type -eq 'tun'})
    if($tun.Count -eq 1 -and $tun[0].interface_name){
      if((Get-NetAdapter -Name $tun[0].interface_name -ErrorAction SilentlyContinue).Status -ne 'Up'){return $false}
    }
    $code=& curl.exe --silent --max-time 10 --connect-timeout 4 --noproxy '*' --output NUL --write-out '%{http_code}' $script:Config.health_url 2>$null
    if($LASTEXITCODE -ne 0 -or $code -notmatch '^2\d\d$'){return $false}
    $gui=Get-Content -LiteralPath "$($script:Config.v2rayn_home)\guiConfigs\guiNConfig.json" -Raw|ConvertFrom-Json
    if(-not $gui.TunModeItem.EnableTun){return $false}
  }
  return $true
}
function Get-TunItGuardName {
  param([string]$Id,[string]$Program)
  if($Id -notmatch '^[a-zA-Z0-9_-]+$'){throw 'Adapter id must contain letters, numbers, underscores or hyphens'}
  $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Program.ToLowerInvariant()))).Substring(0,12)
  "TunIt-Process-$Id-$hash"
}
function Set-TunItGuards {
  param($WslNetwork,[switch]$BlockAll)
  if(Get-NetFirewallProfile|Where-Object {-not $_.Enabled}){throw 'Enable Windows Firewall for every profile before installing fail-closed guards'}
  $entries=@(Get-Content -LiteralPath "$script:State\process-entries.json" -Raw|ConvertFrom-Json)
  $sources=if($BlockAll){@('Any')}else{@(Get-Content -LiteralPath "$script:State\blocked-sources.json" -Raw|ConvertFrom-Json)}
  foreach($entry in $entries){foreach($program in $entry.executables){
    if(-not(Test-Path -LiteralPath $program)){throw "Protected executable not found: $program"}
    $name=Get-TunItGuardName $entry.id $program
    if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){
      Set-NetFirewallRule -Name $name -Enabled True -Direction Outbound -Action Block -Program $program -LocalAddress $sources -Profile Any|Out-Null
    }else{
      New-NetFirewallRule -Name $name -DisplayName "tun-it $($entry.id) TUN only" -Group 'tun-it' -Enabled True -Direction Outbound -Action Block -Program $program -LocalAddress $sources -Profile Any|Out-Null
    }
  }}
  foreach($protocol in @('TCP','UDP')){
    $name="TunIt-Wsl-$protocol"
    if($script:Config.wsl.enabled){
      $localBlocked=@(Get-Content -LiteralPath "$script:State\wsl-block-local.json" -Raw|ConvertFrom-Json)
      $remoteBlocked=@(Get-Content -LiteralPath "$script:State\wsl-block-remote.json" -Raw|ConvertFrom-Json)
      $local=@{Name="TunIt-Wsl-BlockLocal-$protocol";Direction='Inbound';Action='Block';Program=(Get-TunItCore);Protocol=$protocol;LocalPort=$script:Config.wsl.listen_port;LocalAddress=$localBlocked;Profile='Any';Enabled='True'}
      $remote=@{Name="TunIt-Wsl-BlockRemote-$protocol";Direction='Inbound';Action='Block';Program=(Get-TunItCore);Protocol=$protocol;LocalPort=$script:Config.wsl.listen_port;RemoteAddress=$remoteBlocked;Profile='Any';Enabled='True'}
      $allow=@{Name=$name;Direction='Inbound';Action='Allow';Program=(Get-TunItCore);Protocol=$protocol;LocalPort=$script:Config.wsl.listen_port;LocalAddress=$WslNetwork.Host;RemoteAddress=$WslNetwork.Prefix;InterfaceAlias=$WslNetwork.Alias;Profile='Any';Enabled='True'}
      foreach($options in @($local,$remote,$allow)){
        if(Get-NetFirewallRule -Name $options.Name -ErrorAction SilentlyContinue){Set-NetFirewallRule @options|Out-Null}
        else{New-NetFirewallRule @options -DisplayName $options.Name -Group 'tun-it'|Out-Null}
      }
    }else{
      foreach($rule in @($name,"TunIt-Wsl-BlockLocal-$protocol","TunIt-Wsl-BlockRemote-$protocol")){
        Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
      }
    }
  }
}
function Remove-TunItStaleGuards {
  $names=@();$entries=@(Get-Content -LiteralPath "$script:State\process-entries.json" -Raw|ConvertFrom-Json)
  foreach($entry in $entries){foreach($program in $entry.executables){$names+=Get-TunItGuardName $entry.id $program}}
  Get-NetFirewallRule -Group 'tun-it' -ErrorAction SilentlyContinue|Where-Object {$_.Name -like 'TunIt-Process-*' -and $_.Name -notin $names}|Remove-NetFirewallRule
  if($script:Config.PSObject.Properties.Name -contains 'migration'){
    foreach($name in $script:Config.migration.firewall_names){Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue}
  }
}
function Invoke-TunItSync {
  param([switch]$EnableTun)
  $network=$null;$stopped=$false
  if($script:Config.wsl.enabled){$network=Get-TunItWslNetwork}
  $arguments=if($network){@('--host',$network.Host,'--prefix',$network.Prefix)}else{@()}
  Invoke-TunItEngine build -Arguments $arguments|Out-Null
  & (Get-TunItCore) check -c "$script:State\validation.json" 2>"$script:State\reports\validation-error.log"
  if($LASTEXITCODE -ne 0){throw 'Candidate validation failed; v2rayN was left running'}
  $gui="$($script:Config.v2rayn_home)\guiConfigs\guiNConfig.json"
  Copy-Item -LiteralPath $gui -Destination "$script:State\before-sync-gui.json" -Force
  if(-not(Test-Path "$script:State\original-gui.json")){Copy-Item -LiteralPath $gui -Destination "$script:State\original-gui.json"}
  $saved=Get-Content -LiteralPath $gui -Raw|ConvertFrom-Json
  $requireTun=$EnableTun -or $saved.TunModeItem.EnableTun
  Invoke-TunItEngine snapshot|Out-Null
  # During changes, protected processes are completely offline until the new route is active.
  Set-TunItGuards -WslNetwork $network -BlockAll
  try{
    Stop-TunItV2;$stopped=$true
    try{
      Invoke-TunItEngine apply|Out-Null
      if($EnableTun){$saved.TunModeItem.EnableTun=$true;$saved|ConvertTo-Json -Depth 60|Set-Content -LiteralPath $gui -Encoding utf8}
    }finally{Start-TunItV2}
    $healthy=$false
    for($attempt=0;$attempt -lt 6;$attempt++){
      Start-Sleep -Seconds 2
      if(Test-TunItWindows -RequireTun:$requireTun){$healthy=$true;break}
    }
    if(-not $healthy){throw 'Windows connectivity check failed; reverting the v2rayN template'}
    Set-TunItGuards -WslNetwork $network
    Remove-TunItStaleGuards
    if($script:Config.wsl.enabled){foreach($distribution in $script:Config.wsl.distributions){Update-TunItWslRuntime $distribution}}
    Invoke-TunItEngine status
  }catch{
    if($stopped){
      Stop-TunItV2
      try{
        Invoke-TunItEngine restore -Arguments @('--snapshot',"$script:State\before-sync-template.json")|Out-Null
        Copy-Item -LiteralPath "$script:State\before-sync-gui.json" -Destination $gui -Force
      }finally{Start-TunItV2}
    }
    throw
  }finally{if($stopped){Start-TunItV2}}
}
function Update-TunItWslRuntime {
  param([string]$Distribution)
  $identity=Get-TunItWslIdentity $Distribution
  $existing=& wsl.exe -d $Distribution -u root --exec /usr/bin/test -f "/etc/tun-it/users/$($identity.uid).json"
  if($LASTEXITCODE -ne 0){return}
  $runtime=Get-Content -LiteralPath "$script:State\wsl-runtime-base.json" -Raw|ConvertFrom-Json
  $runtime|Add-Member -NotePropertyName uid -NotePropertyValue $identity.uid -Force
  $runtime|Add-Member -NotePropertyName gid -NotePropertyValue $identity.gid -Force
  $runtimePath="$script:State\wsl-refresh.json"
  try{
    $runtime|ConvertTo-Json|Set-Content -LiteralPath $runtimePath -Encoding utf8
    $path="/etc/tun-it/users/$($identity.uid).json"
    Write-TunItWslFile $Distribution $runtimePath ($path+'.staged')
    & wsl.exe -d $Distribution -u root --exec python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.chmod(0o600); p.replace(sys.argv[2])' ($path+'.staged') $path
    if($LASTEXITCODE -ne 0){throw 'WSL runtime refresh failed'}
  }finally{Remove-Item -LiteralPath $runtimePath -Force -ErrorAction SilentlyContinue}
}
function Get-TunItWslIdentity {
  param([string]$Distribution)
  $text=& wsl.exe -d $Distribution --exec python3 -c 'import os,pwd,json; u=pwd.getpwuid(os.getuid()); print(json.dumps(dict(uid=u.pw_uid,gid=u.pw_gid,user=u.pw_name)))'
  if($LASTEXITCODE -ne 0){throw 'Could not read WSL default user; Python 3 must be installed'}
  $identity=$text|ConvertFrom-Json
  if($identity.uid -eq 0){throw 'Configure a regular WSL default user first'}
  $identity
}
function Install-TunItWsl {
  param([string]$Distribution,[switch]$InstallDependencies)
  if($InstallDependencies){
    Invoke-TunItWslDependencies $Distribution
  }
  $identity=Get-TunItWslIdentity $Distribution
  $architecture=(& wsl.exe -d $Distribution --exec uname -m).Trim()
  $arch=switch($architecture){'x86_64'{'amd64'};'aarch64'{'arm64'};default{throw 'Unsupported Linux architecture'}}
  $binary=& $script:Config.python "$script:Root\lib\vendor.py" --state $script:State --arch $arch
  if($LASTEXITCODE -ne 0){throw 'Verified sing-box download failed'}
  $runtime=Get-Content -LiteralPath "$script:State\wsl-runtime-base.json" -Raw|ConvertFrom-Json
  $runtime|Add-Member -NotePropertyName uid -NotePropertyValue $identity.uid -Force
  $runtime|Add-Member -NotePropertyName gid -NotePropertyValue $identity.gid -Force
  $runtimePath="$script:State\wsl-install.json"
  $runtime|ConvertTo-Json|Set-Content -LiteralPath $runtimePath -Encoding utf8
  $stage='/run/tun-it-install-'+[guid]::NewGuid().ToString('N')
  try{
    Write-TunItWslFile $Distribution $runtimePath "$stage/runtime.json"
    Write-TunItWslFile $Distribution ([string]$binary) "$stage/sing-box"
    foreach($name in @('install.sh','enter.py','inside.py','probe.py','tun')){
      Write-TunItWslFile $Distribution "$script:Root\adapters\wsl\$name" "$stage/adapters/wsl/$name"
    }
    & wsl.exe -d $Distribution -u root --exec /bin/bash "$stage/adapters/wsl/install.sh" $stage "$stage/runtime.json" "$stage/sing-box"
    if($LASTEXITCODE -ne 0){throw 'WSL adapter installation failed'}
  }finally{
    & wsl.exe -d $Distribution -u root --exec python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1],ignore_errors=True)' $stage
    Remove-Item -LiteralPath $runtimePath -Force -ErrorAction SilentlyContinue
  }
}
function Invoke-TunItWslDependencies {
  param([string]$Distribution)
  $info=[Diagnostics.ProcessStartInfo]::new('wsl.exe');$info.UseShellExecute=$false;$info.CreateNoWindow=$true
  $info.RedirectStandardInput=$true
  foreach($arg in @('-d',$Distribution,'-u','root','--exec','/bin/sh','-c',
    'set -eu; umask 077; file=$(mktemp /run/tun-it-deps.XXXXXX); trap ''rm -f "$file"'' EXIT; cat >"$file"; /bin/sh "$file"')){$info.ArgumentList.Add($arg)}
  $process=[Diagnostics.Process]::Start($info)
  $process.StandardInput.Write([IO.File]::ReadAllText("$script:Root\adapters\wsl\dependencies.sh"));$process.StandardInput.Close()
  $process.WaitForExit()
  if($process.ExitCode -ne 0){throw 'WSL dependency installation failed'}
  $process.Dispose()
}
function Write-TunItWslFile {
  param([string]$Distribution,[string]$Source,[string]$Destination)
  $info=[Diagnostics.ProcessStartInfo]::new('wsl.exe');$info.UseShellExecute=$false;$info.CreateNoWindow=$true
  $info.RedirectStandardInput=$true;$info.RedirectStandardError=$true;$info.RedirectStandardOutput=$true
  foreach($arg in @('-d',$Distribution,'-u','root','--exec','python3','-c',
    'import os,pathlib,sys; os.umask(0o077); p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(sys.stdin.buffer.read())',$Destination)){$info.ArgumentList.Add($arg)}
  $process=[Diagnostics.Process]::Start($info)
  $errors=$process.StandardError.ReadToEndAsync();$output=$process.StandardOutput.ReadToEndAsync()
  $file=[IO.File]::OpenRead($Source)
  try{$file.CopyTo($process.StandardInput.BaseStream);$process.StandardInput.Close()}finally{$file.Dispose()}
  if(-not $process.WaitForExit(45000)){$process.Kill($true);throw 'WSL private file transfer timed out'}
  if($process.ExitCode -ne 0){throw 'WSL private file transfer failed'}
  $process.Dispose()
}
function Remove-TunItWsl {
  param([string]$Distribution)
  $identity=Get-TunItWslIdentity $Distribution
  $linuxRoot=(& wsl.exe -d $Distribution --exec wslpath -u $script:Root).Trim()
  & wsl.exe -d $Distribution -u root --exec /bin/bash "$linuxRoot/adapters/wsl/remove.sh" ([string]$identity.uid)
  if($LASTEXITCODE -ne 0){throw 'WSL removal refused; host protection retained'}
}
Export-ModuleMember -Function *
