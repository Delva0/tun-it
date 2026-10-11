$ErrorActionPreference='Stop'
function Start-TunItAndroid {
  $c=Get-TunItConfig;$state=Get-TunItState
  if(-not $c.android.enabled){throw 'Install the Android adapter first'}
  $status=Invoke-TunItEngine status|ConvertFrom-Json
  if(-not $status.tun_enabled -or -not $status.node_synced){throw 'Enable v2rayN TUN and synchronize the target first'}
  $programs=@("$($c.android.sdk)\emulator\qemu\windows-x86_64\qemu-system-x86_64.exe","$($c.android.sdk)\emulator\netsimd.exe","$($c.android.sdk)\emulator\emulator.exe")
  foreach($program in $programs){
    $guard=Get-NetFirewallRule -Name (Get-TunItGuardName android $program) -ErrorAction SilentlyContinue
    if(-not $guard -or $guard.Enabled -ne 'True' -or $guard.Action -ne 'Block'){throw 'Android firewall protection incomplete'}
  }
  $qemu=Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue
  if($qemu){Write-Output 'Android is already running.';return}
  $env:ANDROID_HOME=$c.android.sdk;$env:ANDROID_AVD_HOME=$c.android.avd_home
  $info=[Diagnostics.ProcessStartInfo]::new($programs[2]);$info.UseShellExecute=$false
  foreach($arg in @('-avd',$c.android.avd,'-no-boot-anim','-gpu','auto','-memory',([string]$c.android.memory_mb),'-cores',([string]$c.android.cores),'-dns-server',$c.dns_server,'-no-snapshot-load','-feature','-WiFiPacketStream')){$info.ArgumentList.Add($arg)}
  [Diagnostics.Process]::Start($info)|Out-Null
}
function Assert-TunItAndroidClosed {
  $c=Get-TunItConfig
  if(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -eq "$($c.android.sdk)\emulator\qemu\windows-x86_64\qemu-system-x86_64.exe"}){throw 'Close Android before uninstalling its protection'}
}
Export-ModuleMember -Function *
