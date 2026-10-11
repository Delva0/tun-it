#Requires -Version 7.2
[CmdletBinding()]
param([ValidateSet('Install','Uninstall','Start')][string]$Action='Install',
  [string]$StatePath="$env:LOCALAPPDATA\tun-it",[string]$Sdk,[string]$AvdHome,[string]$Avd,[switch]$EnableTun)
$root=Split-Path (Split-Path $PSScriptRoot)
$mapped=@{Install='AndroidInstall';Uninstall='AndroidRemove';Start='StartAndroid'}[$Action]
$options=@{StatePath=$StatePath;Action=$mapped}
if($Sdk){$options.Sdk=$Sdk};if($AvdHome){$options.AvdHome=$AvdHome};if($Avd){$options.Avd=$Avd}
if($EnableTun){$options.EnableTun=$true}
& "$root\TunIt.ps1" @options
