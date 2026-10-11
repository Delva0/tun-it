#Requires -Version 7.2
[CmdletBinding()]
param([ValidateSet('Install','Uninstall')][string]$Action='Install',
  [Parameter(Mandatory)][string]$Distribution,[string]$StatePath="$env:LOCALAPPDATA\tun-it",
  [switch]$EnableTun,[switch]$InstallDependencies)
$root=Split-Path (Split-Path $PSScriptRoot)
$mapped=if($Action -eq 'Install'){'WslInstall'}else{'WslRemove'}
& "$root\TunIt.ps1" -Action $mapped -StatePath $StatePath -Distribution $Distribution -EnableTun:$EnableTun -InstallDependencies:$InstallDependencies
