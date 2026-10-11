$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
foreach($file in Get-ChildItem -LiteralPath $root -Recurse -File|Where-Object {$_.Extension -in '.ps1','.psm1'}){
  $tokens=$null;$errors=$null
  [System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)|Out-Null
  if($errors){throw "$($file.Name): $($errors.Message -join '; ')"}
}
Write-Output 'PowerShell syntax passed.'
