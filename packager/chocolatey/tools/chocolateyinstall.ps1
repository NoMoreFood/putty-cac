$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.80/binaries/puttycac-0.80-installer.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.80/binaries/puttycac-64bit-0.80-installer.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = '26D216E8F78CECBFB2120F4B1888EE90E553B0CBF2F755D8F9D3A498ED11D468'
  checksumType  = 'sha256'
  checksum64    = '572F071DCCF03891A86312CE10D301AA71AAB0A42D79EAA5B6CA72D4F0258641'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
