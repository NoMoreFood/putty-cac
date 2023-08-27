$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.79/binaries/puttycac-0.79-installer.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.79/binaries/puttycac-64bit-0.79-installer.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = '6A11D19193EB8E5D017C493247FE1CB324492255E8A0480BFC4558886C18AC57'
  checksumType  = 'sha256'
  checksum64    = '874C2383DB0A0B3E4B26B99148D9AD0110BBB77111645E3D9AA787BA52BE6590'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
