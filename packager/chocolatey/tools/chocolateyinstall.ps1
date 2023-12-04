$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.79u1/binaries/puttycac-0.79u1-installer.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.79u1/binaries/puttycac-64bit-0.79u1-installer.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = '95266E3D99410CF5B652D743348C1E6507678FBC1A01E554EA304C103E2105F3'
  checksumType  = 'sha256'
  checksum64    = 'FE10BBA7958B81F3414F64BE8BDC847E58D1D8ED05A08C46724857ED568397FA'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
