$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.77u2/binaries/puttycac-0.77u2-installer.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.77u2/binaries/puttycac-64bit-0.77u2-installer.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = '44D0C15BC5E407C3E0160B79246F7D1722FB0994FD7FA65EE8CB1F77CE28E65E'
  checksumType  = 'sha256'
  checksum64    = '9ADABD6C7C354EA01866B3083B6697782D35CE959156988BCC80E42A41A3D72C'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
