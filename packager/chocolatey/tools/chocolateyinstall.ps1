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

  checksum      = '5590A2B63F5AC87FFEF6BAFBF45AD4B97EE32411B3CE2FCBFBB257E7D34C6175'
  checksumType  = 'sha256'
  checksum64    = 'E17EEBC4943F90AC4A48DD99A9A60000FD3908F92F562979F4189D2E8767B9D5'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
