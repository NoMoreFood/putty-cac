$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.82/binaries/puttycac-0.82-x86.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.82/binaries/puttycac-0.82-x64.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = 'F99437D6148C9AC72B9E55E1B820F03CE9713C41EB43134D53B8D2BB8E3A1026'
  checksumType  = 'sha256'
  checksum64    = 'CD22D5200A9DDFA1F1E4C17057531E09A85D9FBFF8984FA1E33D58FC152C8BE3'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
