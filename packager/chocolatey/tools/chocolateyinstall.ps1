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

  checksum      = '48A955AC22E765D23B5C931A20C4B0A26DE427B0DBC9D594D572F21C7353D35C'
  checksumType  = 'sha256'
  checksum64    = 'A667E6C6A1D73AD1435B00D539AFBE4E9939470F970955455D2EDEF4079D7E8E'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
