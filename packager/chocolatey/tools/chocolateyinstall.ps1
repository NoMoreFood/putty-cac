$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.77u1/binaries/puttycac-0.77u1-installer.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.77u1/binaries/puttycac-64bit-0.77u1-installer.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'puTTY CAC*'

  checksum      = '907F201234DE8906276B0EEB9A2CD8363FB64047F0607046D6C45EF12AED8F7E'
  checksumType  = 'sha256'
  checksum64    = '48076176FA7D09A0A7EB51D541B736A632FFE6A709A7DF388B95398F0D8284ED'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
