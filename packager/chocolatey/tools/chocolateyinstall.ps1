$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.81/binaries/puttycac-0.81-installer.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.81/binaries/puttycac-64bit-0.81-installer.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = '0576FEA70A072D37805EDB2CAC5BC74254FABE75544FA9A0DD3B971DA7AEA254'
  checksumType  = 'sha256'
  checksum64    = '537C8670BBEC9C5FB6D120556231B753C226578D37D9383D2209CF2B78AE5FF5'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
