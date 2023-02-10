$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.78u1/binaries/puttycac-0.78u1-installer.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.78u1/binaries/puttycac-64bit-0.78u1-installer.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = 'C8DF457BE4AD9D3F078BE01A6A6272A641DF57B845474B899ED5B0AD5E6AC930'
  checksumType  = 'sha256'
  checksum64    = 'C2E35BD6619EF090C983BE644FC606B858083B5A47CF03852A843B3ECFEBC18D'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
