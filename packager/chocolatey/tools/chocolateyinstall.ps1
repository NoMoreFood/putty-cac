$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.78/binaries/puttycac-0.78-installer.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.78/binaries/puttycac-64bit-0.78-installer.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = '5B788BBDEE9D1926F39576EB786E0CDB207B599788B70634AF87203C0F9149F4'
  checksumType  = 'sha256'
  checksum64    = 'E43DCD6D976CC2132F849DDB5F20EBF82BD2FDB6B509B90D70B14FF113FE8866'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
