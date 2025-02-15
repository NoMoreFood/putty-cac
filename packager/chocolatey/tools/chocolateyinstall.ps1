$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.83/binaries/puttycac-0.83-x86.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.83/binaries/puttycac-0.83-x64.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = 'A98A5A26AC223594BA7ED4672BB1CF0F1145907C1A3895BB89C53AA53A816E42'
  checksumType  = 'sha256'
  checksum64    = '3FAE12AB0A2FDF2CC3221AFD743433836AF157452D042081D78352FAEAF430B5'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
