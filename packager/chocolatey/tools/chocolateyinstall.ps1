$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.82u1/binaries/puttycac-0.82u1-x86.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.82u1/binaries/puttycac-0.82u1-x64.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = 'EA60FC32F2181FC90C9060284E0113EE14B7A95FB8D150C5225DB5056DDF0CF0'
  checksumType  = 'sha256'
  checksum64    = '8C01329F1CB0AA39CB8681A323C000DD1517AB70968371100AC5E3D11B3A89F6'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
