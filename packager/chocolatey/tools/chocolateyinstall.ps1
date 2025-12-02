$ErrorActionPreference = 'Stop';

$packageName= $env:ChocolateyPackageName
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/NoMoreFood/putty-cac/raw/0.83u2/binaries/puttycac-0.83u2-x86.msi'
$url64      = 'https://github.com/NoMoreFood/putty-cac/raw/0.83u2/binaries/puttycac-0.83u2-x64.msi'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  url64bit      = $url64

  softwareName  = 'PuTTY CAC*'

  checksum      = '0BA5265C903BA6DE813A7BB0CED4CD6AA05A10A245045F6696181938C83DB6C9'
  checksumType  = 'sha256'
  checksum64    = 'B49B5B4540A9633D1864560A4073A66EC28ECF227515584BCEE347FA581A6D47'
  checksumType64= 'sha256'

  silentArgs    = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyPackage @packageArgs
