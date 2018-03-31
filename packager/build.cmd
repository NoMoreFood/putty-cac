@ECHO OFF

:: version information
SET VER=0.70u4
SET VERN=0.70.0.4

:: cert info to use for signing
SET CERT=2FA35B20356EFEB88F9E9B5F20221693C57100E5
set TSAURL=http://time.certum.pl/
set LIBNAME=PuTTY-CAC
set LIBURL=https://github.com/NoMoreFood/putty-cac

:: setup environment variables based on location of this script
SET INSTDIR=%~dp0
SET INSTDIR=%INSTDIR:~0,-1%
SET BASEDIR=%INSTDIR%\..
SET BINDIR=%BASEDIR%\binaries

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup paths
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0
SET PATH=%PATH%;%PX86%\Windows Kits\10\bin\10.0.16299.0\x64
SET PATH=%PATH%;%PX86%\Windows Kits\8.1\bin\x64
SET PATH=%PATH%;%PX86%\WiX Toolset v3.11\bin

:: sign the main executables
signtool sign /sha1 %CERT% /fd sha1 /tr %TSAURL% /td sha1 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe" 
signtool sign /sha1 %CERT% /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe" 

:: copy prereqs from build dir and 'real' installer
COPY /Y "%ProgramFiles(x86)%\PuTTY\PuTTY.chm" "%BASEDIR%\doc\"
COPY /Y "%ProgramFiles%\PuTTY\PuTTY.chm" "%BASEDIR%\doc\"
COPY /Y "%ProgramFiles(x86)%\PuTTY\*.url" "%INSTDIR%\"
COPY /Y "%ProgramFiles%\PuTTY\*.url" "%INSTDIR%\"
COPY /Y "%BASEDIR%\windows\*.ico" "%INSTDIR%\"
COPY /Y "%BASEDIR%\windows\README-msi.txt" "%INSTDIR%\"

:: do the build
PUSHD "%INSTDIR%"
candle -arch x86 -dWin64=no -dBuilddir="%BINDIR%\x86\\" -dWinver="%VERN%" -dPuttytextver="PuTTY CAC %VERN%" "%BASEDIR%\windows\installer.wxs"
light -ext WixUIExtension -ext WixUtilExtension -sval installer.wixobj -o "%BINDIR%\puttycac-%VER%-installer.msi"
candle -arch x64 -dWin64=yes -dBuilddir="%BINDIR%\x64\\" -dWinver="%VERN%" -dPuttytextver="PuTTY CAC %VERN%" "%BASEDIR%\windows\installer.wxs"
light -ext WixUIExtension -ext WixUtilExtension -sval installer.wixobj -o "%BINDIR%\puttycac-64bit-%VER%-installer.msi"
POPD

:: sign the msi files
signtool sign /sha1 %CERT% /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.msi"

:: cleanup
DEL /Q "%BASEDIR%\doc\PuTTY.chm"
DEL /Q "%INSTDIR%\*.url"
DEL /Q "%INSTDIR%\*.ico"
DEL /Q "%INSTDIR%\*.wix*"
DEL /Q "%INSTDIR%\*.txt*"
DEL /Q "%BINDIR%\*.wixpdb"

:: output hash information
SET HASHFILE=%BINDIR%\puttycac-hash.txt
IF EXIST "%HASHFILE%" DEL /F "%HASHFILE%"
POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "Get-ChildItem -Include @('*.msi','*.exe') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm SHA256 | Out-File -Append '%HASHFILE%' -Width 256"
POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "Get-ChildItem -Include @('*.msi','*.exe') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm SHA1 | Out-File -Append '%HASHFILE%' -Width 256"
POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "Get-ChildItem -Include @('*.msi','*.exe') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm MD5 | Out-File -Append '%HASHFILE%' -Width 256"
POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "$Data = Get-Content '%HASHFILE%'; $Data.Replace((Get-Item -LiteralPath '%BASEDIR%').FullName,'').Trim() | Set-Content '%HASHFILE%'"

PAUSE