@ECHO OFF
TITLE Building PuTTY-CAC

:: version information
SET VER=0.74
SET VERN=0.74.0.0

:: cert info to use for signing
SET CERT=193A6FACBFBFC43ADB74ABB669543FCBC1C4F26C
set TSAURL=http://time.certum.pl/
set LIBNAME=PuTTY-CAC
set LIBURL=https://github.com/NoMoreFood/putty-cac

:: setup environment variables based on location of this script
SET INSTDIR=%~dp0
SET INSTDIR=%INSTDIR:~0,-1%
SET BASEDIR=%INSTDIR%\..\code
SET BINDIR=%INSTDIR%\..\binaries

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup paths
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0
SET PATH=%PATH%;%PX86%\Windows Kits\10\bin\10.0.18362.0\x64
SET PATH=%PATH%;%PX86%\Windows Kits\8.1\bin\x64
SET PATH=%PATH%;%PX86%\WiX Toolset v3.11\bin

:: cleanup
FOR %%X IN (Win32 x64 Debug Release Temp .vs) DO (
  FORFILES /S /P "%BASEDIR%\windows" /M "%%X" /C "CMD /C IF @isdir==TRUE RD /S /Q @path" >NUL 2>&1
)
FORFILES /S /P "%BINDIR%" /M "*.*" /C "CMD /C IF /I @ext NEQ """exe""" DEL /Q @file"

:: sign the main executables
signtool sign /sha1 %CERT% /fd sha1 /tr %TSAURL% /td sha1 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe" 
signtool sign /sha1 %CERT% /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe" 

:: copy prereqs from build dir and 'real' installer
MKDIR "%BASEDIR%\build"
COPY /Y "%ProgramFiles(x86)%\PuTTY\PuTTY.chm" "%BASEDIR%\doc\"
COPY /Y "%ProgramFiles%\PuTTY\PuTTY.chm" "%BASEDIR%\doc\"
COPY /Y "%ProgramFiles(x86)%\PuTTY\*.url" "%BASEDIR%\build\"
COPY /Y "%ProgramFiles%\PuTTY\*.url" "%BASEDIR%\build\"
COPY /Y "%BASEDIR%\windows\*.ico" "%BASEDIR%\build\"
COPY /Y "%BASEDIR%\windows\README-msi.txt" "%BASEDIR%\build\"
COPY /Y "%INSTDIR%\*.bmp" "%BASEDIR%\build\"

:: do the build
PUSHD "%BASEDIR%\build"
candle -arch x86 -dWin64=no -dBuilddir="%BINDIR%\x86\\" -dDllOk=Yes -dRealPlatform=x86 -dWinver="%VERN%" -dPuttytextver="PuTTY CAC %VERN%" "%BASEDIR%\windows\installer.wxs"
light -ext WixUIExtension -ext WixUtilExtension -sval installer.wixobj -o "%BINDIR%\puttycac-%VER%-installer.msi"
candle -arch x64 -dWin64=yes -dBuilddir="%BINDIR%\x64\\" -dDllOk=Yes -dRealPlatform=x64 -dWinver="%VERN%" -dPuttytextver="PuTTY CAC %VERN%" "%BASEDIR%\windows\installer.wxs"
light -ext WixUIExtension -ext WixUtilExtension -sval installer.wixobj -o "%BINDIR%\puttycac-64bit-%VER%-installer.msi"
POPD

:: sign the msi files
signtool sign /sha1 %CERT% /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.msi"

:: cleanup
RD /S /Q "%BASEDIR%\build"
DEL /F /Q "%BASEDIR%\doc\PuTTY.chm"
DEL /F /Q "%BASEDIR%\code\windows\putty.aps"
DEL /F /Q "%BINDIR%\*.wixpdb"

:: zip up executatables
SET POWERSHELL=POWERSHELL.EXE -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Unrestricted
PUSHD "%BINDIR%\x86%"
%POWERSHELL% -Command "Compress-Archive '*.exe' -DestinationPath '%BINDIR%\puttycac-%VER%.zip'"
POPD
PUSHD "%BINDIR%\x64%"
%POWERSHELL% -Command "Compress-Archive '*.exe' -DestinationPath '%BINDIR%\puttycac-64bit-%VER%.zip'"
POPD

:: output hash information
SET HASHFILE=%BINDIR%\puttycac-hash.txt
IF EXIST "%HASHFILE%" DEL /F "%HASHFILE%"
POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "Get-ChildItem -Include @('*.msi','*.exe','*.zip') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm SHA256 | Out-File -Append '%HASHFILE%' -Width 256"
POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "Get-ChildItem -Include @('*.msi','*.exe','*.zip') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm SHA1 | Out-File -Append '%HASHFILE%' -Width 256"
POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "Get-ChildItem -Include @('*.msi','*.exe','*.zip') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm MD5 | Out-File -Append '%HASHFILE%' -Width 256"
POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "$Data = Get-Content '%HASHFILE%'; $Data.Replace((Get-Item -LiteralPath '%BINDIR%').FullName + '\','').Trim() | Set-Content '%HASHFILE%'"

PAUSE