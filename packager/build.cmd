@ECHO OFF
TITLE Building PuTTY-CAC
SETLOCAL ENABLEDELAYEDEXPANSION
 
:: version information
SET VER=0.82u1
SET VERN=0.82.0.1

:: setup environment variables based on location of this script
SET INSTDIR=%~dp0
SET INSTDIR=%INSTDIR:~0,-1%
SET BASEDIR=%INSTDIR%\..\code
SET BINDIR=%INSTDIR%\..\binaries
SET BLDDIR=%INSTDIR%\..\build

:: cert info to use for signing
set TSAURL=http://time.certum.pl/
set LIBNAME=PuTTY-CAC
set LIBURL=https://github.com/NoMoreFood/putty-cac

:: import vs build tools
FOR /F "DELIMS=" %%X IN ('DIR "%ProgramFiles%\Microsoft Visual Studio\VsDevCmd.bat" /A /S /B') DO SET VS=%%X
CALL "%VS%"

:: build the binaries
CD /D "%INSTDIR%"
RD /S /Q "%BLDDIR%"
RD /S /Q "%BINDIR%"
FOR %%A IN (arm arm64 x86 x64) DO (
  SET ARCH=%%A
  IF /I "%%A" EQU "X86" SET ARCH=Win32
  CMAKE -S ..\code -A !ARCH! -B %BLDDIR%\%%A -D PUTTY_CAC=1 -D PUTTY_EMBEDDED_CHM_FILE=%BASEDIR%\doc\putty.chm
  CMAKE --build %BLDDIR%\%%A --parallel --config Release --target pageant plink pscp psftp pterm putty puttygen puttyimp puttytel
  MKDIR "%BINDIR%\%%A"
  COPY /Y %BLDDIR%\%%A\Release\*.exe "%BINDIR%\%%A"	
)

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup paths
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0
FOR /F "DELIMS=" %%X IN ('DIR "%PX86%\Windows Kits\10\bin\signtool.exe" /B /S /A ^| FINDSTR "\\x64\\"') DO SET PATH=%PATH%;%%~dpX
SET PATH=%PATH%;%PX86%\Windows Kits\8.1\bin\x64
FOR /F "DELIMS=" %%X IN ('DIR "%PX86%\WiX Toolset*" /B /AD') DO SET PATH=%PATH%;%PX86%\%%~nxX\bin

:: cleanup
FOR %%X IN (Win32 x64 Debug Release Temp .vs) DO (
  FORFILES /S /P "%BASEDIR%\windows" /M "%%X" /C "CMD /C IF @isdir==TRUE RD /S /Q @path" >NUL 2>&1
)
FORFILES /S /P "%BINDIR%" /M "*.*" /C "CMD /C IF /I @ext NEQ """exe""" DEL /Q @file"

:: sign the main executables
signtool sign /a /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\arm\*.exe" "%BINDIR%\arm64\*.exe" "%BINDIR%\x64\*.exe" "%BINDIR%\x64\*.exe"  
signtool sign /a /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.msi"

:: copy prereqs from build dir and 'real' installer
MKDIR "%BASEDIR%\build"
COPY /Y "%BASEDIR%\windows\*.url" "%BASEDIR%\build\"
COPY /Y "%BASEDIR%\windows\*.ico" "%BASEDIR%\build\"
COPY /Y "%BASEDIR%\windows\README-msi.txt" "%BASEDIR%\build\"
COPY /Y "%INSTDIR%\*.bmp" "%BASEDIR%\build\"

:: do the build
PUSHD "%BASEDIR%\build"
FOR %%A IN (Arm Arm64 x86 x64) DO (
  IF /I "%%A" EQU "ARM64" SET WIN64=yes
  IF /I "%%A" EQU "X64" SET WIN64=yes
  candle -arch %%A -dWin64=!WIN64! -dBuilddir="%BINDIR%\%%A\\" -dDllOk=Yes -dRealPlatform=%%A -dWinver="%VERN%" -dPUTTY_CAC=1 -dPuttytextver="PuTTY CAC %VERN%" "%BASEDIR%\windows\installer.wxs"
  light -ext WixUIExtension -ext WixUtilExtension -sval installer.wixobj -o "%BINDIR%\puttycac-%VER%-%%A.msi"
)
POPD

:: sign the msi files
signtool sign /a /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.msi"

:: cleanup
RD /S /Q "%BASEDIR%\build"
DEL /F /Q "%BASEDIR%\code\windows\putty.aps"
DEL /F /Q "%BINDIR%\*.wixpdb"

:: zip up executatables
SET POWERSHELL=POWERSHELL.EXE -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Unrestricted
FOR %%A IN (arm arm64 x86 x64) DO (
  PUSHD "%BINDIR%\%%A"
  %POWERSHELL% -Command "Compress-Archive '*.exe' -DestinationPath '%BINDIR%\puttycac-%VER%-%%A.zip'"
  POPD
)

:: output hash information
SET HASHFILE=%BINDIR%\puttycac-hash.txt
IF EXIST "%HASHFILE%" DEL /F "%HASHFILE%"
%POWERSHELL% -Command "Get-ChildItem -Include @('*.msi','*.exe','*.zip') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm SHA256 | Out-File -Append '%HASHFILE%' -Width 256"
%POWERSHELL% -Command "Get-ChildItem -Include @('*.msi','*.exe','*.zip') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm SHA1 | Out-File -Append '%HASHFILE%' -Width 256"
%POWERSHELL% -NoProfile -NonInteractive -NoLogo -Command "Get-ChildItem -Include @('*.msi','*.exe','*.zip') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm MD5 | Out-File -Append '%HASHFILE%' -Width 256"
%POWERSHELL% -NoProfile -NonInteractive -NoLogo -Command "$Data = Get-Content '%HASHFILE%'; $Data.Replace((Get-Item -LiteralPath '%BINDIR%').FullName + '\','').Trim() | Set-Content '%HASHFILE%'"

PAUSE