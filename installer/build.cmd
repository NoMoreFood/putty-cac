@ECHO OFF

SET VER=0.68
IF DEFINED ProgramFiles SET PATH=%PATH%;%ProgramFiles%\WiX Toolset v3.11\bin
IF DEFINED ProgramFiles(x86) SET PATH=%PATH%;%ProgramFiles(x86)%\WiX Toolset v3.11\bin

:: copy prereqs from build dir and 'real' installer
COPY /Y "%ProgramFiles(x86)%\PuTTY\PuTTY.chm" "..\doc"
COPY /Y "%ProgramFiles%\PuTTY\PuTTY.chm" "..\doc"
COPY /Y "%ProgramFiles(x86)%\PuTTY\*.url" ".\"
COPY /Y "%ProgramFiles%\PuTTY\PuTTY\*.url" ".\"
COPY /Y "..\windows\*.ico" .
COPY /Y "..\windows\README-msi.txt" .

:: copy binaries locally
MKDIR .\x86
MKDIR .\x64
COPY /Y "..\executables\*.exe" ".\x86"
COPY /Y "..\executables\x64\*.exe" ".\x64"

:: do the build
candle -arch x86 -dWin64=no -dBuilddir=.\x86\ -dWinver="6.1" -dPuttytextver="PuTTY CAC 0.68" ..\windows\installer.wxs && light -ext WixUIExtension -ext WixUtilExtension -sval installer.wixobj -o "puttycac-%VER%-installer.msi"
candle -arch x64 -dWin64=yes -dBuilddir=.\x64\ -dWinver="6.1" -dPuttytextver="PuTTY CAC 0.68" ..\windows\installer.wxs && light -ext WixUIExtension -ext WixUtilExtension -sval installer.wixobj -o "puttycac-64bit-%VER%-installer.msi"

DEL /Q "..\doc\PuTTY.chm"
RD /S /Q ".\x86"
RD /S /Q ".\x64"
DEL /Q "*.url"
DEL /Q "*.ico"
DEL /Q "*.wix*"
DEL /Q "*.txt*"

PAUSE