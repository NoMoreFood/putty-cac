@ECHO OFF
TITLE Building PuTTY-CAC
SETLOCAL ENABLEDELAYEDEXPANSION

SET SIGN_RELEASE=1
IF /I "%~1" EQU "--unsigned" SET SIGN_RELEASE=
IF NOT "%~1" EQU "" IF DEFINED SIGN_RELEASE GOTO :usage
IF NOT "%~2" EQU "" GOTO :usage

:: version information
SET VER=0.85u3
SET VERN=0.85.3.0

:: setup environment variables based on location of this script
SET INSTDIR=%~dp0
SET INSTDIR=%INSTDIR:~0,-1%
SET BASEDIR=%INSTDIR%\..\code
SET BINDIR=%INSTDIR%\..\binaries
SET BLDDIR=%INSTDIR%\..\build

:: cert info to use for signing
SET TSAURL=http://time.certum.pl/
SET LIBNAME=PuTTY-CAC
SET LIBURL=https://github.com/NoMoreFood/putty-cac

:: import vs build tools
FOR /F "USEBACKQ TOKENS=*" %%X in (`
    "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" ^
        -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
        -property installationPath
`) DO CALL "%%X\Common7\Tools\VsDevCmd.bat"

:: build the binaries
CD /D "%INSTDIR%"
IF EXIST "%BLDDIR%" RD /S /Q "%BLDDIR%"
IF EXIST "%BINDIR%" RD /S /Q "%BINDIR%"
IF EXIST "%BLDDIR%" GOTO :failed
IF EXIST "%BINDIR%" GOTO :failed
FOR %%A IN (arm64 x86 x64) DO (
  SET ARCH=%%A
  IF /I "%%A" EQU "X86" SET ARCH=Win32
  CMAKE -S "%BASEDIR%" -A !ARCH! -B "%BLDDIR%\%%A" -DPUTTY_CAC=1 "-DPUTTY_EMBEDDED_CHM_FILE=%BASEDIR%\doc\putty.chm"
  IF ERRORLEVEL 1 GOTO :failed
  CMAKE --build "%BLDDIR%\%%A" --parallel --config Release --target pageant plink pscp psftp pterm putty puttygen ^
    puttyimp puttytab puttytel
  IF ERRORLEVEL 1 GOTO :failed
  MKDIR "%BINDIR%\%%A"
  IF ERRORLEVEL 1 GOTO :failed
  COPY /Y "%BLDDIR%\%%A\Release\*.exe" "%BINDIR%\%%A"
  IF ERRORLEVEL 1 GOTO :failed
)

:: verify the binaries do not import the dynamic C/C++ runtime
WHERE DUMPBIN.EXE >NUL 2>&1
IF ERRORLEVEL 1 (
  ECHO ERROR: dumpbin.exe not found; cannot verify static runtime linkage.
  GOTO :failed
)
SET CRTDLLS=vcruntime.*\.dll msvcp.*\.dll msvcr.*\.dll msvcm.*\.dll concrt.*\.dll
SET CRTDLLS=%CRTDLLS% ucrtbase.*\.dll api-ms-win-crt-.*\.dll
FOR /R "%BINDIR%" %%F IN (*.exe) DO (
  DUMPBIN.EXE /NOLOGO /DEPENDENTS "%%F" > "%BLDDIR%\dependencies.txt"
  IF ERRORLEVEL 1 GOTO :failed
  FINDSTR /I /R "%CRTDLLS%" "%BLDDIR%\dependencies.txt"
  IF ERRORLEVEL 2 GOTO :failed
  IF NOT ERRORLEVEL 1 (
    ECHO ERROR: %%F imports the dynamic runtime.
    ECHO ERROR: rebuild with the static runtime before packaging.
    GOTO :failed
  )
)

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup paths
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0
FOR /F "DELIMS=" %%X IN ('DIR "%PX86%\Windows Kits\10\bin\signtool.exe" /B /S /A ^| FINDSTR "\\x64\\"') DO SET PATH=%PATH%;%%~dpX
SET PATH=%PATH%;%PX86%\Windows Kits\8.1\bin\x64
FOR /F "DELIMS=" %%X IN ('DIR "%PX86%\WiX Toolset*" /B /AD') DO SET PATH=%PATH%;%PX86%\%%~nxX\bin

:: sign the main executables
IF DEFINED SIGN_RELEASE (
  SIGNTOOL sign /a /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% ^
    "%BINDIR%\arm64\*.exe" "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe"
  IF ERRORLEVEL 1 GOTO :failed
)

:: build and sign the installers
FOR %%A IN (Arm64 x86 x64) DO (
  SET LOWERA=%%A
  IF /I "%%A" EQU "ARM64" SET LOWERA=arm64
  CANDLE -arch %%A -dBuilddir="%BINDIR%\%%A\\" -dDllOk=Yes -dRealPlatform=%%A -dWinver=%VERN% ^
    -dPUTTY_CAC=1 -dPuttytextver="PuTTY CAC %VERN%" -out "%BLDDIR%\installer-%%A.wixobj" ^
    "%BASEDIR%\windows\installer.wxs"
  IF ERRORLEVEL 1 GOTO :failed
  LIGHT -ext WixUIExtension -ext WixUtilExtension -sval -spdb -b "%BASEDIR%\windows" ^
    "%BLDDIR%\installer-%%A.wixobj" -out "%BINDIR%\puttycac-%VER%-!LOWERA!.msi"
  IF ERRORLEVEL 1 GOTO :failed
)
IF DEFINED SIGN_RELEASE (
  SIGNTOOL sign /a /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.msi"
  IF ERRORLEVEL 1 GOTO :failed
)

:: zip the executables
SET PSModulePath=%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules
SET POWERSHELL=POWERSHELL.EXE -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Unrestricted
FOR %%A IN (arm64 x86 x64) DO (
  %POWERSHELL% -Command "$ErrorActionPreference='Stop'; $dest=Join-Path $env:BINDIR 'puttycac-%VER%-%%A.zip';" ^
    "Compress-Archive (Join-Path $env:BINDIR '%%A\*.exe') -DestinationPath $dest -Force"
  IF ERRORLEVEL 1 GOTO :failed
)

:: output hash information
SET HASHFILE=%BINDIR%\puttycac-hash.txt
IF EXIST "%HASHFILE%" DEL /F /Q "%HASHFILE%"
IF EXIST "%HASHFILE%" GOTO :failed
FOR %%H IN (SHA256 SHA1 MD5) DO (
  %POWERSHELL% -Command "$ErrorActionPreference='Stop'; $root=(Get-Item -LiteralPath $env:BINDIR).FullName+'\';" ^
    "$files=Get-ChildItem -Path $root -File -Recurse -Include *.msi,*.exe,*.zip;" ^
    "$format='{0,-9} {1,-64} {2}'; @($format -f 'Algorithm','Hash','Path'; $files | Get-FileHash -Algorithm %%H |" ^
    "ForEach-Object { $format -f $_.Algorithm,$_.Hash,$_.Path.Substring($root.Length) })" ^
    "| Add-Content -Encoding ASCII -LiteralPath $env:HASHFILE"
  IF ERRORLEVEL 1 GOTO :failed
)
EXIT /B 0

:usage
ECHO Usage: %~nx0 [--unsigned]
:failed
EXIT /B 1
