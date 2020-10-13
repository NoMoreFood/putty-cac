echo on

:: setup environment variables based on location of this script
SET INSTDIR=%~dp0
SET INSTDIR=%INSTDIR:~0,-1%
SET BASEDIR=%INSTDIR%\..\code
SET BINDIR=%INSTDIR%\..\binaries

copy /B %BINDIR%\puttycac-hash.txt %BINDIR%\puttycac-hash-test-org.txt

set d2uINfile=%BINDIR%\puttycac-hash-test-org.txt
set d2uOUTfile=%BINDIR%\puttycac-hash-test-org.txt


dos2unix.exe --info -ascii --keep-bom --verbose --keep-utf16 --newfile %d2uINfile% %d2uOUTfile%.unix
unix2dos.exe --info -ascii --keep-bom --verbose --keep-utf16 --newfile %d2uINfile%.unix %d2uOUTfile%.dos
unix2mac.exe --info -ascii --keep-bom --verbose --keep-utf16 --newfile %d2uINfile%.unix %d2uOUTfile%.mac
mac2unix.exe --info -ascii --keep-bom --verbose --keep-utf16 --newfile %d2uINfile%.mac %d2uOUTfile%.back2unix


copy /B %BINDIR%\puttycac-hash-test-org.txt.dos %BINDIR%\puttycac-hash-test-tmp.txt.dos2unix1
copy /B %BINDIR%\puttycac-hash-test-org.txt.unix %BINDIR%\puttycac-hash-test-tmp.txt.dos2unix2
copy /B %BINDIR%\puttycac-hash-test-org.txt.mac %BINDIR%\puttycac-hash-test-tmp.txt.dos2unix3

copy /B %BINDIR%\puttycac-hash-test-org.txt.dos %BINDIR%\puttycac-hash-test-tmp.txt.unix2dos1
copy /B %BINDIR%\puttycac-hash-test-org.txt.unix %BINDIR%\puttycac-hash-test-tmp.txt.unix2dos2
copy /B %BINDIR%\puttycac-hash-test-org.txt.mac %BINDIR%\puttycac-hash-test-tmp.txt.unix2dos3

copy /B %BINDIR%\puttycac-hash-test-org.txt.dos %BINDIR%\puttycac-hash-test-tmp.txt.unix2mac1
copy /B %BINDIR%\puttycac-hash-test-org.txt.unix %BINDIR%\puttycac-hash-test-tmp.txt.unix2mac2
copy /B %BINDIR%\puttycac-hash-test-org.txt.mac %BINDIR%\puttycac-hash-test-tmp.txt.unix2mac3

copy /B %BINDIR%\puttycac-hash-test-org.txt.dos %BINDIR%\puttycac-hash-test-tmp.txt.mac2unix1
copy /B %BINDIR%\puttycac-hash-test-org.txt.unix %BINDIR%\puttycac-hash-test-tmp.txt.mac2unix2
copy /B %BINDIR%\puttycac-hash-test-org.txt.mac %BINDIR%\puttycac-hash-test-tmp.txt.mac2unix3

mkdir %BINDIR%\FOO\
copy %BINDIR%\puttycac-hash-test-tmp.txt.* %BINDIR%\FOO\


::goto :maineof

goto :main

:_2dos
SETLOCAL
CALL :_dos2unix %1
CALL :_mac2unix %1
CALL :_unix2dos %1
ENDLOCAL & SET _result=%_var2% & EXIT /B
goto :eof

:_2unix
SETLOCAL
CALL :_dos2unix %1
CALL :_mac2unix %1
ENDLOCAL & SET _result=%_var2% & EXIT /B
goto :eof

:_2mac
SETLOCAL
CALL :_dos2unix %1
CALL :_unix2mac %1
ENDLOCAL & SET _result=%_var2% & EXIT /B
goto :eof



:_dos2unix
:: dos2unix, powershell => v2
   SETLOCAL
   set _HASHFILE=%1
   POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "$original_file =(Convert-Path %_HASHFILE%) ; $text = [IO.File]::ReadAllText($original_file) -replace \"`r`n\", \"`n\" ; [IO.File]::WriteAllText($original_file, $text)"
ENDLOCAL & SET _result=%_var2% & EXIT /B
goto :eof

:_unix2dos
:: unix2dos, powershell => v2
   SETLOCAL
   set _HASHFILE=%1
   POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "$original_file =(Convert-Path %_HASHFILE%) ; $text = [IO.File]::ReadAllText($original_file) -replace \"`n\", \"`r`n\" ; [IO.File]::WriteAllText($original_file, $text)"
ENDLOCAL & SET _result=%_var2% & EXIT /B
goto :eof

:_unix2mac
:: unix2mac, powershell => v2
   SETLOCAL
   set _HASHFILE=%1
   POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "$original_file =(Convert-Path %_HASHFILE%) ; $text = [IO.File]::ReadAllText($original_file) -replace \"`n\", \"`r\" ; [IO.File]::WriteAllText($original_file, $text)"
ENDLOCAL & SET _result=%_var2% & EXIT /B
goto :eof

:_mac2unix
:: mac2unix, powershell => v2
   SETLOCAL
   set _HASHFILE=%1
   POWERSHELL -NoProfile -NonInteractive -NoLogo -Command "$original_file =(Convert-Path %_HASHFILE%) ; $text = [IO.File]::ReadAllText($original_file) -replace \"`r\", \"`n\" ; [IO.File]::WriteAllText($original_file, $text)"
ENDLOCAL & SET _result=%_var2% & EXIT /B
goto :eof


:main



set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.unix2dos1"
CALL :_2dos %HASHFILE%
set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.unix2dos2"
CALL :_2dos %HASHFILE%
set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.unix2dos3"
CALL :_2dos %HASHFILE%


set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.dos2unix1"
CALL :_2unix %HASHFILE%
set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.dos2unix2"
CALL :_2unix %HASHFILE%
set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.dos2unix3"
CALL :_2unix %HASHFILE%


set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.unix2mac1"
CALL :_2mac %HASHFILE%
set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.unix2mac2"
CALL :_2mac %HASHFILE%
set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.unix2mac3"
CALL :_2mac %HASHFILE%

set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.mac2unix1"
CALL :_2unix %HASHFILE%

set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.mac2unix2"
CALL :_2unix %HASHFILE%

set HASHFILE="%BINDIR%\puttycac-hash-test-tmp.txt.mac2unix3"
CALL :_2unix %HASHFILE%


ENDLOCAL
goto :maineof


:maineof