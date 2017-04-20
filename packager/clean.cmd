@ECHO OFF

FOR %%X IN (Win32 x64 Debug Release Temp .vs) DO (
  FORFILES /S /P "%~dp0..\windows" /M "%%X" /C "CMD /C IF @isdir==TRUE RD /S /Q @path"
)
FOR %%X IN (Win32 x64 Debug Release) DO (
  FORFILES /S /P "%~dp0..\binaries" /M "*.pdb" /C "CMD /C DEL /Q @path"
  FORFILES /S /P "%~dp0..\binaries" /M "*.log" /C "CMD /C DEL /Q @path"
)

PAUSE