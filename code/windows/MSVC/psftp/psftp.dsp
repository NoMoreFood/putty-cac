# Microsoft Developer Studio Project File - Name="psftp" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=psftp - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "psftp.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "psftp.mak" CFG="psftp - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "psftp - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "psftp - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "psftp - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /I "..\..\..\./" /I "..\..\..\charset/" /I "..\..\..\windows/" /I "..\..\..\unix/" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\..\./" /I "..\..\..\charset/" /I "..\..\..\windows/" /I "..\..\..\unix/" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 advapi32.lib comdlg32.lib gdi32.lib imm32.lib ole32.lib shell32.lib user32.lib /nologo /subsystem:console /machine:I386
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "psftp - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /I "..\..\..\./" /I "..\..\..\charset/" /I "..\..\..\windows/" /I "..\..\..\unix/" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /Od /I "..\..\..\./" /I "..\..\..\charset/" /I "..\..\..\windows/" /I "..\..\..\unix/" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 advapi32.lib comdlg32.lib gdi32.lib imm32.lib ole32.lib shell32.lib user32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "psftp - Win32 Release"
# Name "psftp - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\..\agentf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\aqsync.c
# End Source File
# Begin Source File

SOURCE=..\..\..\be_misc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\be_ssh.c

!IF  "$(CFG)" == "psftp - Win32 Release"

!ELSEIF  "$(CFG)" == "psftp - Win32 Debug"

# ADD CPP /Zi

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\callback.c
# End Source File
# Begin Source File

SOURCE=..\..\..\clicons.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cmdline.c
# End Source File
# Begin Source File

SOURCE=..\..\..\conf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\console.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cproxy.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ecc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\errsock.c
# End Source File
# Begin Source File

SOURCE=..\..\..\logging.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mainchan.c
# End Source File
# Begin Source File

SOURCE=..\..\..\marshal.c
# End Source File
# Begin Source File

SOURCE=..\..\..\memory.c
# End Source File
# Begin Source File

SOURCE=..\..\..\misc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\miscucs.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpint.c
# End Source File
# Begin Source File

SOURCE=..\..\..\noshare.c
# End Source File
# Begin Source File

SOURCE=..\..\..\nullplug.c
# End Source File
# Begin Source File

SOURCE=..\..\..\pgssapi.c
# End Source File
# Begin Source File

SOURCE=..\..\..\pinger.c
# End Source File
# Begin Source File

SOURCE=..\..\..\portfwd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\proxy.c
# End Source File
# Begin Source File

SOURCE=..\..\..\psftp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\psftpcommon.c
# End Source File
# Begin Source File

SOURCE=..\..\..\settings.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sftp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sftpcommon.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh.c

!IF  "$(CFG)" == "psftp - Win32 Release"

!ELSEIF  "$(CFG)" == "psftp - Win32 Debug"

# ADD CPP /Zi

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\ssh1bpp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh1censor.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh1connection-client.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh1connection.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh1login.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2bpp-bare.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2bpp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2censor.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2connection-client.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2connection.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2kex-client.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2transhk.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2transport.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2userauth.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshaes.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ssharcf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshargon2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshauxcrypt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshblake2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshblowf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshccp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshcommon.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshcrc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshcrcda.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshdes.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshdh.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshdss.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshecc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshgssc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshhmac.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshmac.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshmd5.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshprng.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshpubk.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshrand.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshrsa.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshsh256.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshsh512.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshsha.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshsha3.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshshare.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshutils.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshverstring.c
# End Source File
# Begin Source File

SOURCE=..\..\..\sshzlib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\stripctrl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\timing.c
# End Source File
# Begin Source File

SOURCE=..\..\..\tree234.c
# End Source File
# Begin Source File

SOURCE=..\..\..\utils.c
# End Source File
# Begin Source File

SOURCE=..\..\..\version.c
# End Source File
# Begin Source File

SOURCE=..\..\..\wcwidth.c
# End Source File
# Begin Source File

SOURCE=..\..\..\wildcard.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\wincapi.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\wincliloop.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\wincons.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\windefs.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\wingss.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winhandl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winhsock.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winmisc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winmiscs.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winnet.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winnohlp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winnoise.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winnojmp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winnpc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winnps.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winpgntc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winproxy.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winsecur.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winselcli.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winsftp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winshare.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winstore.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\wintime.c
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winucs.c
# End Source File
# Begin Source File

SOURCE=..\..\..\x11fwd.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\..\charset\charset.h
# End Source File
# Begin Source File

SOURCE=..\..\..\console.h
# End Source File
# Begin Source File

SOURCE=..\..\..\defs.h
# End Source File
# Begin Source File

SOURCE=..\..\..\ecc.h
# End Source File
# Begin Source File

SOURCE=..\..\..\empty.h
# End Source File
# Begin Source File

SOURCE=..\..\..\licence.h
# End Source File
# Begin Source File

SOURCE=..\..\..\marshal.h
# End Source File
# Begin Source File

SOURCE=..\..\..\misc.h
# End Source File
# Begin Source File

SOURCE=..\..\..\mpint.h
# End Source File
# Begin Source File

SOURCE=..\..\..\mpint_i.h
# End Source File
# Begin Source File

SOURCE=..\..\..\network.h
# End Source File
# Begin Source File

SOURCE=..\..\..\pageant.h
# End Source File
# Begin Source File

SOURCE=..\..\..\pgssapi.h
# End Source File
# Begin Source File

SOURCE=..\..\..\proxy.h
# End Source File
# Begin Source File

SOURCE=..\..\..\psftp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\putty.h
# End Source File
# Begin Source File

SOURCE=..\..\..\puttymem.h
# End Source File
# Begin Source File

SOURCE=..\..\..\puttyps.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sftp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh.h
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh1connection.h
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2connection.h
# End Source File
# Begin Source File

SOURCE=..\..\..\ssh2transport.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshblowf.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshbpp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshchan.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshcr.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshgss.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshgssc.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshppl.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshserver.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshsignals.h
# End Source File
# Begin Source File

SOURCE=..\..\..\sshttymodes.h
# End Source File
# Begin Source File

SOURCE=..\..\..\storage.h
# End Source File
# Begin Source File

SOURCE=..\..\..\terminal.h
# End Source File
# Begin Source File

SOURCE=..\..\..\tree234.h
# End Source File
# Begin Source File

SOURCE=..\..\..\unix\unix.h
# End Source File
# Begin Source File

SOURCE=..\..\..\version.h
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\rcstuff.h
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\wincapi.h
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winhelp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winsecur.h
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\winstuff.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=..\..\..\windows\pscp.ico
# End Source File
# Begin Source File

SOURCE=..\..\..\windows\psftp.rc
# End Source File
# End Group
# End Target
# End Project
