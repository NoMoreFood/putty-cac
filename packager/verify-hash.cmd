echo on

:: setup environment variables based on location of this script
SET INSTDIR=%~dp0
SET INSTDIR=%INSTDIR:~0,-1%
SET BASEDIR=%INSTDIR%\..\code
SET BINDIR=%INSTDIR%\..\binaries

SET PREFIX=puttycac-hash.txt

cd %BINDIR%

md5sum -c %PREFIX%.md5sum
sha1sum -c %PREFIX%.sha1sum
sha256sum -c %PREFIX%.sha256sum
::sha512sum -c *.sha512sum

::FOR %%X IN (.md5sum) DO (
:::  FORFILES /S /P "%BASEDIR%\windows" /M "%%X" /C "CMD /C IF @isdir==TRUE RD /S /Q @path" >NUL 2>&1

busybox md5sum -c %PREFIX%.md5sum
busybox sha1sum -c %PREFIX%.sha1sum
busybox sha256sum -c %PREFIX%.sha256sum
busybox sha512sum -c %PREFIX%.sha512sum
::)

md5sum -c %PREFIX%.hashsums
sha1sum -c %PREFIX%.hashsums
sha256sum -c %PREFIX%.hashsums
::sha512sum -c *.hashsums

::shasum -c %PREFIX%.sha1sum
::shasum -c %PREFIX%.sha256sum
::shasum -c %PREFIX%.sha512sum


rhash --verbose -c %PREFIX%.md5sum
rhash --verbose -c %PREFIX%.sha1sum
rhash --verbose -c %PREFIX%.sha256sum
rhash --verbose -c %PREFIX%.sha512sum
rhash --verbose -c %PREFIX%.hashsums

echo now some tests will fail:
::shasum -c %PREFIX%.hashsums
busybox md5sum -c %PREFIX%.hashsums
busybox sha1sum -c %PREFIX%.hashsums
busybox sha256sum -c %PREFIX%.hashsums
busybox sha512sum -c %PREFIX%.hashsums

cd ..\packager
cd %INSTDIR%