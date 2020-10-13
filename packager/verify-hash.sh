#!/bin/sh

set -vx
BINDIR=$PWD/../binaries/
cd $BINDIR

file *.md5sum *.sha1sum *.sha256sum *.sha512sum *.hashsums
md5sum -c *.md5sum
sha1sum -c *.sha1sum
sha256sum -c *.sha256sum
sha512sum -c *.sha512sum

busybox md5sum -c *.md5sum
busybox sha1sum -c *.sha1sum
busybox sha256sum -c *.sha256sum
busybox sha512sum -c *.sha512sum

md5sum -c *.hashsums
sha1sum -c *.hashsums
sha256sum -c *.hashsums
sha512sum -c *.hashsums

shasum -c *.sha1sum
shasum -c *.sha256sum
shasum -c *.sha512sum

rhash --verbose -c %PREFIX%.md5sum
rhash --verbose -c %PREFIX%.sha1sum
rhash --verbose -c %PREFIX%.sha256sum
rhash --verbose -c %PREFIX%.sha512sum
rhash --verbose -c %PREFIX%.hashsums

echo now some tests will fail:
shasum -c *.hashsums
busybox md5sum -c *.hashsums
busybox sha1sum -c *.hashsums
busybox sha256sum -c *.hashsums
busybox sha512sum -c *.hashsums

cd -