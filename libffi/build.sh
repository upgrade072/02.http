#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib64/libffi.a ]; then
    echo "lib exist"
    exit
fi

VERSION="3.2.1"
if [ ! -f libffi-${VERSION}.tar.gz ]; then
	wget ftp://sourceware.org/pub/libffi/libffi-${VERSION}.tar.gz
fi

rm -rf libffi-${VERSION}
tar xvf libffi-${VERSION}.tar.gz

cd libffi-${VERSION}

./configure \
	--prefix=${ROOTDIR}/../build \
    --with-gnu-ld \
	--enable-static \
	--disable-shared

make
make install

