#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libjansson.a ]; then
    echo "lib exist"
    exit
fi

VERSION="2.12"
if [ ! -f jansson-${VERSION}.tar.gz ]; then
	wget http://www.digip.org/jansson/releases/jansson-${VERSION}.tar.gz
fi

rm -rf jansson-${VERSION}
tar xvf jansson-${VERSION}.tar.gz

cd jansson-${VERSION}

./configure \
	--prefix=${ROOTDIR}/../build \
	--enable-static \
	--disable-shared

make
make install
