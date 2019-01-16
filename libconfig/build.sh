#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libconfig.a ]; then
    echo "lib exist"
    exit
fi

VERSION="1.7.2"
if [ ! -f libconfig-${VERSION}.tar.gz ]; then
	wget https://hyperrealm.github.io/libconfig/dist/libconfig-${VERSION}.tar.gz
fi

rm -rf libconfig-${VERSION}
tar xvf libconfig-${VERSION}.tar.gz

cd libconfig-${VERSION}

./configure \
	--prefix=${ROOTDIR}/../build \
	--enable-static \
	--disable-shared

make
make install
