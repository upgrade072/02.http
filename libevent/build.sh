#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libevent.a ]; then
    echo "lib exist"
    exit
fi

VERSION="2.1.8-stable"
if [ ! -f libevent-${VERSION}.tar.gz ]; then
	wget https://github.com/libevent/libevent/releases/download/release-${VERSION}/libevent-${VERSION}.tar.gz
fi

rm -rf libevent-${VERSION}
tar xvf libevent-${VERSION}.tar.gz

cd libevent-${VERSION}

patch -p2 < ../00-evhttp-add-func.patch

export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):${ROOTDIR}/../build/lib/pkgconfig

./configure \
	--prefix=${ROOTDIR}/../build \
	--enable-static \
	--disable-shared \
	CFLAGS="$(CFLAGS) -I${ROOTDIR}/../build/include" \
	LDFLAGS="$(LDFLAGS) -L${ROOTDIR}/../build/lib" \
	LIBS="$(LIBS) -L${ROOTDIR}/../build/lib -ldl -lpthread"

make
make install
