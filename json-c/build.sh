#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libjson-c.a ]; then
    echo "lib exist"
    exit
fi

VERSION="json-c-0.13.1-20180305"
if [ ! -f ${VERSION}.tar.gz ]; then
	wget https://github.com/json-c/json-c/archive/${VERSION}.tar.gz
fi

rm -rf json-c-${VERSION}
tar xvf ${VERSION}.tar.gz

cd json-c-${VERSION}

export PATH=${HOME}/ac_install/bin:$PATH
export PKG_CONFIG_PATH=${ROOTDIR}/../build/lib/pkgconfig:$PKG_CONFIG_PATH

#./autogen.sh
autoreconf --force --install
./configure \
	--prefix=${ROOTDIR}/../build \
    --with-gnu-ld \
	--enable-threading \
	--enable-static \
	--disable-shared

make
make install
