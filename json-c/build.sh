#!/bin/bash -x

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libjson-c.a ]; then
    echo "lib exist"
    exit
fi

VERSION="0.13.1-20180305" 
if [ ! -f ${VERSION}.zip ]; then
	wget https://github.com/json-c/json-c/archive/json-c-${VERSION}.tar.gz
fi

rm -rf json-c-${VERSION}
tar xvf json-c-${VERSION}.tar.gz

cd json-c-json-c-${VERSION}

export PATH=${HOME}/ac_install/bin:$PATH
export PKG_CONFIG_PATH=${ROOTDIR}/../build/lib/pkgconfig:$PKG_CONFIG_PATH

./autogen.sh
./configure \
	--prefix=${ROOTDIR}/../build \
    --with-gnu-ld \
	--enable-threading \
	--enable-static \
	--disable-shared

make
make install
