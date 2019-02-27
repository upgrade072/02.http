#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libjson-c.a ]; then
    echo "lib exist"
    exit
fi

VERSION="master"
if [ ! -f ${VERSION}.zip ]; then
	wget https://github.com/json-c/json-c/archive/${VERSION}.zip
fi

rm -rf json-c-${VERSION}
unzip ${VERSION}.zip

cd json-c-${VERSION}

export PATH=${HOME}/ac_install/bin:$PATH
export PKG_CONFIG_PATH=${ROOTDIR}/../build/lib/pkgconfig:$PKG_CONFIG_PATH

./autogen.sh
./configure \
	--prefix=${ROOTDIR}/../build \
    --with-gnu-ld \
	--enable-static \
	--disable-shared

make
make install
