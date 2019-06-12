#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libnghttp2.a ]; then
    echo "lib exist"
    exit
fi

VERSION="1.31.1"
if [ ! -f nghttp2-${VERSION}.tar.gz ]; then
	wget https://github.com/nghttp2/nghttp2/releases/download/v${VERSION}/nghttp2-${VERSION}.tar.gz
fi

rm -rf nghttp2-${VERSION}
tar xvf nghttp2-${VERSION}.tar.gz

cd nghttp2-${VERSION}

patch -p2 < ../diff.patch

./configure \
	--prefix=${ROOTDIR}/../build \
	--enable-static \
	--disable-shared \
	LDFLAGS=-L${ROOTDIR}/../build/lib \
	PKG_CONFIG_PATH=${ROOTDIR}/../build/lib/pkgconfig

make
make install

#extra
ar rc third-party/http-parser/http_parser.a third-party/http-parser/http_parser.o
cp third-party/http-parser/http_parser.a ${ROOTDIR}/../build/lib
cp third-party/http-parser/http_parser.h ${ROOTDIR}/../build/include

#for nghttp2 handling (ovld ctrl)
cp lib/*.h ${ROOTDIR}/../build/include
