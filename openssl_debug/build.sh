#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libssl.a ]; then
	echo "lib exist"
	exit
fi

VERSION="1.1.1-pre8"
if [ ! -f openssl-${VERSION}.tar.gz ]; then
	wget https://www.openssl.org/source/openssl-${VERSION}.tar.gz
fi

rm -rf openssl-${VERSION}
tar xvf openssl-${VERSION}.tar.gz

cd openssl-${VERSION}

./config \
	--prefix=${ROOTDIR}/../build \
	no-shared

make
make install_sw