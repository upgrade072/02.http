#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libcli.a ]; then
    echo "lib exist"
    exit
fi

VERSION="1.9.4"
if [ ! -f libcli-${VERSION}.tar.gz ]; then
	wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/libcli/libcli-${VERSION}.tar.gz
fi

rm -rf libcli-${VERSION}
tar xvf libcli-${VERSION}.tar.gz

cd libcli-${VERSION}

patch -p2 < ../diff.patch

make
ar -rc ./libcli.a ./libcli.o
cp ./libcli.h ${ROOTDIR}/../build/include
cp ./libcli.a ${ROOTDIR}/../build/lib
