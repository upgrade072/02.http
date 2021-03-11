#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libcli.a ]; then
    echo "lib exist"
    exit
fi

VERSION="1.10.2"
if [ ! -f V${VERSION}.tar.gz ]; then
	wget https://github.com/dparrish/libcli/archive/V${VERSION}.tar.gz
fi

rm -rf libcli-${VERSION}
tar xvf V${VERSION}.tar.gz

cd libcli-${VERSION}

patch -p2 < ../diff.patch

make
ar -rc ./libcli.a ./libcli.o
cp ./libcli.h ${ROOTDIR}/../build/include
cp ./libcli.a ${ROOTDIR}/../build/lib
