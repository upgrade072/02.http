#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ../../../bin/jslint ]; then
    echo "lib exist"
    exit
fi

VERSION="0.8"
if [ ! -f v${VERSION}.tar.gz ]; then
    wget https://github.com/vincenthz/libjson/archive/v${VERSION}.tar.gz
fi

rm -rf libjson-${VERSION}
tar xvf v${VERSION}.tar.gz

cd libjson-${VERSION}

make
cp jsonlint ~/jslint
cp jsonlint ../../../../bin/jslint
