#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ../../../bin/jslint ]; then
    echo "lib exist"
    exit
fi

VERSION="master"
if [ ! -f ${VERSION}.zip ]; then
    wget https://github.com/vincenthz/libjson/archive/${VSERION}.zip
fi

rm -rf libjson-${VERSION}
unzip ${VERSION}.zip

cd libjson-${VERSION}

make
cp jsonlint ~/jslint
cp jsonlint ../../../../bin/jslint
