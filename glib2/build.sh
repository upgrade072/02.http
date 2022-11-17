#!/bin/bash

export ROOTDIR="${PWD}"
if [  -f ${ROOTDIR}/../build/lib/libglib-2.0.a ]; then
	echo "lib exist"
	exit
fi

VERSION="2.57.3"
if [ ! -f glib-${VERSION}.tar.xz ]; then
	wget https://download.gnome.org/sources/glib/2.57/glib-${VERSION}.tar.xz --no-check-certificate
fi

rm -rf glib-${VERSION}
tar xvf glib-${VERSION}.tar.xz

cd glib-${VERSION}

export PATH=${HOME}/ac_install/bin:$PATH
export PKG_CONFIG_PATH=${ROOTDIR}/../build/lib/pkgconfig:$PKG_CONFIG_PATH
#for some stupid system
#export PYTHON=$(python --version 2>&1 >/dev/null)

./autogen.sh
./configure \
	--prefix=${ROOTDIR}/../build \
    --with-gnu-ld \
	--disable-libmount \
	--with-pcre=internal \
	--disable-man \
	--enable-static \
	--disable-shared \
	--disable-xattr --disable-selinux 

make
make install

