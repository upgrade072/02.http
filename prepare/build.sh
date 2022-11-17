#!/bin/bash

export PATH=${HOME}/ac_install/bin:$PATH

if [ ! -d ${HOME}/ac_install ]; then

	if [ ! -f ./autoconf-2.69.tar.gz ]; then
		curl -O http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
	fi
	if [ ! -f ./automake-1.15.tar.gz ]; then
		curl -O http://ftp.gnu.org/gnu/automake/automake-1.15.tar.gz
	fi
	if [ ! -f ./libtool-2.4.2tar.gz ]; then
		curl -O http://ftp.gnu.org/gnu/libtool/libtool-2.4.2.tar.gz
	fi
	if [ ! -f ./pkg-config-0.29.2.tar.gz ]; then
		wget https://pkg-config.freedesktop.org/releases/pkg-config-0.29.2.tar.gz
	fi

	tar xzf autoconf-2.69.tar.gz
	tar xzf automake-1.15.tar.gz
	tar xzf libtool-2.4.2.tar.gz
	tar xvf pkg-config-0.29.2.tar.gz

	(cd autoconf-2.69 && \
	  ./configure --prefix ${HOME}/ac_install && \
	  make && \
	  make install)

	alias autoconf=${HOME}/ac_install/bin/autoconf

	(cd automake-1.15 && \
	  ./configure --prefix ${HOME}/ac_install && \
	  make && \
	  make install)

	alias automake=${HOME}/ac_install/bin/automake

	(cd libtool-2.4.2 && \
	  ./configure --prefix ${HOME}/ac_install && \
	  make && \
	  make install)

	alias libtool=${HOME}/ac_install/bin/libtool

	(cd pkg-config-0.29.2 && \
	  ./configure --prefix ${HOME}/ac_install --with-internal-glib && \
	  make && \
	  make install)

	alias pkg-config=${HOME}/ac_install/bin/pkg-config
fi

