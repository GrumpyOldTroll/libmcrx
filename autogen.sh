#!/bin/sh -e

autoreconf --install --symlink

libdir() {
        echo $(cd $1/$(gcc -print-multi-os-directory 2>/dev/null); pwd)
}

args="--prefix=/usr \
--sysconfdir=/etc \
--libdir=$(libdir /usr/lib)"

echo
echo "----------------------------------------------------------------"
echo "Initialized build system. For a common configuration please run:"
echo "----------------------------------------------------------------"
echo
echo "./configure CFLAGS='-g -O0' $args"
echo
