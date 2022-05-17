#!/bin/bash
INSTALLDIR=`pwd`/3rdparty
READLINE_LDFLAGS="-L$INSTALLDIR/lib"

echo $INSTALLDIR
echo $READLINE_LDFLAGS

# build and install ncurses from source
tar xvf ncurses-6.1.tar.gz
cd ncurses-6.1/
./configure --prefix=$INSTALLDIR
make
make install
cd ..

# build and install readline from source
tar xvf readline-7.0.tar.gz
cd readline-7.0
LDFLAGS=$READLINE_LDFLAGS ./configure --prefix=$INSTALLDIR --with-ncurses
make
make install
cd ..

# build mbedtls from source
tar xvf mbedtls-2.9.0-apache.tgz
cd mbedtls-2.9.0
rm -rf build
mkdir build
cd build
cmake ..
make
cd ../..

# copy static libraries
cp ./3rdparty/lib/libncurses.a ./3rdparty/lib/libncurses-static.a
cp ./3rdparty/lib/libreadline.a ./3rdparty/lib/libreadline-static.a

# build remote tool from source
make -f Makefile.linux
