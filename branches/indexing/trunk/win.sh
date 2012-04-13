#!/bin/sh

make distclean
./configure --host=i386-mingw32 CXXFLAGS="-Wall -W -O2"
make
