#!/bin/sh
#
#  $1 - python location or empty/unset
#  like /opt/hostedtoolcache/Python/3.8.11/x64

    rm -rf charm
    git clone https://github.com/JHUISI/charm.git --depth 1
    cd charm
    ./configure.sh 

    if [ -n "$1" ]; then
      echo Linking pbc from $pythonLocation
      env C_INCLUDE_PATH=$1/include:$C_INCLUDE_PATH \
          LIBRARY_PATH=$1/lib:$LIBRARY_PATH         \
          make install
    else
      echo Linking pbc from /usr/local
      make install
    fi
    cd ..
    rm -rf charm
