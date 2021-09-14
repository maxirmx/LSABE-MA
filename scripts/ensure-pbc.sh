#!/bin/sh
#
#  $1 - python location or empty/unset
#  like /opt/hostedtoolcache/Python/3.8.11/x64
#

mkdir -p pbc
cd pbc 

if [ ! -f pbc-0.5.14.tar.gz ]; then
  wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
fi

rm -rf pbc-0.5.14
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14

if [ -n "$1" ]; then
  ./configure --prefix=$1
else
  ./configure
fi

make install 
cd ..
rm -rf pbc-0.5.14