#!/bin/sh
env LD_LIBRARY_PATH=$HOME/charm-crypto/lib:$LD_LIBRARY_PATH \
    CPATH=$HOME/charm-crypto/include:$CPATH \
    git clone https://github.com/JHUISI/charm.git && \
    cd charm && ./configure.sh && make install
