#!/bin/sh
    git clone https://github.com/JHUISI/charm.git && \
    cd charm && ./configure.sh && ls -l /usr/local/include && make && make install
