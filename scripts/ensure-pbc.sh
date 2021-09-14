#!/bin/sh
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
tar -xvf pbc-0.5.14.tar.gz && \
cd pbc-0.5.14 && ./configure && make install 