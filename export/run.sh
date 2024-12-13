#!/bin/sh
if [ ! -d bin ]; then 
    mkdir bin 
fi

if [ ! -d bin/cache ]; then 
    mkdir bin/cache
fi
cd ./bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../lib
./demo-jxkr-tail