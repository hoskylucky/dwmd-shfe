#!/bin/bash

output=$1

cd export

rm -fr include && mkdir include && cp -fr ../include/jxkr_mdapi.h ./include/
rm -fr demo && mkdir demo && cp -fr ../package/main*.cpp ./demo/
cp -fr ../build/src/libjxkr_shfeapi.a ./lib/

rm -fr *.tar.gz
tar czvf $output.tar.gz demo include lib etc build.sh run.sh