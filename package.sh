#!/bin/bash

output=$1

cd export

rm -fr include && mkdir include && cp -fr ../include/jxkr*.h ./include/
rm -fr demo && mkdir demo && cp -fr ../src/demo/main*.cpp ./demo/
cp -fr ../build/src/api/libjxkr_dceapi.a ./lib/ && cp -fr ../deps/instanta/lib/liblayer2vi.a ./lib/

rm -fr *.tar.gz
tar czvf $output.tar.gz demo include lib etc build.sh run.sh