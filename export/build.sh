#!/bin/sh

rm -fr build bin
mkdir bin bin/cache
g++ demo/main-jxkr-tail.cpp -o ./bin/demo-jxkr-tail -I./inc -L./lib -ljxkr_shfeapi -lcrypto -ldl -lpthread -lrt -O3 -std=c++11
g++ demo/main-jxkr-normal.cpp -o ./bin/demo-jxkr-normal -I./inc -L./lib -ljxkr_shfeapi -lcrypto -ldl -lpthread -lrt -O3 -std=c++11
g++ demo/main-jxkr-buzyloop.cpp -o ./bin/demo-jxkr-buzyloop -I./inc -L./lib -ljxkr_shfeapi -lcrypto -ldl -lpthread -lrt -O3 -std=c++11