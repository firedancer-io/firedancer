#!/bin/bash

echo "install wrk with:"
echo "  git clone https://github.com/wg/wrk.git"
echo "  cd wrk"
echo "  make"

echo
echo "single thread, small responses"
./wrk -c 1 -d 10 -t 1 --latency http://localhost:4321/small

echo
echo "single thread, big responses"
./wrk -c 1 -d 10 -t 1 --latency http://localhost:4321/big

echo
echo "multi-threaded, small responses"
./wrk -c 30 -d 10 -t 30 --latency http://localhost:4321/small

echo
echo "super multi-threaded, small responses"
./wrk -c 100 -d 10 -t 50 --latency http://localhost:4321/small

echo
echo "multi-threaded, big responses"
./wrk -c 5 -d 10 -t 5 --latency http://localhost:4321/big
