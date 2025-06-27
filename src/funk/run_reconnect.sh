#!/bin/bash

rm -f /mnt/.fd/.gigantic/reconnect_test /tmp/core.*
echo "/tmp/core.%e.%p.%t" | sudo tee /proc/sys/kernel/core_pattern

echo "Starting reconnect test"
while true; do
  ~/firedancer/build/native/gcc/unit-test/test_funk_reconnect &
  sleep 10
  kill -9 %1
  wait
done
