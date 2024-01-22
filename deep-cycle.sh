#!/bin/bash -f

set -x

./deps.sh nuke
./deps.sh install >& /dev/null
./cycle.sh
