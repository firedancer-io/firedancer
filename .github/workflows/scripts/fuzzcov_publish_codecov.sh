#!/bin/bash

set -uEexo pipefail

mkdir -p build/codecovio-bin/

CODECOV=build/codecovio-bin/codecov

if [ ! -f $CODECOV ]
then
    curl -Lo $CODECOV https://uploader.codecov.io/latest/linux/codecov
    chmod +x $CODECOV
fi

for f in build/fuzzcov/lcov/*.lcov
do
    BASE="$(basename $f)"
    $CODECOV \
        -f "${f}" \
        -F "${BASE}"
done
