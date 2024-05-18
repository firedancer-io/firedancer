#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

rm -vf toml-tests.tar.gz
rm -rf tests

wget -O toml-tests.tar.gz https://github.com/toml-lang/toml-test/archive/refs/tags/v1.4.0.tar.gz
tar -xvzf toml-tests.tar.gz
mv toml-test-1.4.0/tests ./tests
rm -rf toml-test-1.4.0
rm -v toml-tests.tar.gz
