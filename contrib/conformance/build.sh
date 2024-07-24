#!/bin/bash

set -ex

mkdir -p dump
cd dump

# Clone conformance
if [ ! -d solana-conformance ]; then
  git clone --depth=1 -q https://github.com/firedancer-io/solana-conformance.git
else
  cd solana-conformance
  git pull -q
  cd ..
fi

# Clone solfuzz-agave
if [ ! -d solfuzz-agave ]; then
  git clone --depth=1 -q https://github.com/firedancer-io/solfuzz-agave.git
else
  cd solfuzz-agave
  git pull -q
  cd ..
fi

# Install solana-conformance deps (requires Python 3.11)
cd solana-conformance
if [ ! -d test_suite_env ]; then
  python3.11 -m venv test_suite_env
  source test_suite_env/bin/activate
  pip install -e .
fi
cd ..

# Compile solfuzz-agave
cd solfuzz-agave
make conformance
cd ..

echo "Successfully built targets"
