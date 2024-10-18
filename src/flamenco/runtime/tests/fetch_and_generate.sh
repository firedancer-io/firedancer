#!/bin/bash

# This commit hash was taken from flamenco/nanopb/README.md
FD_NANOPB_COMMIT=839156b71c64b0a6073ad9c8d793f5913075d9bb

# Create venv and install packages
python3.11 -m venv nanopb_venv
source nanopb_venv/bin/activate
pip install protobuf grpcio-tools

# Fetch nanopb
if [ ! -d nanopb ]; then
  git clone --depth=1 -q https://github.com/nanopb/nanopb.git
  cd nanopb
  git fetch --depth=1 -q origin $FD_NANOPB_COMMIT
  git checkout -q $FD_NANOPB_COMMIT
  cd ..
else
  cd nanopb
  git fetch --depth=1 -q origin $FD_NANOPB_COMMIT
  git checkout -q $FD_NANOPB_COMMIT
  cd ..
fi

# Fetch protosol
if [ ! -d protosol ]; then
  git clone --depth=1 -q https://github.com/firedancer-io/protosol.git
else
  cd protosol
  git pull -q
  cd ..
fi

./nanopb/generator/nanopb_generator.py -I ../.. -I ./protosol/proto -L "" -C ./protosol/proto/*.proto -D generated
