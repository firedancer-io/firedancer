#!/bin/bash

# Create venv and install packages
python3.11 -m venv nanopb_venv
source nanopb_venv/bin/activate
pip install protobuf grpcio-tools

# Fetch nanopb
if [ ! -d nanopb ]; then
  git clone --depth=1 -q https://github.com/nanopb/nanopb.git
else
  cd nanopb
  git pull -q
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

./nanopb/generator/nanopb_generator.py -I ../.. -I ./protosol/proto_v2 -L "" -C ./protosol/proto_v2/*.proto -D generated
./nanopb/generator/nanopb_generator.py -I ../.. -I ./protosol/proto    -L "" -C ./protosol/proto/*.proto    -D generated
