#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_NANOPB_TAG=$(cat ../../../ballet/nanopb/nanopb_tag.txt)

# Create venv and install packages
python3.11 -m venv nanopb_venv
source nanopb_venv/bin/activate
pip install protobuf grpcio-tools

# Fetch nanopb
if [ ! -d nanopb ]; then
  git clone --depth=1 -q https://github.com/nanopb/nanopb.git
  cd nanopb
  git fetch --depth=1 -q origin $FD_NANOPB_TAG:refs/tags$FD_NANOPB_TAG
  git checkout -q $FD_NANOPB_TAG
  cd ..
else
  cd nanopb
  git fetch --depth=1 -q origin $FD_NANOPB_TAG:refs/tags$FD_NANOPB_TAG
  git checkout -q $FD_NANOPB_TAG
  cd ..
fi

# Fetch protosol
if [ ! -d protosol ]; then
  git clone -q https://github.com/firedancer-io/protosol.git
else
  cd protosol
  git pull -q
  cd ..
fi

./nanopb/generator/nanopb_generator.py -I ./protosol/proto -L "" -C ./protosol/proto/*.proto -D generated
