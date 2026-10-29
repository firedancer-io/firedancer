#!/bin/bash
set -euo pipefail

PROJECT_ROOT=../../../..

# Set protosol version
PROTO_VERSION="v18.0.0"

PYTHON=${PYTHON:-python3}
PROTOS="block.proto bundle.proto context.proto cost.proto elf.proto gossip.proto instr.proto metadata.proto shred.proto txn.proto vm.proto vm_serialization.proto"

# Create venv and install packages
if [ ! -e pb_venv ]; then "$PYTHON" -m venv pb_venv; fi
source pb_venv/bin/activate
pip install protobuf grpcio-tools

# Fetch protosol at specified tag/branch
if [ ! -d protosol ]; then
    git clone --depth=1 --branch "$PROTO_VERSION" https://github.com/firedancer-io/protosol.git
else
    cd protosol
    git fetch --tags
    git checkout "$PROTO_VERSION"
    cd ..
fi

rm -rf generated/*.pb.[ch]
(cd protosol/proto && python -m grpc_tools.protoc -I. --include_imports --descriptor_set_out=../../generated/protosol.fds $PROTOS)
python ${PROJECT_ROOT}/src/ballet/pb/fd_pb_gen.py \
  --fds generated/protosol.fds \
  --options protosol/proto \
  --out generated \
  --prefix fd_exec_test \
  $PROTOS
rm generated/protosol.fds
