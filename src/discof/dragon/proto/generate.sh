#!/usr/bin/env bash

# Regenerates the nanopb bindings (*.pb.h, *.pb.c) from the vendored
# .proto files and their .options files.  The tree vendors the nanopb
# runtime but not its generator, so the generator is fetched at the
# pinned tag into a temporary directory, together with a python
# protobuf runtime of a vintage nanopb 0.4.9 supports.  Requires protoc
# and network access.

set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
NANOPB_DIR="$SCRIPT_DIR/../../../third_party/nanopb"
NANOPB_TAG=$(cat "$NANOPB_DIR/nanopb_tag.txt")

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/nanopb"
curl -sL "https://codeload.github.com/nanopb/nanopb/tar.gz/refs/tags/$NANOPB_TAG" \
  | tar xz -C "$WORK/nanopb" --strip-components=1

python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q "protobuf==4.25.3"

cd "$SCRIPT_DIR"
for proto in timestamp solana_storage geyser health; do
  "$WORK/venv/bin/python" "$WORK/nanopb/generator/nanopb_generator.py" \
      --protoc-opt=--experimental_allow_proto3_optional \
      --options-file "$proto.options" "$proto.proto"
  sed -i 's|#include <pb.h>|#include "../../../third_party/nanopb/pb_firedancer.h"|' "$proto.pb.h"
done
