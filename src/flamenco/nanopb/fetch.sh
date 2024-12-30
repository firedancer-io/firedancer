#!/usr/bin/env bash

set -x

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
REPO_URL="https://raw.githubusercontent.com/nanopb/nanopb"
REPO_TAG=$(cat nanopb_tag.txt)

FILES=(
    "pb_common.h"
    "pb_common.c"
    "pb_decode.h"
    "pb_decode.c"
    "pb_encode.h"
    "pb_encode.c"
    "pb.h"
)

for file in "${FILES[@]}"; do
    RAW_URL="$REPO_URL/refs/tags/$REPO_TAG/$file"
    curl -s -o $SCRIPT_DIR/$file $REPO_URL/$REPO_TAG/$file
    # Replace #include "pb.h" with #include "pb_firedancer.h"
    sed -i 's/#include "pb.h"/#include "pb_firedancer.h"/' $file
done