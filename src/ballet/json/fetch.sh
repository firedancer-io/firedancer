#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
REPO_URL="https://raw.githubusercontent.com/ibireme/yyjson"
REPO_COMMIT=$(tr -d '[:space:]' < "$SCRIPT_DIR/yyjson_commit.txt")

FILES=(
    "yyjson.h"
    "yyjson.c"
)

for file in "${FILES[@]}"; do
    curl -sSfL -o "$SCRIPT_DIR/$file" "$REPO_URL/$REPO_COMMIT/src/$file"
done
