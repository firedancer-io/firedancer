#!/bin/bash

# FIXME This whole file should just really be a firedancer-dev
#       invocation with parallelism natively implemented in C.

set -euo pipefail

DIR="$( dirname -- "${BASH_SOURCE[0]}"; )"
DIR="$( realpath -e -- "$DIR"; )"
cd "$DIR/../.."

OBJDIR=${OBJDIR:-build/native/gcc}
NUM_PROCESSES=${NUM_PROCESSES:-12}
PAGE_SZ=gigantic
PAGE_CNT=$(( 7 * NUM_PROCESSES ))

if [ -z "${LOG_PATH:-}" ]; then
  LOG_PATH="$(mktemp -d)"
else
  rm    -rf "$LOG_PATH"
  mkdir -pv "$LOG_PATH"
fi

mkdir -p dump

GIT_REF=${GIT_REF:-$(cat contrib/test/test-vectors-commit-sha.txt)}
REPO_URL="https://github.com/firedancer-io/test-vectors.git"

echo "$GIT_REF"

CACHE="/data/${USER}/.cache/firedancer/test-vectors"
WORK_DIR="dump/test-vectors-$$"

mkdir -p "$(dirname "$CACHE")"

exec {lockfd}>"$CACHE.lock"
flock -x "$lockfd"

if [ ! -d "$CACHE" ]; then
    git clone -q "$REPO_URL" "$CACHE"
fi

git -C "$CACHE" fetch -q --prune
git -C "$CACHE" checkout -q "$GIT_REF"

rm -rf "$WORK_DIR"
rsync -a --link-dest="$CACHE" "$CACHE"/ "$WORK_DIR"

flock -u "$lockfd"
exec {lockfd}>&-

SOL_COMPAT=( "$OBJDIR/unit-test/test_sol_compat" --tile-cpus "f,0-$(( NUM_PROCESSES - 1 ))" )

export FD_LOG_PATH="$LOG_PATH/solfuzz.log"
"${SOL_COMPAT[@]}" \
  "$WORK_DIR/block/fixtures" \
  "$WORK_DIR/syscall/fixtures" \
  "$WORK_DIR/vm_interp/fixtures" \
  "$WORK_DIR/txn/fixtures" \
  "$WORK_DIR/elf_loader/fixtures" \
  "$WORK_DIR/instr/fixtures"

echo "Test vectors success"
