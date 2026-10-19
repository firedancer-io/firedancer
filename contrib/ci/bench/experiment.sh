#!/bin/bash
# Noise experiment: experiment.sh ROUNDS
# replay row, production steps (bench.sh backtest: quiesce + inplace + run_ledger_backtest.sh, 12 GiB cache, 4 GiB partitions),
# 4 firedancer-dev builds of identical source; only code layout differs: a pad object linked right after main.o shifts
# all following .text by p0/p64/p4096/p65536 bytes.  Rotated A/B pairs.  Question: is the ~0.24% cross-binary replay
# offset code layout?
set -euo pipefail
rounds=${1:?rounds}
BENCH_DIR=${BENCH_DIR:?} DUMP_DIR=${DUMP_DIR:?}
X=$BENCH_DIR/x; mkdir -p "$X"
objdir=$(make --silent objdir)
link=$(make -n -W src/app/firedancer-dev/main.c firedancer-dev 2>/dev/null | grep -m1 'firedancer-dev\.tmp' |
       sed -E 's/^.*&& +(gcc -L)/\1/; s/ -o [^ ]*firedancer-dev\.tmp.*$//')
[[ $link == gcc* ]] || { echo "experiment.sh: no link line" >&2; exit 1; }
for p in 0 64 4096 65536; do
  mkdir -p "$BENCH_DIR/p$p/bin"
  if (( p )); then
    printf '__attribute__((used,aligned(64))) void fd_layout_pad(void){ __asm__ volatile(".skip %d - 64, 0x90"); }\n' $p > "$X/pad$p.c"
    gcc -O0 -c -o "$X/pad$p.o" "$X/pad$p.c"
    eval "${link/$objdir\/obj\/app\/firedancer-dev\/main.o/$objdir/obj/app/firedancer-dev/main.o $X/pad$p.o} -o $BENCH_DIR/p$p/bin/firedancer-dev"
  else
    cp "$BENCH_DIR/new/bin/firedancer-dev" "$BENCH_DIR/p$p/bin/"
  fi
  nm "$BENCH_DIR/p$p/bin/firedancer-dev" | grep -E ' T (fd_runtime_block_execute_finalize|fd_executor_txn_execute|main)$' > "$X/p$p.syms" || true
done
for v in p0 p64 p4096 p65536; do  # each side gets its config and the replay row's tools from new/
  cp "$BENCH_DIR/new/bench.toml" "$BENCH_DIR/$v/" 2>/dev/null || true
done
variants=(p0 p64 p4096 p65536)
for r in $(seq "$rounds"); do
  vs=("${variants[@]:r%4}" "${variants[@]:0:r%4}")
  for v in "${vs[@]}"; do
    for ab in a b; do
      echo "$(date +%T) replay $v round $r$ab"
      contrib/ci/bench/bench.sh replay "$v" || echo "$(date +%T) replay $v $r$ab exited $?"
      mv "$BENCH_DIR/$v.replay.log" "$X/replay.$v.$r$ab.log"
      grep -o 'BACKTEST_SUMMARY.*' "$X/replay.$v.$r$ab.log" || true
    done
  done
done
