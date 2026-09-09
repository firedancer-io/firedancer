#!/bin/bash
# PR perf rows.  bench.sh build|replay|snapshot|bench base|new
# Raw results land in $BENCH_DIR/<side>.<what>.*; benchmark_comment.py turns them into the comment.
set -euo pipefail
what=${1:?usage: bench.sh build|replay|snapshot|bench base|new} side=${2:?side}
BENCH_DIR=${BENCH_DIR:-$(realpath ..)/bench}
DUMP_DIR=${DUMP_DIR:-$(realpath ..)/dump}
bin=$BENCH_DIR/$side/bin
out=$BENCH_DIR/$side.$what
mkdir -p "$bin"

quiesce() { # identical host state before every timed run; args: files to pre-read
  sudo killall firedancer-dev 2>/dev/null || true
  rm -f "$DUMP_DIR/accounts.db"
  sudo sysctl -q -w vm.dirty_background_bytes=268435456 vm.dirty_bytes=2147483648 \
                    vm.dirty_expire_centisecs=1000 vm.dirty_writeback_centisecs=100
  sync; sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
  (( $# )) && cat "$@" > /dev/null 2>&1 || true
  for _ in $(seq 60); do  # let writeback drain
    (( $(awk '/^(Dirty|Writeback):/{s+=$2} END{print s}' /proc/meminfo) < 16384 )) && break; sleep 0.5
  done
}

backtest() { # ledger, then run_ledger_backtest.sh args
  local ledger=$DUMP_DIR/$1
  quiesce "$ledger"/shreds.pcapng.zst "$ledger"/snapshot-*.tar.zst "$ledger"/genesis.bin
  rm -f "$out.log"  # fd_log appends
  cat /proc/diskstats > "$out.diskstats.pre"   # disk work of the run = post - pre
  OBJDIR=$BENCH_DIR/$side CI=1 DUMP_DIR=$DUMP_DIR setarch -R \
    ./src/flamenco/runtime/tests/run_ledger_backtest.sh -l "$@" --log "$out.log"
  cat /proc/diskstats > "$out.diskstats.post"
}

case $what in
  build)
    make --silent clean
    TIMEFORMAT='%R %U %S'
    { time make -j"$(nproc)" firedancer > "$out.log" 2>&1 ; } 2> "$out.time"
    make -j"$(nproc)" firedancer-dev >> "$out.log" 2>&1
    cp "$(make --silent objdir)"/bin/{firedancer,firedancer-dev} "$bin/"
    cp contrib/ci/bench/bench.toml "$BENCH_DIR/$side/"  # each side runs the config its checkout knows
    size -A -d "$bin/firedancer" > "$out.size"
    for c in mainnet testnet; do "$bin/firedancer-dev" mem --$c --json > "$out.mem.$c.json"; done
    ;;
  replay)   backtest "${BENCH_LEDGER:-mainnet-424669000-perf-ledger-v4.2.0-beta.1-vat}" \
                     -e "${BENCH_END_SLOT:-424669200}" -m 4000000 ;;
  snapshot) backtest "${BENCH_SNAP_LEDGER:?}" -m 100000000 --snapdc 2 ;;  # load-only ledger: no shreds
  bench)
    { cat "$BENCH_DIR/$side/bench.toml"; printf '[paths]\n    accounts = "%s"\n' "$DUMP_DIR/accounts.db"; } > "$out.toml"
    quiesce
    rm -f "$out.log"
    sudo "$bin/firedancer-dev" bench --no-watch --duration 10 --config "$out.toml" \
         --log-path "$out.log" > /dev/null 2>&1
    ;;
  *) echo "bench.sh: unknown measurement $what" >&2; exit 1 ;;
esac
