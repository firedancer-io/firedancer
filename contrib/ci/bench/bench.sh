#!/bin/bash
# PR perf rows.  bench.sh build|replay|snapshot|bench base|new
# Raw results land in $BENCH_DIR/<side>.<what>.*; benchmark_comment.py turns them into the comment.
set -euo pipefail
what=${1:?usage: bench.sh build|replay|snapshot|bench base|new} side=${2:?side}
BENCH_DIR=${BENCH_DIR:-$(realpath ..)/bench}
DUMP_DIR=${DUMP_DIR:-$(realpath ..)/dump}
SHREDB=/dev/shm/fd-bench-shreds.db  # tmpfs: on disk, writeback holds its inode lock and stalls shred/rserve pwrite() for whole slots
RAMDB=/mnt/fd-bench-ramdb           # snapshot row's accounts.db: brd, so the row times snapin rather than flash write state
BINDIR=/mnt/fd-bench-bin            # timed runs exec firedancer-dev from here
bin=$BENCH_DIR/$side/bin
out=$BENCH_DIR/$side.$what
mkdir -p "$bin"

quiesce() { # identical host state before every timed run; args: files to pre-read
  sudo killall -w firedancer-dev 2>/dev/null || true
  sudo rm -f "$DUMP_DIR/accounts.db" "$SHREDB" "$RAMDB/accounts.db"
  sudo rm -rf "$HOME/.firedancer/fd1"
  sudo sysctl -q -w vm.dirty_background_bytes=268435456 vm.dirty_bytes=2147483648 \
                    vm.dirty_expire_centisecs=1000 vm.dirty_writeback_centisecs=100
  sync; sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
  (( $# )) && cat "$@" > /dev/null 2>&1 || true
  for _ in $(seq 60); do  # let writeback drain
    (( $(awk '/^(Dirty|Writeback):/{s+=$2} END{print s}' /proc/meminfo) < 16384 )) && break; sleep 0.5
  done
}

inplace() { # binary into the one tmpfs file, rewritten in place: tmpfs keeps each offset's page, so both sides' code gets the same physical frames
  if ! mountpoint -q $BINDIR; then
    sudo mkdir -p $BINDIR
    sudo mount -t tmpfs -o huge=never,size=1g,uid=$(id -u),gid=$(id -g) fdbenchbin $BINDIR
  fi
  mkdir -p $BINDIR/bin
  dd if="$bin/firedancer-dev" of=$BINDIR/bin/firedancer-dev bs=4M conv=notrunc status=none
  truncate -s "$(stat -c %s "$bin/firedancer-dev")" $BINDIR/bin/firedancer-dev
  chmod 755 $BINDIR/bin/firedancer-dev
}

backtest() { # ledger, then run_ledger_backtest.sh args
  local ledger=$DUMP_DIR/$1
  quiesce "$ledger"/shreds.pcapng.zst "$ledger"/snapshot-*.tar.zst "$ledger"/genesis.bin
  inplace
  rm -f "$out.log"  # fd_log appends
  OBJDIR=$BINDIR CI=1 DUMP_DIR=$DUMP_DIR setarch -R \
    ./src/flamenco/runtime/tests/run_ledger_backtest.sh -l "$@" --log "$out.log"
}

case $what in
  build)
    make --silent clean
    cpus=$(getconf _NPROCESSORS_ONLN)
    cpuset=$(cat /sys/devices/system/cpu/online)
    taskset -c "$cpuset" make -j"$cpus" firedancer > "$out.log" 2>&1  # untimed: a job's first build runs slow
    make --silent clean
    sync; TIMEFORMAT='%R %U %S'
    { time taskset -c "$cpuset" make -j"$cpus" firedancer > "$out.log" 2>&1 ; } 2> "$out.time"
    make -j"$(nproc)" firedancer-dev >> "$out.log" 2>&1
    cp "$(make --silent objdir)"/bin/{firedancer,firedancer-dev} "$bin/"
    cp contrib/ci/bench/bench.toml "$BENCH_DIR/$side/"  # each side runs the config its checkout knows
    size -A -d "$bin/firedancer" > "$out.size"
    "$bin/firedancer-dev" mem --mainnet --json > "$out.mem.mainnet.json"
    "$bin/firedancer-dev" mem --testnet --json > "$out.mem.testnet.json"
    ;;
  replay)   backtest "${BENCH_LEDGER:-mainnet-424669000-perf-ledger-v4.2.0-beta.1-vat}" \
                     -e "${BENCH_END_SLOT:-424669200}" -m 4000000 --cache-size-gib 12 --partition-size-gib 4 ;;
  snapshot) # load-only ledger: no shreds
    if ! mountpoint -q $RAMDB; then  # brd allocates on first write: one untimed load touches the pages both sides reuse
      { findmnt -rn -o TARGET -S /dev/ram0 || true; } | xargs -r sudo umount  # findmnt exits 1 when nothing is mounted
      sudo rmmod brd 2>/dev/null || true
      sudo modprobe brd rd_nr=1 rd_size=$((160<<20)) max_part=0
      (( $(cat /sys/block/ram0/size) == 160<<21 )) || { echo "bench.sh: brd loaded with other parameters" >&2; exit 1; }
      sudo mkfs.xfs -q -f /dev/ram0
      sudo mkdir -p $RAMDB
      sudo mount /dev/ram0 $RAMDB
      sudo chmod 777 $RAMDB
      ACCOUNTS_DB=$RAMDB/accounts.db out=$out.warmup backtest "${BENCH_SNAP_LEDGER:?}" -m 100000000
    fi
    ACCOUNTS_DB=$RAMDB/accounts.db backtest "${BENCH_SNAP_LEDGER:?}" -m 100000000 ;;
  bench)
    { cat "$BENCH_DIR/$side/bench.toml"; printf '[paths]\n    accounts = "%s"\n    shredb = "%s"\n' "$DUMP_DIR/accounts.db" "$SHREDB"; } > "$out.toml"
    quiesce
    inplace
    rm -f "$out.log"
    sudo $BINDIR/bin/firedancer-dev bench --no-watch --duration 10 --config "$out.toml" \
         --log-path "$out.log" > /dev/null 2>&1
    ;;
  *) echo "bench.sh: unknown measurement $what" >&2; exit 1 ;;
esac
