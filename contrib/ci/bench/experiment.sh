#!/bin/bash
# Noise experiment: experiment.sh ROUNDS
# bench row, production steps (bench.sh quiesce + inplace + --alpenglow --duration 10), A/B pairs of two bencho timers:
#   main: origin/main fd_bencho.c (timer starts/stops at any slot) | win: PR fd_bencho.c (whole 4-slot leader windows)
set -euo pipefail
rounds=${1:?rounds}
BENCH_DIR=${BENCH_DIR:?} DUMP_DIR=${DUMP_DIR:?}
SHREDB=/dev/shm/fd-bench-shreds.db
BINDIR=/mnt/fd-bench-bin
X=$BENCH_DIR/x; mkdir -p "$X" "$BENCH_DIR/main/bin" "$BENCH_DIR/win/bin"
cp "$BENCH_DIR/new/bin/firedancer-dev" "$BENCH_DIR/win/bin/"
src=src/app/shared_dev/commands/bench/fd_bencho.c
cp $src "$X/fd_bencho.win.c"; cp contrib/ci/bench/fd_bencho.main.c $src
make -j"$(nproc)" firedancer-dev > "$X/main.build.log" 2>&1
cp "$(make --silent objdir)"/bin/firedancer-dev "$BENCH_DIR/main/bin/"
cp "$X/fd_bencho.win.c" $src
cmp -s "$BENCH_DIR/main/bin/firedancer-dev" "$BENCH_DIR/win/bin/firedancer-dev" && { echo "experiment.sh: binaries identical" >&2; exit 1; }

quiesce() {
  sudo killall -w firedancer-dev 2>/dev/null || true
  sudo rm -f "$DUMP_DIR/accounts.db" "$SHREDB"
  sudo rm -rf "$HOME/.firedancer/fd1"
  sudo sysctl -q -w vm.dirty_background_bytes=268435456 vm.dirty_bytes=2147483648 \
                    vm.dirty_expire_centisecs=1000 vm.dirty_writeback_centisecs=100
  sync; sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
  for _ in $(seq 60); do
    (( $(awk '/^(Dirty|Writeback):/{s+=$2} END{print s}' /proc/meminfo) < 16384 )) && break; sleep 0.5
  done
}
inplace() { # $1 = binary
  if ! mountpoint -q $BINDIR; then
    sudo mkdir -p $BINDIR
    sudo mount -t tmpfs -o huge=never,size=1g,uid=$(id -u),gid=$(id -g) fdbenchbin $BINDIR
  fi
  mkdir -p $BINDIR/bin
  dd if="$1" of=$BINDIR/bin/firedancer-dev bs=4M conv=notrunc status=none
  truncate -s "$(stat -c %s "$1")" $BINDIR/bin/firedancer-dev
  chmod 755 $BINDIR/bin/firedancer-dev
}
bench() { # $1 = variant
  { cat "$BENCH_DIR/new/bench.toml"; printf '[paths]\n    accounts = "%s"\n    shredb = "%s"\n' "$DUMP_DIR/accounts.db" "$SHREDB"; } > "$out.toml"
  quiesce
  inplace "$BENCH_DIR/$1/bin/firedancer-dev"
  rm -f "$out.log"
  sudo $BINDIR/bin/firedancer-dev bench --alpenglow --no-watch --duration 10 --config "$out.toml" \
       --log-path "$out.log" > /dev/null 2>&1 || echo "$(date +%T) $out exited $?"
  grep -o 'BENCH_SUMMARY.*' "$out.log" || true
}
variants=(main win)
for r in $(seq "$rounds"); do
  vs=("${variants[@]:r%2}" "${variants[@]:0:r%2}")
  for v in "${vs[@]}"; do
    for ab in a b; do
      out=$X/bench.$v.$r$ab
      echo "$(date +%T) bench $v round $r$ab"
      bench "$v"
    done
  done
done
sudo killall -w firedancer-dev 2>/dev/null || true
mountpoint -q $BINDIR && sudo umount $BINDIR || true
