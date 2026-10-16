#!/bin/bash
# Noise experiment: experiment.sh replay|snapshot|bench ROUNDS
# Runs every variant of one row ROUNDS times, interleaved, on the same binary.
set -uo pipefail
what=$1 rounds=$2
BENCH_DIR=${BENCH_DIR:?} DUMP_DIR=${DUMP_DIR:?}
SHREDB=/dev/shm/fd-bench-shreds.db
bin=$BENCH_DIR/new/bin
X=$BENCH_DIR/x; mkdir -p "$X"
sudo modprobe msr || true
gcc -O2 -shared -fPIC -o "$X/fixrand.so" contrib/ci/bench/fixrand.c
gcc -O2 -shared -fPIC -o "$X/fixrand2.so" contrib/ci/bench/fixrand2.c
gcc -O2 -shared -fPIC -o "$X/mlockcur.so" contrib/ci/bench/mlockcur.c
DROP=3
boost() { echo "$1" | sudo tee /sys/devices/system/cpu/cpufreq/boost > /dev/null; }
trap 'boost 1' EXIT
boost 1

RAM=/mnt/fd-ramdb
HB=/mnt/fd-hugebin SB=/mnt/fd-smallbin
trap 'boost 1; sudo systemctl start irqbalance; sudo rm -f $RAM/accounts.db; sudo umount $RAM $HB $SB 2>/dev/null; sudo rmmod brd 2>/dev/null' EXIT

quiesce() { # TRIM SETTLE files...
  local trim=$1 settle=$2; shift 2
  sudo killall firedancer-dev 2>/dev/null || true
  sudo rm -f "$DUMP_DIR/accounts.db" "$SHREDB" $RAM/accounts.db
  sudo sysctl -q -w vm.dirty_background_bytes=268435456 vm.dirty_bytes=2147483648 \
                    vm.dirty_expire_centisecs=1000 vm.dirty_writeback_centisecs=100
  sync; (( DROP )) && sudo sh -c "echo $DROP > /proc/sys/vm/drop_caches"
  (( $# )) && cat "$@" > /dev/null 2>&1 || true
  for _ in $(seq 60); do
    (( $(awk '/^(Dirty|Writeback):/{s+=$2} END{print s}' /proc/meminfo) < 16384 )) && break; sleep 0.5
  done
  if (( trim )); then local t0=$EPOCHREALTIME; sudo fstrim "$(findmnt -n -o TARGET -T "$DUMP_DIR")" || true; echo "$t0 $EPOCHREALTIME" > "$out.trim_s"; fi
  sleep "$settle"
}

sampler() { while :; do echo "T $EPOCHREALTIME"; grep -E ' (nvme[0-9]n1|dm-[0-9]+|md[0-9]+) ' /proc/diskstats; sleep 0.25; done > "$out.dstrace"; }
pre()  { sampler & SAMPLER=$!; cat /proc/vmstat > "$out.vmstat.pre"; cat /proc/interrupts > "$out.irq.pre"; cat /proc/schedstat > "$out.sched.pre"; cat /proc/diskstats > "$out.diskstats.pre";  sudo python3 -I contrib/ci/bench/msr.py snap "$out.msr.pre";  cat /sys/class/hwmon/hwmon*/temp1_input > "$out.temp.pre" 2>/dev/null; cat /proc/loadavg > "$out.load"; }
post() { kill $SAMPLER 2>/dev/null; wait $SAMPLER 2>/dev/null; cat /proc/vmstat > "$out.vmstat.post"; cat /proc/interrupts > "$out.irq.post"; cat /proc/schedstat > "$out.sched.post"; cat /proc/diskstats > "$out.diskstats.post"; sudo python3 -I contrib/ci/bench/msr.py snap "$out.msr.post"; cat /sys/class/hwmon/hwmon*/temp1_input > "$out.temp.post" 2>/dev/null; }

DET="sudo setarch -R env FIXRAND_COMM=* LD_PRELOAD=$X/fixrand.so"

replay() { # all: 12 GiB cache, 4 GiB partitions, warm, auto layout, no trim
  # best | hugecp (binary copied to huge=always tmpfs each run: same cache colours for code) | nd (no drop_caches) | sn1 (1 snapin tile: deterministic accounts layout)
  local v=$1 ledger=$DUMP_DIR/${BENCH_LEDGER:-mainnet-424669000-perf-ledger-v4.2.0-beta.1-vat}
  local envs="sudo env FD_BACKTEST_WARM_ACCOUNTS=1 FD_BACKTEST_AUTO_LAYOUT=1" objdir=$BENCH_DIR/new extra=""
  if [[ $v == nd ]]; then sudo killall firedancer-dev 2>/dev/null; sudo rm -f "$DUMP_DIR/accounts.db"
  else quiesce 0 0 "$ledger"/shreds.pcapng.zst "$ledger"/snapshot-*.tar.zst "$ledger"/genesis.bin; fi
  if [[ $v == hugecp ]]; then
    objdir=$HB/$(basename "$out"); sudo mkdir -p "$objdir/bin"; sudo chown -R "$(id -u):$(id -g)" "$objdir"
    sudo cp "$bin/firedancer-dev" "$objdir/bin/"; sudo find $HB -mindepth 1 -maxdepth 1 ! -path "$objdir" -exec rm -rf {} +
    grep -E '^(Shmem|ShmemHugePages):' /proc/meminfo > "$out.bincopy"
  fi
  [[ $v == sn1 ]] && extra="SNAPIN_TILE_COUNT=1"
  local end=${BENCH_END_SLOT:-424669200}; [[ $v == best600 ]] && end=424669600
  ( sleep 6; p=$(pgrep -n -x firedancer-dev) && sudo python3 -I contrib/ci/bench/pfnmap.py "$p" > "$out.pfn" 2>/dev/null ) &
  local pfn=$!
  rm -f "$out.log"; pre
  env CACHE_GIB=12 PARTITION_GIB=4 $extra BT_PREFIX="$envs" OBJDIR=$objdir CI=1 DUMP_DIR=$DUMP_DIR \
    ./src/flamenco/runtime/tests/run_ledger_backtest.sh -l "$(basename "$ledger")" -e "$end" -m 4000000 --log "$out.log" > /dev/null 2>&1
  post; wait $pfn 2>/dev/null
}

SNAPDB=$DUMP_DIR/snapdb/accounts.db
snapshot() { # every variant: drop_caches, then pre-read the snapshot (loads read RAM, not the RAID they write)
  # ci: today's quiesce order (drop, pre-read, fstrim, load at once)   tpr60: drop, fstrim, pre-read, 60 s rest   tpr45: same, 45 s
  local v=$1 ledger=$DUMP_DIR/${BENCH_SNAP_LEDGER:?}
  sudo killall firedancer-dev 2>/dev/null || true
  mkdir -p "$(dirname $SNAPDB)"; sudo rm -f $SNAPDB
  sync; sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
  [[ $v == tpr* ]] && sudo fstrim "$(findmnt -n -o TARGET -T "$DUMP_DIR")"
  local db=$SNAPDB; [[ $v == ram ]] && { db=$RAM/accounts.db; sudo rm -f $db; }
  cat "$ledger"/snapshot-*.tar.* "$ledger"/genesis.bin > /dev/null
  [[ $v == ci ]] && sudo fstrim "$(findmnt -n -o TARGET -T "$DUMP_DIR")"
  case $v in tpr45) sleep 45 ;; pr60|tpr60) sleep 60 ;; prdrain)
    local t0=$SECONDS q=0 last=""; while (( SECONDS-t0 < 120 )); do
      cur=$(awk '$3 ~ /^nvme[0-9]n1$/ {s+=$8} END{print s}' /proc/diskstats); [[ $cur == "$last" ]] && (( ++q >= 5 )) && break; [[ $cur != "$last" ]] && q=0; last=$cur; sleep 1; done
    echo $((SECONDS-t0)) > "$out.drain_s" ;; esac
  rm -f "$out.log"; pre
  local bt=""
  if command -v bpftrace > /dev/null; then
    sudo timeout 30 bpftrace -e 'tracepoint:block:block_rq_issue /args->dev>>20==259/ { @s[args->dev, args->sector] = nsecs; } tracepoint:block:block_rq_complete /@s[args->dev, args->sector]/ { @us[args->dev] = hist((nsecs - @s[args->dev, args->sector]) / 1000); delete(@s[args->dev, args->sector]); }' > "$out.bpf" 2>&1 & bt=$!
    sleep 2
  fi
  env ACCOUNTS_DB=$db OBJDIR=$BENCH_DIR/new CI=1 DUMP_DIR=$DUMP_DIR setarch -R \
    ./src/flamenco/runtime/tests/run_ledger_backtest.sh -l "$(basename "$ledger")" -m 100000000 --log "$out.log" > /dev/null 2>&1
  [[ -n $bt ]] && { sudo pkill -INT -x bpftrace; wait $bt 2>/dev/null; }
  post
}

bench() { # every arm: one tmpfs file rewritten in place (binary frames fixed for the whole job), --duration 10, pend 16384
  # A: ip | ippack (pack getrandom fixed) | ipshm (main-thread getrandom fixed = workspace+stack VAs) | ipaslr (setarch -R) | ipall (all three + stem seed)
  # B: ipk1..ipk4 (pack seed fixed, 4 distinct salts) | ip (anchor)
  # C: ipnd (no drop) | ipd1 (echo 1) | ipd2 (echo 2) | ipmlock (anon populated+locked in address order) | ipremount (fresh hugetlb files every run)
  local v=$1 pend=16384 exe=$SB/fd pre_="" envs="FIXRAND_LOG=$out.rand LD_PRELOAD=$X/fixrand2.so"
  case $v in
    ippack)   envs="$envs FIXRAND_COMM=pack" ;;
    ipshm)    envs="$envs FIXRAND_COMM=fd" ;;   # comm of the main/forked thread that runs fd_shmem_private_map_rand (exe basename "fd"); no tile name contains "fd"
    ipaslr)   pre_="setarch -R" ;;
    ipall)    pre_="setarch -R"; envs="$envs FIXRAND_COMM=* FD_STEM_FIXED_SEED=1" ;;
    ipk[1-4]) envs="$envs FIXRAND_COMM=pack FIXRAND_SALT=${v#ipk}" ;;
    ipmlock)  envs="$envs LD_PRELOAD=$X/fixrand2.so:$X/mlockcur.so" ;;
  esac
  case $v in ipnd) DROP=0 ;; ipd1) DROP=1 ;; ipd2) DROP=2 ;; *) DROP=3 ;; esac
  { cat "$BENCH_DIR/new/bench.toml"
    printf '[paths]\n    accounts = "%s"\n    shredb = "%s"\n' "$DUMP_DIR/accounts.db" "$SHREDB"; } > "$out.toml"
  quiesce 0 0
  if [[ $v == ipremount ]]; then  # new hugetlb frames per run (exp4 remount, now with fixed code frames)
    sudo find /mnt/.fd -type f -delete
    sudo "$exe" configure fini hugetlbfs --config "$out.toml" > /dev/null 2>&1 || true
  fi
  sudo dd if="$bin/firedancer-dev" of="$exe" bs=4M conv=notrunc status=none
  sudo truncate -s "$(stat -c %s "$bin/firedancer-dev")" "$exe"; sudo chmod 755 "$exe"
  grep -E '^(nr_free_pages|nr_slab_reclaimable|nr_slab_unreclaimable|nr_page_table_pages|nr_file_pages|nr_anon_pages|nr_dentry|nr_inode)' /proc/vmstat > "$out.mm.pre" 2>/dev/null
  sudo cat /proc/slabinfo > "$out.slab.pre" 2>/dev/null; cat /proc/buddyinfo /proc/pagetypeinfo > "$out.buddy.pre" 2>/dev/null
  ( sleep 8; p=$(pgrep -n -f "^$exe bench") || exit
    sudo cat /proc/$p/maps > "$out.maps"; sudo cat /proc/$p/smaps_rollup > "$out.smaps" 2>/dev/null
    sudo python3 -I contrib/ci/bench/pfnmap2.py "$p" > "$out.pfn" 2>/dev/null
    for t in /proc/$p/task/*; do echo "$(cat $t/comm) $(awk '{print $39}' $t/stat)"; done > "$out.tasks"  # comm -> cpu
    pc=$(awk '$1=="pack:0"{print $2}' "$out.tasks")
    [[ -n $pc ]] && command -v perf > /dev/null && sudo perf stat -x, -C "$pc" -e cycles,instructions,branch-misses,dTLB-load-misses,iTLB-load-misses,L1-icache-load-misses,bp_l1_tlb_miss_l2_tlb_miss.all,ls_l1_d_tlb_miss.all_l2_miss -- sleep 2 2> "$out.perf"
  ) &
  local pfn=$!
  rm -f "$out.log" "$out.rand"; pre
  ( sleep 11; curl -s -m 2 http://127.0.0.1:7999/metrics | grep -E '^pack_(microblock_complete|microblock_schedule|txn_insert)_duration_nanos_bucket' > "$out.metrics" ) &
  sudo $pre_ env $envs "$exe" bench --alpenglow --no-watch --duration 10 --config "$out.toml" --log-path "$out.log" > /dev/null 2>&1
  post; wait $pfn 2>/dev/null
}

warmdisk() { # one untimed load-sized O_DIRECT write so no timed load meets a rested drive
  local f=$DUMP_DIR/warm.bin; out=$X/warm
  dd if=/dev/zero of=$f bs=16M count=1800 oflag=direct status=none; rm -f $f
}
pretouch() { sudo dd if=/dev/zero of=/dev/ram0 bs=16M count=$((48*64)) oflag=direct status=none; sudo mkfs.xfs -q -f /dev/ram0; sudo mount /dev/ram0 $RAM; sudo chmod 777 $RAM; }

# Variants run as adjacent A/B pairs (suffix a/b), like the PR job's base/new.
case $what in
  replay)   variants=(best best600) ;;
  snapshot) variants=(ram) ;;
  bench)    [[ -n ${ONLYV:-} ]] && variants=($ONLYV) || case ${XSET:-A} in A) variants=(ip ippack ipshm ipaslr ipall) ;; B) variants=(ipk1 ipk2 ipk3 ipk4 ip) ;; C) variants=(ipnd ipd1 ipd2 ipmlock ipremount ip) ;; esac ;;
esac
if [[ $what == snapshot ]]; then
  for d in /dev/nvme?n1; do { sudo nvme id-ctrl -o json "$d"; sudo nvme fw-log -o json "$d"; } > "$X/nvme.${d#/dev/}.json" 2>/dev/null || true; done
  { command -v bpftrace blktrace perf; cat /sys/kernel/mm/transparent_hugepage/enabled; } > "$X/tools.txt" 2>&1
  sudo modprobe brd rd_nr=1 rd_size=$((160<<20)) max_part=0 && sudo mkfs.xfs -q -f /dev/ram0 && sudo mkdir -p $RAM && sudo mount /dev/ram0 $RAM && sudo chmod 777 $RAM
  out=$X/snapshot.warmload.0; echo "$(date +%T) snapshot untimed warm load"; snapshot ram
fi
if [[ $what == bench || $what == replay ]]; then
  sudo mkdir -p $HB $SB
  mountpoint -q $HB || sudo mount -t tmpfs -o huge=always,size=1g,mode=755 fdhugebin $HB
  mountpoint -q $SB || sudo mount -t tmpfs -o huge=never,size=1g,mode=755 fdsmallbin $SB
fi
for r in $(seq "$rounds"); do
  vs=("${variants[@]:r%${#variants[@]}}" "${variants[@]:0:r%${#variants[@]}}")  # rotate: no arm always follows the same arm
  for v in "${vs[@]}"; do
    for ab in a b; do
      out=$X/$what.$v.$r$ab
      echo "$(date +%T) $what $v round $r$ab"
      $what "$v"
    done
  done
done
