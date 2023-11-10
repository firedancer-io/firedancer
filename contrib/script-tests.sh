#!/bin/bash
set -x

# This script expects OBJDIR and MACHINE to be set

LOG_PATH="/tmp/fd-unit-test-${MACHINE:?}-report"
BIN="${OBJDIR:?}/bin"
UNIT_TEST="${OBJDIR}/unit-test"

rm    -rf $LOG_PATH
mkdir -pv  $LOG_PATH

FD_LOG_PATH="-"
export FD_LOG_PATH

    $BIN/fd_shmem_ctl create test_shmem_0 1 normal 0 0600 \
                  create test_shmem_1 2 normal 0 0600 \
                  create test_shmem_2 3 normal 0 0600 2> /dev/null

taskset -c  2 nice -n -19 $UNIT_TEST/test_shmem_ctl > $LOG_PATH/shmem_ctl 2>&1 & # script
taskset -c  4 nice -n -19 $UNIT_TEST/test_wksp_ctl  > $LOG_PATH/wksp_ctl  2>&1 & # script
taskset -c  6 nice -n -19 $UNIT_TEST/test_alloc_ctl > $LOG_PATH/alloc_ctl 2>&1 & # script
taskset -c  8 nice -n -19 $UNIT_TEST/test_pod_ctl   > $LOG_PATH/pod_ctl   2>&1 & # script
taskset -c 10 nice -n -19 $UNIT_TEST/test_tango_ctl > $LOG_PATH/tango_ctl 2>&1 & # script
wait

taskset -c 12 nice -n -19 $UNIT_TEST/test_ar             --tile-cpus 12      2> $LOG_PATH/ar         &
taskset -c 14 nice -n -19 $UNIT_TEST/test_funk_base      --tile-cpus 14      2> $LOG_PATH/funk_base  &
taskset -c 16 nice -n -19 $UNIT_TEST/test_funk_txn       --tile-cpus 16      2> $LOG_PATH/funk_txn   &
taskset -c 18 nice -n -19 $UNIT_TEST/test_funk_rec       --tile-cpus 18      2> $LOG_PATH/funk_rec   &
taskset -c 20 nice -n -19 $UNIT_TEST/test_funk_val       --tile-cpus 20      2> $LOG_PATH/funk_val   &
taskset -c 22 nice -n -19 $UNIT_TEST/test_funk           --tile-cpus 22      2> $LOG_PATH/funk       &
taskset -c 24 nice -n -19 $UNIT_TEST/test_fxp            --tile-cpus 24      2> $LOG_PATH/fxp        &
taskset -c 26 nice -n -19 $UNIT_TEST/test_uwide          --tile-cpus 26      2> $LOG_PATH/uwide      &

# FIXME: USE FD_IMPORT PCAP FILE
taskset -c 28 nice -n -19 $UNIT_TEST/test_pcap           --tile-cpus 28 --in tmp/test_in.pcap --out tmp/test_out.pcap 2> $LOG_PATH/pcap &

# Needs at least 3/2/1 free normal/huge/gigantic pages on numa 0
taskset -c 30 nice -n -19 $UNIT_TEST/test_shmem          --tile-cpus 30 test_shmem_0 test_shmem_1 test_shmem_2 2> $LOG_PATH/shmem

# Needs at least 1 free gigantic page on numa 1
taskset -c 32 nice -n -19 $UNIT_TEST/test_tcache         --tile-cpus 32      2> $LOG_PATH/tcache     &

taskset -c 34 nice -n -19 $UNIT_TEST/test_cnc            --tile-cpus 34-36/2 2> $LOG_PATH/cnc        &

# Needs at least 1 free gigantic page on numa 0
# Needs a /tmp/test.pcap file
taskset -c 38 nice -n -19 $UNIT_TEST/test_replay         --tile-cpus 38-42/2 --tx-pcap /tmp/test.pcap 2> $LOG_PATH/replay &

taskset -c 44 nice -n -19 $UNIT_TEST/test_tile           --tile-cpus 44-50/2 2> $LOG_PATH/tile_multi &

taskset -c 52 nice -n -19 $UNIT_TEST/test_wksp_used_treap --tile-cpus 52 2> $LOG_PATH/wksp_used_treap &
taskset -c 54 nice -n -19 $UNIT_TEST/test_wksp_free_treap --tile-cpus 54 2> $LOG_PATH/wksp_free_treap &
taskset -c 56 nice -n -19 $UNIT_TEST/test_wksp_admin      --tile-cpus 56 2> $LOG_PATH/wksp_admin      &
taskset -c 58 nice -n -19 $UNIT_TEST/test_wksp_user       --tile-cpus 58 2> $LOG_PATH/wksp_user       &

# Needs at least 1 free gigantic page on numa 0
taskset -c 60 nice -n -19 $UNIT_TEST/test_wksp_helper     --tile-cpus 60 2> $LOG_PATH/wksp_helper     &

# Needs at least 1 free gigantic page on numa 0
taskset -c 62 nice -n -19 $UNIT_TEST/test_wksp            --tile-cpus 62-68/2 2> $LOG_PATH/wksp       &

# Needs at least 1 free gigantic page on numa 1
taskset -c  3 nice -n -19 $UNIT_TEST/test_alloc          --tile-cpus  3-79/2 2> $LOG_PATH/alloc      &

wait
$BIN/fd_shmem_ctl unlink test_shmem_0 0 unlink test_shmem_1 0 unlink test_shmem_2 0 2> /dev/null

taskset -c 2 nice -n -19 $UNIT_TEST/test_tpool --tile-cpus 2-64/2,3-65/2 2> $LOG_PATH/tpool_large &
wait

# todo(mmcgee-jump): reenable those tests https://github.com/firedancer-io/firedancer/issues/761
# # Needs at least 1 free gigantic page on numa 0
# if $UNIT_TEST/test_ipc_init $OBJDIR && \
#     $UNIT_TEST/test_ipc_meta 16     && \
#     $UNIT_TEST/test_ipc_full 16     && \
#     $UNIT_TEST/test_ipc_fini; then
#   echo pass > $LOG_PATH/ipc
# else
#   echo FAIL > $LOG_PATH/ipc
# fi

# # Needs at least 1 free gigantic page on numa 0
# if $UNIT_TEST/test_mux_ipc_init $OBJDIR && \
#     $UNIT_TEST/test_mux_ipc_meta 16 16  && \
#     $UNIT_TEST/test_mux_ipc_full 16 16  && \
#     $UNIT_TEST/test_mux_ipc_fini; then
#   echo pass > $LOG_PATH/mux_ipc
# else
#   echo FAIL > $LOG_PATH/mux_ipc
# fi

wait

for f in `ls $LOG_PATH`; do
  echo $f: `tail -n 2 $LOG_PATH/$f | grep -v "^Log"`
done
