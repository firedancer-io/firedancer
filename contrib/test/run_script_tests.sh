#!/bin/bash
set -x

# This script complements the automatic unit tests
#
# Expects OBJDIR and MACHINE to be set

LOG_PATH="/tmp/fd-unit-test-${MACHINE:?}-report"
BIN="${OBJDIR:?}/bin"
UNIT_TEST="${OBJDIR}/unit-test"

rm    -rf $LOG_PATH
mkdir -pv $LOG_PATH

FD_LOG_PATH="-"
export FD_LOG_PATH
export LLVM_PROFILE_FILE

$UNIT_TEST/test_shmem_ctl   > $LOG_PATH/shmem_ctl   2>&1
$UNIT_TEST/test_wksp_ctl    > $LOG_PATH/wksp_ctl    2>&1
$UNIT_TEST/test_alloc_ctl   > $LOG_PATH/alloc_ctl   2>&1
$UNIT_TEST/test_pod_ctl     > $LOG_PATH/pod_ctl     2>&1
$UNIT_TEST/test_tango_ctl   > $LOG_PATH/tango_ctl   2>&1
$UNIT_TEST/test_wksp_helper > $LOG_PATH/wksp_helper 2>&1 # allocates a gigantic page

# Multi-tile tests
$UNIT_TEST/test_cnc  --tile-cpus 0,2   2> $LOG_PATH/cnc
$UNIT_TEST/test_tile --tile-cpus 0-8/2 2> $LOG_PATH/tile_multi

# FIXME: USE FD_IMPORT PCAP FILE
#$UNIT_TEST/test_pcap --in tmp/test_in.pcap --out tmp/test_out.pcap 2> $LOG_PATH/pcap

# Needs at least 3/2/1 free normal/huge/gigantic pages on numa 0
# FIXME: Fails with ENOMEM
#$BIN/fd_shmem_ctl create test_shmem_0 1 normal 0 0600 \
#              create test_shmem_1 2 normal 0 0600 \
#              create test_shmem_2 3 normal 0 0600 2> /dev/null
#$UNIT_TEST/test_shmem test_shmem_0 test_shmem_1 test_shmem_2 2> $LOG_PATH/shmem
#$BIN/fd_shmem_ctl unlink test_shmem_0 0 unlink test_shmem_1 0 unlink test_shmem_2 0 2> /dev/null

# Needs at least 1 free gigantic page on numa 0
# FIXME: Needs a /tmp/test.pcap file
#$UNIT_TEST/test_replay         --tile-cpus 38-42/2 --tx-pcap /tmp/test.pcap 2> $LOG_PATH/replay

# FIXME: Spawn the tpool job across all available tiles but 0
#nice -n -19 $UNIT_TEST/test_tpool --tile-cpus 2-64/2,3-65/2 2> $LOG_PATH/tpool_large

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
