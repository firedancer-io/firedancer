#!/usr/bin/env sh

# This script runs FD in wen-restart mode
# We need the memory-mapped funk file and the tower checkpoint file

FUNK_FILE=/data/yunzhang/funk_file.bin
TOWER_CHECKPT_FILE=tower.log
RESTART_LOG_FILE=wenrestart.log
touch $RESTART_LOG_FILE
rm -f $RESTART_LOG_FILE

# We also need to know the coordinator pubkey, genesis hash and identity keypair
GENESIS_HASH=8Fzs68yYa5GK1abikVC1xmmfvwjScirK2rh3hvdM6tbU
RESTART_COORDINATOR=6tr7Acuwy5PiEEQMyyDphTeEoY2MAz4nncjEvcZAcERo

# Some info same as normal execution of FD
SHRED_VER=16013
SNAPSHOT_OUT_DIR=./
PRIMARY_IP=147.75.87.225
IDENTITY=fd-identity-keypair.json

# We need the block file here just to remove it, avoiding potentially inconsistent data in this file
BLOCK_FILE=/data/yunzhang/blockstore_file.bin
rm -f $BLOCK_FILE

# FIXME: after Agave releases wen-restart in v2.2.*, and FD suppors v2.2.*, we should change this
CLUSTER_VERSION=2.0.3

# Compile firedancer-dev and cleanup memory
make -j firedancer-dev
sudo ./build/native/gcc/bin/firedancer-dev configure fini all || true

# Write the toml config to wen_restart.toml
echo "
[layout]
    affinity = \"auto\"
    shred_tile_count = 1
    bank_tile_count = 1
[gossip]
    entrypoints = [\"$PRIMARY_IP:8001\"]
    port = 8700
[tiles]
    [tiles.pack]
        use_consumed_cus = false
    [tiles.repair]
        repair_intake_listen_port = 9055
        repair_serve_listen_port = 9056
    [tiles.replay]
        snapshot = \"funk\"
        cluster_version = \"$CLUSTER_VERSION\"
        tower_checkpt = \"$TOWER_CHECKPT_FILE\"
    [tiles.restart]
        in_wen_restart = true
        wen_restart_coordinator = \"$RESTART_COORDINATOR\"
        genesis_hash = \"$GENESIS_HASH\"
    [tiles.batch]
        out_dir = \"$SNAPSHOT_OUT_DIR\"
[consensus]
    vote = false
    expected_shred_version = $SHRED_VER
    identity_path = \"$IDENTITY\"
[log]
    path = \"$RESTART_LOG_FILE\"
    level_stderr = \"NOTICE\"
    level_flush = \"ERR\"
[blockstore]
    shred_max = 16384
    block_max = 512
    txn_max = 1048576
    idx_max = 512
    alloc_max = 10737418240
    file = \"$BLOCK_FILE\"
[funk]
    max_account_records = 10000000
    heap_size_gib = 32
    max_database_transactions = 1024
" > wen_restart.toml

sudo gdb --args build/native/gcc/bin/firedancer-dev dev --config wen_restart.toml
