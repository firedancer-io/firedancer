set -e

EXTRAS=no-solana make -j fddev
make -j


# sudo ./build/native/gcc/bin/fd_shmem_cfg fini || true
# sudo ./build/native/gcc/bin/fd_shmem_cfg init 0700 chali ""

# rm -f snapshot-*
# wget --trust-server-names http://entrypoint3.testnet.solana.com:8899/snapshot.tar.bz2

# rm -f /data/chali/testnet-funk
# ./build/native/gcc/bin/fd_ledger --cmd ingest --funk-page-cnt 140 --index-max 100000000 --txns-max 1024 --funk-only 1 --checkpt-funk /data/chali/testnet-funk --snapshot snapshot-*


rm -f incremental-snapshot-*
wget --trust-server-names http://entrypoint3.testnet.solana.com:8899/incremental-snapshot.tar.bz2

GOSSIP_PORT=$(shuf -i 8000-10000 -n 1)

echo "[gossip]
    port = $GOSSIP_PORT
[tiles]
    [tiles.gossip]
        entrypoints = [\"147.75.84.157\"]
        peer_ports = [8000]
        gossip_listen_port = $GOSSIP_PORT
    [tiles.repair]
        repair_intake_listen_port = $(shuf -i 8000-10000 -n 1)
        repair_serve_listen_port = $(shuf -i 8000-10000 -n 1)
    [tiles.replay]
        snapshot = \"wksp:/data/chali/testnet-funk\"
        incremental = \"$(echo incremental-*)\"
        tpool_thread_count = 13
        funk_sz_gb = 140
        funk_txn_max = 1024
        funk_rec_max = 100000000
[consensus]
    expected_shred_version = 35459
[log]
  path = \"fddev.log\"
  level_stderr = \"NOTICE\"
[development]
    topology = \"firedancer\"
" > testnet.toml

./build/native/gcc/bin/fddev configure fini all || true
./build/native/gcc/bin/fddev --config testnet.toml --no-sandbox --no-clone --no-solana-labs
