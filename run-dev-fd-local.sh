#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# create temporary files in the user's home directory because it's likely to be on a large disk

cleanup() {
  sudo killall fddev2 || true
  fddev2 configure fini all >/dev/null 2>&1 || true
}

trap cleanup EXIT SIGINT SIGTERM

FD_DIR=$SCRIPT_DIR

sudo killall fddev2 || true
sudo killall solana-validator || true

# if fd_frank_ledger is not on path then use the one in the home directory
if ! command -v fddev2 > /dev/null; then
  PATH="$FD_DIR/build/native/clang/bin":$PATH
fi

ENTRYPOINT=$(dig +short entrypoint2.testnet.solana.com)
PRIMARY_IP=$(ip -o -4 addr show scope global | awk '{ print $4 }' | cut -d/ -f1)


FULL_SNAPSHOT=$(wget -c -nc -S --trust-server-names http://$PRIMARY_IP:8899/snapshot.tar.bz2 |& grep 'location:' | cut -d/ -f2)

SNAPSHOT_SLOT=$(echo "$FULL_SNAPSHOT" | cut -d- -f2)

echo "topology = \"firedancer\"
[log]
    level_flush = \"ERR\"
[layout]
    affinity = \"0-26\"
    net_tile_count = 1
    verify_tile_count = 1
    bank_tile_count = 1

[tiles.tvu]
    repair_peer_id = \"6VfruTG68WhnhsngCdN23WgGTDsa7oRTKvhBxshYFxkn\"
    repair_peer_addr = \"$PRIMARY_IP:8008\"
    gossip_peer_addr = \"139.178.68.207:8001\"
    snapshot = \"snapshot-100-FKQ9e5RarvUPRB1rXQmEbbPtAS4qwV363U1x1mJdpQ3W.tar.zst\"
    page_cnt = 25
    validate_snapshot = \"true\"
    check_hash = \"true\"
    tvu_addr         = \"$PRIMARY_IP:9003\"
    tvu_fwd_addr     = \"$PRIMARY_IP:9004\"
    gossip_listen_port = 8010
    repair_listen_port = 8011
    tvu_port           = 9003
    tvu_fwd_port       = 9004

[tiles.quic]
    regular_transaction_listen_port = 8013
    quic_transaction_listen_port = 8019
    vote_transaction_listen_port = 8013
    regular_transaction_my_addr = \"$PRIMARY_IP:8013\"
    quic_transaction_my_addr = \"$PRIMARY_IP:8019\"
    vote_transaction_my_addr = \"$PRIMARY_IP:8013\"

[tiles.gossip]
    gossip_peer_addr = \"$PRIMARY_IP:8001\"
    gossip_my_addr = \"$PRIMARY_IP:8010\"
    gossip_listen_port = 8010

[tiles.repair]
    repair_my_intake_addr = \"$PRIMARY_IP:8012\"
    repair_my_serve_addr = \"$PRIMARY_IP:8011\"
    repair_intake_listen_port = 8012
    repair_serve_listen_port = 8011

[tiles.shred]
    shred_listen_port = 9003

[tiles.replay]
    snapshot = \"$FULL_SNAPSHOT\"
    index_max = 350000000
    txn_max = 1024
    pages = 180

[tiles.store]
    snapshot_slot = $SNAPSHOT_SLOT

[development]
    no_clone = true

[consensus]
    identity_path = \"test-ledger/fd-identity-keypair.json\"

" > fddev.toml

fddev2 --config fddev.toml --no-sandbox --no-solana