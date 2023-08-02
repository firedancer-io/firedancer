#!/bin/bash
set -x

#solana feature status -u mainnet-beta --output json --display-all > mainnet-beta.json
#solana feature status -u testnet --output json --display-all > testnet.json
#solana feature status -u devnet --output json --display-all > devnet.json

python3 gen_features.py ../runtime/fd_features.h ../runtime/fd_features.c

uncrustify  -c ../../../lint.cfg --no-backup --replace ../runtime/fd_features.h
uncrustify  -c ../../../lint.cfg --no-backup --replace ../runtime/fd_features.c
