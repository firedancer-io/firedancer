#!/bin/bash 
set -x

#solana feature status -u mainnet-beta --output json --display-all > mainnet-beta.json
#solana feature status -u testnet --output json --display-all > testnet.json
#solana feature status -u devnet --output json --display-all > devnet.json

python3 gen_features.py fd_features.h fd_features.c

uncrustify  -c ../../../lint.cfg --no-backup --replace fd_features.h
uncrustify  -c ../../../lint.cfg --no-backup --replace fd_features.c

