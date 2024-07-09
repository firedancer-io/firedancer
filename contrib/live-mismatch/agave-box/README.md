# README

`mainnet-upload` service monitors a gcloud bucket and uploads a minifed rocksdb when there is a new directory which lacks a minified rocksdb

## Prerequisites

Run on an Agave mainnet validator box.

```
python3 -m venv venv
source venv/bin/activate
pip3 install requirements.txt
```

also requires `fd_frank_ledger`

## Usage

To run Firedancer on the mainnet, follow these steps:

1. Build with `EXTRAS=no-solana make -j fddev`
2. Edit the `mainnet-upload.service` file to configure your desired settings.
3. Start with `systemctl start mainnet-upload`