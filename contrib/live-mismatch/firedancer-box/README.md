# README

`mainnet` service runs `fddev` in a loop and copies files to directories based on the failure mode.

`ci-upload` service monitors a directory and copies the contents of the monitored directory to a gcloud bucket.

## Prerequisites

`fddev` and `solana` on `PATH`

## Usage

1. Build with `EXTRAS=no-solana make -j fddev`
2. Edit the `mainnet.service` file to configure your desired settings.
3. Start with `systemctl start mainnet`