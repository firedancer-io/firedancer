#!/bin/bash
# Usage: init_vote_acct_local.sh <IDENTITY_KEYPAIR> <ACCOUNT_KEYPAIR>  <STAKE_ACCOUNT_KEYPAIR>
set -e

YELLOW="\033[1;33m"
END="\033[0m"

echo -e "$YELLOW# Configuring solana and airdrop$END"
solana config set --url localhost
solana config set --keypair $1
solana airdrop 3
echo -e "$YELLOW# Create vote account$END"
# solana create-vote-account <ACCOUNT_KEYPAIR> <IDENTITY_KEYPAIR> <WITHDRAWER_PUBKEY> --commission <PERCENTAGE> --config <FILEPATH>
solana create-vote-account $2 $1 $1 --allow-unsafe-authorized-withdrawer
echo -e "$YELLOW# Create stake account and delegate stake$END"
# solana create-stake-account <STAKE_ACCOUNT_KEYPAIR> <AMOUNT> --config <FILEPATH>
solana create-stake-account -k $1 $3 2
# solana delegate-stake <STAKE_ACCOUNT_ADDRESS> <VOTE_ACCOUNT_ADDRESS> --config <FILEPATH>
solana delegate-stake -k $1 $3 $2
echo -e "$YELLOW# In the next epoch, we can send vote txns with validator/vote account being$END"
solana-keygen pubkey $1
echo -e "$YELLOW and $END"
solana-keygen pubkey $2
