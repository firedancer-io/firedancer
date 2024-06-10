#!/bin/bash
# Usage: init_vote_acct_local.sh <IDENTITY_KEYPAIR> <ACCOUNT_KEYPAIR> <AUTHORIZED_KEYPAIR> <STAKE_ACCOUNT_KEYPAIR>
# AUTHORIZED_KEYPAIR can be the same as IDENTITY_KEYPAIR, in which case one should run the following command:
#   init_vote_acct_local.sh validator-keypair.json vote-account-keypair.json validator-keypair.json stake-account-keypair.json
# the json keypair files can be genrated by solana-keygen

set -e

YELLOW="\033[1;33m"
END="\033[0m"

NODE_IDENTITY=$1
VOTE_ACCT_ADDR=$2
AUTH_VOTER=$3
STAKE_ACCT=$4
SOL_AIRDROP=3
SOL_STAKE=2

echo -e "$YELLOW# Configuring solana and airdrop$END"
solana config set --url localhost
solana config set --keypair $NODE_IDENTITY
solana airdrop $SOL_AIRDROP

echo -e "$YELLOW# Create vote account and vote authority$END"
# solana create-vote-account <ACCOUNT_KEYPAIR> <IDENTITY_KEYPAIR> <WITHDRAWER_PUBKEY> --commission <PERCENTAGE> --config <FILEPATH>
solana create-vote-account $VOTE_ACCT_ADDR $NODE_IDENTITY $NODE_IDENTITY --allow-unsafe-authorized-withdrawer

# solana vote-authorize-voter <VOTE_ACCOUNT_ADDRESS> <AUTHORIZED_KEYPAIR> <NEW_AUTHORIZED_PUBKEY> --config <FILEPATH>
solana vote-authorize-voter $VOTE_ACCT_ADDR $NODE_IDENTITY $AUTH_VOTER

echo -e "$YELLOW# Create stake account and delegate stake$END"
# solana create-stake-account <STAKE_ACCOUNT_KEYPAIR> <AMOUNT> --config <FILEPATH>
solana create-stake-account $STAKE_ACCT $SOL_STAKE
# solana delegate-stake <STAKE_ACCOUNT_ADDRESS> <VOTE_ACCOUNT_ADDRESS> --config <FILEPATH>
solana delegate-stake $STAKE_ACCT $VOTE_ACCT_ADDR

echo -e "$YELLOW# In the next epoch, we can send vote txns with node identity/vote account/authorized voter being$END"
solana-keygen pubkey $NODE_IDENTITY
echo -e "$YELLOW and $END"
solana-keygen pubkey $VOTE_ACCT_ADDR
echo -e "$YELLOW and $END"
solana-keygen pubkey $AUTH_VOTER
