#!/bin/bash

# This script (re)creates a ledger with Zk Token Proof Program transactions.
#
# Dependencies: spl-token, solana.
# https://github.com/solana-labs/solana-program-library/tree/token-2022-v1.0.0
# https://github.com/solana-labs/solana/tree/v1.17.6
#
# In another shell, run:
# solana-test-validator --reset

SOLANA=solana
TOKEN=spl-token
#TOKEN=../solana-program-library/target/release/spl-token

CONF=~/.config/solana/cli/config.yml
ALICE_CONF=~/.config/solana/cli/alice.yml

CRED=~/.config/solana/id.json
ALICE_CRED=~/.config/solana/alice.json

function check_solana() {
    $SOLANA help > /dev/null
    if [ $? != 0 ]; then
        echo "solana: command not found"
        exit 1
    fi

    ls $CRED > /dev/null
    if [ $? != 0 ]; then
        echo "solana: credentials not found"
        exit 1
    fi

    ls $CONF > /dev/null
    if [ $? != 0 ]; then
        echo "solana: config not found"
        exit 1
    fi
};

function check_spl_token() {
    $TOKEN help > /dev/null
    if [ $? != 0 ]; then
        echo "spl-token: command not found"
        exit 1
    fi
};

function check_alice() {
    ls $ALICE_CRED > /dev/null
    if [ $? != 0 ]; then
        echo "solana: Alice credentials not found"
        exit 1
    fi

    ls $ALICE_CONF > /dev/null
    if [ $? != 0 ]; then
        echo "solana: Alice config not found"
        exit 1
    fi
};

check_solana
check_spl_token
check_alice

echo - Fund Alice, so she can create her token account
ALICE=$($SOLANA address -C $ALICE_CONF)
$SOLANA transfer $ALICE 10 --allow-unfunded-recipient

echo - Create token
MINT=$($TOKEN --program-id TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb create-token --enable-confidential-transfers auto | grep Address | sed -e 's/.* //g')

echo - Create token account
ADDR=$($TOKEN create-account $MINT | grep Creating | sed -e 's/.* //g')

echo - Configure confidential account
$TOKEN configure-confidential-transfer-account --address $ADDR

echo - Mint tokens
$TOKEN mint $MINT 50000

echo - Deposit confidential tokens
$TOKEN deposit-confidential-tokens $MINT 30000 --address $ADDR

echo - Apply pending balance
$TOKEN apply-pending-balance --address $ADDR

echo - Create Alice\'s token account
ALICE_ATA=$($TOKEN create-account $MINT -C $ALICE_CONF | grep Creating | sed -e 's/.* //g')

echo - Configure Alice\'s confidential account
$TOKEN configure-confidential-transfer-account --address $ALICE_ATA -C $ALICE_CONF

echo - Confidential transfer to Alice
$TOKEN transfer $MINT 10 $ALICE --confidential

echo - Withdraw confidential tokens
$TOKEN withdraw-confidential-tokens $MINT 100 --address $ADDR
