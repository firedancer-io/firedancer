use {
    solana_sdk::{
        signature::{Keypair, Signer, read_keypair_file},
        commitment_config::{CommitmentConfig},
        feature::{self, Feature},
        feature_set,
        nonce::{State as NonceState},
        system_instruction,
        system_program,
        message::Message,
        transaction::Transaction,
        stake::{
            self,
            instruction::{self as stake_instruction, LockupArgs, StakeError},
            state::{
                Authorized, Lockup, Meta, StakeActivationStatus, StakeAuthorize, StakeStateV2,
            },
            tools::{acceptable_reference_epoch_credits, eligible_for_deactivate_delinquent},
        },
    },
    solana_client::{
        rpc_client::{RpcClient},
    },
    solana_rpc_client_nonce_utils::{get_account_with_commitment, nonblocking},
    solana_cli::{
        spend_utils::{SpendAmount, resolve_spend_tx_and_check_account_balance},
    }
};

use crate::instructions;
use crate::utils;

pub fn move_lamports(client: &RpcClient, payer: &Keypair) {
    let from_stake_account = Keypair::new();
    
    let authorized = Authorized {
        staker: payer.pubkey(),
        withdrawer: payer.pubkey(),
    };

    let create_from_stake_account_instruction = stake_instruction::create_account_checked(
        &payer.pubkey(),
        &from_stake_account.pubkey(),
        &authorized,
        1000000000,
    );

    let transaction = utils::create_message_and_sign(&create_from_stake_account_instruction, &payer, vec![&payer, &from_stake_account], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created From Stake Account {:?} - Slot: {:?}", from_stake_account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    let to_stake_account = Keypair::new();

    let create_to_stake_account_instruction = stake_instruction::create_account_checked(
        &payer.pubkey(),
        &to_stake_account.pubkey(),
        &authorized,
        1000000000,
    );

    let transaction = utils::create_message_and_sign(&create_to_stake_account_instruction, &payer, vec![&payer, &to_stake_account], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created To Stake Account {:?} - Slot: {:?}", to_stake_account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    let move_lamports_instruction = vec![stake_instruction::move_lamports(
        &from_stake_account.pubkey(),
        &to_stake_account.pubkey(),
        &payer.pubkey(),
        10000000,
    )];
    let transaction = utils::create_message_and_sign(&move_lamports_instruction, &payer, vec![&payer], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Moved Lamport from {:?} to {:?} - Slot: {:?}", from_stake_account.pubkey(), to_stake_account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
}

pub fn move_stake(client: &RpcClient, payer: &Keypair) {
    let from_stake_account = Keypair::new();
    
    let authorized = Authorized {
        staker: payer.pubkey(),
        withdrawer: payer.pubkey(),
    };

    let create_from_stake_account_instructions = stake_instruction::create_account_checked(
        &payer.pubkey(),
        &from_stake_account.pubkey(),
        &authorized,
        1000000000,
    );

    let transaction = utils::create_message_and_sign(&create_from_stake_account_instructions, &payer, vec![&payer, &from_stake_account], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created From Stake Account {:?} - Slot: {:?}", from_stake_account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    let voter = read_keypair_file("/data/kbhargava/ledgers/ledger-gen-cluster/keys-0/vote.json").unwrap();

    let delegate_stake_account_instruction = vec![stake_instruction::delegate_stake(
        &from_stake_account.pubkey(),
        &payer.pubkey(),
        &voter.pubkey(),
    )];
    let transaction = utils::create_message_and_sign(&delegate_stake_account_instruction, &payer, vec![&payer], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Delegated Stake Account {:?} to {:?} - Slot: {:?}", from_stake_account.pubkey(), voter.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    let to_stake_account = Keypair::new();

    let create_to_stake_account_instruction = stake_instruction::create_account_checked(
        &payer.pubkey(),
        &to_stake_account.pubkey(),
        &authorized,
        1000000000,
    );

    let transaction = utils::create_message_and_sign(&create_to_stake_account_instruction, &payer, vec![&payer, &to_stake_account], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created To Stake Account {:?} - Slot: {:?}", to_stake_account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    utils::wait_atleast_n_slots(&client, 1000);
    let move_lamports_instruction = vec![stake_instruction::move_stake(
        &from_stake_account.pubkey(),
        &to_stake_account.pubkey(),
        &payer.pubkey(),
        100000000,
    )];

    let transaction = utils::create_message_and_sign(&move_lamports_instruction, &payer, vec![&payer], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Moved Stake from {:?} to {:?} - Slot: {:?}", from_stake_account.pubkey(), to_stake_account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
}