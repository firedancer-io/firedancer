use {
    solana_sdk::{
        signature::{Keypair, Signer},
        commitment_config::{CommitmentConfig},
        nonce::{State as NonceState},
        system_instruction,
        system_program,
        message::Message,
        transaction::Transaction,
    },
    solana_client::{
        rpc_client::{RpcClient},
    },
    solana_rpc_client_nonce_utils::{get_account_with_commitment, nonblocking},
};

use crate::instructions;
use crate::utils;

pub fn create_nonce_account(client: &RpcClient, payer: &Keypair) {
    let blockhash = client.get_latest_blockhash().unwrap();
    let (nonce_account, create_nonce_instructions) = instructions::create_nonce_account_instructions(None, &payer, 2000000);
    let transaction = utils::create_message_and_sign(&create_nonce_instructions, &payer, vec![&payer, &nonce_account], blockhash);
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Nonce Account: {:?} - Slot: {:?}", nonce_account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    let nonce_blockhash = match get_account_with_commitment(client, &nonce_account.pubkey(), CommitmentConfig::processed())
        .and_then(|ref a| nonblocking::state_from_account(a)).unwrap()
    {
        NonceState::Initialized(ref data) => data.blockhash(),
        _ => panic!("Nonce Account not Initialized"),
    };
    println!("Nonce Blockhash: {:?}", nonce_blockhash);

    let new_account = Keypair::new();

    let minimum_balance = client
        .get_minimum_balance_for_rent_exemption(NonceState::size())
        .unwrap();

    let open_account_instruction = system_instruction::create_account(
        &payer.pubkey(),
        &new_account.pubkey(),
        minimum_balance,
        0,
        &system_program::id(),
    );

    let message = Message::new_with_nonce(
        vec![open_account_instruction],
        Some(&payer.pubkey()),
        &nonce_account.pubkey(),
        &payer.pubkey(),
    );
    let mut transaction = Transaction::new_unsigned(message);
    let _ = transaction.try_sign(&vec![&payer, &new_account], nonce_blockhash).unwrap();
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Opened Account: {:?}", new_account.pubkey());

    utils::wait_atleast_n_slots(&client, 2);

    // will fail if we don't update the nonce blockhash
    let nonce_blockhash = match get_account_with_commitment(client, &nonce_account.pubkey(), CommitmentConfig::processed())
        .and_then(|ref a| nonblocking::state_from_account(a)).unwrap()
    {
        NonceState::Initialized(ref data) => data.blockhash(),
        _ => panic!("Nonce Account not Initialized"),
    };
    println!("Nonce Blockhash: {:?}", nonce_blockhash);

    let new_account = Keypair::new();

    let minimum_balance = client
        .get_minimum_balance_for_rent_exemption(NonceState::size())
        .unwrap();

    let open_account_instruction = system_instruction::create_account(
        &payer.pubkey(),
        &new_account.pubkey(),
        minimum_balance,
        0,
        &system_program::id(),
    );

    let message = Message::new_with_nonce(
        vec![open_account_instruction],
        Some(&payer.pubkey()),
        &nonce_account.pubkey(),
        &payer.pubkey(),
    );
    let mut transaction = Transaction::new_unsigned(message);
    let _ = transaction.try_sign(&vec![&payer, &new_account], nonce_blockhash).unwrap();
    println!("Transaction: {:?}", transaction);
    utils::wait_atleast_n_slots(&client, 2);
    // let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG).unwrap();
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();

    utils::wait_atleast_n_slots(&client, 2);

    let nonce_blockhash = match get_account_with_commitment(client, &nonce_account.pubkey(), CommitmentConfig::processed())
        .and_then(|ref a| nonblocking::state_from_account(a)).unwrap()
    {
        NonceState::Initialized(ref data) => data.blockhash(),
        _ => panic!("Nonce Account not Initialized"),
    };
    println!("Nonce Blockhash: {:?}", nonce_blockhash);
}
