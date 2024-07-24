use {
    solana_sdk::{
        signature::{Keypair, Signer},
        commitment_config::{CommitmentConfig},
        hash::Hash,
        nonce::{
            state::DurableNonce,
            State as NonceState
        },
        system_instruction,
    },
    solana_client::{
        rpc_client::{RpcClient},
    },
    solana_rpc_client_nonce_utils::{get_account_with_commitment, nonblocking},
    std::{
        thread,
        time::Duration,
    },
};

use crate::instructions;
use crate::utils;

pub fn create_nonce_account(client: &RpcClient, payer: &Keypair) -> Keypair{
    let (nonce_account, create_nonce_instructions) = instructions::create_nonce_account_instructions(None, &payer, 2000000);
    let transaction = utils::create_message_and_sign(&create_nonce_instructions, &payer, vec![&payer, &nonce_account], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Nonce Account: {:?} - Slot: {:?}", nonce_account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    nonce_account
}

pub fn get_nonce_from_account(client: &RpcClient, nonce_account: &Keypair) -> Hash {
    match get_account_with_commitment(client, &nonce_account.pubkey(), CommitmentConfig::processed())
        .and_then(|ref a| nonblocking::state_from_account(a)).unwrap()
    {
        NonceState::Initialized(ref data) => data.blockhash(),
        _ => panic!("Nonce Account not Initialized"),
    }
}

pub fn valid_nonce_transfer(client: &RpcClient, payer: &Keypair) {
    let nonce_account = create_nonce_account(&client, &payer);
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let account = Keypair::new();

    let minimum_balance = client
        .get_minimum_balance_for_rent_exemption(NonceState::size())
        .unwrap();

    let open_account_instructions = vec![system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        minimum_balance,
        0,
        &account.pubkey(),
    )];

    let transaction = utils::nonce_create_message_and_sign(open_account_instructions, &payer, vec![&payer, &account], &nonce_account, get_nonce_from_account(&client, &nonce_account));
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let transfer_instructions = instructions::transfer_lamports_instructions(&payer, &account, 1000);
    let transaction = utils::nonce_create_message_and_sign(transfer_instructions, &payer, vec![&payer], &nonce_account, get_nonce_from_account(&client, &nonce_account));
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Transferred Lamports to Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));
}

pub fn invalid_nonce_transfer(client: &RpcClient, payer: &Keypair) {
    let nonce_account = create_nonce_account(&client, &payer);
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let account = Keypair::new();

    let minimum_balance = client
        .get_minimum_balance_for_rent_exemption(NonceState::size())
        .unwrap();

    let open_account_instructions = vec![system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        minimum_balance,
        0,
        &account.pubkey(),
    )];

    let transaction = utils::nonce_create_message_and_sign(open_account_instructions, &payer, vec![&payer, &account], &nonce_account, get_nonce_from_account(&client, &nonce_account));
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let transfer_instructions = instructions::transfer_lamports_instructions(&account, &payer, minimum_balance);
    let transaction = utils::nonce_create_message_and_sign(transfer_instructions, &payer, vec![&payer, &account], &nonce_account, get_nonce_from_account(&client, &nonce_account));
    let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG);
    println!("Attempted to Transfer Lamports to Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    utils::wait_atleast_n_slots(&client, 2);

    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));
}

pub fn same_nonce_transfer(client: &RpcClient, payer: &Keypair) {
    let nonce_account = create_nonce_account(&client, &payer);
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let account = Keypair::new();

    let minimum_balance = client
        .get_minimum_balance_for_rent_exemption(NonceState::size())
        .unwrap();

    let open_account_instructions = vec![system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        minimum_balance,
        0,
        &account.pubkey(),
    )];

    let transaction = utils::nonce_create_message_and_sign(open_account_instructions, &payer, vec![&payer, &account], &nonce_account, get_nonce_from_account(&client, &nonce_account));
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let nonce_blockhash = get_nonce_from_account(&client, &nonce_account);

    let transfer_instructions = instructions::transfer_lamports_instructions(&payer, &account, 1000);
    let transaction = utils::nonce_create_message_and_sign(transfer_instructions, &payer, vec![&payer], &nonce_account, nonce_blockhash);
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Transferred Lamports to Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let transfer_instructions = instructions::transfer_lamports_instructions(&payer, &account, 2000);
    let transaction = utils::nonce_create_message_and_sign(transfer_instructions, &payer, vec![&payer], &nonce_account, nonce_blockhash);
    let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG);
    println!("Attempted to Transfer Lamports to Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));
}

pub fn valid_recent_block_hash(client: &RpcClient, payer: &Keypair) {
    let account = Keypair::new();

    let open_account_instructions = vec![system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        client.get_minimum_balance_for_rent_exemption(0).unwrap(),
        0,
        &payer.pubkey(),
    )];

    utils::wait_atleast_n_slots(&client, 2);

    let transaction = utils::create_message_and_sign(&open_account_instructions, &payer, vec![&payer, &account], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
}

pub fn invalid_recent_block_hash(client: &RpcClient, payer: &Keypair) {
    let account = Keypair::new();

    let open_account_instructions = vec![system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        client.get_minimum_balance_for_rent_exemption(0).unwrap(),
        0,
        &payer.pubkey(),
    )];

    let transaction = utils::create_message_and_sign(&open_account_instructions, &payer, vec![&payer, &account], client.get_latest_blockhash().unwrap());

    utils::wait_atleast_n_slots(&client, 160);
    let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG).unwrap();
    println!("Created Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
}

pub fn same_recent_block_hash(client: &RpcClient, payer: &Keypair) {
    let account = Keypair::new();

    let open_account_instructions = vec![system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        client.get_minimum_balance_for_rent_exemption(0).unwrap(),
        0,
        &payer.pubkey(),
    )];

    let transaction = utils::create_message_and_sign(&open_account_instructions, &payer, vec![&payer, &account], client.get_latest_blockhash().unwrap());
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    let recent_blockhash = client.get_latest_blockhash().unwrap();

    let transfer_instructions = instructions::transfer_lamports_instructions(&payer, &account, 1000);
    let transaction = utils::create_message_and_sign(&transfer_instructions, &payer, vec![&payer], recent_blockhash);
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Transferred Lamports to Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());

    let transfer_instructions = instructions::transfer_lamports_instructions(&payer, &account, 1000);
    let transaction = utils::create_message_and_sign(&transfer_instructions, &payer, vec![&payer], recent_blockhash);
    let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG).unwrap();
    println!("Attempted to Transfer Lamports to Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
}


pub fn advance_advance_same_slot(client: &RpcClient, payer: &Keypair) {
    let nonce_account = create_nonce_account(&client, &payer);
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let account = Keypair::new();

    let minimum_balance = client
        .get_minimum_balance_for_rent_exemption(NonceState::size())
        .unwrap();

    let open_account_instructions = vec![system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        minimum_balance,
        0,
        &account.pubkey(),
    )];

    let transaction = utils::nonce_create_message_and_sign(open_account_instructions, &payer, vec![&payer, &account], &nonce_account, get_nonce_from_account(&client, &nonce_account));
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let current_blockhash = client.get_latest_blockhash().unwrap();
    let next_nonce = DurableNonce::from_blockhash(&current_blockhash);
    println!("Current Blockhash: {:?}", current_blockhash);
    println!("Next Nonce: {:?}", next_nonce);

    let nonce_blockhash = get_nonce_from_account(&client, &nonce_account);

    let transfer_instructions = instructions::transfer_lamports_instructions(&payer, &account, 1000);
    let transaction = utils::nonce_create_message_and_sign(transfer_instructions, &payer, vec![&payer], &nonce_account, nonce_blockhash);
    let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG).unwrap();
    println!("Transferred Lamports: {:?} - Slot: {:?}", transaction.signatures[0], client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));
    
    thread::sleep(Duration::from_millis(10));

    let transfer_instructions = instructions::transfer_lamports_instructions(&payer, &account, 2000);
    let transaction = utils::nonce_create_message_and_sign(transfer_instructions, &payer, vec![&payer], &nonce_account, *next_nonce.as_hash());
    let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG).unwrap();
    println!("Transferred Lamports: {:?} - Slot: {:?}", transaction.signatures[0], client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));
}

pub fn advance_withdraw_same_slot(client: &RpcClient, payer: &Keypair) {
    let nonce_account = create_nonce_account(&client, &payer);
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    utils::wait_atleast_n_slots(&client, 1);

    let account = Keypair::new();

    let minimum_balance = client
        .get_minimum_balance_for_rent_exemption(NonceState::size())
        .unwrap();

    let open_account_instructions = vec![system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        minimum_balance,
        0,
        &account.pubkey(),
    )];

    let transaction = utils::nonce_create_message_and_sign(open_account_instructions, &payer, vec![&payer, &account], &nonce_account, get_nonce_from_account(&client, &nonce_account));
    let _ = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Created Account: {:?} - Slot: {:?}", account.pubkey(), client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let current_blockhash = client.get_latest_blockhash().unwrap();
    let next_nonce = DurableNonce::from_blockhash(&current_blockhash);
    println!("Current Blockhash: {:?}", current_blockhash);
    println!("Next Nonce: {:?}", next_nonce);

    let nonce_blockhash = get_nonce_from_account(&client, &nonce_account);

    let transfer_instructions = instructions::transfer_lamports_instructions(&payer, &account, 1000);
    let transaction = utils::nonce_create_message_and_sign(transfer_instructions, &payer, vec![&payer], &nonce_account, nonce_blockhash);
    let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG).unwrap();
    println!("Transferred Lamports: {:?} - Slot: {:?}", transaction.signatures[0], client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));

    let withdraw_instructions = vec![system_instruction::withdraw_nonce_account(
        &nonce_account.pubkey(),
        &payer.pubkey(),
        &account.pubkey(),
        10,
    )];

    let transaction = utils::nonce_create_message_and_sign(withdraw_instructions, &payer, vec![&payer], &nonce_account, *next_nonce.as_hash());
    let _ = client.send_transaction_with_config(&transaction, *utils::SKIP_PREFLIGHT_CONFIG).unwrap();
    println!("Withdrew Lamports: {:?} - Slot: {:?}", transaction.signatures[0], client.get_slot_with_commitment(CommitmentConfig::processed()).unwrap());
    println!("Current Nonce Blockhash: {:?}", get_nonce_from_account(&client, &nonce_account));
}