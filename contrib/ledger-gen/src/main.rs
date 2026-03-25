#![allow(warnings)]

use {
    solana_sdk::{
        signature::{read_keypair_file},
    },
    solana_client::{
        rpc_client::{RpcClient},
    },
    solana_commitment_config::CommitmentConfig,
    std::{
        env,
        sync::Arc,
        time::Instant,
    },
    solana_rpc_client_api::config::RpcSendTransactionConfig,
    solana_sdk::signature::Signer,
    solana_sdk::transaction::Transaction,
    tokio::{
        task,
        time::{sleep, Duration},
    },
    solana_sdk_ids::sysvar,
    solana_system_interface::{program as system_program, instruction as system_instruction},
    solana_keypair::Keypair,
    solana_address_lookup_table_interface,
    solana_clock::Clock,
    solana_message::{Message, AddressLookupTableAccount, v0::Message as MessageV0, VersionedMessage},
    solana_sdk::account::from_account,
    solana_transaction::versioned::VersionedTransaction,
};

mod instructions;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set Up Connection, Program, and Payer
    let rpc = env::args()
        .find(|arg| arg.starts_with("rpc="))
        .and_then(|arg| arg.split('=').nth(1).map(String::from))
        .expect("HTTP URL must be provided as 'rpc=http://url:port'");

    let rpc_client = RpcClient::new_with_commitment(&rpc, CommitmentConfig::processed());
    let arc_client = Arc::new(RpcClient::new_with_commitment(&rpc, CommitmentConfig::confirmed()));

    println!("Using RPC Client: {}", rpc);

    let payer_path = env::args()
        .find(|arg| arg.starts_with("payer="))
        .and_then(|arg| arg.split('=').nth(1).map(String::from))
        .expect("Payer file path must be provided as 'payer=/path/to/file'");
    let payer = read_keypair_file(&payer_path).unwrap();

    // TXNS

    // Create more RPC clients for better parallelization
    let num_clients = 20; // Increased from 10 to 20
    let clients: Vec<Arc<RpcClient>> = (0..num_clients)
        .map(|_| Arc::new(RpcClient::new_with_commitment(&rpc, CommitmentConfig::processed())))
        .collect();

    let account_count = 100000;
    let batch_size = 1000; // Create accounts in batches
    let max_parallel_accounts = 50; // Max parallel account creation tasks

    println!("Creating {} accounts in batches of {}...", account_count, batch_size);
    let accounts: Vec<Arc<Keypair>> = (0..account_count).map(|i| Arc::new(Keypair::new())).collect();

    // Create accounts in parallel batches
    let account_creation_tasks: Vec<_> = accounts
        .chunks(batch_size)
        .enumerate()
        .map(|(batch_idx, account_batch)| {
            let client = clients[batch_idx % clients.len()].clone();
            let payer_pubkey = payer.pubkey();
            let payer_keypair = Keypair::new_from_array(payer.to_bytes()[..32].try_into().unwrap()); // Create a copy of the payer keypair
            let account_batch: Vec<Arc<Keypair>> = account_batch.iter().cloned().collect();
            task::spawn(async move {
                let mut results = Vec::new();
                let blockhash = client.get_latest_blockhash().unwrap();

                for account in account_batch {
                    let instruction = system_instruction::create_account(
                        &payer_pubkey,
                        &account.pubkey(),
                        1000000000,
                        0,
                        &system_program::id()
                    );
                    let tx = Transaction::new_signed_with_payer(
                        &[instruction],
                        Some(&payer_pubkey),
                        &[&payer_keypair, account.as_ref()],
                        blockhash
                    );
                    let result = client.send_transaction_with_config(&tx, *utils::SKIP_PREFLIGHT_CONFIG);
                    results.push((account.pubkey(), result));
                }
                results
            })
        })
        .collect();

    // Process account creation in parallel
    let mut all_account_results = Vec::new();
    let batch_results = join_all(account_creation_tasks).await;
    for batch_result in batch_results {
        if let Ok(results) = batch_result {
            all_account_results.extend(results);
        }
    }

    println!("Account creation completed! Created {} accounts", all_account_results.len());
    sleep(Duration::from_secs(2)).await;

    println!("Starting high-speed transaction spam with {} parallel clients", num_clients);

    let mut transaction_count = 0u64;
    let start_time = Instant::now();

    // Optimized transaction spamming with better batching
    let tx_batch_size = 1000; // Send 1000 transactions per batch
    let mut blockhash_refresh_counter = 0;
    let blockhash_refresh_interval = 3; // Refresh blockhash every 3 batches
    let mut current_blockhash = rpc_client.get_latest_blockhash().unwrap();

    loop {
        let batch_start = Instant::now();

        // Get fresh blockhash less frequently to reduce RPC calls
        if blockhash_refresh_counter % blockhash_refresh_interval == 0 {
            current_blockhash = rpc_client.get_latest_blockhash().unwrap();
        }
        blockhash_refresh_counter += 1;

        // Create transactions and send them in parallel
        let mut successful_txs = 0;
        let mut failed_txs = 0;

        // Process transactions in chunks across multiple clients
        let chunk_size = tx_batch_size / clients.len();
        let mut tasks = Vec::new();

        for (client_idx, client) in clients.iter().enumerate() {
            let client = client.clone();
            let accounts = accounts.clone(); // Clone the accounts for this task
            let blockhash = current_blockhash;
            let start_idx = client_idx * chunk_size;
            let end_idx = std::cmp::min(start_idx + chunk_size, tx_batch_size);

            let task = task::spawn(async move {
                let mut results = Vec::new();
                for i in start_idx..end_idx {
                    // Use a simple pattern to select accounts
                    let account_idx = i % accounts.len();
                    let account = &accounts[account_idx];

                    let tx = Transaction::new_signed_with_payer(
                        &[],
                        Some(&account.pubkey()),
                        &[account.as_ref()],
                        blockhash
                    );
                    let result = client.send_transaction_with_config(&tx, *utils::SKIP_PREFLIGHT_CONFIG);
                    results.push(result);
                }
                results
            });
            tasks.push(task);
        }

        // Wait for all tasks to complete
        let batch_results = join_all(tasks).await;
        for batch_result in batch_results {
            if let Ok(results) = batch_result {
                for result in results {
                    match result {
                        Ok(_) => successful_txs += 1,
                        Err(_) => failed_txs += 1,
                    }
                }
            }
        }

        transaction_count += successful_txs as u64;
        let batch_duration = batch_start.elapsed();
        let total_duration = start_time.elapsed();
        let tps = transaction_count as f64 / total_duration.as_secs_f64();

        println!("Batch completed in {:?} - Success: {}, Failed: {}, Total: {} txns, TPS: {:.2}",
                batch_duration, successful_txs, failed_txs, transaction_count, tps);

        // Adaptive delay based on performance
        if failed_txs > successful_txs / 2 {
            sleep(Duration::from_millis(50)).await; // Slow down if too many failures
        } else {
            sleep(Duration::from_millis(5)).await; // Minimal delay for good performance
        }
    }

    // ALUT

    let get_clock_result = rpc_client
        .get_account_with_commitment(&sysvar::clock::id(), CommitmentConfig::finalized())?;
    let clock_account = get_clock_result.value.expect("Clock account doesn't exist");
    let clock: Clock = from_account(&clock_account)
        .ok_or("Failed to deserialize clock sysvar")?;

    let authority_address = payer.pubkey();
    let payer_address = payer.pubkey();

    let (create_lookup_table_ix, lookup_table_address) =
        solana_address_lookup_table_interface::instruction::create_lookup_table(authority_address, payer_address, clock.slot);
    println!("Created lookup table: {:?}", lookup_table_address);

    let blockhash = rpc_client.get_latest_blockhash()?;

    let mut tx = Transaction::new_unsigned(Message::new(
        &[create_lookup_table_ix],
        Some(&payer.pubkey()), // Fee payer
    ));

    let signers = vec![&payer];
    tx.try_sign(&signers, blockhash)?;

    let result = rpc_client.send_and_confirm_transaction( &tx );
    println!("Result: {:?}", result);

    // create two new accounts, add 1 sol in each one add them to the table and transfer between them
    let account1 = Keypair::new();
    let account2 = Keypair::new();

    let instruction = system_instruction::create_account(
        &payer_address,
        &account1.pubkey(),
        1000000000,
        0,
        &system_program::id()
    );
    let tx = Transaction::new_signed_with_payer( &[instruction], Some(&payer_address), &[&payer, &account1], blockhash );
    let result = rpc_client.send_and_confirm_transaction( &tx );
    println!("Created account1: {:?}", account1.pubkey());

    let instruction = system_instruction::create_account(
        &payer_address,
        &account2.pubkey(),
        1000000000,
        0,
        &system_program::id()
    );
    let tx = Transaction::new_signed_with_payer( &[instruction], Some(&payer_address), &[&payer, &account2], blockhash );
    let result = rpc_client.send_and_confirm_transaction( &tx );
    println!("Created account2: {:?}", account2.pubkey());

    // add the accounts to the table
    let accounts_to_add = vec![account1.pubkey(), account2.pubkey()];

    let extend_lookup_table_ix = solana_address_lookup_table_interface::instruction::extend_lookup_table(
        lookup_table_address,
        authority_address,
        Some(payer_address),
        accounts_to_add.clone(),
    );

    let mut tx = Transaction::new_unsigned(Message::new(
        &[extend_lookup_table_ix],
        Some(&payer.pubkey()),
    ));

    let signers = vec![&payer];
    tx.try_sign(&signers, blockhash)?;
    let result = rpc_client.send_and_confirm_transaction(&tx);

    sleep(Duration::from_secs(2)).await;

    let lookup_table_account_data = rpc_client.get_account(&lookup_table_address)?;
    let lookup_table = solana_address_lookup_table_interface::state::AddressLookupTable::deserialize(&lookup_table_account_data.data)?;

    while ( true ) {
        let alut_account = AddressLookupTableAccount {
            key: lookup_table_address,
            addresses: lookup_table.addresses.to_vec(),
        };

        let ix1 = system_instruction::transfer( &payer.pubkey(), &account1.pubkey(), 10 );
        let ix2 = system_instruction::transfer( &payer.pubkey(), &account2.pubkey(), 10 );

        let recent_blockhash = rpc_client.get_latest_blockhash()?;

        let msg = MessageV0::try_compile(
            &payer.pubkey(),
            &[ix1, ix2],
            &[alut_account],
            recent_blockhash,
        )?;

        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&payer])?;
        let tx_result = rpc_client.send_and_confirm_transaction(&tx);
        println!("Transaction result: {:?}", tx_result);
    }

    Ok(())

}
