use {
    solana_sdk::{
        bpf_loader_upgradeable::{
            self,
            UpgradeableLoaderState,
        },
        nonce,
        signature::{Keypair, Signer},
        transaction::Transaction,
        message::Message,
        instruction::{Instruction, AccountMeta},
        pubkey::Pubkey,
        system_program,
        system_instruction,
        sysvar::{recent_blockhashes, rent}
    },
    solana_client::{
        connection_cache::ConnectionCache,
        rpc_client::RpcClient,
        send_and_confirm_transactions_in_parallel::{send_and_confirm_transactions_in_parallel_blocking, SendAndConfirmConfig}
    },
    solana_cli::{
        program::calculate_max_chunk_size,
    },
    std::{
        sync::Arc,
    },
};


/// Sets Up Buffer Account in Order to Deploy Program
///
/// # Arguments
/// * `client` - RPC Client
/// * `payer` - Keypair of the Payer
/// * `program_data` - Program Data
///
/// # Returns
/// * `buffer_account` - Buffer Account Keypair
///
/// # Examples
/// ```
/// let buffer_account = programs::set_up_buffer_account(&client, &payer, &program_data);
/// ```
pub fn set_up_buffer_account(client: &Arc<RpcClient>, payer: &Keypair, program_data: &Vec<u8>) -> Keypair {
    let blockhash = client.get_latest_blockhash().unwrap();
    let buffer_account = Keypair::new();

    let min_rent_exempt_program_data_balance = client.get_minimum_balance_for_rent_exemption(
        UpgradeableLoaderState::size_of_programdata(program_data.len()),
    ).unwrap();

    let create_program_account_instruction = bpf_loader_upgradeable::create_buffer(
        &payer.pubkey(),
        &buffer_account.pubkey(),
        &payer.pubkey(),
        min_rent_exempt_program_data_balance,
        program_data.len(),
    );

    let buffer_transaction = Transaction::new_signed_with_payer(
        &create_program_account_instruction.unwrap(),
        Some(&payer.pubkey()),
        &[&payer, &buffer_account],
        client.get_latest_blockhash().unwrap(),
    );
    let _ = client.send_and_confirm_transaction(&buffer_transaction).unwrap();

    let create_msg = |offset: u32, bytes: Vec<u8>| {
        let write_instruction = bpf_loader_upgradeable::write(
            &buffer_account.pubkey(),
            &payer.pubkey(),
            offset,
            bytes,
        );
        return Message::new_with_blockhash(&[write_instruction], Some(&payer.pubkey()), &blockhash);
    };

    let chunk_size = calculate_max_chunk_size(&create_msg);
    // messages vector
    let mut messages = vec![];
    for (chunk, i) in program_data.chunks(chunk_size).zip(0..) {
        let message = create_msg((i * chunk_size) as u32, chunk.to_vec());
        messages.push(message);
    }

    let connection_cache = ConnectionCache::new_quic("connection_cache_cli_program_v4_quic", 1);

    let cache = match connection_cache {
        ConnectionCache::Quic(cache) => cache,
        _ => unreachable!(),
    };

    let tpu_client_fut =
        solana_client::nonblocking::tpu_client::TpuClient::new_with_connection_cache(
            client.get_inner_client().clone(),
            "ws://localhost:8900/",
            solana_client::tpu_client::TpuClientConfig::default(),
            cache,
        );
    let tpu_client = client
        .runtime()
        .block_on(tpu_client_fut)
        .expect("Should return a valid tpu client");

    let _ = send_and_confirm_transactions_in_parallel_blocking(
        client.clone(),
        Some(tpu_client),
        &messages,
        &[payer],
        SendAndConfirmConfig {
            resign_txs_count: Some(1),
            with_spinner: true,
        },
    ).unwrap();

    println!("Program Data in Buffer Account: {:?}", buffer_account.pubkey());

    buffer_account
}

/// Instructions for Deploying a Program
///
/// # Arguments
/// * `client` - RPC Client
/// * `payer` - Keypair of the Payer
/// * `program_keypair` - Keypair of the Program Account
/// * `buffer_account` - Keypair of the Buffer Account
/// * `program_length` - Length of the Program
///
/// # Returns
/// * `program_account` - Program Account Keypair
/// * `deploy_instructions` - Deploy Instructions
///
/// # Required Signers
/// * `payer`
/// * `program_account`
///
/// # Examples
/// ```
/// let (program_account, deploy_instructions) = programs::deploy_program_instructions(&client, &payer, None, &buffer_account_deploy, program_data.len());
/// ```
pub fn deploy_program_instructions(client: &RpcClient, payer: &Keypair, program_keypair: Option<Keypair>, buffer_account: &Keypair, program_length: usize) -> (Keypair, Vec<Instruction>) {
    let program_account = program_keypair.unwrap_or_else(Keypair::new);

    let deploy_instructions = bpf_loader_upgradeable::deploy_with_max_program_len(
        &payer.pubkey(),
        &program_account.pubkey(),
        &buffer_account.pubkey(),
        &payer.pubkey(),
        client.get_minimum_balance_for_rent_exemption(
            UpgradeableLoaderState::size_of_program(),
        ).unwrap(),
        program_length,
    ).unwrap();

    (program_account, deploy_instructions)
}

/// Instructions for Invoking a Program
///
/// # Arguments
/// * `client` - RPC Client
/// * `payer` - Keypair of the Payer
/// * `program_account` - Keypair of the Program Account
/// * `account_data` - Account Data
///
/// # Returns
/// * `run_account` - Run Account Keypair
/// * `invoke_instructions` - Invoke Instructions
///
/// # Required Signers
/// * `payer`
/// * `run_account`
///
/// # Examples
/// ```
/// let (run_account, invoke_program_instructions) = programs::invoke_program_instructions(&client, &payer, &program_account, &account_data);
/// ```
pub fn invoke_program_instructions(client: &RpcClient, payer: &Keypair, program_account: &Keypair, account_data: &[u8]) -> (Keypair, Vec<Instruction>) {
    let mut invoke_instructions = Vec::new();

    let run_account = Keypair::new();

    let open_account_instruction = system_instruction::create_account(
        &payer.pubkey(),
        &run_account.pubkey(),
        client.get_minimum_balance_for_rent_exemption(account_data.len()).unwrap(),
        account_data.len() as u64,
        &program_account.pubkey(),
    );
    invoke_instructions.push(open_account_instruction);

    let account_metas = vec![
        AccountMeta::new(run_account.pubkey(), false),
    ];

    let invoke_instruction = Instruction::new_with_bytes(
        program_account.pubkey(),
        &account_data,
        account_metas,
    );
    invoke_instructions.push(invoke_instruction);

    (run_account, invoke_instructions)
}

/// Instructions for Upgrading a Program
///
/// # Arguments
/// * `payer` - Keypair of the Payer
/// * `upgrade_buffer_account` - Keypair of the Upgrade Buffer Account
/// * `program_account` - Keypair of the Program Account
///
/// # Returns
/// * `upgrade_instructions` - Upgrade Instructions
///
/// # Required Signers
/// * `payer`
///
/// # Examples
/// ```
/// let upgrade_buffer_instructions = programs::upgrade_program_instructions(&payer, &buffer_account_upgrade, &program_account);
/// ```
pub fn upgrade_program_instructions(payer: &Keypair, upgrade_buffer_account: &Keypair, program_account: &Keypair) -> Vec<Instruction> {
    let upgrade_instruction = bpf_loader_upgradeable::upgrade(
        &program_account.pubkey(),
        &upgrade_buffer_account.pubkey(),
        &payer.pubkey(),
        &payer.pubkey(),
    );

    vec![upgrade_instruction]
}

/// Instructions for Closing a Program
///
/// # Arguments
/// * `payer` - Keypair of the Payer
/// * `program_account` - Keypair of the Program Account
///
/// # Returns
/// * `close_instructions` - Close Instructions
///
/// # Required Signers
/// * `payer`
///
/// # Examples
/// ```
/// let close_program_instructions = programs::close_program_instructions(&payer, &program_account);
/// ```
pub fn close_program_instructions(payer: &Keypair, program_account: &Keypair) -> Vec<Instruction> {
    let (program_data_address, _) = Pubkey::find_program_address(&[program_account.pubkey().as_ref()], &bpf_loader_upgradeable::id());

    let close_instruction = bpf_loader_upgradeable::close_any(
        &program_data_address,
        &payer.pubkey(),
        Some(&payer.pubkey()),
        Some(&program_account.pubkey()),
    );

    vec![close_instruction]
}

pub fn create_nonce_account_instructions(nonce_account: Option<Keypair>, payer: &Keypair, lamports: u64) -> (Keypair, Vec<Instruction>)  {
    let mut nonce_account_instructions = Vec::new();

    let nonce_account = nonce_account.unwrap_or_else(|| Keypair::new());

    let open_account_instruction = system_instruction::create_account(
        &payer.pubkey(),
        &nonce_account.pubkey(),
        lamports,
        nonce::State::size() as u64,
        &system_program::id(),
    );
    nonce_account_instructions.push(open_account_instruction);

    let initialize_nonce_account_instruction = Instruction::new_with_bincode(
        system_program::id(),
        &system_instruction::SystemInstruction::InitializeNonceAccount(payer.pubkey()),
        vec![
            AccountMeta::new(nonce_account.pubkey(), false),
            AccountMeta::new_readonly(recent_blockhashes::id(), false),
            AccountMeta::new_readonly(rent::id(), false),
        ],
    );

    nonce_account_instructions.push(initialize_nonce_account_instruction);    

    (nonce_account, nonce_account_instructions)
}


pub fn transfer_lamports_instructions(from: &Keypair, to: &Keypair, lamports: u64) -> Vec<Instruction> {
    let transfer_instruction = system_instruction::transfer(&from.pubkey(), &to.pubkey(), lamports);

    vec![transfer_instruction]
}
