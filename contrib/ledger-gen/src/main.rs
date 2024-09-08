#![allow(warnings)]

use {
    solana_sdk::{
        signature::{read_keypair_file},
        commitment_config::{CommitmentConfig}
    },
    solana_client::{
        rpc_client::{RpcClient},
    },
    std::{
        env,
        sync::Arc,
    },
};

mod ledgers;
mod instructions;
mod utils;

mod bpf_loader;
mod nonce;
mod stake;

/// Workflow for Creating Ledgers
/// * Set up all buffer accounts
/// * Call specific instructions function
///     * deploy_program_instructions
///     * invoke_program_instructions
///     * upgrade_program_instructions
///     * close_program_instructions
/// * Create Transaction
///     * Use create_message_and_sign
///         * Can combine instructions in first argument
///         * Add correct signers in third argument
/// * Send Transaction using client.send_and_confirm_transaction
/// * Use utils::wait_atleast_n_slots to wait for a certain number of slots before sending next transaction
//
// Running the Program
// cargo run --payer=/path/to/payer.json (usually faucet.json for multi-node setup)
fn main() {
    // Set Up Connection, Program, and Payer
    let rpc_client = RpcClient::new_with_commitment("http://localhost:8899", CommitmentConfig::processed());
    let arc_client = Arc::new(RpcClient::new_with_commitment("http://localhost:8899", CommitmentConfig::confirmed()));

    let payer_path = env::args()
        .find(|arg| arg.starts_with("payer="))
        .and_then(|arg| arg.split('=').nth(1).map(String::from))
        .expect("Payer file path must be provided as 'payer=/path/to/file'");
    let payer = read_keypair_file(&payer_path).unwrap();

    // Set Up Program and Account Data
    let program_data = utils::read_and_verify_elf("helloworld.so").unwrap();
    let account_data = vec![0u8; 4];

    // ----------------------- ONLY CHANGE BELOW THIS LINE -----------------------
    // ledgers::bpf_loader_ledger(&rpc_client, &arc_client, &payer, &program_data, &account_data);
    // ledgers::stake_ledger(&rpc_client, &payer);
}
