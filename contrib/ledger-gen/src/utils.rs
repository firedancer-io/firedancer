use {
    lazy_static::lazy_static,
    solana_client::{
        rpc_client::RpcClient,
    },
    solana_rpc_client_api::config::RpcSendTransactionConfig,
    solana_sdk::{
        transaction::Transaction,
        instruction::Instruction,
        signature::{Keypair, Signer},
        hash::Hash,
        message::Message,
    },
    solana_feature_set::FeatureSet,
    solana_compute_budget::{
        compute_budget::ComputeBudget,
    },
    solana_program_runtime::{
        invoke_context::InvokeContext,
    },
    solana_rbpf::{
        elf::Executable,
        verifier::RequisiteVerifier,
    },
    std::{
        fs::File,
        io::Read,
        sync::Arc,
    },
};

pub fn create_message_and_sign(instructions: &Vec<Instruction>, payer: &Keypair, signers: Vec<&Keypair>, blockhash: Hash) -> Transaction {
    let message = Message::new_with_blockhash(&instructions, Some(&payer.pubkey()), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    let _ = transaction.try_sign(&signers, blockhash).unwrap();
    transaction
}

pub fn wait_atleast_n_slots(client: &RpcClient, n: u64) {
    let current_slot = client.get_slot().unwrap();
    let target_slot = current_slot + n;
    loop {
        let current_slot = client.get_slot().unwrap();
        if current_slot >= target_slot {
            break;
        }
    }
}

lazy_static! {
    pub static ref SKIP_PREFLIGHT_CONFIG: RpcSendTransactionConfig = RpcSendTransactionConfig {
        skip_preflight: true,
        ..Default::default()
    };
}
