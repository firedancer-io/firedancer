use {
    solana_sdk::{
        signature::{Keypair},
    },
    solana_client::{
        rpc_client::{RpcClient},
    },
    std::{
        sync::Arc,
    },
};

use crate::bpf_loader;
use crate::nonce;

/// CI Link: gs://firedancer-ci-resources/v18multi-bpf-loader.tar.gz
pub fn bpf_loader_ledger(client: &RpcClient, arc_client: &Arc<RpcClient>, payer: &Keypair, program_data: &Vec<u8>, account_data: &Vec<u8>) {
    println!("Running deploy_invoke_same_slot...");
    bpf_loader::deploy_invoke_same_slot(&client, &arc_client, &payer, &program_data, &account_data);
    println!("Running deploy_invoke_diff_slot...");
    bpf_loader::deploy_invoke_diff_slot(&client, &arc_client, &payer, &program_data, &account_data);

    println!("Running upgrade_invoke_same_slot...");
    bpf_loader::upgrade_invoke_same_slot(&client, &arc_client, &payer, &program_data, &account_data);
    println!("Running upgrade_invoke_diff_slot...");
    bpf_loader::upgrade_invoke_diff_slot(&client, &arc_client, &payer, &program_data, &account_data);

    println!("Running deploy_close_same_slot...");
    bpf_loader::deploy_close_same_slot(&client, &arc_client, &payer, &program_data, &account_data);
    println!("Running deploy_close_diff_slot...");
    bpf_loader::deploy_close_diff_slot(&client, &arc_client, &payer, &program_data, &account_data);

    println!("Running close_invoke_same_slot...");
    bpf_loader::close_invoke_same_slot(&client, &arc_client, &payer, &program_data, &account_data);
    println!("Running close_invoke_diff_slot...");
    bpf_loader::close_invoke_diff_slot(&client, &arc_client, &payer, &program_data, &account_data);

    println!("Running close_redeploy_same_slot...");
    bpf_loader::close_redeploy_same_slot(&client, &arc_client, &payer, &program_data, &account_data);
    println!("Running close_redeploy_diff_slot...");
    bpf_loader::close_redeploy_diff_slot(&client, &arc_client, &payer, &program_data, &account_data);
}

/// CI Link: gs://firedancer-ci-resources/v18multi-blockhash-and-nonce.tar.gz
pub fn nonce_ledger(client: &RpcClient, payer: &Keypair) {
    println!("Running valid_recent_block_hash...");
    nonce::valid_recent_block_hash(&client, &payer);
    println!("Running invalid_recent_block_hash...");
    nonce::invalid_recent_block_hash(&client, &payer);
    println!("Running same_recent_block_hash...");
    nonce::same_recent_block_hash(&client, &payer);

    println!("Running valid_nonce_transfer...");
    nonce::valid_nonce_transfer(&client, &payer);
    println!("Running invalid_nonce_transfer...");
    nonce::invalid_nonce_transfer(&client, &payer);
    println!("Running same_nonce_transfer...");
    nonce::same_nonce_transfer(&client, &payer);
}

pub fn nonce_warnings_ledger(client: &RpcClient, payer: &Keypair) {
    // nonce::advance_advance_same_slot(&client, &payer);
    nonce::advance_withdraw_same_slot(&client, &payer);
}