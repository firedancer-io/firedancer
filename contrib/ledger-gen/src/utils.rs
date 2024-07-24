use {
    lazy_static::lazy_static,
    solana_client::{
        rpc_client::RpcClient,
    },
    solana_rpc_client_api::config::RpcSendTransactionConfig,
    solana_sdk::{
        feature_set::FeatureSet,
        transaction::Transaction,
        instruction::Instruction,
        signature::{Keypair, Signer},
        hash::Hash,
        message::Message,
        commitment_config::CommitmentConfig,
    },
    solana_bpf_loader_program::{
        syscalls::create_program_runtime_environment_v1,
    },
    solana_program_runtime::{
        invoke_context::InvokeContext,
        compute_budget::ComputeBudget,
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

pub fn read_and_verify_elf(program_location: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(program_location)
        .map_err(|err| format!("Unable to open program file: {err}"))?;
    let mut program_data = Vec::new();
    file.read_to_end(&mut program_data)
        .map_err(|err| format!("Unable to read program file: {err}"))?;

    // Verify the program
    let program_runtime_environment = create_program_runtime_environment_v1(
        &FeatureSet::all_enabled(),
        &ComputeBudget::default(),
        true,
        false,
    )
    .unwrap();
    let executable =
        Executable::<InvokeContext>::from_elf(&program_data, Arc::new(program_runtime_environment))
            .map_err(|err| format!("ELF error: {err}"))?;

    executable
        .verify::<RequisiteVerifier>()
        .map_err(|err| format!("ELF error: {err}"))?;

    Ok(program_data)
}

pub fn create_message_and_sign(instructions: &Vec<Instruction>, payer: &Keypair, signers: Vec<&Keypair>, blockhash: Hash) -> Transaction {
    let message = Message::new_with_blockhash(&instructions, Some(&payer.pubkey()), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    let _ = transaction.try_sign(&signers, blockhash).unwrap();
    transaction
}

pub fn nonce_create_message_and_sign(instructions: Vec<Instruction>, payer: &Keypair, signers: Vec<&Keypair>, nonce_account: &Keypair, nonce_blockhash: Hash) -> Transaction {
    let message = Message::new_with_nonce(instructions, Some(&payer.pubkey()), &nonce_account.pubkey(), &payer.pubkey());
    let mut transaction = Transaction::new_unsigned(message);
    let _ = transaction.try_sign(&signers, nonce_blockhash).unwrap();
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
        preflight_commitment: Some(CommitmentConfig::processed().commitment),
        ..RpcSendTransactionConfig::default()
    };
}
