#include "fd_builtin_programs.h"

/* BuiltIn programs need "bogus" executable accounts to exist.
   These are loaded and ignored during execution. */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/native_loader.rs#L19 */
void write_builtin_bogus_account( fd_global_ctx_t *global, const unsigned char *pubkey, unsigned char *data, unsigned long sz ) {
  fd_solana_account_t account = {
    .lamports = 1,
    .rent_epoch = 0,
    .data_len = sz,
    .data = (unsigned char *) data,
    .executable = (uchar) 1
  };
  fd_memcpy( account.owner.key, global->solana_native_loader, 32 );

  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->current_slot, (fd_pubkey_t *) pubkey, &account );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/inline_spl_token.rs#L74 */
/* TODO: move this somewhere more appropiate */
void write_inline_spl_native_mint_program_account( fd_global_ctx_t* global ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/inline_spl_token.rs#L86-L90 */
    uchar data[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  fd_solana_account_t account = {
    .lamports = 1000000000,
    .rent_epoch = 1,
    .data_len = sizeof(data),
    .data = (unsigned char *) data,
    .executable = (uchar) 0
  };
  fd_memcpy( account.owner.key, global->solana_spl_token, 32 );
  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->current_slot, (fd_pubkey_t *) global->solana_spl_native_mint, &account );
}

void fd_builtin_programs_init( fd_global_ctx_t* global ) {

  /* List of BuiltIn's created during genesis:
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/builtins.rs#L201 */

  uchar system_program_data[] = {115, 121, 115, 116, 101, 109, 95, 112, 114, 111, 103, 114, 97, 109}; /* "system_program".as_bytes() */
  write_builtin_bogus_account( global, global->solana_system_program, (uchar *) &system_program_data, sizeof(system_program_data) );

  uchar compute_budget_program_data[] = {99, 111, 109, 112, 117, 116, 101, 95, 98, 117, 100, 103, 101, 116, 95, 112, 114, 111, 103, 114, 97, 109}; /* "compute_budget_program".as_bytes() */
  write_builtin_bogus_account( global, global->solana_compute_budget_program, (uchar *) &compute_budget_program_data, sizeof(compute_budget_program_data) );

  uchar vote_program_data[] = {118, 111, 116, 101, 95, 112, 114, 111, 103, 114, 97, 109}; /* "vote_program".as_bytes() */
  write_builtin_bogus_account( global, global->solana_vote_program, (uchar *) &vote_program_data, sizeof(vote_program_data) );

  uchar stake_program_data[] = {115, 116, 97, 107, 101, 95, 112, 114, 111, 103, 114, 97, 109}; /* "stake_program".as_bytes() */
  write_builtin_bogus_account( global, global->solana_stake_program, (uchar *) &stake_program_data, sizeof(stake_program_data) );

  uchar config_program_data[] = {99, 111, 110, 102, 105, 103, 95, 112, 114, 111, 103, 114, 97, 109}; /* "config_program".as_bytes() */
  write_builtin_bogus_account( global, global->solana_config_program, (uchar *) &config_program_data, sizeof(config_program_data) );

  uchar zk_token_proof_program_data[] = {122, 107, 95, 116, 111, 107, 101, 110, 95, 112, 114, 111, 111, 102, 95, 112, 114, 111, 103, 114, 97, 109}; /* "zk_token_proof_program".as_bytes() */
  write_builtin_bogus_account( global, global->solana_zk_token_proof_program, (uchar *) &zk_token_proof_program_data, sizeof(zk_token_proof_program_data) );

  uchar address_lookup_table_program_data[] = {97, 100, 100, 114, 101, 115, 115, 95, 108, 111, 111, 107, 117, 112, 95, 116, 97, 98, 108, 101, 95, 112, 114, 111, 103, 114, 97, 109}; /* "address_lookup_table_program".as_bytes() */
  write_builtin_bogus_account( global, global->solana_address_lookup_table_program, (uchar *) &address_lookup_table_program_data, sizeof(address_lookup_table_program_data) );

  uchar solana_bpf_loader_deprecated_program_data[] = {115, 111, 108, 97, 110, 97, 95, 98, 112, 102, 95, 108, 111, 97, 100, 101, 114, 95, 100, 101, 112, 114, 101, 99, 97, 116, 101, 100, 95, 112, 114, 111, 103, 114, 97, 109}; /* "solana_bpf_loader_deprecated_program".as_bytes() */
  write_builtin_bogus_account( global, global->solana_bpf_loader_deprecated_program, (uchar *) &solana_bpf_loader_deprecated_program_data, sizeof(solana_bpf_loader_deprecated_program_data) );

  uchar solana_bpf_loader_program_with_jit_data[] = {115, 111, 108, 97, 110, 97, 95, 98, 112, 102, 95, 108, 111, 97, 100, 101, 114, 95, 112, 114, 111, 103, 114, 97, 109, 95, 119, 105, 116, 104, 95, 106, 105, 116}; /* "solana_bpf_loader_program_with_jit".as_bytes() */
  write_builtin_bogus_account( global, global->solana_bpf_loader_program_with_jit, (uchar *) &solana_bpf_loader_program_with_jit_data, sizeof(solana_bpf_loader_program_with_jit_data) );

  uchar solana_bpf_loader_upgradeable_program_with_jit_data[] = {115, 111, 108, 97, 110, 97, 95, 98, 112, 102, 95, 108, 111, 97, 100, 101, 114, 95, 117, 112, 103, 114, 97, 100, 101, 97, 98, 108, 101, 95, 112, 114, 111, 103, 114, 97, 109, 95, 119, 105, 116, 104, 95, 106, 105, 116}; /* "solana_bpf_loader_upgradeable_program_with_jit".as_bytes() */
  write_builtin_bogus_account( global, global->solana_bpf_loader_upgradeable_program_with_jit, (uchar *) &solana_bpf_loader_upgradeable_program_with_jit_data, sizeof(solana_bpf_loader_upgradeable_program_with_jit_data) );

  /* Precompiles have empty account data */
  write_builtin_bogus_account( global, global->solana_keccak_secp_256k_program, NULL, 0 );
  write_builtin_bogus_account( global, global->solana_ed25519_sig_verify_program, NULL, 0 );

  /* Inline SPL token mint program ("inlined to avoid an external dependency on the spl-token crate") */
  write_inline_spl_native_mint_program_account( global );
}
