#include "fd_builtin_programs.h"

/* BuiltIn programs need "bogus" executable accounts to exist.
   These are loaded and ignored during execution.

   Bogus accounts are marked as "executable", but their data is a
   hardcoded ASCII string. */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/native_loader.rs#L19 */
void
write_builtin_bogus_account( fd_global_ctx_t * global,
                             uchar const       pubkey[ static 32 ],
                             char const *      data,
                             ulong             sz ) {

  fd_solana_account_t account = {
    .lamports   = 1,
    .rent_epoch = 0,
    .data_len   = sz,
    .data       = (uchar*) data,
    .executable = (uchar) 1
  };
  fd_memcpy( account.owner.key, global->solana_native_loader, 32 );

  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.slot, (fd_pubkey_t *) pubkey, &account );
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
  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.slot, (fd_pubkey_t *) global->solana_spl_native_mint, &account );
}

void fd_builtin_programs_init( fd_global_ctx_t* global ) {

  /* List of BuiltIn's created during genesis:
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/builtins.rs#L201 */

  write_builtin_bogus_account( global, global->solana_system_program,         "system_program",         14UL );
  write_builtin_bogus_account( global, global->solana_compute_budget_program, "compute_budget_program", 22UL );
  write_builtin_bogus_account( global, global->solana_vote_program,           "vote_program",           12UL );
  write_builtin_bogus_account( global, global->solana_stake_program,          "stake_program",          13UL );
  write_builtin_bogus_account( global, global->solana_config_program,         "config_program",         14UL );

  if (global->features.zk_token_sdk_enabled) {
    write_builtin_bogus_account( global, global->solana_zk_token_proof_program, "zk_token_proof_program", 22UL );
  }

  write_builtin_bogus_account( global, global->solana_address_lookup_table_program,   "address_lookup_table_program",          28UL );
  write_builtin_bogus_account( global, global->solana_bpf_loader_deprecated_program,  "solana_bpf_loader_deprecated_program",  36UL );
  write_builtin_bogus_account( global, global->solana_bpf_loader_program,             "solana_bpf_loader_program",             25UL );
  write_builtin_bogus_account( global, global->solana_bpf_loader_upgradeable_program, "solana_bpf_loader_upgradeable_program", 37UL );

  /* Precompiles have empty account data */
  write_builtin_bogus_account( global, global->solana_keccak_secp_256k_program,   NULL, 0 );
  write_builtin_bogus_account( global, global->solana_ed25519_sig_verify_program, NULL, 0 );

  /* Inline SPL token mint program ("inlined to avoid an external dependency on the spl-token crate") */
  write_inline_spl_native_mint_program_account( global );
}
