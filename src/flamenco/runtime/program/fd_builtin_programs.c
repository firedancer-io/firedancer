#include "fd_builtin_programs.h"

/* BuiltIn programs need "bogus" executable accounts to exist.
   These are loaded and ignored during execution.

   Bogus accounts are marked as "executable", but their data is a
   hardcoded ASCII string. */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/native_loader.rs#L19 */
void
fd_write_builtin_bogus_account( fd_global_ctx_t * global,
                                uchar const       pubkey[ static 32 ],
                                char const *      data,
                                ulong             sz ) {

  fd_acc_mgr_t *      acc_mgr = global->acc_mgr;
  fd_funk_txn_t *     txn     = global->funk_txn;
  fd_pubkey_t const * key     = (fd_pubkey_t const *)pubkey;
  FD_BORROWED_ACCOUNT_DECL(rec);

  int err = fd_acc_mgr_modify( acc_mgr, txn, key, 1, sz, rec);
  FD_TEST( !err );

  rec->meta->dlen            = sz;
  rec->meta->info.lamports   = 1UL;
  rec->meta->info.rent_epoch = 0UL;
  rec->meta->info.executable = 1;
  fd_memcpy( rec->meta->info.owner, global->solana_native_loader, 32 );
  memcpy( rec->data, data, sz );

  err = fd_acc_mgr_commit( acc_mgr, rec, global->bank.slot );
  FD_TEST( !err );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/inline_spl_token.rs#L74 */
/* TODO: move this somewhere more appropiate */
void
write_inline_spl_native_mint_program_account( fd_global_ctx_t * global ) {

  fd_acc_mgr_t *      acc_mgr = global->acc_mgr;
  fd_funk_txn_t *     txn     = global->funk_txn;
  fd_pubkey_t const * key     = (fd_pubkey_t const *)global->solana_spl_native_mint;
  FD_BORROWED_ACCOUNT_DECL(rec);

  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/inline_spl_token.rs#L86-L90 */
  static uchar const data[] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  int err = fd_acc_mgr_modify( acc_mgr, txn, key, 1, sizeof(data), rec );
  FD_TEST( !err );

  rec->meta->dlen            = sizeof(data);
  rec->meta->info.lamports   = 1000000000UL;
  rec->meta->info.rent_epoch = 1UL;
  rec->meta->info.executable = 0;
  fd_memcpy( rec->meta->info.owner, global->solana_spl_token, 32 );
  memcpy( rec->data, data, sizeof(data) );

  err = fd_acc_mgr_commit( acc_mgr, rec, global->bank.slot );
  FD_TEST( !err );
}

void fd_builtin_programs_init( fd_global_ctx_t* global ) {

  /* List of BuiltIn's created during genesis:
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/builtins.rs#L201 */

  fd_write_builtin_bogus_account( global, global->solana_system_program,         "system_program",         14UL );
  fd_write_builtin_bogus_account( global, global->solana_vote_program,           "vote_program",           12UL );
  fd_write_builtin_bogus_account( global, global->solana_stake_program,          "stake_program",          13UL );
  fd_write_builtin_bogus_account( global, global->solana_config_program,         "config_program",         14UL );

  if( FD_FEATURE_ACTIVE( global, zk_token_sdk_enabled ) ) {
    fd_write_builtin_bogus_account( global, global->solana_zk_token_proof_program, "zk_token_proof_program", 22UL );
  }

  fd_write_builtin_bogus_account( global, global->solana_address_lookup_table_program,   "address_lookup_table_program",          28UL );
  fd_write_builtin_bogus_account( global, global->solana_bpf_loader_deprecated_program,  "solana_bpf_loader_deprecated_program",  36UL );

  if (global->features.vote_state_add_vote_latency == ULONG_MAX) {
    fd_write_builtin_bogus_account( global, global->solana_bpf_loader_program,             "solana_bpf_loader_program_with_jit",             34UL );
    fd_write_builtin_bogus_account( global, global->solana_bpf_loader_upgradeable_program, "solana_bpf_loader_upgradeable_program_with_jit", 46UL );
  } else {
    fd_write_builtin_bogus_account( global, global->solana_bpf_loader_program,             "solana_bpf_loader_program",             25UL );
    fd_write_builtin_bogus_account( global, global->solana_bpf_loader_upgradeable_program, "solana_bpf_loader_upgradeable_program", 37UL );
  }

  fd_write_builtin_bogus_account( global, global->solana_compute_budget_program, "compute_budget_program", 22UL );

  /* Precompiles have empty account data */
  fd_write_builtin_bogus_account( global, global->solana_keccak_secp_256k_program,   NULL, 0 );
  fd_write_builtin_bogus_account( global, global->solana_ed25519_sig_verify_program, NULL, 0 );

  /* Inline SPL token mint program ("inlined to avoid an external dependency on the spl-token crate") */
  write_inline_spl_native_mint_program_account( global );
}
