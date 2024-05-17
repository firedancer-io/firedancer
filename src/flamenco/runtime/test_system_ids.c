#include "fd_system_ids.h"


static inline void
assert_eq( char const * base58,
           fd_pubkey_t   key     ) {
  uchar decoded[32] = { 0 };
  fd_base58_decode_32( base58, decoded );
  FD_TEST( fd_memeq( decoded, key.uc, 32UL ) );
}

static inline int
old_fd_pubkey_is_sysvar_id( fd_pubkey_t const * acct ) {
  if (memcmp(acct->key, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_recent_block_hashes_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_clock_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_slot_history_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_slot_hashes_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_epoch_schedule_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_epoch_rewards_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_fees_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_rent_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_stake_history_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_last_restart_slot_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  return 0;
}

static inline int
old_fd_pubkey_is_builtin_program( fd_pubkey_t const * acct ) {
  if (memcmp(acct->key, fd_solana_config_program_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  /* TODO: it is unclear why the stake program is not builtin and is thus writable in tests */
  // if (memcmp(acct->key, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_solana_stake_program_config_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_solana_system_program_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  if (memcmp(acct->key, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t)) == 0) return 1;
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  assert_eq( "Sysvar1111111111111111111111111111111111111", fd_sysvar_owner_id                          );
  assert_eq( "SysvarRecentB1ockHashes11111111111111111111", fd_sysvar_recent_block_hashes_id            );
  assert_eq( "SysvarC1ock11111111111111111111111111111111", fd_sysvar_clock_id                          );
  assert_eq( "SysvarS1otHistory11111111111111111111111111", fd_sysvar_slot_history_id                   );
  assert_eq( "SysvarS1otHashes111111111111111111111111111", fd_sysvar_slot_hashes_id                    );
  assert_eq( "SysvarEpochSchedu1e111111111111111111111111", fd_sysvar_epoch_schedule_id                 );
  assert_eq( "SysvarFees111111111111111111111111111111111", fd_sysvar_fees_id                           );
  assert_eq( "SysvarRent111111111111111111111111111111111", fd_sysvar_rent_id                           );
  assert_eq( "SysvarStakeHistory1111111111111111111111111", fd_sysvar_stake_history_id                  );
  assert_eq( "SysvarLastRestartS1ot1111111111111111111111", fd_sysvar_last_restart_slot_id              );
  assert_eq( "Sysvar1nstructions1111111111111111111111111", fd_sysvar_instructions_id                   );
  assert_eq( "SysvarEpochRewards1111111111111111111111111", fd_sysvar_epoch_rewards_id                  );
  assert_eq( "NativeLoader1111111111111111111111111111111", fd_solana_native_loader_id                  );
  assert_eq( "Feature111111111111111111111111111111111111", fd_solana_feature_program_id                );
  assert_eq( "Config1111111111111111111111111111111111111", fd_solana_config_program_id                 );
  assert_eq( "Stake11111111111111111111111111111111111111", fd_solana_stake_program_id                  );
  assert_eq( "StakeConfig11111111111111111111111111111111", fd_solana_stake_program_config_id           );
  assert_eq( "11111111111111111111111111111111",            fd_solana_system_program_id                 );
  assert_eq( "Vote111111111111111111111111111111111111111", fd_solana_vote_program_id                   );
  assert_eq( "BPFLoader1111111111111111111111111111111111", fd_solana_bpf_loader_deprecated_program_id  );
  assert_eq( "BPFLoader2111111111111111111111111111111111", fd_solana_bpf_loader_program_id             );
  assert_eq( "BPFLoaderUpgradeab1e11111111111111111111111", fd_solana_bpf_loader_upgradeable_program_id );
  assert_eq( "LoaderV411111111111111111111111111111111111", fd_solana_bpf_loader_v4_program_id          );
  assert_eq( "Ed25519SigVerify111111111111111111111111111", fd_solana_ed25519_sig_verify_program_id     );
  assert_eq( "KeccakSecp256k11111111111111111111111111111", fd_solana_keccak_secp_256k_program_id       );
  assert_eq( "ComputeBudget111111111111111111111111111111", fd_solana_compute_budget_program_id         );
  assert_eq( "ZkTokenProof1111111111111111111111111111111", fd_solana_zk_token_proof_program_id         );
  assert_eq( "AddressLookupTab1e1111111111111111111111111", fd_solana_address_lookup_table_program_id   );
  assert_eq( "So11111111111111111111111111111111111111112", fd_solana_spl_native_mint_id                );
  assert_eq( "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", fd_solana_spl_token_id                      );
  assert_eq( "ZkE1Gama1Proof11111111111111111111111111111", fd_solana_zk_el_gamal_program_id            );

  char const * const test_pubkeys[ 34 ] = {
    "Sysvar1111111111111111111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarS1otHistory11111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "SysvarRent111111111111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "SysvarLastRestartS1ot1111111111111111111111",
    "Sysvar1nstructions1111111111111111111111111",
    "SysvarEpochRewards1111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
    "Feature111111111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "StakeConfig11111111111111111111111111111111",
    "11111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "LoaderV411111111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "ZkTokenProof1111111111111111111111111111111",
    "AddressLookupTab1e1111111111111111111111111",
    "So11111111111111111111111111111111111111112",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH",
    "9yoZqrXpNpP8vfE7XhN3jPxzALpFA8C5Nvs1RNXQigCQ",
    "11111111111111111111111111111112",
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
  };
  for( ulong j=0UL; j<34UL; j++ ) {
    fd_pubkey_t decoded[ 1 ];
    FD_TEST( fd_base58_decode_32( test_pubkeys[ j ], decoded->uc ) );

    FD_TEST( fd_pubkey_is_sysvar_id        ( decoded ) == old_fd_pubkey_is_sysvar_id      ( decoded ) );
    FD_TEST( fd_pubkey_is_builtin_program  ( decoded ) == old_fd_pubkey_is_builtin_program( decoded ) );
    FD_TEST( fd_pubkey_is_sysvar_or_builtin( decoded ) == old_fd_pubkey_is_sysvar_id( decoded ) || old_fd_pubkey_is_builtin_program( decoded ) );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
