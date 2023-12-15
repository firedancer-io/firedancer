#include "fd_system_ids.h"

#include "../../ballet/base58/fd_base58.h"

fd_pubkey_t fd_sysvar_recent_block_hashes_id;
fd_pubkey_t fd_sysvar_clock_id;
fd_pubkey_t fd_sysvar_slot_history_id;
fd_pubkey_t fd_sysvar_slot_hashes_id;
fd_pubkey_t fd_sysvar_epoch_schedule_id;
fd_pubkey_t fd_sysvar_epoch_rewards_id;
fd_pubkey_t fd_sysvar_fees_id;
fd_pubkey_t fd_sysvar_rent_id;
fd_pubkey_t fd_sysvar_stake_history_id;
fd_pubkey_t fd_sysvar_owner_id;
fd_pubkey_t fd_sysvar_last_restart_slot_id;
fd_pubkey_t fd_sysvar_instructions_id;

fd_pubkey_t fd_solana_native_loader_id;
fd_pubkey_t fd_solana_feature_program_id;
fd_pubkey_t fd_solana_config_program_id;
fd_pubkey_t fd_solana_stake_program_id;
fd_pubkey_t fd_solana_stake_program_config_id;
fd_pubkey_t fd_solana_system_program_id;
fd_pubkey_t fd_solana_vote_program_id;
fd_pubkey_t fd_solana_bpf_loader_deprecated_program_id;
fd_pubkey_t fd_solana_bpf_loader_program_id;
fd_pubkey_t fd_solana_bpf_loader_upgradeable_program_id;
fd_pubkey_t fd_solana_bpf_loader_v4_program_id;
fd_pubkey_t fd_solana_ed25519_sig_verify_program_id;
fd_pubkey_t fd_solana_keccak_secp_256k_program_id;
fd_pubkey_t fd_solana_compute_budget_program_id;
fd_pubkey_t fd_solana_zk_token_proof_program_id;
fd_pubkey_t fd_solana_address_lookup_table_program_id;
fd_pubkey_t fd_solana_spl_native_mint_id;
fd_pubkey_t fd_solana_spl_token_id;

/* TODO do this at compile time */

static void __attribute__ ((constructor))
fd_system_ids_setup( void ) {
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111", fd_sysvar_owner_id.uc);
  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111", fd_sysvar_recent_block_hashes_id.uc);
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111", fd_sysvar_clock_id.uc);
  fd_base58_decode_32( "SysvarS1otHistory11111111111111111111111111", fd_sysvar_slot_history_id.uc);
  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111", fd_sysvar_slot_hashes_id.uc);
  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111", fd_sysvar_epoch_schedule_id.uc);
  fd_base58_decode_32( "SysvarFees111111111111111111111111111111111", fd_sysvar_fees_id.uc);
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111", fd_sysvar_rent_id.uc);
  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111", fd_sysvar_stake_history_id.uc);
  fd_base58_decode_32( "SysvarLastRestartS1ot1111111111111111111111", fd_sysvar_last_restart_slot_id.uc);
  fd_base58_decode_32( "Sysvar1nstructions1111111111111111111111111", fd_sysvar_instructions_id.uc);
  fd_base58_decode_32( "SysvarEpochRewards1111111111111111111111111", fd_sysvar_epoch_rewards_id.uc);
  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111", fd_solana_native_loader_id.uc);
  fd_base58_decode_32( "Feature111111111111111111111111111111111111", fd_solana_feature_program_id.uc);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111", fd_solana_config_program_id.uc);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111", fd_solana_stake_program_id.uc);
  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111", fd_solana_stake_program_config_id.uc);
  fd_base58_decode_32( "11111111111111111111111111111111",            fd_solana_system_program_id.uc);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111", fd_solana_vote_program_id.uc);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111", fd_solana_bpf_loader_deprecated_program_id.uc);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111", fd_solana_bpf_loader_program_id.uc);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111", fd_solana_bpf_loader_upgradeable_program_id.uc);
  fd_base58_decode_32( "LoaderV411111111111111111111111111111111111", fd_solana_bpf_loader_v4_program_id.uc);
  fd_base58_decode_32( "Ed25519SigVerify111111111111111111111111111", fd_solana_ed25519_sig_verify_program_id.uc);
  fd_base58_decode_32( "KeccakSecp256k11111111111111111111111111111", fd_solana_keccak_secp_256k_program_id.uc);
  fd_base58_decode_32( "ComputeBudget111111111111111111111111111111", fd_solana_compute_budget_program_id.uc);
  fd_base58_decode_32( "ZkTokenProof1111111111111111111111111111111", fd_solana_zk_token_proof_program_id.uc);
  fd_base58_decode_32( "AddressLookupTab1e1111111111111111111111111", fd_solana_address_lookup_table_program_id.uc);
  fd_base58_decode_32( "So11111111111111111111111111111111111111112", fd_solana_spl_native_mint_id.uc);
  fd_base58_decode_32( "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", fd_solana_spl_token_id.uc);
}

/* TODO use perfect hash table ... */

int
fd_pubkey_is_sysvar_id( fd_pubkey_t const * acct ) {
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

int
fd_pubkey_is_builtin_program( fd_pubkey_t const * acct ) {
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
