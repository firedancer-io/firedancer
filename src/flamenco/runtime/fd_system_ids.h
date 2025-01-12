#ifndef HEADER_fd_src_flamenco_runtime_fd_system_ids_h
#define HEADER_fd_src_flamenco_runtime_fd_system_ids_h

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

extern const fd_pubkey_t fd_sysvar_recent_block_hashes_id;
extern const fd_pubkey_t fd_sysvar_clock_id;
extern const fd_pubkey_t fd_sysvar_slot_history_id;
extern const fd_pubkey_t fd_sysvar_slot_hashes_id;
extern const fd_pubkey_t fd_sysvar_epoch_schedule_id;
extern const fd_pubkey_t fd_sysvar_epoch_rewards_id;
extern const fd_pubkey_t fd_sysvar_fees_id;
extern const fd_pubkey_t fd_sysvar_rent_id;
extern const fd_pubkey_t fd_sysvar_stake_history_id;
extern const fd_pubkey_t fd_sysvar_owner_id;
extern const fd_pubkey_t fd_sysvar_last_restart_slot_id;
extern const fd_pubkey_t fd_sysvar_instructions_id;
extern const fd_pubkey_t fd_sysvar_incinerator_id;
extern const fd_pubkey_t fd_sysvar_rewards_id;

extern const fd_pubkey_t fd_solana_native_loader_id;
extern const fd_pubkey_t fd_solana_feature_program_id;
extern const fd_pubkey_t fd_solana_config_program_id;
extern const fd_pubkey_t fd_solana_stake_program_id;
extern const fd_pubkey_t fd_solana_stake_program_config_id;
extern const fd_pubkey_t fd_solana_system_program_id;
extern const fd_pubkey_t fd_solana_vote_program_id;
extern const fd_pubkey_t fd_solana_bpf_loader_deprecated_program_id;
extern const fd_pubkey_t fd_solana_bpf_loader_program_id;
extern const fd_pubkey_t fd_solana_bpf_loader_upgradeable_program_id;
extern const fd_pubkey_t fd_solana_bpf_loader_v4_program_id;
extern const fd_pubkey_t fd_solana_ed25519_sig_verify_program_id;
extern const fd_pubkey_t fd_solana_keccak_secp_256k_program_id;
extern const fd_pubkey_t fd_solana_secp256r1_program_id;
extern const fd_pubkey_t fd_solana_compute_budget_program_id;
extern const fd_pubkey_t fd_solana_address_lookup_table_program_id;
extern const fd_pubkey_t fd_solana_spl_native_mint_id;
extern const fd_pubkey_t fd_solana_spl_token_id;
extern const fd_pubkey_t fd_solana_zk_token_proof_program_id;
extern const fd_pubkey_t fd_solana_zk_elgamal_proof_program_id;

/* Buffer accounts for BPF migrations
   https://github.com/anza-xyz/agave/blob/v2.1.6/runtime/src/bank/builtins/mod.rs#L151-L165 */
extern const fd_pubkey_t fd_solana_address_lookup_table_program_buffer_address;
extern const fd_pubkey_t fd_solana_config_program_buffer_address;
extern const fd_pubkey_t fd_solana_feature_program_buffer_address;
extern const fd_pubkey_t fd_solana_stake_program_buffer_address;

/* fd_pubkey_is_{pending, active}_reserved_key checks to see if the pubkey is
   a reserved account. They return 1 if the pubkey is in the list, and 
   0 otherwise.
   
   The main difference between the two is that pending reserved keys are feature gated.
   To verify that the pubkey is a reserved key, the caller will need to check that either:
     1. The pubkey is in the set of active reserved keys
     2. The pubkey is in the set of pending reserved keys, AND the associated feature is active.
     
   At the time of writing, all pending reserved keys are feature-gated by add_new_reserved_account_keys.
   However, as more reserved keys get added and placed behind feature gates, this API will need to change. 
   
   Instead of maintaining a map of sysvars and builtins, Agave recommends checking the sysvar owner account, or checking
   the reserved keys below. 
   https://github.com/anza-xyz/agave/blob/v2.1.1/sdk/src/reserved_account_keys.rs */
int 
fd_pubkey_is_active_reserved_key( fd_pubkey_t const * acct );

int 
fd_pubkey_is_pending_reserved_key( fd_pubkey_t const * acct );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_system_ids_h */
