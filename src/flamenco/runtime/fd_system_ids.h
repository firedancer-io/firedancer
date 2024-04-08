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
extern const fd_pubkey_t fd_solana_compute_budget_program_id;
extern const fd_pubkey_t fd_solana_zk_token_proof_program_id;
extern const fd_pubkey_t fd_solana_address_lookup_table_program_id;
extern const fd_pubkey_t fd_solana_spl_native_mint_id;
extern const fd_pubkey_t fd_solana_spl_token_id;

/* fd_pubkey_is_{sysvar_id, builtin_program, sysvar_or_builtin} checks
   whether the provided pubkey is included in the hardcoded list of
   sysvars, builtin programs, or either, respectively.  They return 1 if
   the pubkey is in the list and 0 otherwise.

   fd_pubkey_is_sysvar_or_builtin( x ) returns
   fd_pubkey_is_sysvar_id( x ) || fd_pubkey_is_builtin_program( x )
   except only does one lookup instead of two. */
int
fd_pubkey_is_sysvar_id( fd_pubkey_t const * acct );

int
fd_pubkey_is_builtin_program( fd_pubkey_t const * acct );

int
fd_pubkey_is_sysvar_or_builtin( fd_pubkey_t const * acct );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_system_ids_h */
