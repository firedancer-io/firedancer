#include "fd_system_ids.h"
#include "fd_system_ids_pp.h"

const fd_pubkey_t fd_sysvar_recent_block_hashes_id = { .uc = { SYSVAR_RECENT_BLKHASH_ID } };
const fd_pubkey_t fd_sysvar_clock_id               = { .uc = { SYSVAR_CLOCK_ID          } };
const fd_pubkey_t fd_sysvar_slot_history_id        = { .uc = { SYSVAR_SLOT_HIST_ID      } };
const fd_pubkey_t fd_sysvar_slot_hashes_id         = { .uc = { SYSVAR_SLOT_HASHES_ID    } };
const fd_pubkey_t fd_sysvar_epoch_schedule_id      = { .uc = { SYSVAR_EPOCH_SCHED_ID    } };
const fd_pubkey_t fd_sysvar_epoch_rewards_id       = { .uc = { SYSVAR_EPOCH_REWARDS_ID  } };
const fd_pubkey_t fd_sysvar_fees_id                = { .uc = { SYSVAR_FEES_ID           } };
const fd_pubkey_t fd_sysvar_rent_id                = { .uc = { SYSVAR_RENT_ID           } };
const fd_pubkey_t fd_sysvar_stake_history_id       = { .uc = { SYSVAR_STAKE_HIST_ID     } };
const fd_pubkey_t fd_sysvar_owner_id               = { .uc = { SYSVAR_PROG_ID           } };
const fd_pubkey_t fd_sysvar_last_restart_slot_id   = { .uc = { SYSVAR_LAST_RESTART_ID   } };
const fd_pubkey_t fd_sysvar_instructions_id        = { .uc = { SYSVAR_INSTRUCTIONS_ID   } };
const fd_pubkey_t fd_sysvar_incinerator_id         = { .uc = { SYSVAR_INCINERATOR_ID    } };
const fd_pubkey_t fd_sysvar_rewards_id             = { .uc = { SYSVAR_REWARDS_ID        } };

const fd_pubkey_t fd_solana_native_loader_id                  = { .uc = { NATIVE_LOADER_ID         } };
const fd_pubkey_t fd_solana_feature_program_id                = { .uc = { FEATURE_ID               } };
const fd_pubkey_t fd_solana_config_program_id                 = { .uc = { CONFIG_PROG_ID           } };
const fd_pubkey_t fd_solana_stake_program_id                  = { .uc = { STAKE_PROG_ID            } };
const fd_pubkey_t fd_solana_stake_program_config_id           = { .uc = { STAKE_CONFIG_PROG_ID     } };
const fd_pubkey_t fd_solana_system_program_id                 = { .uc = { SYS_PROG_ID              } };
const fd_pubkey_t fd_solana_vote_program_id                   = { .uc = { VOTE_PROG_ID             } };
const fd_pubkey_t fd_solana_bpf_loader_deprecated_program_id  = { .uc = { BPF_LOADER_1_PROG_ID     } };
const fd_pubkey_t fd_solana_bpf_loader_program_id             = { .uc = { BPF_LOADER_2_PROG_ID     } };
const fd_pubkey_t fd_solana_bpf_loader_upgradeable_program_id = { .uc = { BPF_UPGRADEABLE_PROG_ID  } };
const fd_pubkey_t fd_solana_bpf_loader_v4_program_id          = { .uc = { LOADER_V4_PROG_ID        } };
const fd_pubkey_t fd_solana_ed25519_sig_verify_program_id     = { .uc = { ED25519_SV_PROG_ID       } };
const fd_pubkey_t fd_solana_keccak_secp_256k_program_id       = { .uc = { KECCAK_SECP_PROG_ID      } };
const fd_pubkey_t fd_solana_secp256r1_program_id              = { .uc = { SECP256R1_PROG_ID        } };
const fd_pubkey_t fd_solana_compute_budget_program_id         = { .uc = { COMPUTE_BUDGET_PROG_ID   } };
const fd_pubkey_t fd_solana_address_lookup_table_program_id   = { .uc = { ADDR_LUT_PROG_ID         } };
const fd_pubkey_t fd_solana_spl_native_mint_id                = { .uc = { NATIVE_MINT_ID           } };
const fd_pubkey_t fd_solana_spl_token_id                      = { .uc = { TOKEN_PROG_ID            } };
const fd_pubkey_t fd_solana_spl_token_2022_id                 = { .uc = { TOKEN_2022_PROG_ID       } };
const fd_pubkey_t fd_solana_zk_token_proof_program_id         = { .uc = { ZK_TOKEN_PROG_ID         } };
const fd_pubkey_t fd_solana_zk_elgamal_proof_program_id       = { .uc = { ZK_EL_GAMAL_PROG_ID      } };
const fd_pubkey_t fd_solana_slashing_program_id               = { .uc = { SLASHING_PROG_ID        } };

const fd_pubkey_t fd_solana_address_lookup_table_program_buffer_address   = { .uc = { ADDR_LUT_PROG_BUFFER_ID } };
const fd_pubkey_t fd_solana_config_program_buffer_address                 = { .uc = { CONFIG_PROG_BUFFER_ID } };
const fd_pubkey_t fd_solana_feature_program_buffer_address                = { .uc = { FEATURE_PROG_BUFFER_ID } };
const fd_pubkey_t fd_solana_stake_program_buffer_address                  = { .uc = { STAKE_PROG_BUFFER_ID } };
const fd_pubkey_t fd_solana_slashing_program_buffer_address               = { .uc = { SLASHING_PROG_BUFFER_ID } };

const fd_pubkey_t fd_solana_migration_authority                           = { .uc = { MIGRATION_AUTHORITY_ID } };

/* https://github.com/firedancer-io/agave/blob/66c126b41ec2b55b3f747a4ac4e3ee6b439164a5/sdk/src/reserved_account_keys.rs#L152-L194 */
#define MAP_PERFECT_NAME fd_pubkey_active_reserved_keys_tbl
#define MAP_PERFECT_LG_TBL_SZ 5
#define MAP_PERFECT_T fd_pubkey_t
#define MAP_PERFECT_HASH_C 928U
#define MAP_PERFECT_KEY uc
#define MAP_PERFECT_KEY_T fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>27)&0x1FU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->uc + 8UL ) )

#define MAP_PERFECT_0       ( BPF_LOADER_2_PROG_ID     ),
#define MAP_PERFECT_1       ( BPF_LOADER_1_PROG_ID     ),
#define MAP_PERFECT_2       ( BPF_UPGRADEABLE_PROG_ID  ),
#define MAP_PERFECT_3       ( CONFIG_PROG_ID           ),
#define MAP_PERFECT_4       ( FEATURE_ID               ),
#define MAP_PERFECT_5       ( STAKE_CONFIG_PROG_ID     ),
#define MAP_PERFECT_6       ( STAKE_PROG_ID            ),
#define MAP_PERFECT_7       ( SYS_PROG_ID              ),
#define MAP_PERFECT_8       ( VOTE_PROG_ID             ),
#define MAP_PERFECT_9       ( SYSVAR_CLOCK_ID          ),
#define MAP_PERFECT_10      ( SYSVAR_EPOCH_SCHED_ID    ),
#define MAP_PERFECT_11      ( SYSVAR_FEES_ID           ),
#define MAP_PERFECT_12      ( SYSVAR_INSTRUCTIONS_ID   ),
#define MAP_PERFECT_13      ( SYSVAR_RECENT_BLKHASH_ID ),
#define MAP_PERFECT_14      ( SYSVAR_RENT_ID           ),
#define MAP_PERFECT_15      ( SYSVAR_REWARDS_ID        ),
#define MAP_PERFECT_16      ( SYSVAR_SLOT_HASHES_ID    ),
#define MAP_PERFECT_17      ( SYSVAR_SLOT_HIST_ID      ),
#define MAP_PERFECT_18      ( SYSVAR_STAKE_HIST_ID     ),
#define MAP_PERFECT_19      ( NATIVE_LOADER_ID         ),

#include "../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH



#define MAP_PERFECT_NAME fd_pubkey_pending_reserved_keys_tbl
#define MAP_PERFECT_LG_TBL_SZ 4
#define MAP_PERFECT_T fd_pubkey_t
#define MAP_PERFECT_HASH_C 146U
#define MAP_PERFECT_KEY uc
#define MAP_PERFECT_KEY_T fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>28)&0x0FU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->uc + 8UL ) )

#define MAP_PERFECT_0       ( ADDR_LUT_PROG_ID        ),
#define MAP_PERFECT_1       ( COMPUTE_BUDGET_PROG_ID  ),
#define MAP_PERFECT_2       ( ED25519_SV_PROG_ID      ),
#define MAP_PERFECT_3       ( LOADER_V4_PROG_ID       ),
#define MAP_PERFECT_4       ( KECCAK_SECP_PROG_ID     ),
#define MAP_PERFECT_5       ( ZK_EL_GAMAL_PROG_ID     ),
#define MAP_PERFECT_6       ( ZK_TOKEN_PROG_ID        ),
#define MAP_PERFECT_7       ( SYSVAR_EPOCH_REWARDS_ID ),
#define MAP_PERFECT_8       ( SYSVAR_LAST_RESTART_ID  ),
#define MAP_PERFECT_9       ( SYSVAR_PROG_ID          ),

#include "../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

int
fd_pubkey_is_active_reserved_key( fd_pubkey_t const * acct ) {
  return fd_pubkey_active_reserved_keys_tbl_contains( acct );
}

int
fd_pubkey_is_pending_reserved_key( fd_pubkey_t const * acct ) {
  return fd_pubkey_pending_reserved_keys_tbl_contains( acct );
}

int
fd_pubkey_is_secp256r1_key( fd_pubkey_t const * acct ) {
  return memcmp( acct->uc, fd_solana_secp256r1_program_id.key, sizeof(fd_pubkey_t) )==0;
}
