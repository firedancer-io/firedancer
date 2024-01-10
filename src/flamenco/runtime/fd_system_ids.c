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
const fd_pubkey_t fd_solana_compute_budget_program_id         = { .uc = { COMPUTE_BUDGET_PROG_ID   } };
const fd_pubkey_t fd_solana_zk_token_proof_program_id         = { .uc = { ZK_TOKEN_PROG_ID         } };
const fd_pubkey_t fd_solana_address_lookup_table_program_id   = { .uc = { ADDR_LUT_PROG_ID         } };
const fd_pubkey_t fd_solana_spl_native_mint_id                = { .uc = { NATIVE_MINT_ID           } };
const fd_pubkey_t fd_solana_spl_token_id                      = { .uc = { TOKEN_PROG_ID            } };

#define MAP_PERFECT_NAME fd_pubkey_sysvar_tbl
#define MAP_PERFECT_LG_TBL_SZ 4
#define MAP_PERFECT_T fd_pubkey_t
#define MAP_PERFECT_HASH_C 86U
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

#define MAP_PERFECT_0   ( SYSVAR_RECENT_BLKHASH_ID ),
#define MAP_PERFECT_1   ( SYSVAR_CLOCK_ID          ),
#define MAP_PERFECT_2   ( SYSVAR_SLOT_HIST_ID      ),
#define MAP_PERFECT_3   ( SYSVAR_SLOT_HASHES_ID    ),
#define MAP_PERFECT_4   ( SYSVAR_EPOCH_SCHED_ID    ),
#define MAP_PERFECT_5   ( SYSVAR_EPOCH_REWARDS_ID  ),
#define MAP_PERFECT_6   ( SYSVAR_FEES_ID           ),
#define MAP_PERFECT_7   ( SYSVAR_RENT_ID           ),
#define MAP_PERFECT_8   ( SYSVAR_STAKE_HIST_ID     ),
#define MAP_PERFECT_9   ( SYSVAR_PROG_ID           ),
#define MAP_PERFECT_10  ( SYSVAR_LAST_RESTART_ID   ),
#define MAP_PERFECT_11  ( SYSVAR_INSTRUCTIONS_ID   ),

#include "../../util/tmpl/fd_map_perfect.c"



#define MAP_PERFECT_NAME fd_pubkey_builtin_prog_tbl
#define MAP_PERFECT_LG_TBL_SZ 4
#define MAP_PERFECT_T fd_pubkey_t
#define MAP_PERFECT_HASH_C 13U
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

#define MAP_PERFECT_0   ( NATIVE_LOADER_ID        ),
#define MAP_PERFECT_1   ( FEATURE_ID              ),
#define MAP_PERFECT_2   ( CONFIG_PROG_ID          ),
#define MAP_PERFECT_3   ( STAKE_CONFIG_PROG_ID    ),
#define MAP_PERFECT_4   ( SYS_PROG_ID             ),
#define MAP_PERFECT_5   ( VOTE_PROG_ID            ),
#define MAP_PERFECT_6   ( BPF_LOADER_1_PROG_ID    ),
#define MAP_PERFECT_7   ( BPF_LOADER_2_PROG_ID    ),
#define MAP_PERFECT_8   ( BPF_UPGRADEABLE_PROG_ID ),

#include "../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

#define MAP_PERFECT_NAME fd_pubkey_sysvar_builtin_prog_tbl
#define MAP_PERFECT_LG_TBL_SZ 5
#define MAP_PERFECT_T fd_pubkey_t
#define MAP_PERFECT_HASH_C 6127U
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


#define MAP_PERFECT_0   ( SYSVAR_RECENT_BLKHASH_ID ),
#define MAP_PERFECT_1   ( SYSVAR_CLOCK_ID          ),
#define MAP_PERFECT_2   ( SYSVAR_SLOT_HIST_ID      ),
#define MAP_PERFECT_3   ( SYSVAR_SLOT_HASHES_ID    ),
#define MAP_PERFECT_4   ( SYSVAR_EPOCH_SCHED_ID    ),
#define MAP_PERFECT_5   ( SYSVAR_EPOCH_REWARDS_ID  ),
#define MAP_PERFECT_6   ( SYSVAR_FEES_ID           ),
#define MAP_PERFECT_7   ( SYSVAR_RENT_ID           ),
#define MAP_PERFECT_8   ( SYSVAR_STAKE_HIST_ID     ),
#define MAP_PERFECT_9   ( SYSVAR_PROG_ID           ),
#define MAP_PERFECT_10  ( SYSVAR_LAST_RESTART_ID   ),
#define MAP_PERFECT_11  ( SYSVAR_INSTRUCTIONS_ID   ),

#define MAP_PERFECT_12  ( NATIVE_LOADER_ID        ),
#define MAP_PERFECT_13  ( FEATURE_ID              ),
#define MAP_PERFECT_14  ( CONFIG_PROG_ID          ),
#define MAP_PERFECT_15  ( STAKE_CONFIG_PROG_ID    ),
#define MAP_PERFECT_16  ( SYS_PROG_ID             ),
#define MAP_PERFECT_17  ( VOTE_PROG_ID            ),
#define MAP_PERFECT_18  ( BPF_LOADER_1_PROG_ID    ),
#define MAP_PERFECT_19  ( BPF_LOADER_2_PROG_ID    ),
#define MAP_PERFECT_20  ( BPF_UPGRADEABLE_PROG_ID ),
#include "../../util/tmpl/fd_map_perfect.c"

int fd_pubkey_is_sysvar_id        ( fd_pubkey_t const * acct ) { return fd_pubkey_sysvar_tbl_contains( acct );              }
int fd_pubkey_is_builtin_program  ( fd_pubkey_t const * acct ) { return fd_pubkey_builtin_prog_tbl_contains( acct );        }
int fd_pubkey_is_sysvar_or_builtin( fd_pubkey_t const * acct ) { return fd_pubkey_sysvar_builtin_prog_tbl_contains( acct ); }
