#include "fd_builtin_programs.h"
#include "fd_precompiles.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"

#define BUILTIN_PROGRAM(program_id, name, feature_offset, migration_config) \
    {                                                                       \
        program_id,                                                         \
        name,                                                               \
        feature_offset,                                                     \
        migration_config                                                    \
    }

#define STATELESS_BUILTIN(program_id, migration_config) \
    {                                                   \
        program_id,                                     \
        migration_config                                \
    }

#define CORE_BPF_MIGRATION_CONFIG(source_buffer_address, upgrade_authority_address, enable_feature_offset, builtin_program_id) \
    {                                                                                                                          \
        source_buffer_address,                                                                                                 \
        upgrade_authority_address,                                                                                             \
        enable_feature_offset,                                                                                                 \
        builtin_program_id                                                                                                     \
    }

/* Core BPF migration configs */
static const fd_core_bpf_migration_config_t STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG = {
    &fd_solana_feature_program_buffer_address,
    NULL,
    offsetof(fd_features_t, migrate_feature_gate_program_to_core_bpf),
    FD_CORE_BPF_MIGRATION_TARGET_STATELESS,
    &fd_solana_feature_program_id,
    NULL
};
static const fd_core_bpf_migration_config_t * const MIGRATE_STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG = &STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG;

/* FIXME: update to correct hash when slashing program is finalized */
/* 9260b9ac8dfa1a6ed1022380a713bec7b75979ae136e91f9a86795b51c6c489f */
#define SLASHING_PROG_HASH_SIMD_204 0x92U,0x60U,0xb9U,0xacU,0x8dU,0xfaU,0x1aU,0x6eU,0xd1U,0x02U,0x23U,0x80U,0xa7U,0x13U,0xbeU,0xc7U, \
                                    0xb7U,0x59U,0x79U,0xaeU,0x13U,0x6eU,0x91U,0xf9U,0xa8U,0x67U,0x95U,0xb5U,0x1cU,0x6cU,0x48U,0x9fU
const fd_hash_t fd_solana_slashing_program_verified_build_hash_simd_204 = { .uc = { SLASHING_PROG_HASH_SIMD_204 } };
static const fd_core_bpf_migration_config_t STATELESS_TO_CORE_BPF_SLASHING_PROGRAM_CONFIG = {
    &fd_solana_slashing_program_buffer_address,
    NULL,
    offsetof(fd_features_t, enshrine_slashing_program),
    FD_CORE_BPF_MIGRATION_TARGET_STATELESS,
    &fd_solana_slashing_program_id,
    &fd_solana_slashing_program_verified_build_hash_simd_204
};
static const fd_core_bpf_migration_config_t * const MIGRATE_STATELESS_TO_CORE_BPF_SLASHING_PROGRAM_CONFIG = &STATELESS_TO_CORE_BPF_SLASHING_PROGRAM_CONFIG;

#define SYSTEM_PROGRAM_BUILTIN            BUILTIN_PROGRAM(&fd_solana_system_program_id,                 "system_program",                        NO_ENABLE_FEATURE_ID,                                      NULL)
#define VOTE_PROGRAM_BUILTIN              BUILTIN_PROGRAM(&fd_solana_vote_program_id,                   "vote_program",                          NO_ENABLE_FEATURE_ID,                                      NULL)
#define LOADER_V4_BUILTIN                 BUILTIN_PROGRAM(&fd_solana_bpf_loader_v4_program_id,          "loader_v4",                             offsetof(fd_features_t, enable_loader_v4),                 NULL)
#define BPF_LOADER_DEPRECATED_BUILTIN     BUILTIN_PROGRAM(&fd_solana_bpf_loader_deprecated_program_id,  "solana_bpf_loader_deprecated_program",  NO_ENABLE_FEATURE_ID,                                      NULL)
#define BPF_LOADER_BUILTIN                BUILTIN_PROGRAM(&fd_solana_bpf_loader_program_id,             "solana_bpf_loader_program",             NO_ENABLE_FEATURE_ID,                                      NULL)
#define BPF_LOADER_UPGRADEABLE_BUILTIN    BUILTIN_PROGRAM(&fd_solana_bpf_loader_upgradeable_program_id, "solana_bpf_loader_upgradeable_program", NO_ENABLE_FEATURE_ID,                                      NULL)
#define COMPUTE_BUDGET_PROGRAM_BUILTIN    BUILTIN_PROGRAM(&fd_solana_compute_budget_program_id,         "compute_budget_program",                NO_ENABLE_FEATURE_ID,                                      NULL)
#define ZK_TOKEN_PROOF_PROGRAM_BUILTIN    BUILTIN_PROGRAM(&fd_solana_zk_token_proof_program_id,         "zk_token_proof_program",                offsetof(fd_features_t, zk_token_sdk_enabled),             NULL)
#define ZK_ELGAMAL_PROOF_PROGRAM_BUILTIN  BUILTIN_PROGRAM(&fd_solana_zk_elgamal_proof_program_id,       "zk_elgamal_proof_program",              offsetof(fd_features_t, zk_elgamal_proof_program_enabled), NULL)

#define FEATURE_PROGRAM_BUILTIN           STATELESS_BUILTIN(&fd_solana_feature_program_id,  MIGRATE_STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG)
#define SLASHING_PROGRAM_BUILTIN          STATELESS_BUILTIN(&fd_solana_slashing_program_id, MIGRATE_STATELESS_TO_CORE_BPF_SLASHING_PROGRAM_CONFIG)

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/mod.rs#L133-L143 */
static const fd_stateless_builtin_program_t stateless_programs_builtins[] = {
    FEATURE_PROGRAM_BUILTIN,
    SLASHING_PROGRAM_BUILTIN
};
#define STATELESS_BUILTINS_COUNT (sizeof(stateless_programs_builtins) / sizeof(fd_stateless_builtin_program_t))

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/mod.rs#L34-L131 */
static fd_builtin_program_t const builtin_programs[] = {
    SYSTEM_PROGRAM_BUILTIN,
    VOTE_PROGRAM_BUILTIN,
    LOADER_V4_BUILTIN,
    BPF_LOADER_DEPRECATED_BUILTIN,
    BPF_LOADER_BUILTIN,
    BPF_LOADER_UPGRADEABLE_BUILTIN,
    COMPUTE_BUDGET_PROGRAM_BUILTIN,
    ZK_TOKEN_PROOF_PROGRAM_BUILTIN,
    ZK_ELGAMAL_PROOF_PROGRAM_BUILTIN
};
#define BUILTIN_PROGRAMS_COUNT (sizeof(builtin_programs) / sizeof(fd_builtin_program_t))

/* Used by the compute budget program to determine how many CUs to deduct by default
   https://github.com/anza-xyz/agave/blob/v2.1.13/builtins-default-costs/src/lib.rs#L113-L139 */
static fd_core_bpf_migration_config_t const * migrating_builtins[] = {
  /* Any future migrating builtins should be added here. Intentionally
     not cleaned up to support future migrations. */
  NULL,
};
#define MIGRATING_BUILTINS_COUNT (sizeof(migrating_builtins) / sizeof(fd_core_bpf_migration_config_t const *))

/* https://github.com/anza-xyz/agave/blob/v2.1.13/builtins-default-costs/src/lib.rs#L141-L193 */
#define MAP_PERFECT_NAME fd_non_migrating_builtins_tbl
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

#define MAP_PERFECT_0      ( VOTE_PROG_ID            ),
#define MAP_PERFECT_1      ( SYS_PROG_ID             ),
#define MAP_PERFECT_2      ( COMPUTE_BUDGET_PROG_ID  ),
#define MAP_PERFECT_3      ( BPF_UPGRADEABLE_PROG_ID ),
#define MAP_PERFECT_4      ( BPF_LOADER_1_PROG_ID    ),
#define MAP_PERFECT_5      ( BPF_LOADER_2_PROG_ID    ),
#define MAP_PERFECT_6      ( LOADER_V4_PROG_ID       ),
#define MAP_PERFECT_7      ( KECCAK_SECP_PROG_ID     ),
#define MAP_PERFECT_8      ( ED25519_SV_PROG_ID      ),

#include "../../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

// https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L4944
static int
fd_builtin_is_bpf( fd_accdb_t *         accdb,
                   fd_accdb_fork_id_t   fork_id,
                   fd_pubkey_t const  * pubkey ) {
  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, fork_id, pubkey->uc );
  if( FD_UNLIKELY( !entry.lamports ) ) return 0;

  int is_bpf = !memcmp( entry.owner, fd_solana_bpf_loader_upgradeable_program_id.uc, 32UL );
  fd_accdb_unread_one( accdb, &entry );
  return is_bpf;
}

/* BuiltIn programs need "bogus" executable accounts to exist.
   These are loaded and ignored during execution.

   Bogus accounts are marked as "executable", but their data is a
   hardcoded ASCII string. */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/native_loader.rs#L19 */
void
fd_write_builtin_account( fd_bank_t  *       bank,
                          fd_accdb_t *       accdb,
                          fd_capture_ctx_t * capture_ctx,
                          fd_pubkey_t const  pubkey,
                          void const *       data,
                          ulong              sz ) {
  fd_accdb_svm_write(
      bank, accdb, capture_ctx,
      &pubkey,
      &fd_solana_native_loader_id, /* owner */
      data, sz,                    /* data */
      1UL,                         /* lamports_min */
      1                            /* exec_bit */
  );
}

void
fd_builtin_programs_init( fd_bank_t *        bank,
                          fd_accdb_t *       accdb,
                          fd_capture_ctx_t * capture_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/v2.3.7/builtins/src/lib.rs#L52 */
  fd_builtin_program_t const * builtins = fd_builtins();

  for( ulong i=0UL; i<fd_num_builtins(); i++ ) {
    /** https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L4949 */
    if( bank->f.slot==0UL && builtins[i].enable_feature_offset==NO_ENABLE_FEATURE_ID && !fd_builtin_is_bpf( accdb, bank->accdb_fork_id, builtins[i].pubkey ) ) {
      fd_write_builtin_account( bank, accdb, capture_ctx, *builtins[i].pubkey, builtins[i].data, strlen( builtins[i].data ) );
    } else if( builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( bank->f.slot, &bank->f.features, builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      continue;
    } else if( builtins[i].enable_feature_offset!=NO_ENABLE_FEATURE_ID && !FD_FEATURE_ACTIVE_OFFSET( bank->f.slot, &bank->f.features, builtins[i].enable_feature_offset ) ) {
      continue;
    } else {
      fd_write_builtin_account( bank, accdb, capture_ctx, *builtins[i].pubkey, builtins[i].data, strlen(builtins[i].data) );
    }
  }

  /* Precompiles have empty account data */
  fd_write_builtin_account( bank, accdb, capture_ctx, fd_solana_keccak_secp_256k_program_id, "", 0 );
  fd_write_builtin_account( bank, accdb, capture_ctx, fd_solana_ed25519_sig_verify_program_id, "", 0 );
  fd_write_builtin_account( bank, accdb, capture_ctx, fd_solana_secp256r1_program_id, "", 0 );
}

fd_builtin_program_t const *
fd_builtins( void ) {
  return builtin_programs;
}

ulong
fd_num_builtins( void ) {
  return BUILTIN_PROGRAMS_COUNT;
}

fd_stateless_builtin_program_t const *
fd_stateless_builtins( void ) {
  return stateless_programs_builtins;
}

ulong
fd_num_stateless_builtins( void ) {
  return STATELESS_BUILTINS_COUNT;
}

uchar
fd_is_migrating_builtin_program( fd_bank_t const *   bank,
                                 fd_pubkey_t const * pubkey,
                                 uchar *             migrated_yet ) {
  *migrated_yet = 0;

  for( ulong i=0; i<MIGRATING_BUILTINS_COUNT; i++ ) {
    fd_core_bpf_migration_config_t const * config = migrating_builtins[i];
    if( !config ) continue;

    if( !memcmp( pubkey->uc, config->builtin_program_id->key, sizeof(fd_pubkey_t) ) ) {
      if( config->enable_feature_offset!=NO_ENABLE_FEATURE_ID &&
        FD_FEATURE_ACTIVE_OFFSET( bank->f.slot, &bank->f.features, config->enable_feature_offset ) ) {
        /* The program has been migrated to BPF. */
        *migrated_yet = 1;
      }

      return 1;
    }
  }

  /* No migration config exists for this program */
  return 0;
}

FD_FN_PURE uchar
fd_is_non_migrating_builtin_program( fd_pubkey_t const * pubkey ) {
  return !!( fd_non_migrating_builtins_tbl_contains( pubkey ) );
}
