#include "fd_builtin_programs.h"
#include "fd_precompiles.h"
#include "../fd_system_ids.h"
#include "../fd_system_ids_pp.h"
#include "../../accdb/fd_accdb_impl_v1.h"

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

#define PRECOMPILE(program_id, feature_offset, verify_fn) \
    {                                                     \
        program_id,                                       \
        feature_offset,                                   \
        verify_fn                                         \
    }

/* Core BPF migration configs */
static const fd_core_bpf_migration_config_t BUILTIN_TO_CORE_BPF_STAKE_PROGRAM_CONFIG = {
    &fd_solana_stake_program_buffer_address,
    NULL,
    offsetof(fd_features_t, migrate_stake_program_to_core_bpf),
    FD_CORE_BPF_MIGRATION_TARGET_BUILTIN,
    &fd_solana_stake_program_id,
    NULL
};
static const fd_core_bpf_migration_config_t * const MIGRATE_BUILTIN_TO_CORE_BPF_STAKE_PROGRAM_CONFIG = &BUILTIN_TO_CORE_BPF_STAKE_PROGRAM_CONFIG;

static const fd_core_bpf_migration_config_t BUILTIN_TO_CORE_BPF_CONFIG_PROGRAM_CONFIG = {
    &fd_solana_config_program_buffer_address,
    NULL,
    offsetof(fd_features_t, migrate_config_program_to_core_bpf),
    FD_CORE_BPF_MIGRATION_TARGET_BUILTIN,
    &fd_solana_config_program_id,
    NULL
};
static const fd_core_bpf_migration_config_t * const MIGRATE_BUILTIN_TO_CORE_BPF_CONFIG_PROGRAM_CONFIG = &BUILTIN_TO_CORE_BPF_CONFIG_PROGRAM_CONFIG;

static const fd_core_bpf_migration_config_t BUILTIN_TO_CORE_BPF_ADDRESS_LOOKUP_TABLE_PROGRAM_CONFIG = {
    &fd_solana_address_lookup_table_program_buffer_address,
    NULL,
    offsetof(fd_features_t, migrate_address_lookup_table_program_to_core_bpf),
    FD_CORE_BPF_MIGRATION_TARGET_BUILTIN,
    &fd_solana_address_lookup_table_program_id,
    NULL
};
static const fd_core_bpf_migration_config_t * const MIGRATE_BUILTIN_TO_CORE_BPF_ADDRESS_LOOKUP_TABLE_PROGRAM_CONFIG = &BUILTIN_TO_CORE_BPF_ADDRESS_LOOKUP_TABLE_PROGRAM_CONFIG;

static const fd_core_bpf_migration_config_t STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG = {
    &fd_solana_feature_program_buffer_address,
    NULL,
    offsetof(fd_features_t, migrate_feature_gate_program_to_core_bpf),
    FD_CORE_BPF_MIGRATION_TARGET_STATELESS,
    &fd_solana_feature_program_id,
    NULL
};
static const fd_core_bpf_migration_config_t * const MIGRATE_STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG = &STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG;

/* 192ed727334abe822d5accba8b886e25f88b03c76973c2e7290cfb55b9e1115f */
#define SLASHING_PROG_HASH_SIMD_204 0x19U,0x2eU,0xd7U,0x27U,0x33U,0x4aU,0xbeU,0x82U,0x2dU,0x5aU,0xccU,0xbaU,0x8bU,0x88U,0x6eU,0x25U, \
                                    0xf8U,0x8bU,0x03U,0xc7U,0x69U,0x73U,0xc2U,0xe7U,0x29U,0x0cU,0xfbU,0x55U,0xb9U,0xe1U,0x11U,0x5fU
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

#define SYSTEM_PROGRAM_BUILTIN                BUILTIN_PROGRAM(&fd_solana_system_program_id,                 "system_program",                        NO_ENABLE_FEATURE_ID,                                      NULL)
#define VOTE_PROGRAM_BUILTIN                  BUILTIN_PROGRAM(&fd_solana_vote_program_id,                   "vote_program",                          NO_ENABLE_FEATURE_ID,                                      NULL)
#define STAKE_PROGRAM_BUILTIN                 BUILTIN_PROGRAM(&fd_solana_stake_program_id,                  "stake_program",                         NO_ENABLE_FEATURE_ID,                                      MIGRATE_BUILTIN_TO_CORE_BPF_STAKE_PROGRAM_CONFIG)
#define CONFIG_PROGRAM_BUILTIN                BUILTIN_PROGRAM(&fd_solana_config_program_id,                 "config_program",                        NO_ENABLE_FEATURE_ID,                                      MIGRATE_BUILTIN_TO_CORE_BPF_CONFIG_PROGRAM_CONFIG)
#define LOADER_V4_BUILTIN                     BUILTIN_PROGRAM(&fd_solana_bpf_loader_v4_program_id,          "loader_v4",                             offsetof(fd_features_t, enable_loader_v4),                 NULL)
#define ADDRESS_LOOKUP_TABLE_PROGRAM_BUILTIN  BUILTIN_PROGRAM(&fd_solana_address_lookup_table_program_id,   "address_lookup_table_program",          NO_ENABLE_FEATURE_ID,                                      MIGRATE_BUILTIN_TO_CORE_BPF_ADDRESS_LOOKUP_TABLE_PROGRAM_CONFIG)
#define BPF_LOADER_DEPRECATED_BUILTIN         BUILTIN_PROGRAM(&fd_solana_bpf_loader_deprecated_program_id,  "solana_bpf_loader_deprecated_program",  NO_ENABLE_FEATURE_ID,                                      NULL)
#define BPF_LOADER_BUILTIN                    BUILTIN_PROGRAM(&fd_solana_bpf_loader_program_id,             "solana_bpf_loader_program",             NO_ENABLE_FEATURE_ID,                                      NULL)
#define BPF_LOADER_UPGRADEABLE_BUILTIN        BUILTIN_PROGRAM(&fd_solana_bpf_loader_upgradeable_program_id, "solana_bpf_loader_upgradeable_program", NO_ENABLE_FEATURE_ID,                                      NULL)
#define COMPUTE_BUDGET_PROGRAM_BUILTIN        BUILTIN_PROGRAM(&fd_solana_compute_budget_program_id,         "compute_budget_program",                NO_ENABLE_FEATURE_ID,                                      NULL)
#define ZK_TOKEN_PROOF_PROGRAM_BUILTIN        BUILTIN_PROGRAM(&fd_solana_zk_token_proof_program_id,         "zk_token_proof_program",                offsetof(fd_features_t, zk_token_sdk_enabled),             NULL)
#define ZK_ELGAMAL_PROOF_PROGRAM_BUILTIN      BUILTIN_PROGRAM(&fd_solana_zk_elgamal_proof_program_id,       "zk_elgamal_proof_program",              offsetof(fd_features_t, zk_elgamal_proof_program_enabled), NULL)

#define FEATURE_PROGRAM_BUILTIN               STATELESS_BUILTIN(&fd_solana_feature_program_id,  MIGRATE_STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG)
#define SLASHING_PROGRAM_BUILTIN              STATELESS_BUILTIN(&fd_solana_slashing_program_id, MIGRATE_STATELESS_TO_CORE_BPF_SLASHING_PROGRAM_CONFIG)

#define SECP256R1_PROGRAM_PRECOMPILE          PRECOMPILE(&fd_solana_secp256r1_program_id,          offsetof(fd_features_t, enable_secp256r1_precompile), fd_precompile_secp256r1_verify)
#define KECCAK_SECP_PROGRAM_PRECOMPILE        PRECOMPILE(&fd_solana_keccak_secp_256k_program_id,   NO_ENABLE_FEATURE_ID,                                 fd_precompile_secp256k1_verify)
#define ED25519_SV_PROGRAM_PRECOMPILE         PRECOMPILE(&fd_solana_ed25519_sig_verify_program_id, NO_ENABLE_FEATURE_ID,                                 fd_precompile_ed25519_verify)

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/mod.rs#L133-L143 */
static const fd_stateless_builtin_program_t stateless_programs_builtins[] = {
    FEATURE_PROGRAM_BUILTIN,
    SLASHING_PROGRAM_BUILTIN
};
#define STATELESS_BUILTINS_COUNT (sizeof(stateless_programs_builtins) / sizeof(fd_stateless_builtin_program_t))

static const fd_precompile_program_t precompiles[] = {
    SECP256R1_PROGRAM_PRECOMPILE,
    KECCAK_SECP_PROGRAM_PRECOMPILE,
    ED25519_SV_PROGRAM_PRECOMPILE
};
#define PRECOMPILE_PROGRAMS_COUNT (sizeof(precompiles) / sizeof(fd_precompile_program_t))

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/mod.rs#L34-L131 */
static fd_builtin_program_t const builtin_programs[] = {
    SYSTEM_PROGRAM_BUILTIN,
    VOTE_PROGRAM_BUILTIN,
    STAKE_PROGRAM_BUILTIN,
    CONFIG_PROGRAM_BUILTIN,
    LOADER_V4_BUILTIN,
    ADDRESS_LOOKUP_TABLE_PROGRAM_BUILTIN,
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
    MIGRATE_BUILTIN_TO_CORE_BPF_STAKE_PROGRAM_CONFIG,
    MIGRATE_BUILTIN_TO_CORE_BPF_CONFIG_PROGRAM_CONFIG,
    MIGRATE_BUILTIN_TO_CORE_BPF_ADDRESS_LOOKUP_TABLE_PROGRAM_CONFIG,
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
fd_builtin_is_bpf( fd_funk_t *               funk,
                   fd_funk_txn_xid_t const * xid,
                   fd_pubkey_t const  *      pubkey ) {
  fd_txn_account_t rec[1];
  int err = fd_txn_account_init_from_funk_readonly( rec, pubkey, funk, xid );
  if( !!err ) {
    return 0;
  }

  fd_pubkey_t const * owner = fd_txn_account_get_owner( rec );
  return memcmp( owner, &fd_solana_bpf_loader_upgradeable_program_id, sizeof(fd_solana_bpf_loader_upgradeable_program_id) )==0;
}


/* BuiltIn programs need "bogus" executable accounts to exist.
   These are loaded and ignored during execution.

   Bogus accounts are marked as "executable", but their data is a
   hardcoded ASCII string. */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/native_loader.rs#L19 */
void
fd_write_builtin_account( fd_bank_t  *              bank,
                          fd_accdb_user_t *         accdb,
                          fd_funk_txn_xid_t const * xid,
                          fd_capture_ctx_t *        capture_ctx,
                          fd_pubkey_t const         pubkey,
                          char const *              data,
                          ulong                     sz ) {

  fd_txn_account_t rec[1];
  fd_funk_rec_prepare_t prepare = {0};

  int ok = !!fd_txn_account_init_from_funk_mutable( rec, &pubkey, accdb, xid, 1, sz, &prepare );
  FD_TEST( ok );

  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash(
    &pubkey,
    fd_txn_account_get_meta( rec ),
    fd_txn_account_get_data( rec ),
    prev_hash );

  fd_txn_account_set_data( rec, data, sz );
  fd_txn_account_set_lamports( rec, 1UL );
  fd_txn_account_set_executable( rec, 1 );
  fd_txn_account_set_owner( rec, &fd_solana_native_loader_id );

  fd_hashes_update_lthash( rec->pubkey, rec->meta, prev_hash, bank, capture_ctx );

  fd_txn_account_mutable_fini( rec, accdb, &prepare );

  fd_bank_capitalization_set( bank, fd_bank_capitalization_get( bank ) + 1UL );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/inline_spl_token.rs#L74 */
/* TODO: move this somewhere more appropiate */
static void
write_inline_spl_native_mint_program_account( fd_accdb_user_t *         accdb,
                                              fd_funk_txn_xid_t const * xid ) {

  if( true ) {
    /* FIXME: This is a hack that corresponds to the cluster type field
       in Agave. This needs to get implemented properly in Firedancer. */
    return;
  }

  fd_pubkey_t const * key  = (fd_pubkey_t const *)&fd_solana_spl_native_mint_id;
  fd_txn_account_t rec[1];

  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/inline_spl_token.rs#L86-L90 */
  static uchar const data[] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  fd_funk_rec_prepare_t prepare = {0};
  int ok = !!fd_txn_account_init_from_funk_mutable( rec, key, accdb, xid, 1, sizeof(data), &prepare );
  FD_TEST( ok );

  fd_txn_account_set_lamports( rec, 1000000000UL );
  fd_txn_account_set_executable( rec, 0 );
  fd_txn_account_set_owner( rec, &fd_solana_spl_token_id );
  fd_txn_account_set_data( rec, data, sizeof(data) );

  fd_txn_account_mutable_fini( rec, accdb, &prepare );
}

// <rant> Why are these not in the genesis block themselves?! the hackery to deal with subtle solana variants
//        because of the "special knowledge" required for these accounts is counter productive... </rant>

void
fd_builtin_programs_init( fd_bank_t *               bank,
                          fd_accdb_user_t *         accdb,
                          fd_funk_txn_xid_t const * xid,
                          fd_capture_ctx_t *        capture_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/v2.3.7/builtins/src/lib.rs#L52 */
  fd_builtin_program_t const * builtins = fd_builtins();

  fd_funk_t * funk = fd_accdb_user_v1_funk( accdb );
  for( ulong i=0UL; i<fd_num_builtins(); i++ ) {
    /** https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L4949 */
    if( fd_bank_slot_get( bank )==0UL && builtins[i].enable_feature_offset==NO_ENABLE_FEATURE_ID && !fd_builtin_is_bpf( funk, xid, builtins[i].pubkey ) ) {
      fd_write_builtin_account( bank, accdb, xid, capture_ctx, *builtins[i].pubkey, builtins[i].data, strlen( builtins[i].data ) );
    } else if( builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( fd_bank_slot_get( bank ), fd_bank_features_query( bank ), builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      continue;
    } else if( builtins[i].enable_feature_offset!=NO_ENABLE_FEATURE_ID && !FD_FEATURE_ACTIVE_OFFSET( fd_bank_slot_get( bank ), fd_bank_features_query( bank ), builtins[i].enable_feature_offset ) ) {
      continue;
    } else {
      fd_write_builtin_account( bank, accdb, xid, capture_ctx, *builtins[i].pubkey, builtins[i].data, strlen(builtins[i].data) );
    }
  }

  /* Precompiles have empty account data */
  fd_write_builtin_account( bank, accdb, xid, capture_ctx, fd_solana_keccak_secp_256k_program_id, "", 0 );
  fd_write_builtin_account( bank, accdb, xid, capture_ctx, fd_solana_ed25519_sig_verify_program_id, "", 0 );
  if( FD_FEATURE_ACTIVE_BANK( bank, enable_secp256r1_precompile ) ) {
    fd_write_builtin_account( bank, accdb, xid, capture_ctx, fd_solana_secp256r1_program_id, "", 0 );
  }

  /* Inline SPL token mint program ("inlined to avoid an external dependency on the spl-token crate") */
  write_inline_spl_native_mint_program_account( accdb, xid );
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

fd_precompile_program_t const *
fd_precompiles( void ) {
  return precompiles;
}

ulong
fd_num_precompiles( void ) {
  return PRECOMPILE_PROGRAMS_COUNT;
}

uchar
fd_is_migrating_builtin_program( fd_bank_t const *   bank,
                                 fd_pubkey_t const * pubkey,
                                 uchar *             migrated_yet ) {
  *migrated_yet = 0;

  for( ulong i=0; i<MIGRATING_BUILTINS_COUNT; i++ ) {
    fd_core_bpf_migration_config_t const * config = migrating_builtins[i];
    if( !memcmp( pubkey->uc, config->builtin_program_id->key, sizeof(fd_pubkey_t) ) ) {
      if( config->enable_feature_offset!=NO_ENABLE_FEATURE_ID &&
        FD_FEATURE_ACTIVE_OFFSET( fd_bank_slot_get( bank ), fd_bank_features_query( bank ), config->enable_feature_offset ) ) {
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
