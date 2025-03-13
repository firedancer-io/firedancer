#include "fd_builtin_programs.h"
#include "../fd_runtime.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../fd_system_ids_pp.h"

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

#define NO_CORE_BPF_MIGRATION_CONFIG NULL

#define DEFINE_CORE_BPF_MIGRATION_CONFIG(name, buffer_address, feature_offset, program_id) \
    static const fd_core_bpf_migration_config_t name = {                                   \
        buffer_address,                                                                    \
        NULL,                                                                              \
        offsetof(fd_features_t, feature_offset),                                           \
        program_id                                                                         \
    };                                                                                     \
    static const fd_core_bpf_migration_config_t * const MIGRATE_##name = &name

DEFINE_CORE_BPF_MIGRATION_CONFIG(BUILTIN_TO_CORE_BPF_STAKE_PROGRAM_CONFIG,                &fd_solana_stake_program_buffer_address,                migrate_stake_program_to_core_bpf,                &fd_solana_stake_program_id);
DEFINE_CORE_BPF_MIGRATION_CONFIG(BUILTIN_TO_CORE_BPF_CONFIG_PROGRAM_CONFIG,               &fd_solana_config_program_buffer_address,               migrate_config_program_to_core_bpf,               &fd_solana_config_program_id);
DEFINE_CORE_BPF_MIGRATION_CONFIG(BUILTIN_TO_CORE_BPF_ADDRESS_LOOKUP_TABLE_PROGRAM_CONFIG, &fd_solana_address_lookup_table_program_buffer_address, migrate_address_lookup_table_program_to_core_bpf, &fd_solana_address_lookup_table_program_id);
DEFINE_CORE_BPF_MIGRATION_CONFIG(STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG,       &fd_solana_feature_program_buffer_address,              migrate_feature_gate_program_to_core_bpf,         &fd_solana_feature_program_id);

#define SYSTEM_PROGRAM_BUILTIN                BUILTIN_PROGRAM(&fd_solana_system_program_id,                 "system_program",                        NO_ENABLE_FEATURE_ID,                                             NO_CORE_BPF_MIGRATION_CONFIG)
#define VOTE_PROGRAM_BUILTIN                  BUILTIN_PROGRAM(&fd_solana_vote_program_id,                   "vote_program",                          NO_ENABLE_FEATURE_ID,                                             NO_CORE_BPF_MIGRATION_CONFIG)
#define STAKE_PROGRAM_BUILTIN                 BUILTIN_PROGRAM(&fd_solana_stake_program_id,                  "stake_program",                         NO_ENABLE_FEATURE_ID,                                             MIGRATE_BUILTIN_TO_CORE_BPF_STAKE_PROGRAM_CONFIG)
#define CONFIG_PROGRAM_BUILTIN                BUILTIN_PROGRAM(&fd_solana_config_program_id,                 "config_program",                        NO_ENABLE_FEATURE_ID,                                             MIGRATE_BUILTIN_TO_CORE_BPF_CONFIG_PROGRAM_CONFIG)
#define LOADER_V4_BUILTIN                     BUILTIN_PROGRAM(&fd_solana_bpf_loader_v4_program_id,          "loader_v4",                             offsetof(fd_features_t, enable_program_runtime_v2_and_loader_v4), NO_CORE_BPF_MIGRATION_CONFIG)
#define ADDRESS_LOOKUP_TABLE_PROGRAM_BUILTIN  BUILTIN_PROGRAM(&fd_solana_address_lookup_table_program_id,   "address_lookup_table_program",          NO_ENABLE_FEATURE_ID,                                             MIGRATE_BUILTIN_TO_CORE_BPF_ADDRESS_LOOKUP_TABLE_PROGRAM_CONFIG)
#define BPF_LOADER_DEPRECATED_BUILTIN         BUILTIN_PROGRAM(&fd_solana_bpf_loader_deprecated_program_id,  "solana_bpf_loader_deprecated_program",  NO_ENABLE_FEATURE_ID,                                             NO_CORE_BPF_MIGRATION_CONFIG)
#define BPF_LOADER_BUILTIN                    BUILTIN_PROGRAM(&fd_solana_bpf_loader_program_id,             "solana_bpf_loader_program",             NO_ENABLE_FEATURE_ID,                                             NO_CORE_BPF_MIGRATION_CONFIG)
#define BPF_LOADER_UPGRADEABLE_BUILTIN        BUILTIN_PROGRAM(&fd_solana_bpf_loader_upgradeable_program_id, "solana_bpf_loader_upgradeable_program", NO_ENABLE_FEATURE_ID,                                             NO_CORE_BPF_MIGRATION_CONFIG)
#define COMPUTE_BUDGET_PROGRAM_BUILTIN        BUILTIN_PROGRAM(&fd_solana_compute_budget_program_id,         "compute_budget_program",                NO_ENABLE_FEATURE_ID,                                             NO_CORE_BPF_MIGRATION_CONFIG)
#define ZK_TOKEN_PROOF_PROGRAM_BUILTIN        BUILTIN_PROGRAM(&fd_solana_zk_token_proof_program_id,         "zk_token_proof_program",                offsetof(fd_features_t, zk_token_sdk_enabled),                    NO_CORE_BPF_MIGRATION_CONFIG)
#define ZK_ELGAMAL_PROOF_PROGRAM_BUILTIN      BUILTIN_PROGRAM(&fd_solana_zk_elgamal_proof_program_id,       "zk_elgamal_proof_program",              offsetof(fd_features_t, zk_elgamal_proof_program_enabled),        NO_CORE_BPF_MIGRATION_CONFIG)

#define FEATURE_PROGRAM_BUILTIN               STATELESS_BUILTIN(&fd_solana_feature_program_id, MIGRATE_STATELESS_TO_CORE_BPF_FEATURE_GATE_PROGRAM_CONFIG)

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/mod.rs#L133-L143 */
static const fd_stateless_builtin_program_t stateless_programs_builtins[] = {
    FEATURE_PROGRAM_BUILTIN
};
#define STATELESS_BUILTINS_COUNT (sizeof(stateless_programs_builtins) / sizeof(fd_stateless_builtin_program_t))

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/mod.rs#L34-L131 */
fd_builtin_program_t const builtin_programs[] = {
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
fd_core_bpf_migration_config_t const * migrating_builtins[] = {
    MIGRATE_BUILTIN_TO_CORE_BPF_STAKE_PROGRAM_CONFIG,
    MIGRATE_BUILTIN_TO_CORE_BPF_CONFIG_PROGRAM_CONFIG,
    MIGRATE_BUILTIN_TO_CORE_BPF_ADDRESS_LOOKUP_TABLE_PROGRAM_CONFIG,
};
#define MIGRATING_BUILTINS_COUNT (sizeof(migrating_builtins) / sizeof(fd_core_bpf_migration_config_t const *))

/* Using MAP_PERFECT instead of a list for optimization
   https://github.com/anza-xyz/agave/blob/v2.1.13/builtins-default-costs/src/lib.rs#L141-L193 */
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


/* BuiltIn programs need "bogus" executable accounts to exist.
   These are loaded and ignored during execution.

   Bogus accounts are marked as "executable", but their data is a
   hardcoded ASCII string. */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/native_loader.rs#L19 */
void
fd_write_builtin_account( fd_exec_slot_ctx_t * slot_ctx,
                          fd_pubkey_t const    pubkey,
                          char const *         data,
                          ulong                sz ) {

  fd_acc_mgr_t *      acc_mgr = slot_ctx->acc_mgr;
  fd_funk_txn_t *     txn     = slot_ctx->funk_txn;
  FD_TXN_ACCOUNT_DECL( rec );

  int err = fd_acc_mgr_modify( acc_mgr, txn, &pubkey, 1, sz, rec);
  FD_TEST( !err );

  rec->meta->dlen            = sz;
  rec->meta->info.lamports   = 1UL;
  rec->meta->info.rent_epoch = 0UL;
  rec->meta->info.executable = 1;
  fd_memcpy( rec->meta->info.owner, fd_solana_native_loader_id.key, 32 );
  memcpy( rec->data, data, sz );

  slot_ctx->slot_bank.capitalization++;

  // err = fd_acc_mgr_commit( acc_mgr, rec, slot_ctx );
  FD_TEST( !err );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/inline_spl_token.rs#L74 */
/* TODO: move this somewhere more appropiate */
static void
write_inline_spl_native_mint_program_account( fd_exec_slot_ctx_t * slot_ctx ) {
  // really?! really!?
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  if( epoch_bank->cluster_type != 3)
    return;

  fd_acc_mgr_t *      acc_mgr = slot_ctx->acc_mgr;
  fd_funk_txn_t *     txn     = slot_ctx->funk_txn;
  fd_pubkey_t const * key     = (fd_pubkey_t const *)&fd_solana_spl_native_mint_id;
  FD_TXN_ACCOUNT_DECL( rec );

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
  fd_memcpy( rec->meta->info.owner, fd_solana_spl_token_id.key, 32 );
  memcpy( rec->data, data, sizeof(data) );

  FD_TEST( !err );
}

void fd_builtin_programs_init( fd_exec_slot_ctx_t * slot_ctx ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/runtime/src/bank/builtins/mod.rs#L33
  fd_builtin_program_t const * builtins = fd_builtins();
  for( ulong i=0UL; i<fd_num_builtins(); i++ ) {
    if( builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( slot_ctx->slot_bank.slot, slot_ctx->epoch_ctx->features, builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      continue;
    } else if( builtins[i].enable_feature_offset!=NO_ENABLE_FEATURE_ID && !FD_FEATURE_ACTIVE_OFFSET( slot_ctx->slot_bank.slot, slot_ctx->epoch_ctx->features, builtins[i].enable_feature_offset ) ) {
      continue;
    } else {
      fd_write_builtin_account( slot_ctx, *builtins[i].pubkey, builtins[i].data, strlen(builtins[i].data) );
    }
  }

  //TODO: remove when no longer necessary
  if( FD_FEATURE_ACTIVE( slot_ctx->slot_bank.slot, slot_ctx->epoch_ctx->features, zk_token_sdk_enabled ) ) {
    fd_write_builtin_account( slot_ctx, fd_solana_zk_token_proof_program_id, "zk_token_proof_program", 22UL );
  }

  if( FD_FEATURE_ACTIVE( slot_ctx->slot_bank.slot, slot_ctx->epoch_ctx->features, zk_elgamal_proof_program_enabled ) ) {
    fd_write_builtin_account( slot_ctx, fd_solana_zk_elgamal_proof_program_id, "zk_elgamal_proof_program", 24UL );
  }

  /* Precompiles have empty account data */
  if( slot_ctx->epoch_ctx->epoch_bank.cluster_version[0]<2 ) {
    char data[1] = {1};
    fd_write_builtin_account( slot_ctx, fd_solana_keccak_secp_256k_program_id, data, 1 );
    fd_write_builtin_account( slot_ctx, fd_solana_ed25519_sig_verify_program_id, data, 1 );
    if( FD_FEATURE_ACTIVE( slot_ctx->slot_bank.slot, slot_ctx->epoch_ctx->features, enable_secp256r1_precompile ) )
      fd_write_builtin_account( slot_ctx, fd_solana_secp256r1_program_id, data, 1 );
  } else {
    fd_write_builtin_account( slot_ctx, fd_solana_keccak_secp_256k_program_id, "", 0 );
    fd_write_builtin_account( slot_ctx, fd_solana_ed25519_sig_verify_program_id, "", 0 );
    if( FD_FEATURE_ACTIVE( slot_ctx->slot_bank.slot, slot_ctx->epoch_ctx->features, enable_secp256r1_precompile ) )
      fd_write_builtin_account( slot_ctx, fd_solana_secp256r1_program_id, "", 0 );
  }

  /* Inline SPL token mint program ("inlined to avoid an external dependency on the spl-token crate") */
  write_inline_spl_native_mint_program_account( slot_ctx );
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
fd_is_migrating_builtin_program( fd_exec_txn_ctx_t const * txn_ctx,
                                 fd_pubkey_t const *       pubkey,
                                 uchar *                   migrated_yet ) {
  *migrated_yet = 0;

  for( ulong i=0; i<MIGRATING_BUILTINS_COUNT; i++ ) {
    fd_core_bpf_migration_config_t const * config = migrating_builtins[i];
    if( !memcmp( pubkey->uc, config->builtin_program_id->key, sizeof(fd_pubkey_t) ) ) {
      if( config->enable_feature_offset!=NO_ENABLE_FEATURE_ID &&
        FD_FEATURE_ACTIVE_OFFSET( txn_ctx->slot_bank->slot, txn_ctx->features, config->enable_feature_offset ) ) {
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
