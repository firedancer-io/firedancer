#ifndef HEADER_fd_src_flamenco_runtime_program_fd_buildin_programs_h
#define HEADER_fd_src_flamenco_runtime_program_fd_buildin_programs_h

#include "../../fd_flamenco_base.h"
#include "../../runtime/fd_system_ids.h"
#include "../../features/fd_features.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_system_ids.h"
#include "../fd_system_ids_pp.h"

#define NO_ENABLE_FEATURE_ID ULONG_MAX

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L43-L66
   Configuration for migrating a built-in program to Core BPF */
struct fd_core_bpf_migration_config {
  fd_pubkey_t const * source_buffer_address;
  fd_pubkey_t *       upgrade_authority_address;
  ulong               enable_feature_offset;
  fd_pubkey_t const * builtin_program_id;
};
typedef struct fd_core_bpf_migration_config fd_core_bpf_migration_config_t;

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/prototypes.rs#L7-L13
   Transitions of built-in programs at epoch boundaries when features are activated */
struct fd_builtin_program {
  fd_pubkey_t const *                    pubkey;
  char const *                           data;
  ulong                                  enable_feature_offset;
  fd_core_bpf_migration_config_t const * core_bpf_migration_config;
};
typedef struct fd_builtin_program fd_builtin_program_t;

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/prototypes.rs#L31-L35
   Transitions of stateless built-in programs at epoch boundaries when features are activated */
struct fd_stateless_builtin_program {
  fd_pubkey_t const *                    pubkey;
  fd_core_bpf_migration_config_t const * core_bpf_migration_config;
};
typedef struct fd_stateless_builtin_program fd_stateless_builtin_program_t;

FD_PROTOTYPES_BEGIN

/* Initialize the builtin program accounts */
void
fd_builtin_programs_init( fd_exec_slot_ctx_t * slot_ctx );

void
fd_write_builtin_account( fd_exec_slot_ctx_t * slot_ctx,
                          fd_pubkey_t const    pubkey,
                          char const *         data,
                          ulong                sz );

fd_builtin_program_t const *
fd_builtins( void );

ulong
fd_num_builtins( void );

fd_stateless_builtin_program_t const *
fd_stateless_builtins( void );

ulong
fd_num_stateless_builtins( void );

FD_PROTOTYPES_END

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

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/mod.rs#L34-L131 */
static const fd_builtin_program_t builtin_programs[] = {
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
#define BUILTIN_PROGRAMS_COUNT sizeof(builtin_programs) / sizeof(fd_builtin_program_t)


/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/mod.rs#L133-L143 */
static const fd_stateless_builtin_program_t stateless_programs_builtins[] = {
    FEATURE_PROGRAM_BUILTIN
};
#define STATELESS_BUILTINS_COUNT sizeof(stateless_programs_builtins) / sizeof(fd_stateless_builtin_program_t)

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_buildin_programs_h */
