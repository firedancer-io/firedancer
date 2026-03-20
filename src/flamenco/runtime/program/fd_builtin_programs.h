#ifndef HEADER_fd_src_flamenco_runtime_program_fd_builtin_programs_h
#define HEADER_fd_src_flamenco_runtime_program_fd_builtin_programs_h

#include "../../fd_flamenco_base.h"
#include "../fd_bank.h"
#include "../fd_system_ids_pp.h"
#include "fd_bpf_loader_program.h"

#define FD_CORE_BPF_MIGRATION_TARGET_BUILTIN   (0)
#define FD_CORE_BPF_MIGRATION_TARGET_STATELESS (1)

/* https://github.com/anza-xyz/agave/blob/v2.3.0/builtins/src/core_bpf_migration.rs#L17-L43
   Configuration for migrating a built-in program to Core BPF.
   - `migration_target` is one of
      FD_CORE_BPF_MIGRATION_TARGET_{BUILTIN,STATELESS}. */
struct fd_core_bpf_migration_config {
  fd_pubkey_t const * source_buffer_address;
  fd_pubkey_t *       upgrade_authority_address;
  ulong               enable_feature_offset;
  uchar               migration_target;
  fd_pubkey_t const * builtin_program_id;
  fd_hash_t const *   verified_build_hash;
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

/* It's technically possible to craft a buffer account that can cause
   the temporary ProgramData account data buffer to exceed
   FD_RUNTIME_ACC_SZ_MAX.

   This is because PROGRAMDATA_METADATA_SIZE is 8 bytes larger than
   BUFFER_METADATA_SIZE, so the worst-case size of the temporary
   account buffer is FD_RUNTIME_ACC_SZ_MAX + 8 bytes.

   To be conservative, and obvious, we use FD_RUNTIME_ACC_SZ_MAX +
   PROGRAMDATA_METADATA_SIZE.

   Such a buffer account will not be deployed, because the derived
   ProgramData size will exceed MAX_PERMITTED_DATA_LENGTH, but we still
   need to ensure that the temporary ProgramData account buffer is
   large enough. */

struct fd_tmp_account {
  fd_pubkey_t       addr;
  fd_account_meta_t meta;
  uchar             data[PROGRAMDATA_METADATA_SIZE + FD_RUNTIME_ACC_SZ_MAX]__attribute__((aligned(8UL)));
  ulong             data_sz;
};
typedef struct fd_tmp_account fd_tmp_account_t;

FD_PROTOTYPES_BEGIN

/* Initialize the builtin program accounts */
void
fd_builtin_programs_init( fd_bank_t *               bank,
                          fd_accdb_user_t *         accdb,
                          fd_funk_txn_xid_t const * xid,
                          fd_capture_ctx_t *        capture_ctx );

void
fd_write_builtin_account( fd_bank_t  *              bank,
                          fd_accdb_user_t *         accdb,
                          fd_funk_txn_xid_t const * xid,
                          fd_capture_ctx_t *        capture_ctx,
                          fd_pubkey_t const         pubkey,
                          void const *              data,
                          ulong                     sz );

fd_builtin_program_t const *
fd_builtins( void );

ulong
fd_num_builtins( void );

fd_stateless_builtin_program_t const *
fd_stateless_builtins( void );

ulong
fd_num_stateless_builtins( void );

/*  `migrated_yet` is an output value thats set based on the rules below:

    | Return Value | *migrated_yet     | Description                                                              |
    |--------------|-------------------|--------------------------------------------------------------------------|
    |      0       |        0          | Program is not a migrating builtin program                               |
    |      1       |        0          | Program is a migrating builtin program id, BUT has not been migrated yet |
    |      1       |        1          | Program is a migrating builtin program id, AND has been migrated to BPF  |
*/
uchar
fd_is_migrating_builtin_program( fd_bank_t const *   bank,
                                 fd_pubkey_t const * pubkey,
                                 uchar *             migrated_yet );

uchar
fd_is_non_migrating_builtin_program( fd_pubkey_t const * pubkey );

void
fd_migrate_builtin_to_core_bpf( fd_bank_t *                            bank,
                                fd_accdb_user_t *                      accdb,
                                fd_funk_txn_xid_t const *              xid,
                                fd_runtime_stack_t *                   runtime_stack,
                                fd_core_bpf_migration_config_t const * config,
                                fd_capture_ctx_t *                     capture_ctx );

void
fd_upgrade_core_bpf_program( fd_bank_t *                            bank,
                             fd_accdb_user_t *                      accdb,
                             fd_funk_txn_xid_t const *              xid,
                             fd_runtime_stack_t *                   runtime_stack,
                             fd_pubkey_t const *                    builtin_program_id,
                             fd_pubkey_t const *                    source_buffer_address,
                             fd_capture_ctx_t *                     capture_ctx );

/* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L402-L408 */
void
fd_upgrade_loader_v2_program_with_loader_v3_program( fd_bank_t *               bank,
                                                     fd_accdb_user_t *         accdb,
                                                     fd_funk_txn_xid_t const * xid,
                                                     fd_runtime_stack_t *      runtime_stack,
                                                     fd_pubkey_t const *       loader_v2_program_address,
                                                     fd_pubkey_t const *       source_buffer_address,
                                                     int                       allow_prefunded,
                                                     fd_capture_ctx_t *        capture_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_builtin_programs_h */
