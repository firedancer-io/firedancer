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

/*  `migrated_yet` is an output value thats set based on the rules below:

    | Return Value | *migrated_yet     | Description                                                              |
    |--------------|-------------------|--------------------------------------------------------------------------|
    |      0       |        0          | Program is not a migrating builtin program                               |
    |      1       |        0          | Program is a migrating builtin program id, BUT has not been migrated yet |
    |      1       |        1          | Program is a migrating builtin program id, AND has been migrated to BPF  |
*/
uchar
fd_is_migrating_builtin_program( fd_exec_txn_ctx_t const * txn_ctx,
                                 fd_pubkey_t const *       pubkey,
                                 uchar *                   migrated_yet );

uchar
fd_is_non_migrating_builtin_program( fd_pubkey_t const * pubkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_buildin_programs_h */
