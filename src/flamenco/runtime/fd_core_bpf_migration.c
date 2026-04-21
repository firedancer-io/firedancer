#include "fd_accdb_svm.h"
#include "sysvar/fd_sysvar_rent.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_builtin_programs.h"
#include "program/fd_program_util.h"
#include "fd_runtime_stack.h"
#include "fd_pubkey_utils.h"
#include "fd_system_ids.h"
#include "../accdb/fd_accdb_sync.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "../progcache/fd_prog_load.h"
#include "../vm/fd_vm.h"
#include <assert.h>

static fd_pubkey_t
get_program_data_address( fd_pubkey_t const * program_addr ) {
  uchar const * seed    = program_addr->uc;
  ulong         seed_sz = 32UL;
  fd_pubkey_t   out;
  uint          custom_err;
  uchar         out_bump_seed;
  int err = fd_pubkey_find_program_address( &fd_solana_bpf_loader_upgradeable_program_id, 1UL, &seed, &seed_sz, &out, &out_bump_seed, &custom_err );
  if( FD_UNLIKELY( err ) ) {
    /* https://github.com/anza-xyz/solana-sdk/blob/address%40v2.1.0/address/src/syscalls.rs#L277-L279 */
    FD_LOG_ERR(( "Unable to find a viable program address bump seed" ));
  }
  return out;
}

fd_tmp_account_t *
tmp_account_new( fd_tmp_account_t * acc,
                 ulong              acc_sz ) {
  acc->data_sz = acc_sz;
  fd_memset( acc->data, 0, acc_sz );
  return acc;
}

fd_tmp_account_t *
tmp_account_read( fd_tmp_account_t *        acc,
                  fd_accdb_user_t *         accdb,
                  fd_funk_txn_xid_t const * xid,
                  fd_pubkey_t const *       addr ) {
  fd_accdb_ro_t ro[1];
  if( FD_LIKELY( !fd_accdb_open_ro( accdb, ro, xid, addr ) ) ) return NULL;
  tmp_account_new( acc, fd_accdb_ref_data_sz( ro ) );
  acc->meta = *ro->meta;
  acc->addr = *addr;
  fd_memcpy( acc->data, fd_accdb_ref_data_const( ro ), fd_accdb_ref_data_sz( ro ) );
  acc->data_sz = fd_accdb_ref_data_sz( ro );
  fd_accdb_close_ro( accdb, ro );
  return acc;
}

void
tmp_account_store( fd_tmp_account_t *        acc,
                   fd_accdb_user_t *         accdb,
                   fd_funk_txn_xid_t const * xid,
                   fd_bank_t *               bank,
                   fd_capture_ctx_t *        capture_ctx ) {
  if( FD_UNLIKELY( fd_pubkey_eq( &acc->addr, &fd_solana_system_program_id ) ) ) {
    FD_LOG_ERR(( "Attempted to write to the system program account" ));
  }

  fd_accdb_rw_t rw[1]; fd_accdb_svm_update_t update[1];
  FD_TEST( fd_accdb_svm_open_rw( accdb, bank, xid, rw, update, &acc->addr, acc->data_sz, FD_ACCDB_FLAG_CREATE ) );

  fd_accdb_ref_exec_bit_set( rw, acc->meta.executable );
  fd_accdb_ref_owner_set   ( rw, acc->meta.owner      );
  fd_accdb_ref_lamports_set( rw, acc->meta.lamports   );
  fd_accdb_ref_data_set    ( accdb, rw, acc->data, acc->data_sz );

  fd_accdb_svm_close_rw( accdb, bank, capture_ctx, rw, update );
}

/* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_core_bpf.rs#L12 */

struct target_core_bpf {
  fd_pubkey_t        program_address;
  fd_tmp_account_t * program_data_account;
  fd_pubkey_t        upgrade_authority_address;
  uint               has_upgrade_authority_address : 1;
};

typedef struct target_core_bpf target_core_bpf_t;

/* https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L19 */

struct target_builtin {
  fd_tmp_account_t * program_account;
  fd_pubkey_t        program_data_address;
  ulong              program_data_account_lamports;
};

typedef struct target_builtin target_builtin_t;

/* https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L25-L91 */

target_builtin_t *
target_builtin_new_checked( target_builtin_t *        target_builtin,
                            fd_pubkey_t const *       program_address,
                            int                       migration_target,
                            int                       relax_programdata_account_check_migration,
                            fd_accdb_user_t *         accdb,
                            fd_funk_txn_xid_t const * xid,
                            fd_runtime_stack_t *      runtime_stack ) {

  /* https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L31-L53 */

  fd_tmp_account_t * program_account = &runtime_stack->bpf_migration.program_account;
  switch( migration_target ) {
  case FD_CORE_BPF_MIGRATION_TARGET_BUILTIN:
    if( FD_UNLIKELY( !tmp_account_read( program_account, accdb, xid, program_address ) ) ) {
      /* CoreBpfMigrationError::AccountNotFound(*program_address) */
      return NULL;
    }
    if( FD_UNLIKELY( 0!=memcmp( program_account->meta.owner, &fd_solana_native_loader_id, 32 ) ) ) {
      /* CoreBpfMigrationError::IncorrectOwner(*program_address) */
      return NULL;
    }
    break;
  case FD_CORE_BPF_MIGRATION_TARGET_STATELESS: {
    /* Program account should not exist */
    fd_accdb_ro_t ro[1];
    int progdata_exists = !!fd_accdb_open_ro( accdb, ro, xid, program_address );
    if( progdata_exists ) {
      /* CoreBpfMigrationError::AccountAlreadyExists(*program_address) */
      fd_accdb_close_ro( accdb, ro );
      return NULL;
    }
    break;
  }
  default:
    FD_LOG_ERR(( "invalid migration_target %d", migration_target ));
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L55 */

  fd_pubkey_t program_data_address = get_program_data_address( program_address );

  /* https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L57-L82 */

  ulong program_data_account_lamports = 0UL;
  do {
    /* Program data account should not exist */
    fd_accdb_ro_t ro[1];
    int progdata_exists = !!fd_accdb_open_ro( accdb, ro, xid, &program_data_address );

    /* SIMD-0444: relax_programdata_account_check_migration
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L57-L70 */
    if( relax_programdata_account_check_migration ) {
      /* The program data account should not exist, but a system
         account with funded lamports is acceptable. */
      if( FD_UNLIKELY( progdata_exists ) ) {
        if( FD_UNLIKELY( !fd_pubkey_eq( fd_accdb_ref_owner( ro ), &fd_solana_system_program_id ) ) ) {
          /* CoreBpfMigrationError::ProgramHasDataAccount(*program_address) */
          fd_accdb_close_ro( accdb, ro );
          return NULL;
        } else {
          program_data_account_lamports = fd_accdb_ref_lamports( ro );
          fd_accdb_close_ro( accdb, ro );
        }
      }
    } else {
      /* If relax_programdata_account_check_migration is not enabled,
         we do not allow the program data account to exist at all. */
      if( FD_UNLIKELY( progdata_exists ) ) {
        /* CoreBpfMigrationError::AccountAlreadyExists(*program_address) */
        fd_accdb_close_ro( accdb, ro );
        return NULL;
      }
    }
  } while(0);

  /* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L63-L67 */

  *target_builtin = (target_builtin_t) {
    .program_account               = program_account,
    .program_data_address          = program_data_address,
    .program_data_account_lamports = program_data_account_lamports
  };
  return target_builtin;
}

/* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/target_core_bpf.rs#L26-L93 */
static target_core_bpf_t *
target_core_bpf_new_checked( target_core_bpf_t *       target_core_bpf,
                             fd_pubkey_t const *       program_address,
                             fd_accdb_user_t *         accdb,
                             fd_funk_txn_xid_t const * xid,
                             fd_runtime_stack_t *      runtime_stack ) {
  fd_pubkey_t program_data_address = get_program_data_address( program_address );

  /* The program account should exist */
  fd_tmp_account_t * program_account = &runtime_stack->bpf_migration.program_account;
  if( FD_UNLIKELY( !tmp_account_read( program_account, accdb, xid, program_address ) ) ) {
    return NULL;
  }

  /* The program account should be owned by the upgradeable loader */
  if( FD_UNLIKELY( 0!=memcmp( program_account->meta.owner, &fd_solana_bpf_loader_upgradeable_program_id, sizeof(fd_pubkey_t) ) ) ) {
    return NULL;
  }

  /* The program account should be executable */
  if( FD_UNLIKELY( !program_account->meta.executable ) ) {
    return NULL;
  }

  /* Decode and validate program account state */
  fd_bpf_upgradeable_loader_state_t program_state[1];
  if( FD_UNLIKELY( FD_EXECUTOR_INSTR_SUCCESS!=fd_bpf_loader_program_get_state( &program_account->meta, program_state ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_program( program_state ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( 0!=memcmp( &program_state->inner.program.programdata_address, &program_data_address, sizeof(fd_pubkey_t) ) ) ) {
    return NULL;
  }

  /* The program data account should exist */
  fd_tmp_account_t * program_data_account = &runtime_stack->bpf_migration.new_target_program;
  if( FD_UNLIKELY( !tmp_account_read( program_data_account, accdb, xid, &program_data_address ) ) ) {
    return NULL;
  }

  /* The program data account should be owned by the upgradeable loader */
  if( FD_UNLIKELY( 0!=memcmp( program_data_account->meta.owner, &fd_solana_bpf_loader_upgradeable_program_id, sizeof(fd_pubkey_t) ) ) ) {
    return NULL;
  }

  /* Decode and validate program data account state */
  fd_bpf_upgradeable_loader_state_t programdata_state[1];
  if( FD_UNLIKELY( FD_EXECUTOR_INSTR_SUCCESS!=fd_bpf_loader_program_get_state( &program_data_account->meta, programdata_state ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_program_data( programdata_state ) ) ) {
    return NULL;
  }

  /* Extract upgrade authority from program data state */
  fd_pubkey_t upgrade_authority_address;
  if( programdata_state->inner.program_data.has_upgrade_authority_address ) {
    upgrade_authority_address = programdata_state->inner.program_data.upgrade_authority_address;
  } else {
    fd_memset( &upgrade_authority_address, 0, sizeof(fd_pubkey_t) );
  }

  *target_core_bpf = (target_core_bpf_t) {
    .program_address                = *program_address,
    .program_data_account           = program_data_account,
    .upgrade_authority_address      = upgrade_authority_address,
    .has_upgrade_authority_address  = (uint)!!programdata_state->inner.program_data.has_upgrade_authority_address
  };
  return target_core_bpf;
}

/* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L25-L82

   Agave uses a separate TargetBpfV2 struct, but it has the
   same layout as target_builtin_t so we reuse that. */
static target_builtin_t *
target_bpf_v2_new_checked( target_builtin_t *        target_bpf_v2,
                           fd_pubkey_t const *       program_address,
                           int                       allow_prefunded,
                           fd_accdb_user_t *         accdb,
                           fd_funk_txn_xid_t const * xid,
                           fd_runtime_stack_t *      runtime_stack ) {

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L30-L33 */
  fd_tmp_account_t * program_account = &runtime_stack->bpf_migration.program_account;
  if( FD_UNLIKELY( !tmp_account_read( program_account, accdb, xid, program_address ) ) ) {
    /* CoreBpfMigrationError::AccountNotFound(*program_address) */
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L35-L38 */
  if( FD_UNLIKELY( 0!=memcmp( program_account->meta.owner, &fd_solana_bpf_loader_program_id, FD_PUBKEY_FOOTPRINT ) ) ) {
    /* CoreBpfMigrationError::IncorrectOwner(*program_address) */
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L40-L45 */
  if( FD_UNLIKELY( !program_account->meta.executable ) ) {
    /* CoreBpfMigrationError::ProgramAccountNotExecutable(*program_address) */
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L47 */
  fd_pubkey_t program_data_address = get_program_data_address( program_address );

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L49-L74 */
  ulong program_data_account_lamports = 0UL;
  do {
    fd_accdb_ro_t ro[1];
    int progdata_exists = !!fd_accdb_open_ro( accdb, ro, xid, &program_data_address );

    /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L49-L74 */
    if( FD_LIKELY( allow_prefunded ) ) {
      /* The program data account should not exist, but a system
         account with funded lamports is acceptable.

         https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L50-L61 */
      if( FD_UNLIKELY( progdata_exists ) ) {
        if( FD_UNLIKELY( !fd_pubkey_eq( fd_accdb_ref_owner( ro ), &fd_solana_system_program_id ) ) ) {
          /* CoreBpfMigrationError::ProgramHasDataAccount(*program_address) */
          fd_accdb_close_ro( accdb, ro );
          return NULL;
        } else {
          program_data_account_lamports = fd_accdb_ref_lamports( ro );
          fd_accdb_close_ro( accdb, ro );
        }
      }
    } else {
      /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/target_bpf_v2.rs#L62-L74 */
      if( FD_UNLIKELY( progdata_exists ) ) {
        /* CoreBpfMigrationError::ProgramHasDataAccount(*program_address) */
        fd_accdb_close_ro( accdb, ro );
        return NULL;
      }
    }
  } while(0);

  *target_bpf_v2 = (target_builtin_t) {
    .program_account               = program_account,
    .program_data_address          = program_data_address,
    .program_data_account_lamports = program_data_account_lamports
  };
  return target_bpf_v2;
}

/* This function contains the deployment checks that are equivalent to
   Agave's directly_invoke_loader_v3_deploy.

   There is no direct equivalent in Agave to this function, because
   we are not updating the program cache here. However, we do the same
   checks that our program cache does upon deployment.

   This is safe because the bpf migration code runs at the epoch
   boundary, before any transaction execution. The program cache
   automatically invalidates all programs at the start of an epoch
   boundary, so we do not need to explicitly update the cache during the
   migration.

   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L120-L218 */
static int
fd_directly_invoke_loader_v3_deploy_checks( fd_bank_t const *    bank,
                                            fd_runtime_stack_t * runtime_stack,
                                            uchar const *        elf,
                                            ulong                elf_sz ) {
  fd_features_t const * features = &bank->f.features;
  ulong                 slot     = bank->f.slot;

  /* ELF verification with deploy checks enabled */
  fd_prog_versions_t versions = fd_prog_versions( features, slot );
  fd_sbpf_loader_config_t loader_config = {
    .elf_deploy_checks = 1,
    .sbpf_min_version  = versions.min_sbpf_version,
    .sbpf_max_version  = versions.max_sbpf_version,
  };
  fd_sbpf_elf_info_t elf_info[1];
  if( FD_UNLIKELY( fd_sbpf_elf_peek( elf_info, elf, elf_sz, &loader_config )!=FD_SBPF_ELF_SUCCESS ) ) return 1;

  /* Setup program (includes calldests) */
  fd_sbpf_program_t * prog = fd_sbpf_program_new(
    runtime_stack->bpf_migration.progcache_validate.sbpf_footprint,
    elf_info,
    runtime_stack->bpf_migration.progcache_validate.rodata );
  if( FD_UNLIKELY( !prog ) ) return 1;

  fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  if( FD_UNLIKELY( !syscalls ) ) return 1;
  if( FD_UNLIKELY( fd_vm_syscall_register_slot( syscalls, slot, features, /* is_deploy */ 1 )!=FD_VM_SUCCESS ) ) return 1;

  /* fd_sbpf_program_load checks */
  if( FD_UNLIKELY( fd_sbpf_program_load(
    prog,
    elf,
    elf_sz,
    syscalls,
    &loader_config,
    runtime_stack->bpf_migration.progcache_validate.programdata,
    sizeof(runtime_stack->bpf_migration.progcache_validate.programdata) ) ) ) return 1;

  /* fd_vm_validate checks */
  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  if( FD_UNLIKELY( !vm ) ) return 1;
  vm = fd_vm_init( vm,
                   NULL,
                   0UL,
                   0UL,
                   prog->rodata,
                   prog->rodata_sz,
                   prog->text,
                   prog->info.text_cnt,
                   prog->info.text_off,
                   prog->info.text_sz,
                   prog->entry_pc,
                   prog->calldests,
                   elf_info->sbpf_version,
                   syscalls,
                   NULL,
                   NULL,
                   NULL,
                   0U,
                   NULL,
                   0,
                   FD_FEATURE_ACTIVE( slot, features, account_data_direct_mapping ),
                   FD_FEATURE_ACTIVE( slot, features, syscall_parameter_address_restrictions ),
                   FD_FEATURE_ACTIVE( slot, features, virtual_address_space_adjustments ),
                   0,
                   0UL );
  if( FD_UNLIKELY( !vm ) ) return 1;
  if( FD_UNLIKELY( fd_vm_validate( vm )!=FD_VM_SUCCESS ) ) return 1;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L51-L75 */

static fd_tmp_account_t *
source_buffer_new_checked( fd_tmp_account_t *        acc,
                           fd_accdb_user_t *         accdb,
                           fd_funk_txn_xid_t const * xid,
                           fd_pubkey_t const *       pubkey,
                           fd_hash_t const *         verified_build_hash ) {

  if( FD_UNLIKELY( !tmp_account_read( acc, accdb, xid, pubkey ) ) ) {
    /* CoreBpfMigrationError::AccountNotFound(*buffer_address) */
    return NULL;
  }

  if( FD_UNLIKELY( 0!=memcmp( acc->meta.owner, &fd_solana_bpf_loader_upgradeable_program_id, 32 ) ) ) {
    /* CoreBpfMigrationError::IncorrectOwner(*buffer_address) */
    return NULL;
  }

  if( acc->data_sz < BUFFER_METADATA_SIZE ) {
    /* CoreBpfMigrationError::InvalidBufferAccount(*buffer_address) */
    return NULL;
  }

  fd_bpf_upgradeable_loader_state_t state[1];
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode( state, acc->data, BUFFER_METADATA_SIZE ) ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( state->discriminant!=fd_bpf_upgradeable_loader_state_enum_buffer ) ) {
    /* CoreBpfMigrationError::InvalidBufferAccount(*buffer_address) */
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L61-L71 */
  if( verified_build_hash ) {
    /* Strip trailing zero-padding before hashing
       https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L61-L63 */
    uchar const * data       = (uchar const *)acc->data;
    ulong         offset     = BUFFER_METADATA_SIZE;
    ulong         end_offset = acc->data_sz;
    while( end_offset>offset && data[end_offset-1]==0 ) end_offset--;
    uchar const * buffer_program_data    = data + offset;
    ulong         buffer_program_data_sz = end_offset - offset;

    fd_hash_t hash;
    fd_sha256_hash( buffer_program_data, buffer_program_data_sz, hash.uc );
    if( FD_UNLIKELY( 0!=memcmp( hash.uc, verified_build_hash->uc, FD_HASH_FOOTPRINT ) ) ) {
      /* CoreBpfMigrationError::BuildHashMismatch */
      return NULL;
    }
  }

  return acc;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L82-L95 */

static fd_tmp_account_t *
new_target_program_account( fd_tmp_account_t *        acc,
                            target_builtin_t const *  target,
                            fd_rent_t const *         rent ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L86-L88 */
  fd_bpf_upgradeable_loader_state_t state = {
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program,
    .inner = {
      .program = {
        .programdata_address = target->program_data_address,
      }
    }
  };

  ulong state_sz = fd_bpf_upgradeable_loader_state_size( &state );
  tmp_account_new( acc, state_sz );
  acc->meta.lamports   = fd_rent_exempt_minimum_balance( rent, SIZE_OF_PROGRAM );
  acc->meta.executable = 1;
  memcpy( acc->meta.owner, fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) );

  ulong out_sz = 0UL;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_encode( &state, acc->data, state_sz, &out_sz ) ) ) {
    FD_LOG_ERR(( "fd_bpf_upgradeable_loader_state_encode failed" ));
  }

  return acc;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L108-L153 */
static fd_tmp_account_t *
new_target_program_data_account( fd_tmp_account_t *       acc,
                                 fd_tmp_account_t const * source,
                                 fd_pubkey_t const *      upgrade_authority_address,
                                 fd_rent_t const *        rent,
                                 ulong                    slot ) {
  ulong const buffer_metadata_sz = BUFFER_METADATA_SIZE;

  if( FD_UNLIKELY( source->data_sz < buffer_metadata_sz ) )
    return NULL; /* CoreBpfMigrationError::InvalidBufferAccount */

  fd_bpf_upgradeable_loader_state_t state;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode( &state, source->data, buffer_metadata_sz ) ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( state.discriminant!=fd_bpf_upgradeable_loader_state_enum_buffer ) )
    return NULL; /* CoreBpfMigrationError::InvalidBufferAccount */

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L118-L125 */
  if( upgrade_authority_address ) {
    if( FD_UNLIKELY( !state.inner.buffer.has_authority_address ||
                     !fd_pubkey_eq( upgrade_authority_address, &state.inner.buffer.authority_address ) ) ) {
      return NULL; /* CoreBpfMigrationError::UpgradeAuthorityMismatch */
    }
  }

  void const * elf      = (uchar const *)source->data    + buffer_metadata_sz;
  ulong        elf_sz   = /*           */source->data_sz - buffer_metadata_sz;

  ulong        space    = PROGRAMDATA_METADATA_SIZE + elf_sz;
  ulong        lamports = fd_rent_exempt_minimum_balance( rent, space );
  fd_pubkey_t  owner    = fd_solana_bpf_loader_upgradeable_program_id;

  fd_bpf_upgradeable_loader_state_t programdata_meta = {
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
    .inner = {
      .program_data = {
        .slot = slot,
        .has_upgrade_authority_address = !!upgrade_authority_address,
        .upgrade_authority_address     = upgrade_authority_address ? *upgrade_authority_address : (fd_pubkey_t){{0}}
      }
    }
  };

  tmp_account_new( acc, space );
  acc->meta.lamports = lamports;
  memcpy( acc->meta.owner, owner.uc, sizeof(fd_pubkey_t) );
  ulong out_sz = 0UL;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_encode( &programdata_meta, acc->data, PROGRAMDATA_METADATA_SIZE, &out_sz ) ) ) {
    FD_LOG_ERR(( "fd_bpf_upgradeable_loader_state_encode failed" ));
  }
  fd_memcpy( (uchar *)acc->data+PROGRAMDATA_METADATA_SIZE, elf, elf_sz );

  return acc;
}

void
migrate_builtin_to_core_bpf1( fd_core_bpf_migration_config_t const * config,
                              fd_accdb_user_t *                      accdb,
                              fd_funk_txn_xid_t const *              xid,
                              fd_bank_t *                            bank,
                              fd_runtime_stack_t *                   runtime_stack,
                              fd_pubkey_t const *                    builtin_program_id,
                              fd_capture_ctx_t *                     capture_ctx ) {
  target_builtin_t target[1];
  if( FD_UNLIKELY( !target_builtin_new_checked(
      target,
      builtin_program_id,
      config->migration_target,
      FD_FEATURE_ACTIVE_BANK( bank, relax_programdata_account_check_migration ),
      accdb,
      xid,
      runtime_stack ) ) )
    return;

  fd_tmp_account_t * source = &runtime_stack->bpf_migration.source;
  if( FD_UNLIKELY( !source_buffer_new_checked(
      source,
      accdb,
      xid,
      config->source_buffer_address,
      config->verified_build_hash ) ) )
    return;

  fd_rent_t const * rent = &bank->f.rent;
  ulong const       slot = bank->f.slot;

  fd_tmp_account_t * new_target_program = &runtime_stack->bpf_migration.new_target_program;
  if( FD_UNLIKELY( !new_target_program_account(
      new_target_program,
      target,
      rent ) ) )
    return;
  new_target_program->addr = *builtin_program_id;

  fd_tmp_account_t * new_target_program_data = &runtime_stack->bpf_migration.new_target_program_data;
  if( FD_UNLIKELY( !new_target_program_data_account(
      new_target_program_data,
      source,
      config->upgrade_authority_address,
      rent,
      slot ) ) )
    return;
  new_target_program_data->addr = target->program_data_address;

  ulong old_data_sz;
  if( FD_UNLIKELY( fd_ulong_checked_add( target->program_account->data_sz, source->data_sz, &old_data_sz ) ) ) return;

  ulong new_data_sz;
  if( FD_UNLIKELY( fd_ulong_checked_add( new_target_program->data_sz, new_target_program_data->data_sz, &new_data_sz ) ) ) return;

  assert( new_target_program_data->data_sz>=PROGRAMDATA_METADATA_SIZE );
  /* FIXME call fd_directly_invoke_loader_v3_deploy */

  /* https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L267-L281 */
  ulong lamports_to_burn;
  if( FD_UNLIKELY( fd_ulong_checked_add( target->program_account->meta.lamports, source->meta.lamports, &lamports_to_burn ) ) ) return;
  if( FD_UNLIKELY( fd_ulong_checked_add( lamports_to_burn, target->program_data_account_lamports, &lamports_to_burn ) ) )       return;

  ulong lamports_to_fund;
  if( FD_UNLIKELY( fd_ulong_checked_add( new_target_program->meta.lamports, new_target_program_data->meta.lamports, &lamports_to_fund ) ) ) return;

  /* Write back accounts */
  tmp_account_store( new_target_program,      accdb, xid, bank, capture_ctx );
  tmp_account_store( new_target_program_data, accdb, xid, bank, capture_ctx );
  fd_tmp_account_t * empty = &runtime_stack->bpf_migration.empty;
  tmp_account_new( empty, 0UL );
  empty->addr = source->addr;
  tmp_account_store( empty, accdb, xid, bank, capture_ctx );

  /* FIXME "remove the built-in program from the bank's list of builtins" */
  /* FIXME "update account data size delta" */
}

/* Mimics migrate_builtin_to_core_bpf().
   https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/mod.rs#215-303 */
void
fd_migrate_builtin_to_core_bpf( fd_bank_t *                            bank,
                                fd_accdb_user_t *                      accdb,
                                fd_funk_txn_xid_t const *              xid,
                                fd_runtime_stack_t *                   runtime_stack,
                                fd_core_bpf_migration_config_t const * config,
                                fd_capture_ctx_t *                     capture_ctx ) {
  migrate_builtin_to_core_bpf1( config, accdb, xid, bank, runtime_stack, config->builtin_program_id, capture_ctx );
}

/* Mimics upgrade_core_bpf_program().
   https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L319-L377 */
void
fd_upgrade_core_bpf_program( fd_bank_t *                            bank,
                             fd_accdb_user_t *                      accdb,
                             fd_funk_txn_xid_t const *              xid,
                             fd_runtime_stack_t *                   runtime_stack,
                             fd_pubkey_t const *                    builtin_program_id,
                             fd_pubkey_t const *                    source_buffer_address,
                             fd_capture_ctx_t *                     capture_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L327 */
  target_core_bpf_t target[1];
  if( FD_UNLIKELY( !target_core_bpf_new_checked( target, builtin_program_id, accdb, xid, runtime_stack ) ) ) {
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L328 */
  fd_tmp_account_t * source = &runtime_stack->bpf_migration.source;
  if( FD_UNLIKELY( !source_buffer_new_checked( source, accdb, xid, source_buffer_address, NULL ) ) ) {
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L331-L332  */
  fd_tmp_account_t * new_target_program_data = &runtime_stack->bpf_migration.new_target_program_data;
  fd_pubkey_t program_data_address = get_program_data_address( builtin_program_id );

  ulong program_data_len = source->data_sz - BUFFER_METADATA_SIZE;
  ulong new_account_size = PROGRAMDATA_METADATA_SIZE + program_data_len;

  tmp_account_new( new_target_program_data, new_account_size );
  new_target_program_data->addr = program_data_address;

  fd_rent_t const * rent = &bank->f.rent;
  new_target_program_data->meta.lamports   = fd_rent_exempt_minimum_balance( rent, new_account_size );
  new_target_program_data->meta.executable = 0;
  fd_memcpy( new_target_program_data->meta.owner, &fd_solana_bpf_loader_upgradeable_program_id, sizeof(fd_pubkey_t) );

  fd_bpf_upgradeable_loader_state_t programdata_state[1] = {{
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
    .inner = { .program_data = {
      .slot = bank->f.slot,
      .upgrade_authority_address = target->upgrade_authority_address,
      .has_upgrade_authority_address = target->has_upgrade_authority_address
    }}
  }};

  ulong out_sz = 0UL;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_encode( programdata_state, new_target_program_data->data, PROGRAMDATA_METADATA_SIZE, &out_sz ) ) ) {
    return;
  }

  fd_memcpy( new_target_program_data->data + PROGRAMDATA_METADATA_SIZE,
             source->data + BUFFER_METADATA_SIZE,
             program_data_len );

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.4/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L339-L346 */
  ulong old_data_sz;
  if( FD_UNLIKELY( fd_ulong_checked_add( target->program_data_account->data_sz, source->data_sz, &old_data_sz ) ) ) return;
  ulong new_data_sz = new_target_program_data->data_sz;

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.4/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L349-L355 */
  uchar const * elf    = new_target_program_data->data + PROGRAMDATA_METADATA_SIZE;
  ulong         elf_sz = program_data_len;
  if( FD_UNLIKELY( fd_directly_invoke_loader_v3_deploy_checks( bank, runtime_stack, elf, elf_sz ) ) ) return;

  /* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L359-L364 */
  ulong lamports_to_burn;
  if( FD_UNLIKELY( fd_ulong_checked_add( target->program_data_account->meta.lamports, source->meta.lamports, &lamports_to_burn ) ) ) return;

  /* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L366-L371 */
  fd_pubkey_t source_addr = source->addr;
  tmp_account_store( new_target_program_data, accdb, xid, bank, capture_ctx );

  fd_tmp_account_t * empty = &runtime_stack->bpf_migration.empty;
  tmp_account_new( empty, 0UL );
  empty->addr = source_addr;
  tmp_account_store( empty, accdb, xid, bank, capture_ctx );

  /* https://github.com/anza-xyz/agave/blob/v3.1.7/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L374 */
  /* FIXME "update account data size delta" */
  (void)old_data_sz;
  (void)new_data_sz;

  fd_memset( &runtime_stack->bpf_migration, 0, sizeof(runtime_stack->bpf_migration) );
}

/* Mimics upgrade_loader_v2_program_with_loader_v3_program().
   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L402-L474 */
void
fd_upgrade_loader_v2_program_with_loader_v3_program( fd_bank_t *               bank,
                                                     fd_accdb_user_t *         accdb,
                                                     fd_funk_txn_xid_t const * xid,
                                                     fd_runtime_stack_t *      runtime_stack,
                                                     fd_pubkey_t const *       loader_v2_program_address,
                                                     fd_pubkey_t const *       source_buffer_address,
                                                     int                       allow_prefunded,
                                                     fd_capture_ctx_t *        capture_ctx ) {

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L411-L412 */
  target_builtin_t target[1];
  if( FD_UNLIKELY( !target_bpf_v2_new_checked(
      target,
      loader_v2_program_address,
      allow_prefunded,
      accdb,
      xid,
      runtime_stack ) ) )
    return;

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L413 */
  fd_tmp_account_t * source = &runtime_stack->bpf_migration.source;
  if( FD_UNLIKELY( !source_buffer_new_checked( source, accdb, xid, source_buffer_address, NULL ) ) )
    return;

  fd_rent_t const * rent = &bank->f.rent;
  ulong             slot = bank->f.slot;

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L416-L417 */
  fd_tmp_account_t * new_target_program = &runtime_stack->bpf_migration.new_target_program;
  if( FD_UNLIKELY( !new_target_program_account( new_target_program, target, rent ) ) )
    return;
  new_target_program->addr = *loader_v2_program_address;

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L419-L421 */
  fd_tmp_account_t * new_target_program_data = &runtime_stack->bpf_migration.new_target_program_data;
  if( FD_UNLIKELY( !new_target_program_data_account( new_target_program_data, source, NULL, rent, slot ) ) ) {
    return;
  }
  new_target_program_data->addr = target->program_data_address;

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L427-L435 */
  ulong old_data_sz;
  if( FD_UNLIKELY( fd_ulong_checked_add( target->program_account->data_sz, source->data_sz, &old_data_sz ) ) ) return;

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L432-L435 */
  ulong new_data_sz;
  if( FD_UNLIKELY( fd_ulong_checked_add( new_target_program->data_sz, new_target_program_data->data_sz, &new_data_sz ) ) ) return;

  if( FD_UNLIKELY( new_target_program_data->data_sz<PROGRAMDATA_METADATA_SIZE ) ) {
    FD_LOG_CRIT(( "invariant violation: new target programdata too small" ));
  }

  /* Agave calls directly_invoke_loader_v3_deploy to deploy the new
     program to the program cache. We don't do that, but instead we
     perform the same checks as directly_invoke_loader_v3_deploy
     without modifying the program cache. We need to do the checks
     at this point so that we can fail the upgrade if the ELF is
     invalid.

     This is safe because the bpf migration code runs at the epoch
     boundary, before any transaction execution. The program cache
     automatically invalidates all programs at the start of an epoch
     boundary, so we do not need to explicitly update the cache during the
     migration.

     https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L437-L443*/
  uchar const * elf    = (uchar const *)new_target_program_data->data + PROGRAMDATA_METADATA_SIZE;
  ulong         elf_sz = new_target_program_data->data_sz - PROGRAMDATA_METADATA_SIZE;
  if( FD_UNLIKELY( fd_directly_invoke_loader_v3_deploy_checks( bank, runtime_stack, elf, elf_sz ) ) ) return;

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L451-L459 */
  ulong lamports_to_burn;
  if( FD_UNLIKELY( fd_ulong_checked_add( target->program_account->meta.lamports, source->meta.lamports, &lamports_to_burn ) ) ) return;
  if( FD_UNLIKELY( fd_ulong_checked_add( lamports_to_burn, target->program_data_account_lamports, &lamports_to_burn ) ) )       return;

  ulong lamports_to_fund;
  if( FD_UNLIKELY( fd_ulong_checked_add( new_target_program->meta.lamports, new_target_program_data->meta.lamports, &lamports_to_fund ) ) ) return;

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L462-L468 */
  tmp_account_store( new_target_program,      accdb, xid, bank, capture_ctx );
  tmp_account_store( new_target_program_data, accdb, xid, bank, capture_ctx );

  fd_tmp_account_t * empty = &runtime_stack->bpf_migration.empty;
  tmp_account_new( empty, 0UL );
  empty->addr = source->addr;
  tmp_account_store( empty, accdb, xid, bank, capture_ctx );

  /* NB: Agave updates "delta_off_chain", using these two fields,
     which is not consensus-critical (only used for Agave stats)
     so we don't update this in our migration code or store this in
     our bank. */
  (void)old_data_sz;
  (void)new_data_sz;

  fd_memset( &runtime_stack->bpf_migration, 0, sizeof(runtime_stack->bpf_migration) );
}
