#include "sysvar/fd_sysvar_rent.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_builtin_programs.h"
#include "fd_runtime_stack.h"
#include "fd_pubkey_utils.h"
#include "fd_system_ids.h"
#include "fd_hashes.h"
#include <assert.h>

static fd_pubkey_t
get_program_data_address( fd_pubkey_t const * program_addr ) {
  uchar const * seed    = program_addr->uc;
  ulong         seed_sz = 32UL;
  fd_pubkey_t   out;
  uint          custom_err;
  uchar         out_bump_seed;
  fd_pubkey_find_program_address( &fd_solana_bpf_loader_upgradeable_program_id, 1UL, &seed, &seed_sz, &out, &out_bump_seed, &custom_err );
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

  fd_accdb_rw_t rw[1];
  fd_accdb_open_rw( accdb, rw, xid, &acc->addr, acc->data_sz, FD_ACCDB_FLAG_CREATE );
  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash( &acc->addr, rw->meta, fd_accdb_ref_data_const( rw->ro ), prev_hash );

  fd_accdb_ref_exec_bit_set( rw, acc->meta.executable );
  fd_accdb_ref_owner_set   ( rw, acc->meta.owner      );
  fd_accdb_ref_lamports_set( rw, acc->meta.lamports   );
  fd_accdb_ref_data_set    ( accdb, rw, acc->data, acc->data_sz );

  fd_hashes_update_lthash( &acc->addr, rw->meta, prev_hash, bank, capture_ctx );
  fd_accdb_close_rw( accdb, rw );
}

/* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_core_bpf.rs#L12 */

struct target_core_bpf {
  fd_pubkey_t        program_address;
  fd_tmp_account_t * program_data_account;
  fd_pubkey_t        upgrade_authority_address;
  uint               has_upgrade_authority_address : 1;
};

typedef struct target_core_bpf target_core_bpf_t;

/* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L13 */

struct target_builtin {
  fd_tmp_account_t * program_account;
  fd_pubkey_t        program_data_address;
};

typedef struct target_builtin target_builtin_t;

/* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L22 */

target_builtin_t *
target_builtin_new_checked( target_builtin_t *        target_builtin,
                            fd_pubkey_t const *       program_address,
                            int                       migration_target,
                            fd_accdb_user_t *         accdb,
                            fd_funk_txn_xid_t const * xid,
                            fd_runtime_stack_t *      runtime_stack ) {

  /* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L27-L49 */

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

  /* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L51 */

  fd_pubkey_t program_data_address = get_program_data_address( program_address );

  /* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L53-L61 */

  do {
    /* Program data account should not exist */
    fd_accdb_ro_t ro[1];
    int progdata_exists = !!fd_accdb_open_ro( accdb, ro, xid, &program_data_address );
    if( progdata_exists ) {
      /* CoreBpfMigrationError::AccountAlreadyExists(*program_address) */
      fd_accdb_close_ro( accdb, ro );
      return NULL;
    }
  } while(0);

  /* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L63-L67 */

  *target_builtin = (target_builtin_t) {
    .program_account      = program_account,
    .program_data_address = program_data_address
  };
  return target_builtin;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.2/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L22-L49 */

static fd_tmp_account_t *
source_buffer_new_checked( fd_tmp_account_t *        acc,
                           fd_accdb_user_t *         accdb,
                           fd_funk_txn_xid_t const * xid,
                           fd_pubkey_t const *       pubkey ) {

  if( FD_UNLIKELY( !tmp_account_read( acc, accdb, xid, pubkey ) ) ) {
    /* CoreBpfMigrationError::AccountNotFound(*buffer_address) */
    return NULL;
  }

  if( FD_UNLIKELY( 0!=memcmp( acc->meta.owner, &fd_solana_bpf_loader_upgradeable_program_id, 32 ) ) ) {
    /* CoreBpfMigrationError::IncorrectOwner(*buffer_address) */
    return NULL;
  }

  ulong const buffer_metadata_sz = 37UL;
  if( acc->data_sz < buffer_metadata_sz ) {
    /* CoreBpfMigrationError::InvalidBufferAccount(*buffer_address) */
    return NULL;
  }

  fd_bpf_upgradeable_loader_state_t state[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      bpf_upgradeable_loader_state, state,
      acc->data, acc->data_sz,
      NULL ) ) ) {
    return NULL;
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

  tmp_account_new( acc, fd_bpf_upgradeable_loader_state_size( &state ) );
  acc->meta.lamports   = fd_rent_exempt_minimum_balance( rent, SIZE_OF_PROGRAM );
  acc->meta.executable = 1;
  memcpy( acc->meta.owner, fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) );

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
  if( !fd_bincode_decode_static(
      bpf_upgradeable_loader_state,
      &state,
      source->data,
      buffer_metadata_sz,
      NULL ) )
    return NULL;

  if( FD_UNLIKELY( state.discriminant!=fd_bpf_upgradeable_loader_state_enum_buffer ) )
    return NULL; /* CoreBpfMigrationError::InvalidBufferAccount */

  if( FD_UNLIKELY( state.inner.buffer.has_authority_address != (!!upgrade_authority_address) ) )
    return NULL; /* CoreBpfMigrationError::InvalidBufferAccount */

  if( FD_UNLIKELY( upgrade_authority_address &&
                   !fd_pubkey_eq( upgrade_authority_address, &state.inner.buffer.authority_address ) ) )
    return NULL; /* CoreBpfMigrationError::UpgradeAuthorityMismatch */

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
  fd_bincode_encode_ctx_t ctx = { .data=acc->data, .dataend=(uchar *)acc->data+PROGRAMDATA_METADATA_SIZE };
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_encode( &programdata_meta, &ctx )!=FD_BINCODE_SUCCESS ) ) {
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
      accdb,
      xid,
      runtime_stack ) ) )
    return;

  fd_tmp_account_t * source = &runtime_stack->bpf_migration.source;
  if( FD_UNLIKELY( !source_buffer_new_checked(
      source,
      accdb,
      xid,
      config->source_buffer_address ) ) )
    return;

  fd_rent_t const * rent = fd_bank_rent_query( bank );
  ulong const       slot = fd_bank_slot_get  ( bank );

  fd_tmp_account_t * new_target_program = &runtime_stack->bpf_migration.new_target_program;
  if( FD_UNLIKELY( !new_target_program_account(
      new_target_program,
      target,
      rent ) ) )
    return;

  fd_tmp_account_t * new_target_program_data = &runtime_stack->bpf_migration.new_target_program_data;
  if( FD_UNLIKELY( !new_target_program_data_account(
      new_target_program_data,
      source,
      config->upgrade_authority_address,
      rent,
      slot ) ) )
    return;

  ulong old_data_sz;
  if( FD_UNLIKELY( __builtin_uaddl_overflow(
      target->program_account->data_sz,
      source->data_sz,
      &old_data_sz ) ) ) {
    return;
  }
  ulong new_data_sz;
  if( FD_UNLIKELY( __builtin_uaddl_overflow(
      new_target_program     ->data_sz,
      new_target_program_data->data_sz,
      &new_data_sz ) ) ) {
    return;
  }

  assert( new_target_program_data->data_sz>=PROGRAMDATA_METADATA_SIZE );
  /* FIXME call fd_directly_invoke_loader_v3_deploy */

  ulong lamports_to_burn;
  if( FD_UNLIKELY( __builtin_uaddl_overflow(
      target->program_account->meta.lamports,
      source->meta.lamports,
      &lamports_to_burn ) ) ) {
    return;
  }
  ulong lamports_to_fund;
  if( FD_UNLIKELY( __builtin_uaddl_overflow(
      new_target_program     ->meta.lamports,
      new_target_program_data->meta.lamports,
      &lamports_to_fund ) ) ) {
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L286-L297 */
  ulong capitalization = fd_bank_capitalization_get( bank );
  int cap_ok = 1;
  if( lamports_to_burn>lamports_to_fund ) {
    cap_ok = __builtin_usubl_overflow(
        capitalization,
        (lamports_to_burn-lamports_to_fund),
        &capitalization );
  } else if( lamports_to_burn<lamports_to_fund ) {
    cap_ok = __builtin_uaddl_overflow(
        capitalization,
        (lamports_to_fund-lamports_to_burn),
        &capitalization );
  }
  if( FD_UNLIKELY( !cap_ok ) ) {
    FD_LOG_ERR(( "Capitalization overflow while migrating builtin program to core BPF" ));
  }
  fd_bank_capitalization_set( bank, capitalization );

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
   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L235-L318 */
void
fd_migrate_builtin_to_core_bpf( fd_bank_t *                            bank,
                                fd_accdb_user_t *                      accdb,
                                fd_funk_txn_xid_t const *              xid,
                                fd_runtime_stack_t *                   runtime_stack,
                                fd_core_bpf_migration_config_t const * config,
                                fd_capture_ctx_t *                     capture_ctx ) {
  migrate_builtin_to_core_bpf1( config, accdb, xid, bank, runtime_stack, config->builtin_program_id, capture_ctx );
}
