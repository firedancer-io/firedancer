#include "fd_bpf_loader_v3_program.h"

#include "../fd_pubkey_utils.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../../vm/fd_vm_syscalls.h"
#include "../../vm/fd_vm_interp.h"
#include "../../vm/fd_vm_disasm.h"
#include "fd_bpf_loader_serialization.h"
#include "fd_bpf_program_util.h"
#include "fd_native_cpi.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#include <stdlib.h>
 
/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L67-L69 */
#define DEFAULT_LOADER_COMPUTE_UNITS     (570UL )
#define DEPRECATED_LOADER_COMPUTE_UNITS  (1140UL)
#define UPGRADEABLE_LOADER_COMPUTE_UNITS (2370UL)
/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/sdk/program/src/bpf_loader_upgradeable.rs#L29-L120 */
#define SIZE_OF_PROGRAM                  (36UL  ) /* UpgradeableLoaderState::size_of_program() */
#define BUFFER_METADATA_SIZE             (37UL  ) /* UpgradeableLoaderState::size_of_buffer_metadata() */
#define PROGRAMDATA_METADATA_SIZE        (45UL  ) /* UpgradeableLoaderState::size_of_programdata_metadata() */
#define SIZE_OF_UNINITIALIZED            (4UL   ) /* UpgradeableLoaderState::size_of_uninitialized() */

/* This is literally called before every single instruction execution */
int
fd_bpf_loader_v3_is_executable( fd_exec_slot_ctx_t * slot_ctx,
                                fd_pubkey_t const *  pubkey ) {
  int err = 0;
  fd_account_meta_t const * meta = fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn, 
                                                        (fd_pubkey_t *) pubkey, NULL, &err );
  if( FD_UNLIKELY( !fd_acc_exists( meta ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  if( FD_UNLIKELY( memcmp( meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  if( FD_UNLIKELY( meta->info.executable!=1 ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = (uchar *)meta     + meta->hlen,
    .dataend = (char *) ctx.data + meta->dlen,
    .valloc  = slot_ctx->valloc,
  };

  fd_bpf_upgradeable_loader_state_t loader_state = {0};
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode( &loader_state, &ctx ) ) ) {
    FD_LOG_WARNING(( "fd_bpf_upgradeable_loader_state_decode failed" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Check if programdata account exists */
  fd_account_meta_t const * programdata_meta = 
    (fd_account_meta_t const *)fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn, 
                                                    (fd_pubkey_t *) &loader_state.inner.program.programdata_address, NULL, &err );
  if( FD_UNLIKELY( !fd_acc_exists( programdata_meta ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_bincode_destroy_ctx_t ctx_d = { .valloc = slot_ctx->valloc };
  fd_bpf_upgradeable_loader_state_destroy( &loader_state, &ctx_d );

  return 0;
}

/* TODO: This can be combined with the other bpf loader state decode function */
fd_account_meta_t const *
read_bpf_upgradeable_loader_state_for_program( fd_exec_txn_ctx_t *                 txn_ctx,
                                               uchar                               program_id,
                                               fd_bpf_upgradeable_loader_state_t * result,
                                               int *                               opt_err ) {

  fd_borrowed_account_t * rec = NULL;
  int err = fd_txn_borrowed_account_view_idx( txn_ctx, program_id, &rec );
  if( FD_UNLIKELY( err ) ) {
    *opt_err = err;
    return NULL;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = rec->const_data,
    .dataend = rec->const_data + rec->const_meta->dlen,
    .valloc  = txn_ctx->valloc,
  };

  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode( result, &ctx ) ) ) {
    FD_LOG_WARNING(( "fd_bpf_upgradeable_loader_state_decode failed" ));
    *opt_err = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return NULL;
  }

  return rec->const_meta;  /* UGLY!!!!! */
}

/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L105-L171 */
int
deploy_program( fd_exec_instr_ctx_t * instr_ctx,
                uchar * const         programdata,
                ulong                 programdata_size ) {   
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(),
                                                                          fd_sbpf_syscalls_footprint() ) );
  if( FD_UNLIKELY( !syscalls ) ) {
    FD_LOG_WARNING(( "Failed to register syscalls" ));
    return FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE;
  }
  fd_vm_syscall_register_all( syscalls );

  /* Load executable */
  fd_sbpf_elf_info_t  _elf_info[ 1UL ];
  fd_sbpf_elf_info_t * elf_info = fd_sbpf_elf_peek( _elf_info, programdata, programdata_size );
  if( FD_UNLIKELY( !elf_info ) ) {
    FD_LOG_WARNING(( "Elf info failing" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate rodata segment */
  void * rodata = fd_scratch_alloc( 32UL, elf_info->rodata_footprint );
  if( FD_UNLIKELY( !rodata ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate program buffer */
  ulong  prog_align        = fd_sbpf_program_align();
  ulong  prog_footprint    = fd_sbpf_program_footprint( elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_scratch_alloc( prog_align, prog_footprint ), elf_info, rodata );
  if( FD_UNLIKELY( !prog ) ) {
    FD_LOG_ERR(( "fd_sbpf_program_new() failed: %s", fd_sbpf_strerror() ));
  } 

  /* Load program */
  if( FD_UNLIKELY( fd_sbpf_program_load( prog, programdata, programdata_size, syscalls ) ) ) {
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
  }

  /* Verify the program */
  fd_vm_exec_context_t vm_ctx = {
    .entrypoint          = (long)prog->entry_pc,
    .program_counter     = 0UL,
    .instruction_counter = 0UL,
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( prog->text ),
    .instrs_sz           = prog->text_cnt,
    .instrs_offset       = prog->text_off,
    .syscall_map         = syscalls,
    .calldests           = prog->calldests,
    .input               = NULL,
    .input_sz            = 0UL,
    .read_only           = (uchar *)fd_type_pun_const( prog->rodata ),
    .read_only_sz        = prog->rodata_sz,
    .heap_sz             = instr_ctx->txn_ctx->heap_size,
    /* TODO: configure heap allocator */
    .instr_ctx           = instr_ctx,
  };

  ulong validate_result = fd_vm_context_validate( &vm_ctx );
  if( FD_UNLIKELY( validate_result!=FD_VM_SBPF_VALIDATE_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L195-L218 */
int
write_program_data( fd_borrowed_account_t * program,
                    ulong                   program_data_offset,
                    uchar *                 bytes,
                    ulong                   bytes_len ) {
  ulong write_offset = fd_ulong_sat_add( program_data_offset, bytes_len );
  if( FD_UNLIKELY( program->meta->dlen<write_offset ) ) {
    FD_LOG_WARNING(( "Write overflow %lu < %lu", program->meta->dlen, write_offset ));
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  if( FD_UNLIKELY( program_data_offset>=program->meta->dlen ) ) {
    FD_LOG_WARNING(( "Write offset out of bounds" ));
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  fd_memcpy( program->data+program_data_offset, bytes, bytes_len );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* get_state() */
/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/sdk/src/transaction_context.rs#L968-L972 */
int 
fd_bpf_loader_v3_program_read_state( fd_exec_instr_ctx_t *               instr_ctx,
                                     fd_borrowed_account_t *             borrowed_acc, 
                                     fd_bpf_upgradeable_loader_state_t * state ) {
    /* Check to see if the buffer account is already initialized */
    fd_bincode_decode_ctx_t ctx = {
      .data    = borrowed_acc->const_data,
      .dataend = borrowed_acc->const_data + borrowed_acc->const_meta->dlen,
      .valloc  = instr_ctx->valloc,
    };

    int err = fd_bpf_upgradeable_loader_state_decode( state, &ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    return FD_BINCODE_SUCCESS;
}

/* set_state() */
/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/sdk/src/transaction_context.rs#L976-L985 */
int 
fd_bpf_loader_v3_program_write_state( fd_exec_instr_ctx_t *               instr_ctx,
                                      fd_borrowed_account_t *             borrowed_acc, 
                                      fd_bpf_upgradeable_loader_state_t * state ) {
  ulong state_size = fd_bpf_upgradeable_loader_state_size( state );

  if( FD_UNLIKELY( state_size>borrowed_acc->meta->dlen ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  fd_bincode_encode_ctx_t ctx = {
    .data    = borrowed_acc->data, 
    .dataend = borrowed_acc->data + state_size
  };

  int err = fd_bpf_upgradeable_loader_state_encode( state, &ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  borrowed_acc->meta->slot = instr_ctx->slot_ctx->slot_bank.slot;

  return FD_BINCODE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1299-L1331 */
int
common_close_account( fd_pubkey_t * authority_address, 
                      fd_exec_instr_ctx_t * instr_ctx,
                      fd_bpf_upgradeable_loader_state_t * state ) {
  uchar const *       instr_acc_idxs = instr_ctx->instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs       = instr_ctx->txn_ctx->accounts;

  if( FD_UNLIKELY( !authority_address ) ) {
    FD_LOG_WARNING(( "Account is immutable" ));
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }
  if( FD_UNLIKELY( memcmp( authority_address, &txn_accs[ instr_acc_idxs[ 2UL ] ], sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_WARNING(( "Incorrect authority provided" ));
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 2UL ) ) ) {
    FD_LOG_WARNING(( "Authority did not sign" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  fd_borrowed_account_t * close_account = NULL;
  int err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &close_account );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "Borrowed account lookup for close account failed" ));
    return err;
  }
  fd_borrowed_account_t * recipient_account = NULL;
  err = fd_instr_borrowed_account_modify_idx( instr_ctx, 1UL, 0UL, &recipient_account );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "Borrowed account lookup for recipient account failed" ));
    return err;
  }

  ulong result = 0UL;
  err = fd_ulong_checked_add( recipient_account->meta->info.lamports, 
                              close_account->meta->info.lamports, 
                              &result );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed checked add of recipient and close account balances" ));
    return err;
  }
  recipient_account->meta->info.lamports = result;
  close_account->meta->info.lamports     = 0UL;

  state->discriminant = fd_bpf_upgradeable_loader_state_enum_uninitialized;
  err = fd_bpf_loader_v3_program_write_state( instr_ctx, close_account, state );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "Bpf loader state write for close account failed" ));
    return err;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}


/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1332-L1501 */
int
execute( fd_exec_instr_ctx_t * instr_ctx, fd_sbpf_validated_program_t * prog ) {
  /* TODO: This will be updated once belt-sanding is merged in. I am not changing
     the existing VM setup/invocation. */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( instr_ctx->valloc, 
                                                                          fd_sbpf_syscalls_align(),
                                                                          fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls );
  
  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1362-L1368 */
  ulong input_sz = 0;
  ulong pre_lens[ 256UL ];
  uchar * input = fd_bpf_loader_input_serialize_aligned( *instr_ctx, &input_sz, pre_lens );
  if( FD_UNLIKELY( input==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  /* TODO: (topointon): correctly set check_align and check_size in vm setup */
  fd_vm_exec_context_t vm_ctx = {
    .entrypoint          = (long)prog->entry_pc,
    .program_counter     = 0UL,
    .instruction_counter = 0UL,
    .compute_meter       = instr_ctx->txn_ctx->compute_meter,
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( fd_sbpf_validated_program_rodata( prog ) + ( prog->text_off ) ),
    .instrs_sz           = prog->text_cnt,
    .instrs_offset       = prog->text_off,
    .syscall_map         = syscalls,
    .calldests           = prog->calldests,
    .input               = input,
    .input_sz            = input_sz,
    .read_only           = fd_sbpf_validated_program_rodata( prog ),
    .read_only_sz        = prog->rodata_sz,
    /* TODO: configure heap allocator */
    .instr_ctx           = instr_ctx,
    .heap_sz = instr_ctx->txn_ctx->heap_size,
    .due_insn_cnt = 0,
    .previous_instruction_meter = instr_ctx->txn_ctx->compute_meter,
    .alloc               = { .offset = 0UL }
  };

  memset( vm_ctx.register_file, 0, sizeof(vm_ctx.register_file) );
  vm_ctx.register_file[1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm_ctx.register_file[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  ulong interp_res = fd_vm_interp_instrs( &vm_ctx );
  if( FD_UNLIKELY( interp_res!=0UL ) ) {
    FD_LOG_ERR(( "fd_vm_interp_instrs() failed: %lu", interp_res ));
  }

  /* TODO: Add log for "Program consumed {} of {} compute units "*/

  instr_ctx->txn_ctx->compute_meter = vm_ctx.compute_meter;

  /* TODO: vm should report */
  if( vm_ctx.register_file[0]!=0 ) {
    fd_valloc_free( instr_ctx->valloc, input );
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  /* TODO: vm should report */
  if( vm_ctx.cond_fault ) {
    fd_valloc_free( instr_ctx->valloc, input );
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;;
  }

  if( FD_UNLIKELY( fd_bpf_loader_input_deserialize_aligned( *instr_ctx, pre_lens, input, input_sz )!=0 ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L566-L1444 */
int
process_loader_upgradeable_instruction( fd_exec_instr_ctx_t * instr_ctx ) {
  FD_LOG_WARNING(("Processing loader upgradeable instruction"));

  uchar const * data = instr_ctx->instr->data;

  fd_bpf_upgradeable_loader_program_instruction_t instruction = {0};
  fd_bincode_decode_ctx_t decode_ctx = {0};
  decode_ctx.data    = data;
  decode_ctx.dataend = &data[ instr_ctx->instr->data_sz ];
  decode_ctx.valloc  = instr_ctx->valloc;

  int err = fd_bpf_upgradeable_loader_program_instruction_decode( &instruction, &decode_ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "Bincode decode for instruction failed" ));
    return err;
  }

  uchar const * instr_acc_idxs   = instr_ctx->instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs   = instr_ctx->txn_ctx->accounts;
  fd_pubkey_t const * program_id = &instr_ctx->instr->program_id_pubkey;

  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L476-L493 */
  if( fd_bpf_upgradeable_loader_program_instruction_is_initialize_buffer( &instruction ) ) {
    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<2U ) ) {
      FD_LOG_WARNING(( "Not enough account keys for instruction" ));
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_borrowed_account_t * buffer = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &buffer );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for buffer account failed" ));
      return err;
    }

    fd_bpf_upgradeable_loader_state_t buffer_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, buffer, &buffer_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf loader state read for buffer account failed" ));
      return err;
    }

    if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_uninitialized( &buffer_state ) ) ) {
      FD_LOG_WARNING(( "Buffer account is already initialized" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];

    buffer_state.discriminant                   = fd_bpf_upgradeable_loader_state_enum_buffer;
    buffer_state.inner.buffer.authority_address = (fd_pubkey_t*)authority_key;

    err = fd_bpf_loader_v3_program_write_state( instr_ctx, buffer, &buffer_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf loader state write for buffer account failed" ));
      return err;
    }
  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L494-L525 */
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_write( &instruction ) ) {
    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<2 ) ) {
      FD_LOG_WARNING(( "Not enough account keys for instruction" ));
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_borrowed_account_t * buffer = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &buffer );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for buffer account failed" ));
      return err;
    }

    fd_bpf_upgradeable_loader_state_t loader_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, buffer, &loader_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf loader state read for buffer account failed" ));
      return err;
    }

    if( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( FD_UNLIKELY( !loader_state.inner.buffer.authority_address ) ) {
        FD_LOG_WARNING(( "Buffer is immutable" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }
      fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];
      if( FD_UNLIKELY( memcmp( loader_state.inner.buffer.authority_address, authority_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Incorrect buffer authority provided" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
        FD_LOG_WARNING(( "Buffer authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
    } else {
      FD_LOG_WARNING(( "Invalid Buffer account" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    ulong program_data_offset = fd_ulong_sat_add( BUFFER_METADATA_SIZE, instruction.inner.write.offset );
    err = write_program_data( buffer, 
                              program_data_offset, 
                              instruction.inner.write.bytes,
                              instruction.inner.write.bytes_len );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L526-L702 */
  } else if( fd_bpf_upgradeable_loader_program_instruction_is_deploy_with_max_data_len( &instruction ) ) {
    FD_LOG_WARNING(("IS DEPLOY IS DEPLOY"));
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L527-L541 */
    if( instr_ctx->instr->acct_cnt<4U ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_pubkey_t const * payer_key       = &txn_accs[ instr_acc_idxs[ 0UL ] ];
    fd_pubkey_t const * programdata_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];
    /* rent is accessed directly from the epoch bank and the clock from the
       slot context. However, a check must be done to make sure that the 
       sysvars are correctly included in the set of transaction accounts. */
    err = fd_check_sysvar_account( instr_ctx, 4UL, &fd_sysvar_rent_id ); 
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    err = fd_check_sysvar_account( instr_ctx, 5UL, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    fd_sol_sysvar_clock_t clock = {0};
    if( FD_UNLIKELY( !fd_sysvar_clock_read( &clock, instr_ctx->slot_ctx ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<8U ) ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 7UL ] ];

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L542-L560 */
    /* Verify Program account */

    fd_borrowed_account_t * program = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 2UL, 0UL, &program );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for program account failed" ));
      return err;
    }

    fd_bpf_upgradeable_loader_state_t loader_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, program, &loader_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf state read for program account failed" ));
      return err;
    }
    if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) ) {
      FD_LOG_WARNING(( "Program account is already initialized" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }
    if( FD_UNLIKELY( program->const_meta->dlen<SIZE_OF_PROGRAM ) ) {
      FD_LOG_WARNING(( "Program account too small" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL; 
    }
    if( FD_UNLIKELY( program->const_meta->info.lamports<fd_rent_exempt_minimum_balance( instr_ctx->slot_ctx,
                                                                                        program->const_meta->dlen ) ) ) {
      FD_LOG_WARNING(( "Program account not rent-exempt" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT;
    }
    fd_pubkey_t * new_program_id = program->pubkey;

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L561-L600 */
    /* Verify Buffer account */

    fd_borrowed_account_t * buffer = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 3UL, 0UL, &buffer );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for buffer account failed" ));
      return err;
    }

    fd_bpf_upgradeable_loader_state_t buffer_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, buffer, &buffer_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bincode decode failed for buffer account loader state" ));
      return err;
    }

    if( fd_bpf_upgradeable_loader_state_is_buffer( &buffer_state ) ) {
      if( FD_UNLIKELY( memcmp( buffer_state.inner.buffer.authority_address, authority_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Buffer and upgrade authority don't match" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 7UL ) ) ) {
        FD_LOG_WARNING(( "Upgrade authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
    } else {
      FD_LOG_WARNING(( "Invalid Buffer account" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_pubkey_t * buffer_key      = buffer->pubkey;
    ulong buffer_data_offset      = BUFFER_METADATA_SIZE;
    ulong buffer_data_len         = fd_ulong_sat_sub( buffer->const_meta->dlen, buffer_data_offset );
    /* UpgradeableLoaderState::size_of_program_data( max_data_len ) */
    ulong programdata_len         = fd_ulong_sat_add( PROGRAMDATA_METADATA_SIZE, 
                                                      instruction.inner.deploy_with_max_data_len.max_data_len ); 
    if( FD_UNLIKELY( buffer->const_meta->dlen<BUFFER_METADATA_SIZE || buffer->const_meta->dlen==0UL ) ) {
      FD_LOG_WARNING(( "Buffer account too small" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    if( FD_UNLIKELY( instruction.inner.deploy_with_max_data_len.max_data_len<buffer_data_len ) ) {
      FD_LOG_WARNING(( "Max data length is too small to hold Buffer data" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    if( FD_UNLIKELY( programdata_len>MAX_PERMITTED_DATA_LENGTH ) ) {
      FD_LOG_WARNING(( "Max data length is too large" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L602-L608 */
    /* Create ProgramData account */
    fd_pubkey_t derived_address[ 1UL ];
    uchar * seeds[ 1UL ];
    seeds[ 0UL ] = (uchar *)new_program_id;
    uchar bump_seed = 0;
    err = fd_pubkey_try_find_program_address( program_id, 1UL, seeds, derived_address, &bump_seed );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Failed to derive program address" ));
      return err;
    }
    if( FD_UNLIKELY( memcmp( derived_address, programdata_key, sizeof(fd_pubkey_t) ) ) ) {
      FD_LOG_WARNING(( "ProgramData address is not derived" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L610-L627 */
    /* Drain the Buffer account to payer before paying for programdata account */
    fd_borrowed_account_t * payer = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &payer );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for payer account failed" ));
      return err;
    }

    ulong payer_lamports = 0UL;
    err = fd_ulong_checked_add( payer->meta->info.lamports, buffer->meta->info.lamports, &payer_lamports );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Checked add on payer and buffer balances failed" ));
      return err;
    }
    payer->meta->info.lamports  = payer_lamports;
    buffer->meta->info.lamports = 0UL;

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L628-L642 */
    /* Pass an extra account to avoid the overly strict unblanaced instruction error */
    /* Invoke the system program to create the new account */
    fd_system_program_instruction_create_account_t create_acct;
    create_acct.lamports = fd_rent_exempt_minimum_balance( instr_ctx->slot_ctx, programdata_len );
    if( !create_acct.lamports ) {
      create_acct.lamports = 1UL;
    }
    create_acct.space    = programdata_len;
    create_acct.owner    = instr_ctx->instr->program_id_pubkey;

    fd_system_program_instruction_t instr = {0};
    instr.discriminant         = fd_system_program_instruction_enum_create_account;
    instr.inner.create_account = create_acct;

    fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t*) 
                                              fd_scratch_alloc( FD_VM_RUST_ACCOUNT_META_ALIGN, 
                                                                3UL * sizeof(fd_vm_rust_account_meta_t) );
    fd_native_cpi_create_account_meta( payer_key,       1U, 1U, &acct_metas[ 0UL ] ); 
    fd_native_cpi_create_account_meta( programdata_key, 1U, 1U, &acct_metas[ 1UL ] );
    fd_native_cpi_create_account_meta( buffer_key,      0U, 1U, &acct_metas[ 2UL ] );

    /* caller_program_id == program_id */
    fd_pubkey_t signers[ 1UL ];
    err = fd_pubkey_derive_pda( program_id, 1UL, seeds, &bump_seed, signers );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    err = fd_native_cpi_execute_system_program_instruction( instr_ctx, &instr, acct_metas, 3UL, signers, 1UL );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L644-L665 */
    /* Load and verify the program bits */
    if( FD_UNLIKELY( buffer_data_offset>=buffer->meta->dlen ) ) {
      FD_LOG_WARNING(( "Buffer data offset is out of bounds" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    uchar * programdata_data = buffer->data + buffer_data_offset;
    ulong   programdata_size = fd_ulong_sat_add( SIZE_OF_PROGRAM, programdata_len );

    err = deploy_program( instr_ctx, programdata_data, programdata_size );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Failed to deploy program" ));
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L667-L691 */
    /* Update the ProgramData account and record the program bits */
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L669-L674 */
    fd_borrowed_account_t * programdata = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 1UL, programdata_len, &programdata );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for programdata account failed" ));
      return err;
    }

    fd_bpf_upgradeable_loader_state_t programdata_loader_state = {
      .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
      .inner.program_data = {
        .slot                      = clock.slot,
        .upgrade_authority_address = (fd_pubkey_t *)authority_key,
      },
    };
    err = fd_bpf_loader_v3_program_write_state( instr_ctx, programdata, &programdata_loader_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf state write for programdata account failed" ));
      return err;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L675-L689 */
    if( FD_UNLIKELY( PROGRAMDATA_METADATA_SIZE+buffer_data_len>=programdata->meta->dlen ) ) {
      FD_LOG_WARNING(( "ProgramData account too small" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    if( FD_UNLIKELY( buffer_data_offset>=buffer->meta->dlen ) ) {
      FD_LOG_WARNING(( "Buffer account too small" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    uchar * dst_slice       = programdata->data + PROGRAMDATA_METADATA_SIZE;
    ulong dst_slice_len     = buffer_data_len; 
    const uchar * src_slice = buffer->const_data + buffer_data_offset;
    fd_memcpy( dst_slice, src_slice, dst_slice_len );

    /* Update the programdata's metadata */
    programdata->meta->dlen            = programdata_len;
    programdata->meta->info.executable = 0U;
    programdata->meta->info.lamports   = fd_rent_exempt_minimum_balance( instr_ctx->slot_ctx, programdata_len );
    programdata->meta->info.rent_epoch = 0UL;
    programdata->meta->slot            = clock.slot;
    fd_memcpy( &programdata->meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) );
    buffer->meta->dlen = BUFFER_METADATA_SIZE;

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L692-L699 */
    /* Update the Program account */
    loader_state.discriminant = fd_bpf_upgradeable_loader_state_enum_program;
    fd_memcpy( &loader_state.inner.program.programdata_address, programdata_key, sizeof(fd_pubkey_t) );
    err = fd_bpf_loader_v3_program_write_state( instr_ctx, program, &loader_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bincode encode for program account failed" ));
      return err;
    }
    err = fd_account_set_executable2( instr_ctx, program->pubkey, program->meta, 1 );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Couldn't set account to executable" ));
      return err;
    }
  } else if( fd_bpf_upgradeable_loader_program_instruction_is_upgrade( &instruction ) ) {
    FD_LOG_NOTICE(("init upgrade"));
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L704-L714 */
    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<3U ) ) {
      FD_LOG_WARNING(( "Not enough account keys for instruction" ));
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_pubkey_t const * programdata_key = &txn_accs[ instr_acc_idxs[ 0UL ] ];

    /* rent is accessed directly from the epoch bank and the clock from the
       slot context. However, a check must be done to make sure that the 
       sysvars are correctly included in the set of transaction accounts. */
    err = fd_check_sysvar_account( instr_ctx, 4UL, &fd_sysvar_rent_id ); 
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    err = fd_check_sysvar_account( instr_ctx, 5UL, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<7U ) ) {
      FD_LOG_WARNING(( "Not enough account keys for instruction" ));
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 6UL ] ];

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L716-L745 */
    /* Verify Program account */

    fd_borrowed_account_t * program = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 1UL, 0UL, &program );
    if( FD_UNLIKELY( !program->meta->info.executable ) ) {
      FD_LOG_WARNING(( "Program account not executable" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE;
    }
    if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, program->pubkey ) ) ) {
      FD_LOG_WARNING(( "Program account not writeable" ));
    }
    if( FD_UNLIKELY( memcmp( &program->meta->info.owner, program_id, sizeof(fd_pubkey_t) ) ) ) {
      FD_LOG_WARNING(( "Program account not owned by loader" ));
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }
    fd_bpf_upgradeable_loader_state_t program_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, program, &program_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bincode decode for program account failed" ));
      return err;
    }
    if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_is_program( &program_state ) ) ) {
      if( FD_UNLIKELY( memcmp( &program_state.inner.program.programdata_address, programdata_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Program and ProgramData account mismatch" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
    } else {
      FD_LOG_WARNING(( "Invalid Program account" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L747-L773 */
    /* Verify Buffer account */

    fd_borrowed_account_t * buffer = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 2UL, 0UL, &buffer );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for buffer account failed" ));
      return err;
    }
    fd_bpf_upgradeable_loader_state_t buffer_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, buffer, &buffer_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bincode decode for buffer account failed" ));
      return err;
    }
    if( fd_bpf_upgradeable_loader_state_is_buffer( &buffer_state ) ) {
      if( FD_UNLIKELY( memcmp( buffer_state.inner.buffer.authority_address, authority_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Buffer and upgrade authority don't match" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 6UL ) ) ) {
        FD_LOG_WARNING(( "Upgrade authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
    } else {
      FD_LOG_WARNING(( "Invalid Buffer account" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    ulong buffer_lamports    = buffer->meta->info.lamports;
    ulong buffer_data_offset = BUFFER_METADATA_SIZE;
    ulong buffer_data_len    = fd_ulong_sat_sub( buffer->meta->dlen, buffer_data_offset );
    if( FD_UNLIKELY( buffer->meta->dlen<BUFFER_METADATA_SIZE || buffer->meta->dlen==0UL ) ) {
      FD_LOG_WARNING(( "Buffer account too small" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L775-L823 */
    /* Verify ProgramData account */
    fd_borrowed_account_t * programdata = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &programdata );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for programdata account failed" ));
      return err;
    }
    ulong programdata_data_offset      = PROGRAMDATA_METADATA_SIZE;
    ulong programdata_balance_required = fd_rent_exempt_minimum_balance( instr_ctx->slot_ctx, 
                                                                         programdata->const_meta->dlen );
    if( programdata_balance_required==0UL ) {
      programdata_balance_required = 1UL;
    }
    if( FD_UNLIKELY( programdata->meta->dlen < fd_ulong_sat_add( PROGRAMDATA_METADATA_SIZE, buffer_data_len ) ) ) {
      FD_LOG_WARNING(( "ProgramData account not large enough" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    if( FD_UNLIKELY( fd_ulong_sat_add( programdata->meta->info.lamports, buffer_lamports )<programdata_balance_required ) ) {
      FD_LOG_WARNING(( "Buffer account balance too low to fund upgrade" ));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
    fd_bpf_upgradeable_loader_state_t programdata_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, programdata, &programdata_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bincode decode for programdata account failed" ));
      return err;
    }

    fd_sol_sysvar_clock_t clock = {0};
    if( FD_UNLIKELY( !fd_sysvar_clock_read( &clock, instr_ctx->slot_ctx ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    if( fd_bpf_upgradeable_loader_state_is_program_data( &programdata_state ) ) {
      if( FD_UNLIKELY( clock.slot==programdata_state.inner.program_data.slot ) ) {
        FD_LOG_WARNING(( "Program was deployed in this block already" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      if( FD_UNLIKELY( !programdata_state.inner.program_data.upgrade_authority_address ) ) {
        FD_LOG_WARNING(( "Prrogram not upgradeable" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }
      if( FD_UNLIKELY( memcmp( programdata_state.inner.program_data.upgrade_authority_address, authority_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Incorrect upgrade authority provided" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 6UL ) ) ) {
        FD_LOG_WARNING(( "Upgrade authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
    } else {
      FD_LOG_WARNING(( "Invalid ProgramData account" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    ulong programdata_len = programdata->meta->dlen;

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L825-L845 */
    /* Load and verify the program bits */
    ulong programdata_size = fd_ulong_sat_add( SIZE_OF_PROGRAM, programdata_len );
    if( FD_UNLIKELY( buffer_data_offset>=buffer->meta->dlen ) ) {
      FD_LOG_WARNING(( "Buffer data offset is out of bounds" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    err = deploy_program( instr_ctx, buffer->data+buffer_data_offset, programdata_size );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Failed to deploy program" ));
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L846-L874 */
    /* Update the ProgramData account, record the upgraded data, and zero the rest */
    programdata_state.discriminant                                 = fd_bpf_upgradeable_loader_state_enum_program_data;
    programdata_state.inner.program_data.slot                      = clock.slot;
    programdata_state.inner.program_data.upgrade_authority_address = (fd_pubkey_t *)authority_key;
    err = fd_bpf_loader_v3_program_write_state( instr_ctx, programdata, &programdata_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf state write for programdata account failed" ));
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L846-L875 */
    /* We want to copy over the data and zero out the rest */
    if( FD_UNLIKELY( programdata_data_offset+buffer_data_len >= programdata->meta->dlen ) ) { 
      FD_LOG_WARNING(( "ProgramData account too small" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    if( FD_UNLIKELY( buffer_data_offset>=buffer->meta->dlen ) ){
      FD_LOG_WARNING(( "Buffer account too small" ));
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    uchar * dst_slice     = programdata->data + programdata_data_offset;
    ulong   dst_slice_len = buffer_data_len; 
    uchar * src_slice     = buffer->data + buffer_data_offset;
    fd_memcpy( dst_slice, src_slice, dst_slice_len );
    fd_memset( dst_slice + dst_slice_len, 0, programdata->meta->dlen - programdata_data_offset - dst_slice_len );

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L876-L891 */
    /* Fund ProgramData to rent-exemption, spill the rest */
    fd_borrowed_account_t * spill = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 3UL, 0UL, &spill );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for spill account failed" ));
      return err;
    }
    ulong spill_addend = fd_ulong_sat_sub( fd_ulong_sat_add( programdata->meta->info.lamports, buffer_lamports ), 
                                           programdata_balance_required );
    ulong result = 0UL;
    err = fd_ulong_checked_add( spill->meta->info.lamports, spill_addend, &result );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Failed checked add to update spill account balance" ));
      return err;
    }
    spill->meta->info.lamports       = result;
    buffer->meta->info.lamports      = 0UL;
    programdata->meta->info.lamports = programdata_balance_required;
    buffer->meta->dlen               = PROGRAMDATA_METADATA_SIZE; /* UpgradeableLoaderState::size_of_buffer(0) */
  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L893-L957 */
  } else if( fd_bpf_upgradeable_loader_program_instruction_is_set_authority( &instruction ) ) {
    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<2U ) ) {
      FD_LOG_WARNING(( "Not enough account keys for instruction" ));
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_borrowed_account_t * account = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for account failed" ));
      return err;
    }
    fd_pubkey_t const * present_authority_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];
    fd_pubkey_t * new_authority               = NULL;
    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt>=3UL ) ) {
      new_authority = (fd_pubkey_t *)&txn_accs[ instr_acc_idxs[ 2UL ] ];
    } 

    fd_bpf_upgradeable_loader_state_t account_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, account, &account_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bincode decode for account failed" ));
      return err;
    }

    if( fd_bpf_upgradeable_loader_state_is_buffer( &account_state ) ) {
      if( FD_UNLIKELY( !new_authority ) ) {
        FD_LOG_WARNING(( "Buffer authority is not optional" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !account_state.inner.buffer.authority_address ) ) {
        FD_LOG_WARNING(( "Buffer is immutable" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }
      if( FD_UNLIKELY( memcmp( account_state.inner.buffer.authority_address, present_authority_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Incorrect buffer authority provided" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
        FD_LOG_WARNING(( "Buffer authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      account_state.inner.buffer.authority_address = new_authority;
      err = fd_bpf_loader_v3_program_write_state( instr_ctx, account, &account_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state write for account failed" ));
        return err;
      }
    } else if( fd_bpf_upgradeable_loader_state_is_program_data( &account_state ) ) {
      if( FD_UNLIKELY( !account_state.inner.program_data.upgrade_authority_address ) ) {
        FD_LOG_WARNING(( "Program not upgradeable" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }
      if( FD_UNLIKELY( memcmp( account_state.inner.program_data.upgrade_authority_address, present_authority_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Incorrect program authority provided" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
        FD_LOG_WARNING(( "Program authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      account_state.inner.program_data.upgrade_authority_address = new_authority;
      err = fd_bpf_loader_v3_program_write_state( instr_ctx, account, &account_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bincode encode for program data account failed" ));
        return err;
      }
    } else {
      FD_LOG_WARNING(( "Account does not support authorities" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L958-L1030 */
  } else if( fd_bpf_upgradeable_loader_program_instruction_is_set_authority_checked( &instruction ) ) {
    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<3U ) ) {
      FD_LOG_WARNING(( "Not enough account keys for instruction" ));
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_borrowed_account_t * account = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for account failed" ));
      return err;
    }
    fd_pubkey_t const * present_authority_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];
    fd_pubkey_t const * new_authority_key     = &txn_accs[ instr_acc_idxs[ 2UL ] ];

    fd_bpf_upgradeable_loader_state_t account_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, account, &account_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bincode decode for account failed" ));
      return err;
    }

    if( fd_bpf_upgradeable_loader_state_is_buffer( &account_state ) ) {
      if( FD_UNLIKELY( !account_state.inner.buffer.authority_address ) ) {
        FD_LOG_WARNING(( "Buffer is immutable" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }
      if( FD_UNLIKELY( memcmp( account_state.inner.buffer.authority_address, present_authority_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Incorrect buffer authority provided" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
        FD_LOG_WARNING(( "Buffer authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 2UL ) ) ) {
        FD_LOG_WARNING(( "New authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      account_state.inner.buffer.authority_address = (fd_pubkey_t*)new_authority_key;
      err = fd_bpf_loader_v3_program_write_state( instr_ctx, account, &account_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bincode encode for buffer account failed" ));
        return err;
      }
    } else if( fd_bpf_upgradeable_loader_state_is_program_data( &account_state ) ) {
      if( FD_UNLIKELY( !account_state.inner.program_data.upgrade_authority_address ) ) {
        FD_LOG_WARNING(( "Program not upgradeable" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }
      if( FD_UNLIKELY( memcmp( account_state.inner.program_data.upgrade_authority_address, present_authority_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Incorrect program authority provided" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
        FD_LOG_WARNING(( "Program authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 2UL ) ) ) {
        FD_LOG_WARNING(( "New authority did not sign" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      account_state.inner.program_data.upgrade_authority_address = (fd_pubkey_t*)new_authority_key;
      err = fd_bpf_loader_v3_program_write_state( instr_ctx, account, &account_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state wr encode for program data account failed" ));
        return err;
      }
    } else {
      FD_LOG_WARNING(( "Account does not support authorities" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1031-L1134 */
  } else if( fd_bpf_upgradeable_loader_program_instruction_is_close( &instruction ) ) {
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1032-L1046 */
    if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<2U ) ) {
      FD_LOG_WARNING(( "Not enough account keys for instruction" ));
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    if( FD_UNLIKELY( instr_acc_idxs[ 0UL ]==instr_acc_idxs[ 1UL ] ) ) {
      FD_LOG_WARNING(( "Recipient is the same as the account being closed" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_borrowed_account_t * close_account = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &close_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for close account failed" ));
      return err;
    }
    fd_pubkey_t * close_key = close_account->pubkey;
    fd_bpf_upgradeable_loader_state_t close_account_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, close_account, &close_account_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf state read for close account failed" ));
      return err;
    }
    close_account->meta->dlen = SIZE_OF_UNINITIALIZED;
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1049-L1056 */
    if( !fd_bpf_upgradeable_loader_state_is_uninitialized( &close_account_state ) ) {
      fd_borrowed_account_t * recipient_account = NULL;
      err = fd_instr_borrowed_account_modify_idx( instr_ctx, 1UL, 0UL, &recipient_account );
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "Borrowed account lookup for recipient account failed" ));
        return err;
      }
      ulong result = 0UL;
      err = fd_ulong_checked_add( recipient_account->meta->info.lamports,
                                  close_account->meta->info.lamports,
                                  &result );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "Checked add on recipient and close account balances failed" ));
        return err;
      }
      recipient_account->meta->info.lamports = result;
      close_account->meta->info.lamports     = 0UL;

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1057-L1068 */
    } else if( fd_bpf_upgradeable_loader_state_is_buffer( &close_account_state ) ) {
      if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<3U ) ) {
        FD_LOG_WARNING(( "Not enough account keys for instruction" ));
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
      err = common_close_account( close_account_state.inner.buffer.authority_address, instr_ctx, &close_account_state );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1069-L1129 */
    } else if( fd_bpf_upgradeable_loader_state_is_program_data( &close_account_state ) ) {
      if( FD_UNLIKELY( instr_ctx->instr->acct_cnt<4U ) ) {
        FD_LOG_WARNING(( "Not enough account keys for instruction" ));
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
      fd_borrowed_account_t * program_account = NULL;
      err = fd_instr_borrowed_account_modify_idx( instr_ctx, 3UL, 0UL, &program_account );
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "Borrowed account lookup for program account failed" ));
        return err;
      }
      fd_pubkey_t * program_key = program_account->pubkey;

      if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, program_key ) ) ) {
        FD_LOG_WARNING(( "Program account is not writable" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      if( FD_UNLIKELY( memcmp( program_account->const_meta->info.owner, program_id, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Program account not owned by loader" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
      }
      fd_sol_sysvar_clock_t clock = {0};
      if( FD_UNLIKELY( !fd_sysvar_clock_read( &clock, instr_ctx->slot_ctx ) ) ) {
        FD_LOG_WARNING(( "Unable to read clock sysvar" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }
      if( FD_UNLIKELY( clock.slot==close_account_state.inner.program_data.slot ) ) {
        FD_LOG_WARNING(( "Program was deployed in this block already" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      } 

      fd_bpf_upgradeable_loader_state_t program_state = {0};
      err = fd_bpf_loader_v3_program_read_state( instr_ctx, program_account, &program_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state read for program account failed" ));
        return err;
      }
      if( fd_bpf_upgradeable_loader_state_is_program( &program_state ) ) {
        if( FD_UNLIKELY( memcmp( &program_state.inner.program.programdata_address, close_key, sizeof(fd_pubkey_t) ) ) ) {
          FD_LOG_WARNING(( "Program account does not match ProgramData account" ));
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }
        err = common_close_account( close_account_state.inner.program_data.upgrade_authority_address, 
                                    instr_ctx, 
                                    &close_account_state );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }

        /* The Agave client updates the account state upon closing an account
           in their loaded prograam cache. Checking for a program can be
           checked by checking to see if the programdata account's loader state 
           is unitialized. */
      } else {
        FD_LOG_WARNING(( "Invalid program account" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
    } else {
      FD_LOG_WARNING(( "Account does not support closing" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG; 
    }
  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1136-L1294 */
  } else if( fd_bpf_upgradeable_loader_program_instruction_is_extend_program( &instruction ) ) {
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1137-L1172 */
    uint additional_bytes = instruction.inner.extend_program.additional_bytes;
    if( FD_UNLIKELY( additional_bytes==0U ) ) {
      FD_LOG_WARNING(( "Additional bytes must be greater than 0" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_borrowed_account_t * programdata_account = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, 0UL, &programdata_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for programdata account failed" ));
      return err;
    }
    fd_pubkey_t * programdata_key = programdata_account->pubkey;

    if( FD_UNLIKELY( memcmp( program_id, programdata_account->const_meta->info.owner, sizeof(fd_pubkey_t) ) ) ) {
      FD_LOG_WARNING(( "ProgramData owner is invalid" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }
    if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, programdata_key ) ) ) {
      FD_LOG_WARNING(( "ProgramData is not writable" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_borrowed_account_t * program_account = NULL;
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 1UL, 0UL, &program_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for program account failed" ));
      return err;
    }
    if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, program_account->pubkey ) ) ) {
      FD_LOG_WARNING(( "Program account is not writable" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    if( FD_UNLIKELY( memcmp( program_id, program_account->const_meta->info.owner, sizeof(fd_pubkey_t) ) ) ) {
      FD_LOG_WARNING(( "Program account not owned by loader" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }
    
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1172-L1190 */    
    fd_bpf_upgradeable_loader_state_t program_state = {0};
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, program_account, &program_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf state read for program account failed" ));
      return err;
    }
    if( fd_bpf_upgradeable_loader_state_is_program( &program_state ) ) {
      if( FD_UNLIKELY( memcmp( &program_state.inner.program.programdata_address, programdata_key, sizeof(fd_pubkey_t) ) ) ) {
        FD_LOG_WARNING(( "Program account does not match ProgramData account" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
    } else {
      FD_LOG_WARNING(( "Invalid program account" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1191-L1230 */
    ulong old_len = programdata_account->const_meta->dlen;
    ulong new_len = fd_ulong_sat_add( old_len, additional_bytes );
    if( FD_UNLIKELY( new_len>MAX_PERMITTED_DATA_LENGTH ) ) {
      FD_LOG_WARNING(( "Extended ProgramData length of %lu bytes exceeds max account data length of %lu bytes",
                       new_len, MAX_PERMITTED_DATA_LENGTH ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
    }

    fd_sol_sysvar_clock_t clock = {0};
    if( FD_UNLIKELY( !fd_sysvar_clock_read( &clock, instr_ctx->slot_ctx ) ) ) {
      FD_LOG_WARNING(( "Unable to read the slot sysvar" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    fd_bpf_upgradeable_loader_state_t programdata_state = {0};
    fd_pubkey_t * upgrade_authority_address = NULL;
    err = fd_bpf_loader_v3_program_read_state( instr_ctx, programdata_account, &programdata_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf state read for programdata account failed" ));
      return err;
    }
    if( fd_bpf_upgradeable_loader_state_is_program_data( &programdata_state ) ) {
      if( FD_UNLIKELY( clock.slot==programdata_state.inner.program_data.slot ) ) {
        FD_LOG_WARNING(( "Program was extended in this block already" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if( FD_UNLIKELY( !programdata_state.inner.program_data.upgrade_authority_address ) ) {
        FD_LOG_WARNING(( "Cannot extend ProgramData accounts that are not upgradeable" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }
      upgrade_authority_address = programdata_state.inner.program_data.upgrade_authority_address;
    } else {
      FD_LOG_WARNING(( "ProgramData state is invalid" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1232-L1256 */
    ulong balance          = programdata_account->const_meta->info.lamports;
    ulong min_balance      = fd_rent_exempt_minimum_balance( instr_ctx->slot_ctx, new_len );
    min_balance            = fd_ulong_if( min_balance>0UL, min_balance, 1UL );
    ulong required_payment = fd_ulong_sat_sub( min_balance, balance );

    if( FD_UNLIKELY( required_payment>0UL ) ) {
      fd_pubkey_t const * payer_key = &txn_accs[ instr_acc_idxs[ 3UL ] ];
      
      fd_system_program_instruction_t instr = {
        .discriminant   = fd_system_program_instruction_enum_transfer,
        .inner.transfer = required_payment
      };

      fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t *)fd_scratch_alloc( 
                                                                              FD_VM_RUST_ACCOUNT_META_ALIGN, 
                                                                              2UL * sizeof(fd_vm_rust_account_meta_t) );
      fd_native_cpi_create_account_meta( payer_key,       1UL, 1UL, &acct_metas[ 0UL ] );
      fd_native_cpi_create_account_meta( programdata_key, 0UL, 1UL, &acct_metas[ 1UL ] );

      err = fd_native_cpi_execute_system_program_instruction( instr_ctx, &instr, acct_metas, 2UL, NULL, 0UL );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1258-L1293 */
    err = fd_instr_borrowed_account_modify_idx( instr_ctx, 0UL, new_len, &programdata_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for programdata account failed" ));
      return err;
    }

    err = 0;
    if( FD_UNLIKELY( !fd_account_set_data_length2( instr_ctx, programdata_account->meta, programdata_account->pubkey, new_len, 0, &err ) ) ) {
      return err;
    }

    if( FD_UNLIKELY( PROGRAMDATA_METADATA_SIZE>programdata_account->meta->dlen ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    err = deploy_program( instr_ctx, programdata_account->data + PROGRAMDATA_METADATA_SIZE, fd_ulong_sat_add( SIZE_OF_PROGRAM, new_len ) );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Failed to deploy program" ));
      return err;
    }

    /* Setting the discriminant and upgrade authority address here should 
       be a no-op because these values shouldn't change. These can probably be
       removed, but can help to mirror against Agave client's implementation. */
    programdata_state.discriminant                                 = fd_bpf_upgradeable_loader_state_enum_program_data;
    programdata_state.inner.program_data.slot                      = clock.slot;
    programdata_state.inner.program_data.upgrade_authority_address = upgrade_authority_address;
    
    err = fd_bpf_loader_v3_program_write_state( instr_ctx, programdata_account, &programdata_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bincode encode for programdata account failed" ));
      return err;
    }
  } else {
    FD_LOG_WARNING(( "ProgramData state is invalid" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* process_instruction_inner() */
/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L394-L564 */
int 
fd_bpf_loader_v3_program_execute( fd_exec_instr_ctx_t ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    /* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L491-L529 */
    fd_borrowed_account_t * program_account = NULL;

    /* TODO: Agave uses `get_last_program_key`, we should have equivalent semantics:
       https://github.com//anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L491-L492 */
    fd_pubkey_t const *     program_id      = &ctx.instr->program_id_pubkey;
    int err = fd_txn_borrowed_account_view_idx( ctx.txn_ctx, ctx.instr->program_id, &program_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup failed for program account" ));
      return err;
    }

    /* Program management insturction */
    if( !memcmp( &fd_solana_native_loader_id, program_account->const_meta->info.owner, sizeof(fd_pubkey_t) ) ) {
      if( !memcmp( &fd_solana_bpf_loader_upgradeable_program_id, program_id, sizeof(fd_pubkey_t) ) ) {
        if( FD_UNLIKELY( UPGRADEABLE_LOADER_COMPUTE_UNITS>ctx.txn_ctx->compute_meter ) ) {
          FD_LOG_WARNING(( "Insufficient compute units for upgradeable loader" ));
          return FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED;
        }
        ctx.txn_ctx->compute_meter = fd_ulong_sat_sub( ctx.txn_ctx->compute_meter, UPGRADEABLE_LOADER_COMPUTE_UNITS );
        return process_loader_upgradeable_instruction( &ctx );
      } else if( !memcmp( &fd_solana_bpf_loader_program_id, program_id, sizeof(fd_pubkey_t) ) ) {
        if( FD_UNLIKELY( DEFAULT_LOADER_COMPUTE_UNITS>ctx.txn_ctx->compute_meter ) ) {
          FD_LOG_WARNING(( "Insufficient compute units for upgradeable loader" ));
          return FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED;
        }
        ctx.txn_ctx->compute_meter = fd_ulong_sat_sub( ctx.txn_ctx->compute_meter, DEFAULT_LOADER_COMPUTE_UNITS );
        FD_LOG_WARNING(( "BPF loader management instructions are no longer supported" ));
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      } else if( !memcmp( &fd_solana_bpf_loader_deprecated_program_id, program_id, sizeof(fd_pubkey_t) ) ) {
        if( FD_UNLIKELY( DEPRECATED_LOADER_COMPUTE_UNITS>ctx.txn_ctx->compute_meter ) ) {
          FD_LOG_WARNING(( "Insufficient compute units for upgradeable loader" ));
          return FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED;
        }
        ctx.txn_ctx->compute_meter = fd_ulong_sat_sub( ctx.txn_ctx->compute_meter, DEPRECATED_LOADER_COMPUTE_UNITS );
        FD_LOG_WARNING(( "Deprecated loader is no longer supported" ));
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      } else {
        FD_LOG_WARNING(( "Invalid BPF loader id" ));
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L532-L549 */
    /* Program invocation */
    if( FD_UNLIKELY( !program_account->const_meta->info.executable ) ) {
      FD_LOG_WARNING(( "Program is not executable" ));
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    fd_sbpf_validated_program_t * prog = NULL;
    if( FD_UNLIKELY( fd_bpf_load_cache_entry( ctx.slot_ctx, &ctx.instr->program_id_pubkey, &prog ) ) ) {
      FD_LOG_WARNING(( "Program cache load for program failed" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L551-L563 */
    /* The Agave client stores a loaded program type state in its implementation 
      of the loaded program cache. It checks to see if an account is able to be
      executed. It is possible for a program to be in the DelayVisibility state or
      Closed state but it won't be reflected in the Firedancer cache. Program 
      accounts that are in this state should exit with an invalid account data 
      error. For programs that are recently deployed or upgraded, they should not
      be allowed to be executed for the remainder of the slot. For closed 
      accounts, they're uninitalized and shouldn't be executed as well.
      
      For the former case the slot that the 
      program was last updated in is in the program data account.
      This means that if the slot in the program data account is greater than or
      equal to the current execution slot, then the account is in a 
      'LoadedProgramType::DelayVisiblity' state.
      
      The latter case as described above is a tombstone account which is in a Closed
      state. This occurs when a program data account is closed. However, our cache
      does not track this. Instead, this can be checked for by seeing if the program
      account's respective program data account is uninitialized. This should only
      happen when the account is closed. */
    fd_bpf_upgradeable_loader_state_t program_account_state = {0};
    err = fd_bpf_loader_v3_program_read_state( &ctx, program_account, &program_account_state ); 
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf state read for program account failed" ));
      return err;
    }
    
    fd_borrowed_account_t * program_data_account = NULL;
    fd_pubkey_t * programdata_pubkey = (fd_pubkey_t *)&program_account_state.inner.program.programdata_address;
    err = fd_txn_borrowed_account_executable_view( ctx.txn_ctx, programdata_pubkey, &program_data_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup for program data account failed" ));
      return err;
    }
    
    fd_bpf_upgradeable_loader_state_t program_data_account_state = {0};
    err = fd_bpf_loader_v3_program_read_state( &ctx, program_data_account, &program_data_account_state );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bpf state read for program data account failed" ));
      return err;
    }

    if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_is_uninitialized( &program_data_account_state ) ) ) {
      /* The account is likely closed. */
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    ulong program_data_slot = program_data_account_state.inner.program_data.slot;
    if( FD_UNLIKELY( program_data_slot>=ctx.slot_ctx->slot_bank.slot ) ) {
      /* The account was likely just deployed or upgraded. Corresponds to
        'LoadedProgramType::DelayVisibility' */
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    return execute( &ctx, prog );
  } FD_SCRATCH_SCOPE_END;
}
