#include "fd_bpf_loader_v3_program.h"

/* For additional context see https://solana.com/docs/programs/deploying#state-accounts */

#include "../fd_pubkey_utils.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../../vm/fd_vm.h"
#include "fd_bpf_loader_serialization.h"
#include "fd_bpf_program_util.h"
#include "fd_native_cpi.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#include <stdlib.h>

static char * trace_buf;

static void __attribute__((constructor)) make_buf(void) {
  trace_buf = (char*)malloc(256*1024);
}

static void __attribute__((destructor)) free_buf(void) {
  free(trace_buf);
}

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
    .valloc  = fd_scratch_virtual(),
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
    .valloc  = fd_scratch_virtual(),
  };

  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode( result, &ctx ) ) ) {
    FD_LOG_WARNING(( "fd_bpf_upgradeable_loader_state_decode failed" ));
    *opt_err = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return NULL;
  }

  return rec->const_meta;
}

/* https://github.com/anza-xyz/agave/blob/9b22f28104ec5fd606e4bb39442a7600b38bb671/programs/bpf_loader/src/lib.rs#L216-L229 */
ulong
calculate_heap_cost( ulong heap_size, ulong heap_cost, int round_up_heap_size, int * err ) {
  #define KIBIBYTE_MUL_PAGES       (1024UL * 32UL)
  #define KIBIBYTE_MUL_PAGES_SUB_1 (KIBIBYTE_MUL_PAGES - 1UL)

  if( round_up_heap_size ) {
    heap_size = fd_ulong_sat_add( heap_size, KIBIBYTE_MUL_PAGES_SUB_1 );
  }

  if( FD_UNLIKELY( heap_size==0UL ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    return 0UL;
  }

  heap_size = fd_ulong_sat_mul( fd_ulong_sat_sub( heap_size / KIBIBYTE_MUL_PAGES, 1UL ), heap_cost );
  return heap_size;

  #undef KIBIBYTE_MUL_PAGES
  #undef KIBIBYTE_MUL_PAGES_SUB_1
}

/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L105-L171

   Our arguments to deploy_program are different from the Agave version because we handle the caching of deployed programs differently.
   In Firedancer we lack the concept of ProgramCacheEntryType entirely https://github.com/anza-xyz/agave/blob/114d94a25e9631f9bf6349c4b833d7900ef1fb1c/program-runtime/src/loaded_programs.rs#L158

   In Agave there is a separate caching structure that is used to store the deployed programs. In Firedancer the deployed, validated program
   is stored as metadata for the account in the funk record.

   See https://github.com/firedancer-io/firedancer/blob/9c1df680b3f38bebb0597e089766ec58f3b41e85/src/flamenco/runtime/program/fd_bpf_loader_v3_program.c#L1640
   for how we handle the concept of 'LoadedProgramType::DelayVisibility' in Firedancer.

   As a concrete example, our version of deploy_program does not have the 'account_size' argument because we do not update the funk record here. */
int
deploy_program( fd_exec_instr_ctx_t * instr_ctx,
                uchar * const         programdata,
                ulong                 programdata_size ) {
  bool deploy_mode = true;
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(),
                                                                          fd_sbpf_syscalls_footprint() ) );
  if( FD_UNLIKELY( !syscalls ) ) {
    FD_LOG_WARNING(( "Failed to register syscalls" ));
    return FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE;
  }
  fd_vm_syscall_register_all( syscalls, 1 );

  /* Load executable */
  fd_sbpf_elf_info_t  _elf_info[ 1UL ];
  fd_sbpf_elf_info_t * elf_info = fd_sbpf_elf_peek( _elf_info, programdata, programdata_size, deploy_mode );
  if( FD_UNLIKELY( !elf_info ) ) {
    FD_LOG_WARNING(( "Elf info failing" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate rodata segment */
  void * rodata = fd_scratch_alloc( FD_SBPF_PROG_RODATA_ALIGN, elf_info->rodata_footprint );
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
  if( FD_UNLIKELY( fd_sbpf_program_load( prog, programdata, programdata_size, syscalls, deploy_mode ) ) ) {
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
  }

  /* Validate the program */
  fd_vm_t _vm[ 1UL ];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );

  vm = fd_vm_init(
    /* vm        */ vm,
    /* instr_ctx */ instr_ctx,
    /* heap_max  */ instr_ctx->txn_ctx->heap_size,
    /* entry_cu  */ instr_ctx->txn_ctx->compute_meter,
    /* rodata    */ prog->rodata,
    /* rodata_sz */ prog->rodata_sz,
    /* text      */ prog->text,
    /* text_cnt  */ prog->text_cnt,
    /* text_off  */ prog->text_off, /* FIXME: What if text_off is not multiple of 8 */
    /* text_sz   */ prog->text_sz,
    /* entry_pc  */ prog->entry_pc,
    /* calldests */ prog->calldests,
    /* syscalls  */ syscalls,
    /* input     */ NULL,
    /* input_sz  */ 0,
    /* trace     */ NULL,
    /* sha       */ NULL);
  if ( FD_UNLIKELY( vm == NULL ) ) {
    FD_LOG_ERR(( "NULL vm" ));
  }

  int validate_result = fd_vm_validate( vm );
  if( FD_UNLIKELY( validate_result!=FD_VM_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L195-L218 */
int
write_program_data( fd_exec_instr_ctx_t *   instr_ctx,
                    ulong                   instr_acc_idx,
                    ulong                   program_data_offset,
                    uchar *                 bytes,
                    ulong                   bytes_len ) {
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, instr_acc_idx, program ) {

  ulong write_offset = fd_ulong_sat_add( program_data_offset, bytes_len );
  if( FD_UNLIKELY( program->meta->dlen<write_offset ) ) {
    FD_LOG_WARNING(( "Write overflow %lu < %lu", program->meta->dlen, write_offset ));
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  uchar * data = NULL;
  ulong   dlen = 0UL;
  int err = fd_account_get_data_mut( instr_ctx, instr_acc_idx, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  if( FD_UNLIKELY( program_data_offset>dlen ) ) {
    FD_LOG_WARNING(( "Write offset out of bounds" ));
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  if( FD_LIKELY( bytes_len ) ) {
    fd_memcpy( data+program_data_offset, bytes, bytes_len );
  }

  } FD_BORROWED_ACCOUNT_DROP( program );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* get_state() */
/* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/sdk/src/transaction_context.rs#L968-L972 */
int
fd_bpf_loader_v3_program_get_state( fd_exec_instr_ctx_t *               instr_ctx,
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
fd_bpf_loader_v3_program_set_state( fd_exec_instr_ctx_t *               instr_ctx,
                                    ulong                               instr_acc_idx,
                                    fd_bpf_upgradeable_loader_state_t * state ) {
  ulong state_size = fd_bpf_upgradeable_loader_state_size( state );

  uchar * data = NULL;
  ulong   dlen = 0UL;
  
  int err = fd_account_get_data_mut( instr_ctx, instr_acc_idx, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  if( FD_UNLIKELY( state_size>dlen ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  fd_bincode_encode_ctx_t ctx = {
    .data    = data,
    .dataend = data + state_size
  };

  err = fd_bpf_upgradeable_loader_state_encode( state, &ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

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

  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, close_account     ) {
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 1UL, recipient_account ) {

  int err = fd_account_checked_add_lamports( instr_ctx, 1UL, close_account->meta->info.lamports );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  err = fd_account_set_lamports( instr_ctx, 0UL, 0UL );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  state->discriminant = fd_bpf_upgradeable_loader_state_enum_uninitialized;
  err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, state );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "Bpf loader state write for close account failed" ));
    return err;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;

  } FD_BORROWED_ACCOUNT_DROP( recipient_account );
  } FD_BORROWED_ACCOUNT_DROP( close_account     );
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

  fd_vm_syscall_register_all( syscalls, 0 );

  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1362-L1368 */
  ulong input_sz = 0;
  ulong pre_lens[ 256UL ];
  uchar * input = fd_bpf_loader_input_serialize_aligned( *instr_ctx, &input_sz, pre_lens );
  if( FD_UNLIKELY( input==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );

  /* TODO: (topointon): correctly set check_align and check_size in vm setup */
  vm = fd_vm_init(
    /* vm        */ vm,
    /* instr_ctx */ instr_ctx,
    /* heap_max  */ instr_ctx->txn_ctx->heap_size, /* TODO configure heap allocator */
    /* entry_cu  */ instr_ctx->txn_ctx->compute_meter,
    /* rodata    */ fd_sbpf_validated_program_rodata( prog ),
    /* rodata_sz */ prog->rodata_sz,
    /* text      */ (ulong *)((ulong)fd_sbpf_validated_program_rodata( prog ) + (ulong)prog->text_off), /* Note: text_off is byte offset */
    /* text_cnt  */ prog->text_cnt,
    /* text_off  */ prog->text_off,
    /* text_sz   */ prog->text_sz,
    /* entry_pc  */ prog->entry_pc,
    /* calldests */ prog->calldests,
    /* syscalls  */ syscalls,
    /* input     */ input,
    /* input_sz  */ input_sz,
    /* trace     */ NULL,
    /* sha       */ sha);
  if ( FD_UNLIKELY( vm == NULL ) ) {
    FD_LOG_ERR(( "null vm" )); 
  }

#ifdef FD_DEBUG_SBPF_TRACES
  uchar * signature = (uchar*)vm->instr_ctx->txn_ctx->_txn_raw->raw + vm->instr_ctx->txn_ctx->txn_descriptor->signature_off;
  uchar sig[64];
  /* TODO (topointon): make this run-time configurable, no need for this ifdef */
  fd_base58_decode_64( "LKBxtETTpyVDbW1kT5fFucSpmdPoXfKW8QUxdzE8ggwCaXayByPbceQA6KwqGy2WNh89aAG3r2Qjm9VNY9FPtw9", sig );
  if( FD_UNLIKELY( !memcmp( signature, sig, 64UL ) ) ) {
    ulong event_max = 1UL<<30;
    ulong event_data_max = 2048UL;
    vm->trace = fd_vm_trace_join( fd_vm_trace_new( fd_valloc_malloc(
    instr_ctx->txn_ctx->valloc, fd_vm_trace_align(), fd_vm_trace_footprint( event_max, event_data_max ) ), event_max, event_data_max ) );
    if( FD_UNLIKELY( !vm->trace ) ) FD_LOG_ERR(( "unable to create trace" ));
  }
#endif

  /* https://github.com/anza-xyz/agave/blob/9b22f28104ec5fd606e4bb39442a7600b38bb671/programs/bpf_loader/src/lib.rs#L288-L298 */
  ulong heap_size = instr_ctx->txn_ctx->heap_size;
  ulong heap_cost = FD_VM_HEAP_COST;
  int round_up_heap_size = FD_FEATURE_ACTIVE( instr_ctx->slot_ctx, round_up_heap_size );
  int heap_err = 0;
  ulong heap_cost_result = calculate_heap_cost( heap_size, heap_cost, round_up_heap_size, &heap_err );
  if( FD_UNLIKELY( heap_err ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if( FD_UNLIKELY( heap_cost_result>vm->cu ) ) {
    return FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED;
  }
  vm->cu -= heap_cost_result;

  int exec_err = fd_vm_exec( vm );

  if( FD_UNLIKELY( vm->trace ) ) {
    int err = fd_vm_trace_printf( vm->trace, vm->syscalls );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_vm_trace_printf failed (%i-%s)", err, fd_vm_strerror( err ) ));
    }
    fd_valloc_free( instr_ctx->txn_ctx->valloc, fd_vm_trace_delete( fd_vm_trace_leave( vm->trace ) ) );
  }

  if( FD_UNLIKELY( exec_err!=FD_VM_SUCCESS ) ) {
    fd_valloc_free( instr_ctx->valloc, input );
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  /* TODO: Add log for "Program consumed {} of {} compute units "*/

  instr_ctx->txn_ctx->compute_meter = vm->cu;

  /* TODO: vm should report */
  if( FD_UNLIKELY( vm->reg[0] ) ) {
    //TODO: vm should report this error
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
  switch( instruction.discriminant ) {
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L476-L493 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_initialize_buffer: {
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, buffer ) {

      fd_bpf_upgradeable_loader_state_t buffer_state = {0};
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, buffer, &buffer_state );
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

      err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &buffer_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf loader state write for buffer account failed" ));
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( buffer );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L494-L525 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_write: {
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, buffer ) {

      fd_bpf_upgradeable_loader_state_t loader_state = {0};
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, buffer, &loader_state );
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

      } FD_BORROWED_ACCOUNT_DROP( buffer );

      ulong program_data_offset = fd_ulong_sat_add( BUFFER_METADATA_SIZE, instruction.inner.write.offset );
      err = write_program_data( instr_ctx,
                                0UL,
                                program_data_offset,
                                instruction.inner.write.bytes,
                                instruction.inner.write.bytes_len );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L526-L702 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_deploy_with_max_data_len: {
      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L527-L541 */
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 4U ) ) ) {
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
      if( fd_account_check_num_insn_accounts( instr_ctx, 8U ) ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
      fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 7UL ] ];

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L542-L560 */
      /* Verify Program account */

      fd_bpf_upgradeable_loader_state_t loader_state = {0};
      fd_pubkey_t * new_program_id = NULL;
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, program ) {

      err = fd_bpf_loader_v3_program_get_state( instr_ctx, program, &loader_state );
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
      new_program_id = program->pubkey;

      } FD_BORROWED_ACCOUNT_DROP( program );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L561-L600 */
      /* Verify Buffer account */

      fd_borrowed_account_t * buffer = NULL;
      err = fd_instr_borrowed_account_view_idx( instr_ctx, 3UL, &buffer );
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "Borrowed account lookup for buffer account failed" ));
        return err;
      }

      fd_pubkey_t * buffer_key = NULL;
      ulong buffer_data_offset = 0UL;
      ulong buffer_data_len    = 0UL;
      ulong programdata_len    = 0UL;
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, buffer ) {

      fd_bpf_upgradeable_loader_state_t buffer_state = {0};
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, buffer, &buffer_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bincode decode failed for buffer account loader state" ));
        return err;
      }

      if( fd_bpf_upgradeable_loader_state_is_buffer( &buffer_state ) ) {
        if( FD_UNLIKELY( (authority_key==NULL) != (buffer_state.inner.buffer.authority_address == NULL) ||
            (authority_key!=NULL && memcmp( buffer_state.inner.buffer.authority_address, authority_key, sizeof(fd_pubkey_t) ) ) ) ) {
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
      buffer_key         = buffer->pubkey;
      buffer_data_offset = BUFFER_METADATA_SIZE;
      buffer_data_len    = fd_ulong_sat_sub( buffer->const_meta->dlen, buffer_data_offset );
      /* UpgradeableLoaderState::size_of_program_data( max_data_len ) */
      programdata_len    = fd_ulong_sat_add( PROGRAMDATA_METADATA_SIZE,
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

      } FD_BORROWED_ACCOUNT_DROP( buffer );

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
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, payer  ) {
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, buffer ) {

      err = fd_account_checked_add_lamports( instr_ctx, 0UL, buffer->meta->info.lamports );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
      err = fd_account_set_lamports( instr_ctx, 3UL, 0UL );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( buffer );
      } FD_BORROWED_ACCOUNT_DROP( payer  );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L628-L642 */
      /* Pass an extra account to avoid the overly strict unblanaced instruction error */
      /* Invoke the system program to create the new account */
      fd_system_program_instruction_create_account_t create_acct;
      create_acct.lamports = fd_rent_exempt_minimum_balance( instr_ctx->slot_ctx, programdata_len );
      if( !create_acct.lamports ) {
        create_acct.lamports = 1UL;
      }
      create_acct.space = programdata_len;
      create_acct.owner = instr_ctx->instr->program_id_pubkey;

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
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, buffer ) {
      if( FD_UNLIKELY( buffer_data_offset>buffer->meta->dlen ) ) {
        FD_LOG_WARNING(( "Buffer data offset is out of bounds" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      uchar * buffer_data = buffer->data + buffer_data_offset;

      err = deploy_program( instr_ctx, buffer_data, buffer_data_len );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "Failed to deploy program" ));
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( buffer );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L667-L691 */
      /* Update the ProgramData account and record the program bits */
      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L669-L674 */
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 1UL, programdata ) {

      fd_bpf_upgradeable_loader_state_t programdata_loader_state = {
        .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
        .inner.program_data = {
          .slot                      = clock.slot,
          .upgrade_authority_address = (fd_pubkey_t *)authority_key,
        },
      };
      err = fd_bpf_loader_v3_program_set_state( instr_ctx, 1UL, &programdata_loader_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state write for programdata account failed" ));
        return err;
      }

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L675-L689 */
      if( FD_UNLIKELY( PROGRAMDATA_METADATA_SIZE+buffer_data_len>programdata->meta->dlen ) ) {
        uchar * sig = (uchar *)instr_ctx->txn_ctx->_txn_raw->raw + instr_ctx->txn_ctx->txn_descriptor->signature_off;
        FD_LOG_WARNING(( "ProgramData account too small %32J %lu %lu", sig, buffer_data_len, programdata->meta->dlen ));
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }
      if( FD_UNLIKELY( buffer_data_offset>buffer->meta->dlen ) ) {
        FD_LOG_WARNING(( "Buffer account too small" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      uchar * programdata_data = NULL;
      ulong   programdata_dlen = 0UL;
      err = fd_account_get_data_mut( instr_ctx, 1UL, &programdata_data, &programdata_dlen );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      uchar *   dst_slice = programdata_data + PROGRAMDATA_METADATA_SIZE;
      ulong dst_slice_len = buffer_data_len;

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, buffer ) {

      if( FD_UNLIKELY( buffer_data_offset>buffer->meta->dlen ) ) {
        FD_LOG_WARNING(( "Buffer account too small" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }
      const uchar * src_slice = buffer->const_data + buffer_data_offset;
      fd_memcpy( dst_slice, src_slice, dst_slice_len );
      /* Update buffer data length.
         BUFFER_METADATA_SIZE == UpgradeableLoaderState::size_of_buffer(0) */
      err = fd_account_set_data_length( instr_ctx, 3UL, BUFFER_METADATA_SIZE );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( buffer      );
      } FD_BORROWED_ACCOUNT_DROP( programdata );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L692-L699 */
      /* Update the Program account */

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, program ) {

      loader_state.discriminant = fd_bpf_upgradeable_loader_state_enum_program;
      fd_memcpy( &loader_state.inner.program.programdata_address, programdata_key, sizeof(fd_pubkey_t) );
      err = fd_bpf_loader_v3_program_set_state( instr_ctx, 2UL, &loader_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bincode encode for program account failed" ));
        return err;
      }
      err = fd_account_set_executable( instr_ctx, 2UL, 1 );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "Couldn't set account to executable" ));
        return err;
      }

      FD_LOG_INFO(( "Program deployed %32J", program->pubkey ));

      } FD_BORROWED_ACCOUNT_DROP( program );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L703-L891 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_upgrade: {
      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L704-L714 */
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 3U ) ) ) {
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

      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 7U ) ) ) {
        FD_LOG_WARNING(( "Not enough account keys for instruction" ));
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
      fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 6UL ] ];

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L716-L745 */
      /* Verify Program account */
      
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 1UL, program ) {

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
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, program, &program_state );
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

      } FD_BORROWED_ACCOUNT_DROP( program );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L747-L773 */
      /* Verify Buffer account */

      ulong buffer_lamports    = 0UL;
      ulong buffer_data_offset = 0UL;
      ulong buffer_data_len    = 0UL;

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, buffer ) {

      fd_bpf_upgradeable_loader_state_t buffer_state = {0};
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, buffer, &buffer_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bincode decode for buffer account failed" ));
        return err;
      }
      if( fd_bpf_upgradeable_loader_state_is_buffer( &buffer_state ) ) {
        if( FD_UNLIKELY( (authority_key==NULL) != (buffer_state.inner.buffer.authority_address == NULL) ||
            (authority_key!=NULL && memcmp( buffer_state.inner.buffer.authority_address, authority_key, sizeof(fd_pubkey_t) ) ) ) ) {
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
      buffer_lamports    = buffer->meta->info.lamports;
      buffer_data_offset = BUFFER_METADATA_SIZE;
      buffer_data_len    = fd_ulong_sat_sub( buffer->meta->dlen, buffer_data_offset );
      if( FD_UNLIKELY( buffer->meta->dlen<BUFFER_METADATA_SIZE || buffer->meta->dlen==0UL ) ) {
        FD_LOG_WARNING(( "Buffer account too small" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }
      
      } FD_BORROWED_ACCOUNT_DROP( buffer );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L775-L823 */
      /* Verify ProgramData account */

      ulong                             programdata_data_offset      = PROGRAMDATA_METADATA_SIZE;
      fd_bpf_upgradeable_loader_state_t programdata_state            = {0};
      fd_sol_sysvar_clock_t             clock                        = {0};
      ulong                             programdata_balance_required = 0UL;

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, programdata ) {

      programdata_balance_required = fd_ulong_max( 1UL, fd_rent_exempt_minimum_balance( instr_ctx->slot_ctx, programdata->const_meta->dlen ) );
    
      if( FD_UNLIKELY( programdata->meta->dlen<fd_ulong_sat_add( PROGRAMDATA_METADATA_SIZE, buffer_data_len ) ) ) {
        FD_LOG_WARNING(( "ProgramData account not large enough" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }
      if( FD_UNLIKELY( fd_ulong_sat_add( programdata->meta->info.lamports, buffer_lamports )<programdata_balance_required ) ) {
        FD_LOG_WARNING(( "Buffer account balance too low to fund upgrade" ));
        return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
      }
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, programdata, &programdata_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bincode decode for programdata account failed" ));
        return err;
      }

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

      } FD_BORROWED_ACCOUNT_DROP( programdata );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L825-L845 */
      /* Load and verify the program bits */

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, buffer ) {

      if( FD_UNLIKELY( buffer_data_offset>buffer->meta->dlen ) ) {
        FD_LOG_WARNING(( "Buffer data offset is out of bounds" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      uchar * buffer_data = buffer->data + buffer_data_offset;
      err = deploy_program( instr_ctx, buffer_data, buffer_data_len );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "Failed to deploy program" ));
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( buffer );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L846-L874 */
      /* Update the ProgramData account, record the upgraded data, and zero the rest */

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, programdata ) {

      programdata_state.discriminant                                 = fd_bpf_upgradeable_loader_state_enum_program_data;
      programdata_state.inner.program_data.slot                      = clock.slot;
      programdata_state.inner.program_data.upgrade_authority_address = (fd_pubkey_t *)authority_key;
      err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &programdata_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state write for programdata account failed" ));
        return err;
      }

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L846-L875 */
      /* We want to copy over the data and zero out the rest */
      if( FD_UNLIKELY( programdata_data_offset+buffer_data_len>programdata->meta->dlen ) ) {
        FD_LOG_WARNING(( "ProgramData account too small" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      uchar * programdata_data = NULL;
      ulong   programdata_dlen = 0UL;
      err = fd_account_get_data_mut( instr_ctx, 0UL, &programdata_data, &programdata_dlen );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
      uchar * dst_slice     = programdata_data + programdata_data_offset;
      ulong   dst_slice_len = buffer_data_len;

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, buffer ) {

      if( FD_UNLIKELY( buffer_data_offset>buffer->meta->dlen ) ){
        FD_LOG_WARNING(( "Buffer account too small" ));
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      uchar * src_slice     = buffer->data + buffer_data_offset;
      fd_memcpy( dst_slice, src_slice, dst_slice_len );
      fd_memset( dst_slice + dst_slice_len, 0, programdata->meta->dlen - programdata_data_offset - dst_slice_len );

      } FD_BORROWED_ACCOUNT_DROP( buffer );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L876-L891 */
      /* Fund ProgramData to rent-exemption, spill the rest */
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, buffer ) {
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, spill  ) {

      ulong spill_addend = fd_ulong_sat_sub( fd_ulong_sat_add( programdata->meta->info.lamports, buffer_lamports ),
                                             programdata_balance_required );
      err = fd_account_checked_add_lamports( instr_ctx, 3UL, spill_addend );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
      err = fd_account_set_lamports( instr_ctx, 2UL, 0UL );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
      err = fd_account_set_lamports( instr_ctx, 0UL, programdata_balance_required );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      programdata->meta->info.lamports = programdata_balance_required;
      /* Buffer account set_data_length */
      err = fd_account_set_data_length( instr_ctx, 2UL, PROGRAMDATA_METADATA_SIZE );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( spill       );
      } FD_BORROWED_ACCOUNT_DROP( buffer      );
      } FD_BORROWED_ACCOUNT_DROP( programdata );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L893-L957 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_set_authority: {
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
        FD_LOG_WARNING(( "Not enough account keys for instruction" ));
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, account ) {

      fd_pubkey_t const * present_authority_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];
      fd_pubkey_t *       new_authority         = NULL;
      if( FD_UNLIKELY( instr_ctx->instr->acct_cnt>=3UL ) ) {
        new_authority = (fd_pubkey_t *)&txn_accs[ instr_acc_idxs[ 2UL ] ];
      }

      fd_bpf_upgradeable_loader_state_t account_state = {0};
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, account, &account_state );
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
        err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &account_state );
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
        err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &account_state );
        if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
          FD_LOG_WARNING(( "Bincode encode for program data account failed" ));
          return err;
        }
      } else {
        FD_LOG_WARNING(( "Account does not support authorities" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      } FD_BORROWED_ACCOUNT_DROP( account );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L958-L1030 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_set_authority_checked: {
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 3U ) ) ) {
        FD_LOG_WARNING(( "Not enough account keys for instruction" ));
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, account ) {

      fd_pubkey_t const * present_authority_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];
      fd_pubkey_t const * new_authority_key     = &txn_accs[ instr_acc_idxs[ 2UL ] ];

      fd_bpf_upgradeable_loader_state_t account_state = {0};
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, account, &account_state );
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
        err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &account_state );
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
        err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &account_state );
        if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
          FD_LOG_WARNING(( "Bpf state wr encode for program data account failed" ));
          return err;
        }
      } else {
        FD_LOG_WARNING(( "Account does not support authorities" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      } FD_BORROWED_ACCOUNT_DROP( account );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1031-L1134 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_close: {

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1032-L1046 */
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
        FD_LOG_WARNING(( "Not enough account keys for instruction" ));
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
      if( FD_UNLIKELY( instr_acc_idxs[ 0UL ]==instr_acc_idxs[ 1UL ] ) ) {
        FD_LOG_WARNING(( "Recipient is the same as the account being closed" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, close_account ) {
      
      fd_pubkey_t * close_key = close_account->pubkey;
      fd_bpf_upgradeable_loader_state_t close_account_state = {0};
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, close_account, &close_account_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state read for close account failed" ));
        return err;
      }
      /* Close account set data length */
      err = fd_account_set_data_length( instr_ctx, 0UL, SIZE_OF_UNINITIALIZED );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1049-L1056 */
      if( fd_bpf_upgradeable_loader_state_is_uninitialized( &close_account_state ) ) {

        FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 1UL, recipient_account ) {

        err = fd_account_checked_add_lamports( instr_ctx, 1UL, close_account->meta->info.lamports );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
        err = fd_account_set_lamports( instr_ctx, 0UL, 0UL );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
        FD_LOG_INFO(( "Closed Uninitialized %32J", close_key ));

        } FD_BORROWED_ACCOUNT_DROP( recipient_account );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1057-L1068 */
      } else if( fd_bpf_upgradeable_loader_state_is_buffer( &close_account_state ) ) {

        fd_borrowed_account_release_write( close_account );

        if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 3U ) ) ) {
          FD_LOG_WARNING(( "Not enough account keys for instruction" ));
          return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
        }

        err = common_close_account( close_account_state.inner.buffer.authority_address, instr_ctx, &close_account_state );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
        FD_LOG_INFO(( "Closed Buffer %32J", close_key ));

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1069-L1129 */
      } else if( fd_bpf_upgradeable_loader_state_is_program_data( &close_account_state ) ) {
        if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 4U ) ) ) {
          FD_LOG_WARNING(( "Not enough account keys for instruction" ));
          return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
        }

        fd_borrowed_account_release_write( close_account );

        FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, program_account ) {

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
        err = fd_bpf_loader_v3_program_get_state( instr_ctx, program_account, &program_state );
        if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
          FD_LOG_WARNING(( "Bpf state read for program account failed" ));
          return err;
        }
        if( fd_bpf_upgradeable_loader_state_is_program( &program_state ) ) {
          if( FD_UNLIKELY( memcmp( &program_state.inner.program.programdata_address, close_key, sizeof(fd_pubkey_t) ) ) ) {
            FD_LOG_WARNING(( "Program account does not match ProgramData account" ));
            return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
          }
          fd_borrowed_account_release_write( program_account );

          err = common_close_account( close_account_state.inner.program_data.upgrade_authority_address,
                                      instr_ctx,
                                      &close_account_state );
          if( FD_UNLIKELY( err ) ) {
            return err;
          }

          /* The Agave client updates the account state upon closing an account
            in their loaded program cache. Checking for a program can be
            checked by checking to see if the programdata account's loader state
            is unitialized. The firedancer implementation also removes closed
            accounts from the loaded program cache at the end of a slot. Closed
            accounts currently get handled in the 
            fd_bpf_loader_v3_is_executable check in fd_executor.c */

        } else {
          FD_LOG_WARNING(( "Invalid program account" ));
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }

        } FD_BORROWED_ACCOUNT_DROP( program_account );
      } else {        
        FD_LOG_WARNING(( "Account does not support closing" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      } FD_BORROWED_ACCOUNT_DROP( close_account );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1136-L1294 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_extend_program: {
      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1137-L1172 */
      uint additional_bytes = instruction.inner.extend_program.additional_bytes;
      if( FD_UNLIKELY( additional_bytes==0U ) ) {
        FD_LOG_WARNING(( "Additional bytes must be greater than 0" ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      }

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, programdata_account ) {

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

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 1UL, program_account ) {

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
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, program_account, &program_state );
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

      } FD_BORROWED_ACCOUNT_DROP( program_account );

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
      err = fd_bpf_loader_v3_program_get_state( instr_ctx, programdata_account, &programdata_state );
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
      ulong min_balance      = fd_ulong_max( fd_rent_exempt_minimum_balance( instr_ctx->slot_ctx, new_len ), 1UL );
      ulong required_payment = fd_ulong_sat_sub( min_balance, balance );

      /* Borrowed accounts need to be dropped before native invocations. Note:
         the programdata account is manually released and acquired within the
         extend instruction to preserve the local variable scoping to maintain
         readability. The scoped macro still successfully handles the case of
         freeing a write lock in case of an early termination. */
      fd_borrowed_account_release_write( programdata_account );

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
      if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( programdata_account ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      /* Programdata account set data length */
      int err = fd_account_set_data_length( instr_ctx, 0UL, new_len );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      if( FD_UNLIKELY( PROGRAMDATA_METADATA_SIZE>programdata_account->meta->dlen ) ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      uchar * programdata_data = programdata_account->data + PROGRAMDATA_METADATA_SIZE;
      ulong   programdata_size = new_len                   - PROGRAMDATA_METADATA_SIZE;

      err = deploy_program( instr_ctx, programdata_data, programdata_size );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "Failed to deploy program" ));
        return err;
      }

      fd_borrowed_account_release_write( programdata_account );

      /* Setting the discriminant and upgrade authority address here can likely
         be a no-op because these values shouldn't change. These can probably be
         removed, but can help to mirror against Agave client's implementation. 
         The set_state function also contains an ownership check. */

      if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( programdata_account ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      programdata_state.discriminant                                 = fd_bpf_upgradeable_loader_state_enum_program_data;
      programdata_state.inner.program_data.slot                      = clock.slot;
      programdata_state.inner.program_data.upgrade_authority_address = upgrade_authority_address;

      err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &programdata_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bincode encode for programdata account failed" ));
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( programdata_account );

      break;
    }
    default: {
      FD_LOG_WARNING(( "ProgramData state is invalid" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
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
    err = fd_bpf_loader_v3_program_get_state( &ctx, program_account, &program_account_state );
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
    err = fd_bpf_loader_v3_program_get_state( &ctx, program_data_account, &program_data_account_state );
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
