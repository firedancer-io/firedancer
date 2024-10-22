#include "fd_bpf_loader_program.h"

/* For additional context see https://solana.com/docs/programs/deploying#state-accounts */

#include "../fd_pubkey_utils.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../../vm/fd_vm.h"
#include "../fd_executor.h"
#include "fd_bpf_loader_serialization.h"
#include "fd_bpf_program_util.h"
#include "fd_native_cpi.h"

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

/* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/sdk/program/src/program_error.rs#L290-L335 */
static inline int
program_error_to_instr_error( ulong  err, 
                              uint * custom_err ) {
  switch( err ) {
    case CUSTOM_ZERO:
      *custom_err = 0;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    case INVALID_ARGUMENT:
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    case INVALID_INSTRUCTION_DATA:
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    case INVALID_ACCOUNT_DATA:
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    case ACCOUNT_DATA_TOO_SMALL:
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    case INSUFFICIENT_FUNDS:
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    case INCORRECT_PROGRAM_ID:
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    case MISSING_REQUIRED_SIGNATURES:
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    case ACCOUNT_ALREADY_INITIALIZED:
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    case UNINITIALIZED_ACCOUNT:
      return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
    case NOT_ENOUGH_ACCOUNT_KEYS:
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    case ACCOUNT_BORROW_FAILED:
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
    case MAX_SEED_LENGTH_EXCEEDED:
      return FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED;
    case INVALID_SEEDS:
      return FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS;
    case BORSH_IO_ERROR:
      return FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR;
    case ACCOUNT_NOT_RENT_EXEMPT:
      return FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT;
    case UNSUPPORTED_SYSVAR:
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    case ILLEGAL_OWNER:
      return FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER;
    case MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED:
      return FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED;
    case INVALID_ACCOUNT_DATA_REALLOC:
      return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
    case MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED:
      return FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED;
    case BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS:
      return FD_EXECUTOR_INSTR_ERR_BUILTINS_MUST_CONSUME_CUS;
    case INVALID_ACCOUNT_OWNER:
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    case ARITHMETIC_OVERFLOW:
      return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
    case IMMUTABLE:
      return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
    case INCORRECT_AUTHORITY:
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    default:
      if( err>>BUILTIN_BIT_SHIFT == 0 ) {
        *custom_err = (uint)err;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
      return FD_EXECUTOR_INSTR_ERR_INVALID_ERR;
  }
}

int
fd_bpf_loader_v2_is_executable( fd_exec_slot_ctx_t * slot_ctx,
                                fd_pubkey_t const *  pubkey ) {
  FD_BORROWED_ACCOUNT_DECL(rec);
  int read_result = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, pubkey, rec );
  if( read_result != FD_ACC_MGR_SUCCESS ) {
    return -1;
  }

  if( memcmp( rec->const_meta->info.owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) != 0 &&
      memcmp( rec->const_meta->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) {
    return -1;
  }

  if( rec->const_meta->info.executable != 1 ) {
    return -1;
  }

  return 0;
}


/* This is literally called before every single instruction execution */
int
fd_bpf_loader_v3_is_executable( fd_exec_slot_ctx_t * slot_ctx,
                                fd_pubkey_t const *  pubkey ) {
  int err = 0;
  fd_account_meta_t const * meta = fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn,
                                                        (fd_pubkey_t *) pubkey, NULL, &err, NULL );
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
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Check if programdata account exists */
  fd_account_meta_t const * programdata_meta =
    (fd_account_meta_t const *)fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn,
                                                    (fd_pubkey_t *) &loader_state.inner.program.programdata_address, NULL, &err, NULL );
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

   Our arguments to deploy_program are different from the Agave version because
   we handle the caching of deployed programs differently. In Firedancer we
   lack the concept of ProgramCacheEntryType entirely.
   https://github.com/anza-xyz/agave/blob/114d94a25e9631f9bf6349c4b833d7900ef1fb1c/program-runtime/src/loaded_programs.rs#L158

   In Agave there is a separate caching structure that is used to store the
   deployed programs. In Firedancer the deployed, validated program is stored as
  metadata for the account in the funk record.

   See https://github.com/firedancer-io/firedancer/blob/9c1df680b3f38bebb0597e089766ec58f3b41e85/src/flamenco/runtime/program/fd_bpf_loader_v3_program.c#L1640
   for how we handle the concept of 'LoadedProgramType::DelayVisibility' in Firedancer.

   As a concrete example, our version of deploy_program does not have the
   'account_size' argument because we do not update the funk record here. */
int
deploy_program( fd_exec_instr_ctx_t * instr_ctx,
                uchar * const         programdata,
                ulong                 programdata_size ) {
  int deploy_mode    = 1;
  int direct_mapping = FD_FEATURE_ACTIVE( instr_ctx->slot_ctx, bpf_account_data_direct_mapping );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(),
                                                                          fd_sbpf_syscalls_footprint() ) );
  if( FD_UNLIKELY( !syscalls ) ) {
    //TODO: full log including err
    fd_log_collector_msg_literal( instr_ctx, "Failed to register syscalls" );
    return FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE;
  }
  fd_vm_syscall_register_slot( syscalls, instr_ctx->slot_ctx, 1);

  /* Load executable */
  fd_sbpf_elf_info_t  _elf_info[ 1UL ];
  fd_sbpf_elf_info_t * elf_info = fd_sbpf_elf_peek( _elf_info, programdata, programdata_size, deploy_mode );
  if( FD_UNLIKELY( !elf_info ) ) {
    //TODO: actual log, this is a custom Firedancer msg
    fd_log_collector_msg_literal( instr_ctx, "Failed to load or verify Elf" );
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
  int err = fd_sbpf_program_load( prog, programdata, programdata_size, syscalls, deploy_mode );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Validate the program */
  fd_vm_t _vm[ 1UL ];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );

  vm = fd_vm_init(
    /* vm              */ vm,
    /* instr_ctx       */ instr_ctx,
    /* heap_max        */ instr_ctx->txn_ctx->heap_size,
    /* entry_cu        */ instr_ctx->txn_ctx->compute_meter,
    /* rodata          */ prog->rodata,
    /* rodata_sz       */ prog->rodata_sz,
    /* text            */ prog->text,
    /* text_cnt        */ prog->text_cnt,
    /* text_off        */ prog->text_off, /* FIXME: What if text_off is not multiple of 8 */
    /* text_sz         */ prog->text_sz,
    /* entry_pc        */ prog->entry_pc,
    /* calldests       */ prog->calldests,
    /* syscalls        */ syscalls,
    /* trace           */ NULL,
    /* sha             */ NULL,
    /* mem_regions     */ NULL,
    /* mem_regions_cnt */ 0,
    /* mem_region_accs */ NULL,
    /* is_deprecated   */ 0,
    /* direct mapping */  direct_mapping );
  if ( FD_UNLIKELY( vm == NULL ) ) {
    FD_LOG_WARNING(( "NULL vm" ));
    return FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE;
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

  uchar * data = NULL;
  ulong   dlen = 0UL;
  int err = fd_account_get_data_mut( instr_ctx, instr_acc_idx, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  ulong write_offset = fd_ulong_sat_add( program_data_offset, bytes_len );
  if( FD_UNLIKELY( program->const_meta->dlen<write_offset ) ) {
    /* Max msg_sz: 24 - 6 + 2*20 = 58 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( instr_ctx,
      "Write overflow %lu < %lu", program->const_meta->dlen, write_offset );
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  if( FD_UNLIKELY( program_data_offset>dlen ) ) {
    FD_LOG_WARNING(( "Write offset out of bounds" )); // custom check/log
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
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }
  if( FD_UNLIKELY( memcmp( authority_address, &txn_accs[ instr_acc_idxs[ 2UL ] ], sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 2UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, close_account     ) {
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 1UL, recipient_account ) {

  int err = fd_account_checked_add_lamports( instr_ctx, 1UL, close_account->const_meta->info.lamports );
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
execute( fd_exec_instr_ctx_t * instr_ctx, fd_sbpf_validated_program_t * prog, uchar is_deprecated ) {

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( instr_ctx->valloc,
                                                                          fd_sbpf_syscalls_align(),
                                                                          fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_slot( syscalls, instr_ctx->slot_ctx, 0 );

  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1362-L1368 */
  ulong                   input_sz                = 0UL;
  ulong                   pre_lens[256]           = {0};
  fd_vm_input_region_t    input_mem_regions[1000] = {0}; /* We can have a max of (3 * num accounts + 1) regions */
  fd_vm_acc_region_meta_t acc_region_metas[256]   = {0}; /* instr acc idx to idx */
  uint                    input_mem_regions_cnt   = 0U;
  int                     direct_mapping          = FD_FEATURE_ACTIVE( instr_ctx->slot_ctx, bpf_account_data_direct_mapping );

  uchar * input = NULL;
  if( FD_UNLIKELY( is_deprecated ) ) {
    input = fd_bpf_loader_input_serialize_unaligned( *instr_ctx, &input_sz, pre_lens,
                                                     input_mem_regions, &input_mem_regions_cnt,
                                                     acc_region_metas, !direct_mapping );
  } else {
    input = fd_bpf_loader_input_serialize_aligned( *instr_ctx, &input_sz, pre_lens,
                                                   input_mem_regions, &input_mem_regions_cnt,
                                                   acc_region_metas, !direct_mapping );
  }

  if( FD_UNLIKELY( input==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );

  ulong pre_insn_cus = instr_ctx->txn_ctx->compute_meter;
  ulong heap_max = true ? instr_ctx->txn_ctx->heap_size : FD_VM_HEAP_DEFAULT; /* TODO:FIXME: fix this */

  /* TODO: (topointon): correctly set check_size in vm setup */
  vm = fd_vm_init(
    /* vm                    */ vm,
    /* instr_ctx             */ instr_ctx,
    /* heap_max              */ heap_max, /* TODO configure heap allocator */
    /* entry_cu              */ instr_ctx->txn_ctx->compute_meter,
    /* rodata                */ prog->rodata,
    /* rodata_sz             */ prog->rodata_sz,
    /* text                  */ (ulong *)((ulong)prog->rodata + (ulong)prog->text_off), /* Note: text_off is byte offset */
    /* text_cnt              */ prog->text_cnt,
    /* text_off              */ prog->text_off,
    /* text_sz               */ prog->text_sz,
    /* entry_pc              */ prog->entry_pc,
    /* calldests             */ prog->calldests,
    /* syscalls              */ syscalls,
    /* trace                 */ NULL,
    /* sha                   */ sha,
    /* input_mem_regions     */ input_mem_regions,
    /* input_mem_regions_cnt */ input_mem_regions_cnt,
    /* acc_region_metas      */ acc_region_metas,
    /* is_deprecated         */ is_deprecated,
    /* direct_mapping        */ direct_mapping );
  if ( FD_UNLIKELY( vm == NULL ) ) {
    /* We throw an error here because it could be the case that the given heap_size > HEAP_MAX.
       In this case, Agave fails the transaction but does not error out.
       
       https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1396 */
    FD_LOG_WARNING(( "null vm" ));
    return FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE;
  }

#ifdef FD_DEBUG_SBPF_TRACES
  uchar * signature = (uchar*)vm->instr_ctx->txn_ctx->_txn_raw->raw + vm->instr_ctx->txn_ctx->txn_descriptor->signature_off;
  uchar sig[64];
  /* TODO (topointon): make this run-time configurable, no need for this ifdef */
  fd_base58_decode_64( "tkacc4VCh2z9cLsQowCnKqX14DmUUxpRyES755FhUzrFxSFvo8kVk444kNTL7kJxYnnANYwRWAdHCgBJupftZrz", sig );
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
  instr_ctx->txn_ctx->compute_meter = vm->cu;

  if( FD_UNLIKELY( vm->trace ) ) {
    int err = fd_vm_trace_printf( vm->trace, vm->syscalls );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_vm_trace_printf failed (%i-%s)", err, fd_vm_strerror( err ) ));
    }
    fd_valloc_free( instr_ctx->txn_ctx->valloc, fd_vm_trace_delete( fd_vm_trace_leave( vm->trace ) ) );
  }

  /* Log consumed compute units and return data.
     https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/lib.rs#L1418-L1429 */
  fd_log_collector_program_consumed( instr_ctx, pre_insn_cus-vm->cu, pre_insn_cus );
  if( FD_UNLIKELY( instr_ctx->txn_ctx->return_data.len ) ) {
    fd_log_collector_program_return( instr_ctx );
  }

  if( FD_UNLIKELY( exec_err!=FD_VM_SUCCESS ) ) {
    fd_valloc_free( instr_ctx->valloc, input );
    if( instr_ctx->txn_ctx->exec_err_kind==FD_EXECUTOR_ERR_KIND_INSTR ) {
      return instr_ctx->txn_ctx->exec_err;
    }
    return FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE;
  }

  /* TODO: vm should report */
  ulong err = vm->reg[0];
  if( FD_UNLIKELY( err ) ) {
    fd_valloc_free( instr_ctx->valloc, input );

    /* https://github.com/anza-xyz/agave/blob/v2.0.9/programs/bpf_loader/src/lib.rs#L1431-L1434 */
    instr_ctx->txn_ctx->exec_err_kind = FD_EXECUTOR_ERR_KIND_INSTR;
    return program_error_to_instr_error( err, &instr_ctx->txn_ctx->custom_err );
  }

  if( FD_UNLIKELY( is_deprecated ) ) {
    if( FD_UNLIKELY( fd_bpf_loader_input_deserialize_unaligned( *instr_ctx, pre_lens, input, input_sz, !direct_mapping )!=0 ) ) {
      fd_valloc_free( instr_ctx->valloc, input );
      return FD_EXECUTOR_INSTR_SUCCESS;
    }
  } else {
    if( FD_UNLIKELY( fd_bpf_loader_input_deserialize_aligned( *instr_ctx, pre_lens, input, input_sz, !direct_mapping )!=0 ) ) {
      fd_valloc_free( instr_ctx->valloc, input );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

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
  decode_ctx.dataend = &data[ instr_ctx->instr->data_sz > 1232UL ? 1232UL : instr_ctx->instr->data_sz ];
  decode_ctx.valloc  = instr_ctx->valloc;

  int err = fd_bpf_upgradeable_loader_program_instruction_decode( &instruction, &decode_ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "Bincode decode for instruction failed" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
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
        FD_LOG_WARNING(( "Bpf loader state read for buffer account failed" )); // custom log
        return err;
      }

      if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_uninitialized( &buffer_state ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Buffer account is already initialized" );
        return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
      }

      fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];

      buffer_state.discriminant                   = fd_bpf_upgradeable_loader_state_enum_buffer;
      buffer_state.inner.buffer.authority_address = (fd_pubkey_t*)authority_key;

      err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &buffer_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf loader state write for buffer account failed" )); // custom log
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
          fd_log_collector_msg_literal( instr_ctx, "Buffer is immutable" );
          return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
        }
        fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 1UL ] ];
        if( FD_UNLIKELY( memcmp( loader_state.inner.buffer.authority_address, authority_key, sizeof(fd_pubkey_t) ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Incorrect buffer authority provided" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Buffer authority did not sign" );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Invalid Buffer account" );
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

      fd_bpf_upgradeable_loader_state_t loader_state   = {0};
      fd_pubkey_t *                     new_program_id = NULL;
      fd_epoch_bank_t *                 epoch_bank     = fd_exec_epoch_ctx_epoch_bank( instr_ctx->slot_ctx->epoch_ctx );
      fd_rent_t       *                 rent           = &epoch_bank->rent;
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, program ) {

      err = fd_bpf_loader_v3_program_get_state( instr_ctx, program, &loader_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state read for program account failed" ));
        return err;
      }
      if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program account already initialized" );
        return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
      }
      if( FD_UNLIKELY( program->const_meta->dlen<SIZE_OF_PROGRAM ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program account too small" );
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }
      if( FD_UNLIKELY( program->const_meta->info.lamports<fd_rent_exempt_minimum_balance( rent,
                                                                                           program->const_meta->dlen ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program account not rent-exempt" );
        return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT;
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
          fd_log_collector_msg_literal( instr_ctx, "Buffer and upgrade authority don't match" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 7UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Upgrade authority did not sign" );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Invalid Buffer account" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      buffer_key         = buffer->pubkey;
      buffer_data_offset = BUFFER_METADATA_SIZE;
      buffer_data_len    = fd_ulong_sat_sub( buffer->const_meta->dlen, buffer_data_offset );
      /* UpgradeableLoaderState::size_of_program_data( max_data_len ) */
      programdata_len    = fd_ulong_sat_add( PROGRAMDATA_METADATA_SIZE,
                                             instruction.inner.deploy_with_max_data_len.max_data_len );

      if( FD_UNLIKELY( buffer->const_meta->dlen<BUFFER_METADATA_SIZE || buffer_data_len==0UL ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Buffer account too small" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      if( FD_UNLIKELY( instruction.inner.deploy_with_max_data_len.max_data_len<buffer_data_len ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Max data length is too small to hold Buffer data" );
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      if( FD_UNLIKELY( programdata_len>MAX_PERMITTED_DATA_LENGTH ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Max data length is too large" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      } FD_BORROWED_ACCOUNT_DROP( buffer );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L602-L608 */
      /* Create ProgramData account */

      fd_pubkey_t derived_address[ 1UL ];
      uchar * seeds[ 1UL ];
      seeds[ 0UL ]    = (uchar *)new_program_id;
      ulong seed_sz   = sizeof(fd_pubkey_t);
      uchar bump_seed = 0;
      err = fd_pubkey_find_program_address( instr_ctx, program_id, 1UL, seeds, &seed_sz, derived_address, &bump_seed );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "Unable to find a viable program address bump seed" )); // Solana panics, error code is undefined
        return err;
      }
      if( FD_UNLIKELY( memcmp( derived_address, programdata_key, sizeof(fd_pubkey_t) ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "ProgramData address is not derived" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L610-L627 */
      /* Drain the Buffer account to payer before paying for programdata account */
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, payer  ) {
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, buffer ) {

      err = fd_account_checked_add_lamports( instr_ctx, 0UL, buffer->const_meta->info.lamports );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
      err = fd_account_set_lamports( instr_ctx, 3UL, 0UL );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( buffer );
      } FD_BORROWED_ACCOUNT_DROP( payer  );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L628-L642 */
      /* Pass an extra account to avoid the overly strict unblanaced instruction error */
      /* Invoke the system program to create the new account */
      fd_system_program_instruction_create_account_t create_acct = {0};
      create_acct.lamports = fd_rent_exempt_minimum_balance( rent, programdata_len );
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
      err = fd_pubkey_derive_pda( instr_ctx, program_id, 1UL, seeds, &seed_sz, &bump_seed, signers );
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
      if( FD_UNLIKELY( buffer_data_offset>buffer->const_meta->dlen ) ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      const uchar * buffer_data = buffer->const_data + buffer_data_offset;

      err = deploy_program( instr_ctx, (uchar*)buffer_data, buffer_data_len );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "Failed to deploy program" )); // custom log
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
      if( FD_UNLIKELY( PROGRAMDATA_METADATA_SIZE+buffer_data_len>programdata->const_meta->dlen ) ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }
      if( FD_UNLIKELY( buffer_data_offset>buffer->const_meta->dlen ) ) {
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

      if( FD_UNLIKELY( buffer_data_offset>buffer->const_meta->dlen ) ) {
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

      /* Max msg_sz: 19 - 2 + 45 = 62 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( instr_ctx, "Deployed program %s", FD_BASE58_ENC_32_ALLOCA( program_id ) );

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

      FD_LOG_INFO(( "Program deployed %s", FD_BASE58_ENC_32_ALLOCA( program->pubkey ) ));

      } FD_BORROWED_ACCOUNT_DROP( program );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L703-L891 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_upgrade: {
      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L704-L714 */
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 3U ) ) ) {
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
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
      fd_pubkey_t const * authority_key = &txn_accs[ instr_acc_idxs[ 6UL ] ];

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L716-L745 */
      /* Verify Program account */

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 1UL, program ) {

      if( FD_UNLIKELY( !program->const_meta->info.executable ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program account not executable" );
        return FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, program->pubkey ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program account not writeable" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      if( FD_UNLIKELY( memcmp( &program->const_meta->info.owner, program_id, sizeof(fd_pubkey_t) ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program account not owned by loader" );
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
          fd_log_collector_msg_literal( instr_ctx, "Program and ProgramData account mismatch" );
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Invalid Program account" );
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
          fd_log_collector_msg_literal( instr_ctx, "Buffer and upgrade authority don't match" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 6UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Upgrade authority did not sign" );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Invalid Buffer account" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      buffer_lamports    = buffer->const_meta->info.lamports;
      buffer_data_offset = BUFFER_METADATA_SIZE;
      buffer_data_len    = fd_ulong_sat_sub( buffer->const_meta->dlen, buffer_data_offset );
      if( FD_UNLIKELY( buffer->const_meta->dlen<BUFFER_METADATA_SIZE || buffer_data_len==0UL ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Buffer account too small" );
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

      fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( instr_ctx->slot_ctx->epoch_ctx );
      fd_rent_t       * rent       = &epoch_bank->rent;

      programdata_balance_required = fd_ulong_max( 1UL, fd_rent_exempt_minimum_balance( rent, programdata->const_meta->dlen ) );

      if( FD_UNLIKELY( programdata->const_meta->dlen<fd_ulong_sat_add( PROGRAMDATA_METADATA_SIZE, buffer_data_len ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "ProgramData account not large enough" );
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }
      if( FD_UNLIKELY( fd_ulong_sat_add( programdata->const_meta->info.lamports, buffer_lamports )<programdata_balance_required ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Buffer account balance too low to fund upgrade" );
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
          fd_log_collector_msg_literal( instr_ctx, "Program was deployed in this block already" );
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }
        if( FD_UNLIKELY( !programdata_state.inner.program_data.upgrade_authority_address ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Prrogram not upgradeable" );
          return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
        }
        if( FD_UNLIKELY( memcmp( programdata_state.inner.program_data.upgrade_authority_address, authority_key, sizeof(fd_pubkey_t) ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Incorrect upgrade authority provided" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 6UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Upgrade authority did not sign" );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Invalid ProgramData account" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      } FD_BORROWED_ACCOUNT_DROP( programdata );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L825-L845 */
      /* Load and verify the program bits */

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, buffer ) {

      if( FD_UNLIKELY( buffer_data_offset>buffer->const_meta->dlen ) ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      const uchar * buffer_data = buffer->const_data + buffer_data_offset;
      err = deploy_program( instr_ctx, (uchar*)buffer_data, buffer_data_len );
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
      if( FD_UNLIKELY( programdata_data_offset+buffer_data_len>programdata->const_meta->dlen ) ) {
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

      if( FD_UNLIKELY( buffer_data_offset>buffer->const_meta->dlen ) ){
        return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
      }

      const uchar * src_slice = buffer->const_data + buffer_data_offset;
      fd_memcpy( dst_slice, src_slice, dst_slice_len );
      fd_memset( dst_slice + dst_slice_len, 0, programdata->const_meta->dlen - programdata_data_offset - dst_slice_len );

      } FD_BORROWED_ACCOUNT_DROP( buffer );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L876-L891 */
      /* Fund ProgramData to rent-exemption, spill the rest */
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, buffer ) {
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, spill  ) {

      ulong spill_addend = fd_ulong_sat_sub( fd_ulong_sat_add( programdata->const_meta->info.lamports, buffer_lamports ),
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

      /* Buffer account set_data_length */
      err = fd_account_set_data_length( instr_ctx, 2UL, BUFFER_METADATA_SIZE );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      } FD_BORROWED_ACCOUNT_DROP( spill       );
      } FD_BORROWED_ACCOUNT_DROP( buffer      );
      } FD_BORROWED_ACCOUNT_DROP( programdata );

      /* Max msg_sz: 19 - 2 + 45 = 62 < 127 => we can use printf */
      //TODO: this is likely the incorrect program_id, do we have new_program_id?
      fd_log_collector_printf_dangerous_max_127( instr_ctx, "Upgraded program %s", FD_BASE58_ENC_32_ALLOCA( program_id ) );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L893-L957 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_set_authority: {
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
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
          fd_log_collector_msg_literal( instr_ctx, "Buffer authority is not optional" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !account_state.inner.buffer.authority_address ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Buffer is immutable" );
          return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
        }
        if( FD_UNLIKELY( memcmp( account_state.inner.buffer.authority_address, present_authority_key, sizeof(fd_pubkey_t) ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Incorrect buffer authority provided" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Buffer authority did not sign" );
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
          fd_log_collector_msg_literal( instr_ctx, "Program not upgradeable" );
          return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
        }
        if( FD_UNLIKELY( memcmp( account_state.inner.program_data.upgrade_authority_address, present_authority_key, sizeof(fd_pubkey_t) ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Incorrect upgrade authority provided" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Upgrade authority did not sign" );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        account_state.inner.program_data.upgrade_authority_address = new_authority;
        err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &account_state );
        if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
          FD_LOG_WARNING(( "Bincode encode for program data account failed" ));
          return err;
        }
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Account does not support authorities" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Max msg_sz: 16 - 2 + 45 = 59 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( instr_ctx, "New authority %s", FD_BASE58_ENC_32_ALLOCA( new_authority ) );

      } FD_BORROWED_ACCOUNT_DROP( account );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L958-L1030 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_set_authority_checked: {
      if( !FD_FEATURE_ACTIVE( instr_ctx->slot_ctx, enable_bpf_loader_set_authority_checked_ix ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      }

      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 3U ) ) ) {
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
          fd_log_collector_msg_literal( instr_ctx, "Buffer is immutable" );
          return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
        }
        if( FD_UNLIKELY( memcmp( account_state.inner.buffer.authority_address, present_authority_key, sizeof(fd_pubkey_t) ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Incorrect buffer authority provided" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Buffer authority did not sign" );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 2UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "New authority did not sign" );
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
          fd_log_collector_msg_literal( instr_ctx, "Program not upgradeable" );
          return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
        }
        if( FD_UNLIKELY( memcmp( account_state.inner.program_data.upgrade_authority_address, present_authority_key, sizeof(fd_pubkey_t) ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Incorrect upgrade authority provided" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Upgrade authority did not sign" );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 2UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "New authority did not sign" );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        account_state.inner.program_data.upgrade_authority_address = (fd_pubkey_t*)new_authority_key;
        err = fd_bpf_loader_v3_program_set_state( instr_ctx, 0UL, &account_state );
        if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
          FD_LOG_WARNING(( "Bpf state wr encode for program data account failed" ));
          return err;
        }
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Account does not support authorities" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Max msg_sz: 16 - 2 + 45 = 59 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( instr_ctx, "New authority %s", FD_BASE58_ENC_32_ALLOCA( new_authority_key ) );

      } FD_BORROWED_ACCOUNT_DROP( account );

      break;
    }
    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1031-L1134 */
    case fd_bpf_upgradeable_loader_program_instruction_enum_close: {

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1032-L1046 */
      if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
      if( FD_UNLIKELY( instr_acc_idxs[ 0UL ]==instr_acc_idxs[ 1UL ] ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Recipient is the same as the account being closed" );
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

        err = fd_account_checked_add_lamports( instr_ctx, 1UL, close_account->const_meta->info.lamports );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
        err = fd_account_set_lamports( instr_ctx, 0UL, 0UL );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
        /* Max msg_sz: 23 - 2 + 45 = 66 < 127 => we can use printf */
        fd_log_collector_printf_dangerous_max_127( instr_ctx,
          "Closed Uninitialized %s", FD_BASE58_ENC_32_ALLOCA( close_key ) );

        } FD_BORROWED_ACCOUNT_DROP( recipient_account );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1057-L1068 */
      } else if( fd_bpf_upgradeable_loader_state_is_buffer( &close_account_state ) ) {

        fd_borrowed_account_release_write( close_account );

        if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 3U ) ) ) {
          return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
        }

        err = common_close_account( close_account_state.inner.buffer.authority_address, instr_ctx, &close_account_state );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
        /* Max msg_sz: 16 - 2 + 45 = 63 < 127 => we can use printf */
        fd_log_collector_printf_dangerous_max_127( instr_ctx,
          "Closed Buffer %s", FD_BASE58_ENC_32_ALLOCA( close_key ) );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1069-L1129 */
      } else if( fd_bpf_upgradeable_loader_state_is_program_data( &close_account_state ) ) {
        if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 4U ) ) ) {
          return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
        }

        fd_borrowed_account_release_write( close_account );

        FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 3UL, program_account ) {

        fd_pubkey_t * program_key = program_account->pubkey;

        if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, program_key ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Program account is not writable" );
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }
        if( FD_UNLIKELY( memcmp( program_account->const_meta->info.owner, program_id, sizeof(fd_pubkey_t) ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Program account not owned by loader" );
          return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
        }
        fd_sol_sysvar_clock_t clock = {0};
        if( FD_UNLIKELY( !fd_sysvar_clock_read( &clock, instr_ctx->slot_ctx ) ) ) {
          return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
        }
        if( FD_UNLIKELY( clock.slot==close_account_state.inner.program_data.slot ) ) {
          fd_log_collector_msg_literal( instr_ctx,"Program was deployed in this block already" );
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
            fd_log_collector_msg_literal( instr_ctx,"Program account does not match ProgramData account" );
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
             accounts are not checked from the cache, instead the account state
             is looked up. */

        } else {
          fd_log_collector_msg_literal( instr_ctx, "Invalid program account" );
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }

        /* Max msg_sz: 17 - 2 + 45 = 60 < 127 => we can use printf */
        fd_log_collector_printf_dangerous_max_127( instr_ctx,
          "Closed Program %s", FD_BASE58_ENC_32_ALLOCA( close_key ) );

        } FD_BORROWED_ACCOUNT_DROP( program_account );
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Account does not support closing" );
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
        fd_log_collector_msg_literal( instr_ctx, "Additional bytes must be greater than 0" );
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
        fd_log_collector_msg_literal( instr_ctx, "ProgramData owner is invalid" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
      }
      if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, programdata_key ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "ProgramData is not writable" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 1UL, program_account ) {

      if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, program_account->pubkey ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program account is not writable" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      if( FD_UNLIKELY( memcmp( program_id, program_account->const_meta->info.owner, sizeof(fd_pubkey_t) ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program account not owned by loader" );
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
          fd_log_collector_msg_literal( instr_ctx, "Program account does not match ProgramData account" );
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }
      } else {
        fd_log_collector_msg_literal( instr_ctx, "Invalid program account" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      } FD_BORROWED_ACCOUNT_DROP( program_account );

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1191-L1230 */
      ulong old_len = programdata_account->const_meta->dlen;
      ulong new_len = fd_ulong_sat_add( old_len, additional_bytes );
      if( FD_UNLIKELY( new_len>MAX_PERMITTED_DATA_LENGTH ) ) {
        /* Max msg_sz: 85 - 6 + 2*20 = 119 < 127 => we can use printf */
        fd_log_collector_printf_dangerous_max_127( instr_ctx,
          "Extended ProgramData length of %lu bytes exceeds max account data length of %lu bytes", new_len, MAX_PERMITTED_DATA_LENGTH );
        return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
      }

      fd_sol_sysvar_clock_t clock = {0};
      if( FD_UNLIKELY( !fd_sysvar_clock_read( &clock, instr_ctx->slot_ctx ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
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
          fd_log_collector_msg_literal( instr_ctx, "Program was extended in this block already" );
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }

        if( FD_UNLIKELY( !programdata_state.inner.program_data.upgrade_authority_address ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Cannot extend ProgramData accounts that are not upgradeable" );
          return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
        }
        upgrade_authority_address = programdata_state.inner.program_data.upgrade_authority_address;
      } else {
        fd_log_collector_msg_literal( instr_ctx, "ProgramData state is invalid" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/programs/bpf_loader/src/lib.rs#L1232-L1256 */
      fd_epoch_bank_t * epoch_bank       = fd_exec_epoch_ctx_epoch_bank( instr_ctx->slot_ctx->epoch_ctx );
      fd_rent_t       * rent             = &epoch_bank->rent;
      ulong             balance          = programdata_account->const_meta->info.lamports;
      ulong             min_balance      = fd_ulong_max( fd_rent_exempt_minimum_balance( rent, new_len ), 1UL );
      ulong             required_payment = fd_ulong_sat_sub( min_balance, balance );

      /* Borrowed accounts need to be dropped before native invocations. Note:
         the programdata account is manually released and acquired within the
         extend instruction to preserve the local variable scoping to maintain
         readability. The scoped macro still successfully handles the case of
         freeing a write lock in case of an early termination. */
      fd_borrowed_account_release_write( programdata_account );

      if( FD_UNLIKELY( required_payment>0UL ) ) {
        if ( FD_UNLIKELY( instr_ctx->instr->acct_cnt<=3UL ) ) {
          return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
        }

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

      if( FD_UNLIKELY( PROGRAMDATA_METADATA_SIZE>programdata_account->const_meta->dlen ) ) {
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

      /* Max msg_sz: 41 - 2 + 20 = 57 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( instr_ctx,
        "Extended ProgramData account by %u bytes", additional_bytes );

      } FD_BORROWED_ACCOUNT_DROP( programdata_account );

      break;
    }
    default: {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* process_instruction_inner() */
/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L394-L564 */
int
fd_bpf_loader_program_execute( fd_exec_instr_ctx_t * ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    /* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L491-L529 */
    fd_borrowed_account_t * program_account = NULL;

    /* TODO: Agave uses `get_last_program_key`, we should have equivalent semantics:
       https://github.com//anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L491-L492 */
    fd_pubkey_t const *     program_id      = &ctx->instr->program_id_pubkey;
    int err = fd_txn_borrowed_account_view_idx( ctx->txn_ctx, ctx->instr->program_id, &program_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "Borrowed account lookup failed for program account" )); // custom log
      return err;
    }

    /* Program management instruction */
    if( FD_UNLIKELY( !memcmp( &fd_solana_native_loader_id, program_account->const_meta->info.owner, sizeof(fd_pubkey_t) ) ) ) {
      if( FD_UNLIKELY( !memcmp( &fd_solana_bpf_loader_upgradeable_program_id, program_id, sizeof(fd_pubkey_t) ) ) ) {
        FD_EXEC_CU_UPDATE( ctx, UPGRADEABLE_LOADER_COMPUTE_UNITS );
        return process_loader_upgradeable_instruction( ctx );
      } else if( FD_UNLIKELY( !memcmp( &fd_solana_bpf_loader_program_id, program_id, sizeof(fd_pubkey_t) ) ) ) {
        FD_EXEC_CU_UPDATE( ctx, DEFAULT_LOADER_COMPUTE_UNITS );
        fd_log_collector_msg_literal( ctx, "BPF loader management instructions are no longer supported" );
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      } else if( FD_UNLIKELY( !memcmp( &fd_solana_bpf_loader_deprecated_program_id, program_id, sizeof(fd_pubkey_t) ) ) ) {
        FD_EXEC_CU_UPDATE( ctx, DEPRECATED_LOADER_COMPUTE_UNITS );
        fd_log_collector_msg_literal( ctx, "Deprecated loader is no longer supported" );
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      } else {
        fd_log_collector_msg_literal( ctx, "Invalid BPF loader id" );
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L532-L549 */
    /* Program invocation. Any invalid programs will be caught here or at the program load. */
    if( FD_UNLIKELY( !program_account->const_meta->info.executable ) ) {
      fd_log_collector_msg_literal( ctx, "Program is not executable" );
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    /* Make sure the program is not in the blacklist */
    if( FD_UNLIKELY( fd_bpf_is_in_program_blacklist( ctx->slot_ctx, &ctx->instr->program_id_pubkey ) ) ) {
      fd_log_collector_msg_literal( ctx, "Program is not cached" );
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
      accounts, they're uninitialized and shouldn't be executed as well.

      For the former case the slot that the
      program was last updated in is in the program data account.
      This means that if the slot in the program data account is greater than or
      equal to the current execution slot, then the account is in a
      'LoadedProgramType::DelayVisiblity' state.

      The latter case as described above is a tombstone account which is in a Closed
      state. This occurs when a program data account is closed. However, our cache
      does not track this. Instead, this can be checked for by seeing if the program
      account's respective program data account is uninitialized. This should only
      happen when the account is closed. 
      
      Every error that comes out of this block is mapped to an InvalidAccountData instruction error in Agave. */

    fd_borrowed_account_t * program_acc_view = NULL;
    int read_result = fd_txn_borrowed_account_view_idx( ctx->txn_ctx, ctx->instr->program_id, &program_acc_view );
    if( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    fd_account_meta_t const * metadata = program_acc_view->const_meta;
    uchar is_deprecated = !memcmp( metadata->info.owner, &fd_solana_bpf_loader_deprecated_program_id, sizeof(fd_pubkey_t) );

    if( !memcmp( metadata->info.owner, &fd_solana_bpf_loader_upgradeable_program_id, sizeof(fd_pubkey_t) ) ) {
      fd_bpf_upgradeable_loader_state_t program_account_state = {0};
      err = fd_bpf_loader_v3_program_get_state( ctx, program_account, &program_account_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state read for program account failed" )); // custom log
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/program_loader.rs#L96-L98 
         Program account and program data account discriminants get checked when loading in program accounts
         into the program cache. If the discriminants are incorrect, the program is marked as closed. */
      if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_program( &program_account_state ) ) ) {
        fd_log_collector_msg_literal( ctx, "Program is not deployed" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      fd_borrowed_account_t * program_data_account = NULL;
      fd_pubkey_t * programdata_pubkey = (fd_pubkey_t *)&program_account_state.inner.program.programdata_address;
      err = fd_txn_borrowed_account_executable_view( ctx->txn_ctx, programdata_pubkey, &program_data_account );
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "Borrowed account lookup for program data account failed" )); // custom log
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      if( FD_UNLIKELY( program_data_account->const_meta->dlen<PROGRAMDATA_METADATA_SIZE ) ) {
        fd_log_collector_msg_literal( ctx, "Program is not deployed" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      fd_bpf_upgradeable_loader_state_t program_data_account_state = {0};
      err = fd_bpf_loader_v3_program_get_state( ctx, program_data_account, &program_data_account_state );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "Bpf state read for program data account failed" )); // custom log
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/program_loader.rs#L100-L104 
         Same as above comment. Program data discriminant must be set correctly. */
      if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_program_data( &program_data_account_state ) ) ) {
        /* The account is closed. */
        fd_log_collector_msg_literal( ctx, "Program is not deployed" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      ulong program_data_slot = program_data_account_state.inner.program_data.slot;
      if( FD_UNLIKELY( program_data_slot>=ctx->slot_ctx->slot_bank.slot ) ) {
        /* The account was likely just deployed or upgraded. Corresponds to
          'LoadedProgramType::DelayVisibility' */
        fd_log_collector_msg_literal( ctx, "Program is not deployed" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }
    }

    /* This should NEVER fail. */
    fd_sbpf_validated_program_t * prog = NULL;
    if( FD_UNLIKELY( fd_bpf_load_cache_entry( ctx->slot_ctx, &ctx->instr->program_id_pubkey, &prog )!=0 ) ) {
      FD_LOG_ERR(( "Failed to load program from bpf cache." ));
    }

    return execute( ctx, prog, is_deprecated );
  } FD_SCRATCH_SCOPE_END;
}
