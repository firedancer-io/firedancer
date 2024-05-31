#include "fd_bpf_loader_v3_program.h"

#include "../fd_account.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../../vm/fd_vm.h"
#include "fd_bpf_loader_serialization.h"
#include "fd_bpf_program_util.h"
#include "fd_native_cpi.h"

#include <stdio.h>

static fd_account_meta_t const *
read_bpf_upgradeable_loader_state( fd_exec_instr_ctx_t * instr_ctx,
                                   fd_pubkey_t const * program_acc,
                                   fd_bpf_upgradeable_loader_state_t * result,
                                   int * opt_err ) {

  fd_borrowed_account_t * rec = NULL;
  int err = fd_instr_borrowed_account_view( instr_ctx, program_acc, &rec );
  if( err ) {
    *opt_err = err;
    return NULL;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = rec->const_data,
    .dataend = rec->const_data + rec->const_meta->dlen,
    .valloc  = instr_ctx->valloc,
  };

  if ( fd_bpf_upgradeable_loader_state_decode( result, &ctx ) ) {
    FD_LOG_DEBUG(("fd_bpf_upgradeable_loader_state_decode failed"));
    *opt_err = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return NULL;
  }

  return rec->const_meta;  /* UGLY!!!!! */
}

fd_account_meta_t const *
read_bpf_upgradeable_loader_state_for_program( fd_exec_txn_ctx_t * txn_ctx,
                                               uchar program_id,
                                               fd_bpf_upgradeable_loader_state_t * result,
                                               int * opt_err ) {

  fd_borrowed_account_t * rec = NULL;
  int err = fd_txn_borrowed_account_view_idx( txn_ctx, program_id, &rec );
  if( err ) {
    *opt_err = err;
    return NULL;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = rec->const_data,
    .dataend = rec->const_data + rec->const_meta->dlen,
    .valloc  = txn_ctx->valloc,
  };

  if ( fd_bpf_upgradeable_loader_state_decode( result, &ctx ) ) {
    FD_LOG_DEBUG(("fd_bpf_upgradeable_loader_state_decode failed"));
    *opt_err = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return NULL;
  }

  return rec->const_meta;  /* UGLY!!!!! */
}

int write_bpf_upgradeable_loader_state( fd_exec_instr_ctx_t * instr_ctx, fd_pubkey_t const * program_acc, fd_bpf_upgradeable_loader_state_t const * loader_state) {
  int err = 0;
  ulong encoded_loader_state_size = fd_bpf_upgradeable_loader_state_size( loader_state );

  fd_borrowed_account_t * acc_data_rec = NULL;

  err = fd_instr_borrowed_account_modify( instr_ctx, program_acc, encoded_loader_state_size, &acc_data_rec );
  if( err != FD_ACC_MGR_SUCCESS ) {
    return err;
  }

  fd_bincode_encode_ctx_t ctx;
  ctx.data = acc_data_rec->data;
  ctx.dataend = (char*)ctx.data + encoded_loader_state_size;

  if ( fd_bpf_upgradeable_loader_state_encode( loader_state, &ctx ) ) {
    FD_LOG_ERR(("fd_bpf_upgradeable_loader_state_encode failed"));
  }

  if (encoded_loader_state_size > acc_data_rec->meta->dlen)
    acc_data_rec->meta->dlen = encoded_loader_state_size;

  acc_data_rec->meta->slot = instr_ctx->slot_ctx->slot_bank.slot;
  return 0;
}

// This is literally called before every single instruction execution... To make it fast we are duplicating some code
int
fd_bpf_loader_v3_is_executable( fd_exec_slot_ctx_t * slot_ctx,
                                fd_pubkey_t const *  pubkey ) {
  int err = 0;
  fd_account_meta_t const * m = fd_acc_mgr_view_raw(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *) pubkey, NULL, &err);
  if (FD_UNLIKELY( !fd_acc_exists( m ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  if( memcmp( m->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t)) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  if( m->info.executable != 1) {
    return FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = (uchar *)m + m->hlen,
    .dataend = (char *) ctx.data + m->dlen,
    .valloc  = slot_ctx->valloc,
  };

  fd_bpf_upgradeable_loader_state_t loader_state;
  if ( fd_bpf_upgradeable_loader_state_decode( &loader_state, &ctx ) ) {
    FD_LOG_WARNING(("fd_bpf_upgradeable_loader_state_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  if( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Check if programdata is closed */
  fd_account_meta_t const * programdata_meta = (fd_account_meta_t const *) fd_acc_mgr_view_raw(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *) &loader_state.inner.program.programdata_address, NULL, &err);
  if (FD_UNLIKELY(!fd_acc_exists(programdata_meta))) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_bincode_destroy_ctx_t ctx_d = { .valloc = slot_ctx->valloc };
  fd_bpf_upgradeable_loader_state_destroy( &loader_state, &ctx_d );


  return 0;
}

int
fd_bpf_loader_v3_user_execute( fd_exec_instr_ctx_t ctx ) {
  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( ctx.valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls );
  /* Load program */

  ulong input_sz = 0;
  ulong pre_lens[256];
  uchar * input = fd_bpf_loader_input_serialize_aligned(ctx, &input_sz, pre_lens);
  if( input==NULL ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_sbpf_validated_program_t * prog = NULL;
  if( fd_bpf_load_cache_entry( ctx.slot_ctx, &ctx.instr->program_id_pubkey, &prog ) != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );

  fd_vm_init(
      /* vm        */ vm,
      /* instr_ctx */ &ctx,
      /* heap_max  */ ctx.txn_ctx->heap_size, /* TODO configure heap allocator */
      /* entry_cu  */ ctx.txn_ctx->compute_meter,
      /* rodata    */ fd_sbpf_validated_program_rodata( prog ),
      /* rodata_sz */ prog->rodata_sz,
      /* text      */ (ulong *)((ulong)fd_sbpf_validated_program_rodata( prog ) + (ulong)prog->text_off), /* Note: text_off is byte offset */
      /* text_cnt  */ prog->text_cnt,
      /* text_off  */ prog->text_off,
      /* entry_pc  */ prog->entry_pc,
      /* calldests */ prog->calldests,
      /* syscalls  */ syscalls,
      /* input     */ input,
      /* input_sz  */ input_sz,
      /* trace     */ NULL,
      /* sha       */ sha
  );

  // FD_LOG_DEBUG(("Starting CUs %lu", ctx.txn_ctx->compute_meter));

#ifdef FD_DEBUG_SBPF_TRACES
uchar * signature = (uchar*)vm->instr_ctx->txn_ctx->_txn_raw->raw + vm->instr_ctx->txn_ctx->txn_descriptor->signature_off;
uchar   sig[64];
fd_base58_decode_64( "LKBxtETTpyVDbW1kT5fFucSpmdPoXfKW8QUxdzE8ggwCaXayByPbceQA6KwqGy2WNh89aAG3r2Qjm9VNY9FPtw9", sig );
if( FD_UNLIKELY( !memcmp( signature, sig, 64UL ) ) ) {
  ulong event_max      = 1UL<<30;
  ulong event_data_max = 2048UL;
  vm->trace = fd_vm_trace_join( fd_vm_trace_new( fd_valloc_malloc(
    ctx.txn_ctx->valloc, fd_vm_trace_align(), fd_vm_trace_footprint( event_max, event_data_max ) ), event_max, event_data_max ) );
  if( FD_UNLIKELY( !vm->trace ) ) FD_LOG_ERR(( "unable to create trace" ));
}
#endif

//int validate_err = fd_vm_validate( &vm );
//if( FD_UNLIKELY( validate_err ) ) FD_LOG_ERR(( "fd_vm_validate failed (%i-%s)", validate_err, fd_vm_strerror( validate_err ) ));
//FD_LOG_WARNING(( "fd_vm_validate success" ));

  int exec_err = fd_vm_exec( vm );

#ifdef FD_DEBUG_SBPF_TRACES
if( FD_UNLIKELY( vm->trace ) ) {
  int err = fd_vm_trace_printf( vm->trace, vm->syscalls );
  if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "fd_vm_trace_printf failed (%i-%s)", err, fd_vm_strerror( err ) ));
  fd_valloc_free( ctx.txn_ctx->valloc, fd_vm_trace_delete( fd_vm_trace_leave( vm->trace ) ) );
}
#endif

  ctx.txn_ctx->compute_meter = vm->cu;

//FD_LOG_DEBUG(( "fd_vm_exec: %i-%s, ic: %lu, pc: %lu, ep: %lu, r0: %lu, cu: %lu, frame_cnt: %lu",
//               exec_err, fd_vm_strerror( exec_err ), vm.ic, vm.pc, vm.entry_pc, vm.reg[0], vm.cu, vm.frame_cnt ));
//FD_LOG_WARNING(( "log coll - len: %lu %s", vm.log_collector.buf ));

  if( FD_UNLIKELY( exec_err ) ) {
    fd_valloc_free( ctx.valloc, input );
    //FD_LOG_WARNING(("fd_vm_exec failed (%i-%s)", exec_err, fd_log_strerror( exec_err ) ));
    // TODO: vm should report this error
    return -1;
  }

  if( FD_UNLIKELY( vm->reg[0] ) ) {
    fd_valloc_free( ctx.valloc, input );
    //FD_LOG_WARNING(( "reg[0] %lu", vm.reg[0] ));
    //TODO: vm should report this error
    return -1;
  }

  if( fd_bpf_loader_input_deserialize_aligned(ctx, pre_lens, input, input_sz) != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  return 0;
}

static int
setup_program( fd_exec_instr_ctx_t * ctx,
               uchar const *     program_data,
               ulong             program_data_len) {
  fd_sbpf_elf_info_t  _elf_info[1];
  fd_sbpf_elf_info_t * elf_info = fd_sbpf_elf_peek( _elf_info, program_data, program_data_len );
  if( FD_UNLIKELY( !elf_info ) ) {
    FD_LOG_HEXDUMP_WARNING(("Program data hexdump", program_data, program_data_len));
    FD_LOG_WARNING(("Elf info failing"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate rodata segment */
  void * rodata = fd_valloc_malloc( ctx->valloc, 32UL,  elf_info->rodata_footprint );
  if (!rodata) {
    /* TODO this is obviously wrong */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate program buffer */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( ctx->valloc, prog_align, prog_footprint ), elf_info, rodata );
  FD_TEST( prog );

  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( ctx->valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls );
  /* Load program */

  if(  0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls ) ) {
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
  }

  fd_vm_t vm = {
    .instr_ctx = ctx,
    .heap_max  = ctx->txn_ctx->heap_size,
    .entry_cu  = ctx->txn_ctx->compute_meter,
    .rodata    = prog->rodata,
    .rodata_sz = prog->rodata_sz,
    .text      = prog->text,
    .text_cnt  = prog->text_cnt,
    .text_off  = prog->text_off, /* FIXME: What if text_off is not multiple of 8 */
    .entry_pc  = prog->entry_pc,
    .calldests = prog->calldests,
    .syscalls  = syscalls,
    .input     = NULL,
    .input_sz  = 0,
    .trace     = NULL,
    .sha       = NULL,
  };

  int err = fd_vm_validate( &vm );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_vm_validate failed (%i-%s)", err, fd_vm_strerror( err ) ));

  fd_valloc_free( ctx->valloc,  fd_sbpf_program_delete( prog ) );
  fd_valloc_free( ctx->valloc,  fd_sbpf_syscalls_delete( syscalls ) );
  fd_valloc_free( ctx->valloc, rodata );
  return 0;
}

static int
common_close_account( fd_exec_instr_ctx_t                 ctx,
                      fd_pubkey_t const *                 authority_acc,
                      fd_account_meta_t *                 close_acc_metadata,
                      fd_account_meta_t *                 recipient_acc_metadata,
                      fd_bpf_upgradeable_loader_state_t * loader_state,
                      fd_pubkey_t const *                 close_acc ) {
  fd_pubkey_t * authority_address;
  switch( loader_state->discriminant ) {
  case fd_bpf_upgradeable_loader_state_enum_buffer:
    authority_address = loader_state->inner.buffer.authority_address;
    break;
  case fd_bpf_upgradeable_loader_state_enum_program_data:
    authority_address = loader_state->inner.program_data.upgrade_authority_address;
    break;
  default:
    FD_LOG_CRIT(( "entered unreachable code (%u)", loader_state->discriminant ));
  }

  if (!authority_address) {
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  if (memcmp(authority_address, authority_acc, sizeof(fd_pubkey_t)) != 0) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }


  if ( !fd_instr_acc_is_signer_idx( ctx.instr, 2 ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  recipient_acc_metadata->info.lamports += close_acc_metadata->info.lamports;
  close_acc_metadata->info.lamports = 0;

  loader_state->discriminant = fd_bpf_upgradeable_loader_state_enum_uninitialized;

  return write_bpf_upgradeable_loader_state( &ctx, close_acc, loader_state );
}

int
fd_bpf_loader_v3_program_execute( fd_exec_instr_ctx_t ctx ) {
  /* Deserialize the Stake instruction */
  uchar const * data            = ctx.instr->data;

  fd_bpf_upgradeable_loader_program_instruction_t instruction;
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.valloc  = ctx.valloc;

  int decode_err;
  if ( ( decode_err = fd_bpf_upgradeable_loader_program_instruction_decode( &instruction, &decode_ctx ) ) ) {
    FD_LOG_DEBUG(("fd_bpf_upgradeable_loader_program_instruction_decode failed: err code: %d, %d", decode_err, ctx.instr->data_sz));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs = ctx.txn_ctx->accounts;

  if( fd_bpf_upgradeable_loader_program_instruction_is_initialize_buffer( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_bpf_upgradeable_loader_state_t loader_state;
    fd_pubkey_t const * buffer_acc = &txn_accs[instr_acc_idxs[0]];

    int err = 0;
    if (FD_UNLIKELY(!read_bpf_upgradeable_loader_state( &ctx, buffer_acc, &loader_state, &err ))) {
      // TODO: Fix leaks...
      return err;
    }

    if( !fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[1]];
    loader_state.discriminant = fd_bpf_upgradeable_loader_state_enum_buffer;
    loader_state.inner.buffer.authority_address = (fd_pubkey_t *)authority_acc;

    return write_bpf_upgradeable_loader_state( &ctx, buffer_acc, &loader_state );
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_write( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    // FIXME: Do we need to check writable?

    fd_pubkey_t const * buffer_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[1]];

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, buffer_acc, &loader_state, &err)) {
      return err;
    }

    if( !fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if( loader_state.inner.buffer.authority_address==NULL ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
    }

    if( memcmp( authority_acc, loader_state.inner.buffer.authority_address, sizeof(fd_pubkey_t) )!=0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if( !fd_instr_acc_is_signer_idx( ctx.instr, 1 ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    // fd_funk_rec_t const * buffer_con_rec = NULL;
    fd_borrowed_account_t * buffer_acc_view = NULL;
    int read_result = fd_instr_borrowed_account_view( &ctx, buffer_acc, &buffer_acc_view );

    if (FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS )) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    fd_account_meta_t const * buffer_acc_metadata = buffer_acc_view->const_meta;

    ulong offset = fd_ulong_sat_add(fd_bpf_upgradeable_loader_state_size( &loader_state ), instruction.inner.write.offset);
    ulong write_end = fd_ulong_sat_add( offset, instruction.inner.write.bytes_len );
    if( buffer_acc_metadata->dlen < write_end ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    fd_borrowed_account_t * buffer_acc_modify = NULL;
    int write_result = fd_instr_borrowed_account_modify(&ctx, buffer_acc, 0, &buffer_acc_modify);
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to get writable handle to buffer data" ));
      return write_result;
    }

    uchar *             buffer_acc_data = buffer_acc_modify->data;

    fd_memcpy( buffer_acc_data + offset, instruction.inner.write.bytes, instruction.inner.write.bytes_len );
    return FD_EXECUTOR_INSTR_SUCCESS;

  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_deploy_with_max_data_len( &instruction ) ) {
    // TODO: the trace count might need to be incremented
    if( ctx.instr->acct_cnt < 4 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t const * payer_acc       = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * programdata_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t const * program_acc     = &txn_accs[instr_acc_idxs[2]];
    fd_pubkey_t const * buffer_acc      = &txn_accs[instr_acc_idxs[3]];
    fd_pubkey_t const * rent_acc        = &txn_accs[instr_acc_idxs[4]];
    fd_pubkey_t const * clock_acc       = &txn_accs[instr_acc_idxs[5]];

    if( ctx.instr->acct_cnt < 8 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[7]];

    fd_borrowed_account_t * program_rec = NULL;
    int result = fd_instr_borrowed_account_view(&ctx, program_acc, &program_rec);
    if( FD_UNLIKELY( result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    fd_bpf_upgradeable_loader_state_t program_loader_state;

    int err = 0;
    if( !read_bpf_upgradeable_loader_state( &ctx, program_acc, &program_loader_state, &err ) ) {
      FD_LOG_WARNING(("Fail here"));
      return err;
    }

    if (!fd_bpf_upgradeable_loader_state_is_uninitialized(&program_loader_state)) {
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    if (program_rec->const_meta->dlen < SIZE_OF_PROGRAM) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    if (program_rec->const_meta->info.lamports < fd_rent_exempt_minimum_balance( ctx.slot_ctx, program_rec->const_meta->dlen )) {
      return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT;
    }

    fd_borrowed_account_t * buffer_rec = NULL;
    result = fd_instr_borrowed_account_view( &ctx, buffer_acc, &buffer_rec );
    if( FD_UNLIKELY( result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    fd_bpf_upgradeable_loader_state_t buffer_acc_loader_state;
    err = 0;
    if ( !read_bpf_upgradeable_loader_state( &ctx, buffer_acc, &buffer_acc_loader_state, &err ) ) {
      FD_LOG_DEBUG(( "failed to read account metadata" ));
      return err;
    }
    if ( !fd_bpf_upgradeable_loader_state_is_buffer( &buffer_acc_loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    if ( buffer_acc_loader_state.inner.buffer.authority_address == NULL ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if ( memcmp( buffer_acc_loader_state.inner.buffer.authority_address, authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if ( !fd_instr_acc_is_signer_idx( ctx.instr, 7 ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    ulong buffer_data_len = fd_ulong_sat_sub( buffer_rec->const_meta->dlen, BUFFER_METADATA_SIZE );
    ulong programdata_len = fd_ulong_sat_add( PROGRAMDATA_METADATA_SIZE, instruction.inner.deploy_with_max_data_len.max_data_len );
    if ( buffer_rec->const_meta->dlen < BUFFER_METADATA_SIZE || buffer_data_len == 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if ( instruction.inner.deploy_with_max_data_len.max_data_len < buffer_data_len ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    if ( programdata_len > MAX_PERMITTED_DATA_LENGTH ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    // let (derived_address, bump_seed) =
    //             Pubkey::find_program_address(&[new_program_id.as_ref()], program_id);
    //         if derived_address != programdata_key {
    //             ic_logger_msg!(log_collector, "ProgramData address is not derived");
    //             return Err(InstructionError::InvalidArgument);
    //         }

    // Drain buffer lamports to payer
    int write_result = fd_instr_borrowed_account_modify( &ctx, buffer_acc, 0UL, &buffer_rec );
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    fd_borrowed_account_t * payer = NULL;
    write_result = fd_instr_borrowed_account_modify( &ctx, payer_acc, 0UL, &payer );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    /* Drain the buffer account to the payer before paying for the programdata account */
    // FIXME: Do checked addition
    ulong buffer_lamports = buffer_rec->meta->info.lamports;
    payer->meta->info.lamports += buffer_lamports;
    // TODO: Does this mean this account is dead?
    buffer_rec->meta->info.lamports  = 0;

    // TODO: deploy program
    err = setup_program( &ctx, buffer_rec->data + BUFFER_METADATA_SIZE, buffer_data_len );
    if ( err != 0 ) {
      return err;
    }

    /* Actually invoke the system program via native cpi */
    fd_system_program_instruction_create_account_t create_acct;
    create_acct.lamports = fd_rent_exempt_minimum_balance(ctx.slot_ctx, programdata_len);
    create_acct.space = programdata_len;
    create_acct.owner = ctx.instr->program_id_pubkey;

    fd_system_program_instruction_t instr;
    instr.discriminant = fd_system_program_instruction_enum_create_account;
    instr.inner.create_account = create_acct;

    /* Setup the accounts passed into the system program create call. Index zero and
       one are the from and to accounts respectively for the transfer. The buffer
       account is also passed in here. */
    FD_SCRATCH_SCOPE_BEGIN {
      fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t *)
                                              fd_scratch_alloc( FD_VM_RUST_ACCOUNT_META_ALIGN, 2 * sizeof(fd_vm_rust_account_meta_t) );
      fd_native_cpi_create_account_meta( payer_acc, 1, 1, &acct_metas[0] );
      fd_native_cpi_create_account_meta( programdata_acc, 1, 1, &acct_metas[1] );
      fd_pubkey_t signers[2];
      ulong signers_cnt = 2;
      signers[0] = *payer_acc;
      signers[1] = *programdata_acc;

      err = fd_native_cpi_execute_system_program_instruction( &ctx, &instr, acct_metas, 2, signers, signers_cnt );
      if (err != 0) {
        return err;
      }
    } FD_SCRATCH_SCOPE_END;

    ulong total_size = PROGRAMDATA_METADATA_SIZE + instruction.inner.deploy_with_max_data_len.max_data_len;
    fd_borrowed_account_t * programdata_rec = NULL;
    int modify_err = fd_instr_borrowed_account_modify( &ctx, programdata_acc, total_size, &programdata_rec );
    FD_TEST( modify_err == FD_ACC_MGR_SUCCESS );
    fd_account_meta_t * meta = programdata_rec->meta;
    uchar * acct_data        = programdata_rec->data;

    fd_bpf_upgradeable_loader_state_t program_data_acc_loader_state = {
      .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
      .inner.program_data.slot = ctx.slot_ctx->slot_bank.slot,
      .inner.program_data.upgrade_authority_address = (fd_pubkey_t *)authority_acc
    };

    fd_bincode_encode_ctx_t encode_ctx;
    encode_ctx.data = acct_data;
    encode_ctx.dataend = acct_data + fd_bpf_upgradeable_loader_state_size(&program_data_acc_loader_state);
    if ( fd_bpf_upgradeable_loader_state_encode( &program_data_acc_loader_state, &encode_ctx ) ) {
      FD_LOG_ERR(("fd_bpf_upgradeable_loader_state_encode failed"));
      fd_memset( acct_data, 0, fd_bpf_upgradeable_loader_state_size(&program_data_acc_loader_state) );
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    meta->dlen = PROGRAMDATA_METADATA_SIZE + instruction.inner.deploy_with_max_data_len.max_data_len;
    meta->info.executable = 0;
    fd_memcpy(&meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t));
    meta->info.lamports = fd_rent_exempt_minimum_balance(ctx.slot_ctx, meta->dlen);
    meta->info.rent_epoch = 0;

    buffer_data_len = fd_ulong_sat_sub(buffer_rec->meta->dlen, BUFFER_METADATA_SIZE);

    err = fd_instr_borrowed_account_view(&ctx, buffer_acc, &buffer_rec);
    fd_memcpy( acct_data + PROGRAMDATA_METADATA_SIZE, buffer_rec->const_data + BUFFER_METADATA_SIZE, buffer_data_len );
    // fd_memset( acct_data+PROGRAMDATA_METADATA_SIZE+buffer_data_len, 0, instruction.inner.deploy_with_max_data_len.max_data_len-buffer_data_len );
      // FD_LOG_WARNING(("AAA: %x", *(acct_data+meta->dlen-3)));
    programdata_rec->meta->slot = ctx.slot_ctx->slot_bank.slot;

    write_result = fd_instr_borrowed_account_modify( &ctx, program_acc, 0UL, &program_rec);
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    fd_bpf_upgradeable_loader_state_t program_acc_loader_state;
    // FIXME: HANDLE ERRORS!
    err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, program_acc, &program_acc_loader_state, &err ))
      return err;

    program_acc_loader_state.discriminant = fd_bpf_upgradeable_loader_state_enum_program;
    fd_memcpy(&program_acc_loader_state.inner.program.programdata_address, programdata_acc, sizeof(fd_pubkey_t));

    write_result = write_bpf_upgradeable_loader_state( &ctx, program_acc, &program_acc_loader_state );
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_DEBUG(( "failed to write loader state "));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    err = fd_account_set_executable2( &ctx, program_acc, program_rec->meta, 1 );
    if (err != 0)
      return err;

    (void)clock_acc;
    (void)rent_acc;

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_upgrade( &instruction ) ) {
    if( ctx.instr->acct_cnt < 7 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t const * programdata_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * program_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t const * buffer_acc = &txn_accs[instr_acc_idxs[2]];
    fd_pubkey_t const * spill_acc = &txn_accs[instr_acc_idxs[3]];
    fd_pubkey_t const * rent_acc = &txn_accs[instr_acc_idxs[4]];
    fd_pubkey_t const * clock_acc = &txn_accs[instr_acc_idxs[5]];
    fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[6]];

    fd_borrowed_account_t * program_acc_rec = NULL;
    int read_result = fd_instr_borrowed_account_view( &ctx, program_acc, &program_acc_rec );
    if( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    fd_sol_sysvar_clock_t clock;
    FD_TEST( fd_sysvar_clock_read( &clock, ctx.slot_ctx ) );

    // Is program executable?
    if( !program_acc_rec->const_meta->info.executable ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE;
    }

    // Is program writable?
    if( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[1] ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    // Is program owner the BPF upgradeable loader?
    if ( memcmp( program_acc_rec->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) {
      FD_LOG_WARNING(("C"));
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }
    if( 0==memcmp( spill_acc->key, buffer_acc->key, 32UL ) )
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
    if( 0==memcmp( spill_acc->key, programdata_acc->key, 32UL ) )
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

    fd_bpf_upgradeable_loader_state_t program_acc_loader_state;
    int err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, program_acc, &program_acc_loader_state, &err)) {
      FD_LOG_DEBUG(( "failed to read account metadata" ));
      return err;
    }

    if( !fd_bpf_upgradeable_loader_state_is_program( &program_acc_loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if( memcmp( &program_acc_loader_state.inner.program.programdata_address, programdata_acc, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_bpf_upgradeable_loader_state_t buffer_acc_loader_state;
    err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, buffer_acc, &buffer_acc_loader_state, &err )) {
      FD_LOG_DEBUG(( "failed to read account metadata" ));
      return err;
    }
    if( !fd_bpf_upgradeable_loader_state_is_buffer( &buffer_acc_loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    if( buffer_acc_loader_state.inner.buffer.authority_address==NULL ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if( memcmp( buffer_acc_loader_state.inner.buffer.authority_address, authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if ( !fd_instr_acc_is_signer_idx( ctx.instr, 6 ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    fd_borrowed_account_t * buffer_acc_view = NULL;
    read_result = fd_instr_borrowed_account_view( &ctx, buffer_acc, &buffer_acc_view );
    if (FD_UNLIKELY(read_result != FD_ACC_MGR_SUCCESS)) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    fd_account_meta_t const * buffer_acc_metadata = buffer_acc_view->const_meta;
    uchar const *             buffer_acc_data     = buffer_acc_view->const_data;

    ulong buffer_data_len = fd_ulong_sat_sub(buffer_acc_metadata->dlen, BUFFER_METADATA_SIZE);
    ulong buffer_lamports = buffer_acc_metadata->info.lamports;
    if( buffer_acc_metadata->dlen < BUFFER_METADATA_SIZE || buffer_data_len==0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_borrowed_account_t * programdata_acc_modify = NULL;
    err = fd_instr_borrowed_account_modify( &ctx, programdata_acc, 0, &programdata_acc_modify);
    if( err != FD_ACC_MGR_SUCCESS ) {
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    fd_account_meta_t * programdata_acc_metadata = programdata_acc_modify->meta;
    uchar * programdata_acc_data                 = programdata_acc_modify->data;
    ulong programdata_data_len                   = programdata_acc_metadata->dlen;

    ulong programdata_balance_required = fd_rent_exempt_minimum_balance( ctx.slot_ctx, programdata_data_len);
    if (programdata_balance_required < 1) {
      programdata_balance_required = 1;
    }

    if (programdata_data_len < fd_ulong_sat_add(PROGRAMDATA_METADATA_SIZE, buffer_data_len)) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    if (programdata_acc_metadata->info.lamports + programdata_acc_metadata->info.lamports < programdata_balance_required) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
    fd_bpf_upgradeable_loader_state_t programdata_loader_state;

    err = 0;
    if( !read_bpf_upgradeable_loader_state( &ctx, programdata_acc, &programdata_loader_state, &err ) )
      return err;
    if (!fd_bpf_upgradeable_loader_state_is_program_data(&programdata_loader_state)) {
      FD_LOG_WARNING(("Invalid ProgramData account"));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if (FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_program_redeployment_cooldown) && clock.slot == programdata_loader_state.inner.program_data.slot) {
      FD_LOG_WARNING(("Program was deployed in this block already"));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    if (!programdata_loader_state.inner.program_data.upgrade_authority_address) {
      FD_LOG_WARNING(("Program not upgradeable"));
      return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
    }

    if (memcmp(programdata_loader_state.inner.program_data.upgrade_authority_address, authority_acc, sizeof(fd_pubkey_t)) != 0) {
      FD_LOG_WARNING(("Incorrect upgrade authority provided"));
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if ( !fd_instr_acc_is_signer_idx( ctx.instr, 6 ) ) {
      FD_LOG_WARNING(("Upgrade authority did not sign"));
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    // TODO: deploy program properly

    /* https://github.com/solana-labs/solana/blob/4d452fc5e9fd465c50b2404354bbc5d84a30fbcb/programs/bpf_loader/src/lib.rs#L898 */
    /* TODO are those bounds checked */
    err = setup_program(&ctx, buffer_acc_data + BUFFER_METADATA_SIZE, SIZE_OF_PROGRAM + programdata_data_len);
    if (err != 0) {
      return err;
    }

    fd_borrowed_account_t * buffer_acc_new = NULL;
    err = fd_instr_borrowed_account_modify( &ctx, buffer_acc, 0, &buffer_acc_new);

    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    fd_account_meta_t * buffer_acc_metadata_new = buffer_acc_new->meta;

    // TODO: min size?
    fd_borrowed_account_t * spill_acc_modify = NULL;
    err = fd_instr_borrowed_account_modify( &ctx, spill_acc, 0, &spill_acc_modify );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }
    fd_account_meta_t * spill_acc_metadata = spill_acc_modify->meta;

    fd_bpf_upgradeable_loader_state_t program_data_acc_loader_state = {
      .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
      .inner.program_data.slot = clock.slot,
      .inner.program_data.upgrade_authority_address = (fd_pubkey_t *)authority_acc,
    };

    fd_bincode_encode_ctx_t encode_ctx = {
      .data = programdata_acc_data,
      .dataend = programdata_acc_data + fd_bpf_upgradeable_loader_state_size(&program_data_acc_loader_state),
    };
    if ( fd_bpf_upgradeable_loader_state_encode( &program_data_acc_loader_state, &encode_ctx ) ) {
      FD_LOG_ERR(("fd_bpf_upgradeable_loader_state_encode failed"));
      fd_memset( programdata_acc_data, 0, fd_bpf_upgradeable_loader_state_size(&program_data_acc_loader_state) );
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    uchar const * buffer_content = buffer_acc_data + BUFFER_METADATA_SIZE;
    uchar * programdata_content = programdata_acc_data + PROGRAMDATA_METADATA_SIZE;
    ulong programdata_content_len = fd_ulong_sat_sub( programdata_acc_metadata->dlen, PROGRAMDATA_METADATA_SIZE );
    fd_memcpy(programdata_content, buffer_content, buffer_data_len);
    fd_memset(programdata_content + buffer_data_len, 0, programdata_content_len - buffer_data_len);

    spill_acc_metadata->info.lamports += programdata_acc_metadata->info.lamports + buffer_lamports - programdata_balance_required;
    buffer_acc_metadata_new->info.lamports = 0;
    programdata_acc_metadata->info.lamports = programdata_balance_required;

    if (FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_program_redeployment_cooldown)) {
      int err;
      if (!fd_account_set_data_length2(&ctx, buffer_acc_metadata_new, buffer_acc, BUFFER_METADATA_SIZE, 0, &err)) {
        return err;
      }
    }

    write_bpf_upgradeable_loader_state( &ctx, programdata_acc, &program_data_acc_loader_state );
    (void)clock_acc;
    (void)rent_acc;

    return FD_EXECUTOR_INSTR_SUCCESS;

  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_set_authority( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t * new_authority_acc = NULL;
    if( ctx.instr->acct_cnt >= 3 ) {
      new_authority_acc = fd_alloca( 1, sizeof(fd_pubkey_t) );
      *new_authority_acc = txn_accs[instr_acc_idxs[2]];
    }

    fd_pubkey_t const * loader_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * present_authority_acc = &txn_accs[instr_acc_idxs[1]];

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if ( !read_bpf_upgradeable_loader_state( &ctx, loader_acc, &loader_state, &err ) ) {
      // FIXME: HANDLE ERRORS!
      return err;
    }

    if ( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if ( new_authority_acc==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if ( loader_state.inner.buffer.authority_address==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if ( memcmp( loader_state.inner.buffer.authority_address, present_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if ( !fd_instr_acc_is_signer_idx( ctx.instr, 1 ) ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      loader_state.inner.buffer.authority_address = new_authority_acc;
      return write_bpf_upgradeable_loader_state( &ctx, loader_acc, &loader_state );
    } else if ( fd_bpf_upgradeable_loader_state_is_program_data( &loader_state ) ) {
      if ( loader_state.inner.program_data.upgrade_authority_address==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if ( memcmp( loader_state.inner.program_data.upgrade_authority_address, present_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if ( !fd_instr_acc_is_signer_idx( ctx.instr, 1 ) ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      loader_state.inner.program_data.upgrade_authority_address = new_authority_acc;

      return write_bpf_upgradeable_loader_state( &ctx, loader_acc, &loader_state );
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_close( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t const * close_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * recipient_acc = &txn_accs[instr_acc_idxs[1]];

    if ( memcmp( close_acc, recipient_acc, sizeof(fd_pubkey_t) ) == 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if ( !read_bpf_upgradeable_loader_state( &ctx, close_acc, &loader_state, &err ) )
      return err;

    fd_borrowed_account_t * close_acc_rec = NULL;
    int write_result = fd_instr_borrowed_account_modify( &ctx, close_acc, 0UL, &close_acc_rec );
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    if ( FD_FEATURE_ACTIVE( ctx.slot_ctx, enable_program_redeployment_cooldown ) ) {
      if ( !fd_account_set_data_length2( &ctx, close_acc_rec->meta, close_acc, SIZE_OF_UNINITIALIZED, 0, &err ) ) {
        return err;
      }
    }

    fd_borrowed_account_t * recipient_acc_rec = NULL;
    write_result = fd_instr_borrowed_account_modify( &ctx, recipient_acc, 0UL, &recipient_acc_rec );
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    if( fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) {
      // FIXME: Do checked addition
      recipient_acc_rec->meta->info.lamports += close_acc_rec->meta->info.lamports;
      close_acc_rec->meta->info.lamports = 0;

      return FD_EXECUTOR_INSTR_SUCCESS;
    } else if ( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( ctx.instr->acct_cnt < 3 ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[2]];

      return common_close_account(ctx, authority_acc, close_acc_rec->meta, recipient_acc_rec->meta, &loader_state, close_acc);
    } else if ( fd_bpf_upgradeable_loader_state_is_program_data( &loader_state ) ) {
      if( ctx.instr->acct_cnt < 4 ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      fd_pubkey_t const * program_acc = &txn_accs[instr_acc_idxs[3]];

      fd_borrowed_account_t * program_acc_rec = NULL;
      write_result = fd_instr_borrowed_account_modify( &ctx, program_acc, 0UL, &program_acc_rec);
      if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      if (!fd_instr_acc_is_writable(ctx.instr, program_acc)) {
        // TODO Log: "Program account is not writable"
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      if (memcmp(program_acc_rec->meta->info.owner, &ctx.instr->program_id_pubkey, sizeof(fd_pubkey_t)) != 0) {
        // TODO Log: "Program account not owned by loader"
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
      }

      if (FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_program_redeployment_cooldown)) {
        fd_sol_sysvar_clock_t clock;
        fd_sysvar_clock_read( &clock, ctx.slot_ctx );
        if (clock.slot == loader_state.inner.program_data.slot) {
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }
      }

      fd_bpf_upgradeable_loader_state_t program_acc_state;
      err = 0;
      if (!read_bpf_upgradeable_loader_state( &ctx, program_acc, &program_acc_state, &err ))
        return err;

      if (!fd_bpf_upgradeable_loader_state_is_program( &program_acc_state )) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      if (memcmp(&program_acc_state.inner.program.programdata_address, close_acc, sizeof(fd_pubkey_t)) != 0) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[2]];

      err = common_close_account(ctx, authority_acc, close_acc_rec->meta, recipient_acc_rec->meta, &loader_state, close_acc);
      if (err != 0) {
        return err;
      }

      /* We need to at least touch the program account */
      program_acc_rec->meta->slot = ctx.slot_ctx->slot_bank.slot;

      // TODO: needs to completed
      if (FD_FEATURE_ACTIVE(ctx.slot_ctx, delay_visibility_of_program_deployment)) {
        // invoke_context.programs_modified_by_tx.replenish(
        //     program_key,
        //     Arc::new(LoadedProgram::new_tombstone(
        //         clock.slot,
        //         LoadedProgramType::Closed,
        //     )),
        // );
      } else {
        // invoke_context
        //     .programs_updated_only_for_global_cache
        //     .replenish(
        //         program_key,
        //         Arc::new(LoadedProgram::new_tombstone(
        //             clock.slot,
        //             LoadedProgramType::Closed,
        //         )),
        //     );
      }
      return FD_EXECUTOR_INSTR_SUCCESS;
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_set_authority_checked( &instruction ) ) {
    if (!FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_bpf_loader_set_authority_checked_ix)) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    if( ctx.instr->acct_cnt < 3 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t const * new_authority_acc = &txn_accs[instr_acc_idxs[2]];

    fd_pubkey_t const * loader_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * present_authority_acc = &txn_accs[instr_acc_idxs[1]];

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, loader_acc, &loader_state, &err)) {
      // FIXME: HANDLE ERRORS!
      return err;
    }

    if( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( loader_state.inner.buffer.authority_address==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if ( memcmp( loader_state.inner.buffer.authority_address, present_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if ( !fd_instr_acc_is_signer_idx( ctx.instr, 1 ) ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      if ( !fd_instr_acc_is_signer_idx( ctx.instr, 2 ) ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      *loader_state.inner.buffer.authority_address = *new_authority_acc;
      return write_bpf_upgradeable_loader_state( &ctx, loader_acc, &loader_state );
    } else if( fd_bpf_upgradeable_loader_state_is_program_data( &loader_state ) ) {
      if( loader_state.inner.program_data.upgrade_authority_address==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if ( memcmp( loader_state.inner.program_data.upgrade_authority_address, present_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if ( !fd_instr_acc_is_signer_idx( ctx.instr, 1 ) ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      if ( !fd_instr_acc_is_signer_idx( ctx.instr, 2 ) ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      *loader_state.inner.program_data.upgrade_authority_address = *new_authority_acc;

      return write_bpf_upgradeable_loader_state( &ctx, loader_acc, &loader_state );
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_close( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t const * close_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * recipient_acc = &txn_accs[instr_acc_idxs[1]];

    if ( memcmp( close_acc, recipient_acc, sizeof(fd_pubkey_t) )==0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, close_acc, &loader_state, &err ))
      return err;

    fd_borrowed_account_t * close_acc_rec = NULL;
    int write_result = fd_instr_borrowed_account_modify( &ctx, close_acc, 0UL, &close_acc_rec );
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    if (FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_program_redeployment_cooldown)) {
      if (!fd_account_set_data_length2(&ctx, close_acc_rec->meta, close_acc, SIZE_OF_UNINITIALIZED, 0, &err)) {
        return err;
      }
      return FD_EXECUTOR_INSTR_SUCCESS;
    }

    fd_borrowed_account_t * recipient_acc_rec = NULL;
    write_result = fd_instr_borrowed_account_modify( &ctx, recipient_acc, 0UL, &recipient_acc_rec);
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    if( fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) {
      // FIXME: Do checked addition
      recipient_acc_rec->meta->info.lamports += close_acc_rec->meta->info.lamports;
      close_acc_rec->meta    ->info.lamports = 0;

      return FD_EXECUTOR_INSTR_SUCCESS;
    } else if ( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( ctx.instr->acct_cnt < 3 ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[2]];

      return common_close_account(ctx, authority_acc, close_acc_rec->meta, recipient_acc_rec->meta, &loader_state, close_acc);
    } else if ( fd_bpf_upgradeable_loader_state_is_program_data( &loader_state ) ) {
      if( ctx.instr->acct_cnt < 4 ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      fd_pubkey_t const * program_acc = &txn_accs[instr_acc_idxs[3]];
      fd_borrowed_account_t * program_acc_rec = NULL;
      write_result = fd_instr_borrowed_account_modify( &ctx, program_acc, 0UL, &program_acc_rec );
      if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      if (!fd_instr_acc_is_writable(ctx.instr, program_acc)) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      if (memcmp(program_acc_rec->meta->info.owner, &ctx.instr->program_id_pubkey, sizeof(fd_pubkey_t)) != 0) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
      }

      if (FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_program_redeployment_cooldown)) {
        fd_sol_sysvar_clock_t clock;
        fd_sysvar_clock_read( &clock, ctx.slot_ctx );
        if (clock.slot == loader_state.inner.program_data.slot) {
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }
      }

      fd_bpf_upgradeable_loader_state_t program_acc_state;
      err = 0;
      if (!read_bpf_upgradeable_loader_state( &ctx, program_acc, &program_acc_state, &err ))
        return err;

      if (!fd_bpf_upgradeable_loader_state_is_program( &program_acc_state )) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      if (memcmp(&program_acc_state.inner.program.programdata_address, close_acc, sizeof(fd_pubkey_t)) != 0) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[2]];

      err = common_close_account(ctx, authority_acc, close_acc_rec->meta, recipient_acc_rec->meta, &loader_state, close_acc);
      if (err != 0) {
        return err;
      }

      if (FD_FEATURE_ACTIVE(ctx.slot_ctx, delay_visibility_of_program_deployment)) {
        // invoke_context.programs_modified_by_tx.replenish(
        //     program_key,
        //     Arc::new(LoadedProgram::new_tombstone(
        //         clock.slot,
        //         LoadedProgramType::Closed,
        //     )),
        // );
      } else {
        // invoke_context
        //     .programs_updated_only_for_global_cache
        //     .replenish(
        //         program_key,
        //         Arc::new(LoadedProgram::new_tombstone(
        //             clock.slot,
        //             LoadedProgramType::Closed,
        //         )),
        //     );
      }
      return FD_EXECUTOR_INSTR_SUCCESS;
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_extend_program( &instruction ) ) {
    if (!FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_bpf_loader_extend_program_ix)) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    uint additional_bytes = instruction.inner.extend_program.additional_bytes;

    if (additional_bytes == 0) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    const uint PROGRAM_DATA_ACCOUNT_INDEX = 0;
    const uint PROGRAM_ACCOUNT_INDEX = 1;
    // const uint OPTIONAL_SYSTEM_PROGRAM_ACCOUNT_INDEX = 2;
    const uint OPTIONAL_PAYER_ACCOUNT_INDEX = 3;

    fd_pubkey_t const * programdata_acc = &txn_accs[instr_acc_idxs[PROGRAM_DATA_ACCOUNT_INDEX]];
    fd_pubkey_t const * program_acc = &txn_accs[instr_acc_idxs[PROGRAM_ACCOUNT_INDEX]];

    fd_borrowed_account_t * programdata_acc_rec = NULL;
    int result = fd_instr_borrowed_account_view( &ctx, programdata_acc, &programdata_acc_rec );
    if (result != 0) {
      return result;
    }

    if (memcmp(programdata_acc_rec->const_meta->info.owner, &ctx.instr->program_id_pubkey, sizeof(fd_pubkey_t)) != 0) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }

    if (!fd_instr_acc_is_writable(ctx.instr, programdata_acc)) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_borrowed_account_t * program_acc_rec = NULL;
    result = fd_instr_borrowed_account_view( &ctx, program_acc, &program_acc_rec );
    if (result != 0) {
      return result;
    }

    if (!fd_instr_acc_is_writable(ctx.instr, program_acc)) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    if (memcmp(program_acc_rec->const_meta->info.owner, &ctx.instr->program_id_pubkey, sizeof(fd_pubkey_t)) != 0) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }

    fd_bpf_upgradeable_loader_state_t program_acc_state;
    int err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, program_acc, &program_acc_state, &err ))
      return err;

    if (!fd_bpf_upgradeable_loader_state_is_program( &program_acc_state )) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if (memcmp(&program_acc_state.inner.program.programdata_address, programdata_acc, sizeof(fd_pubkey_t)) != 0) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    ulong old_len = programdata_acc_rec->const_meta->dlen;
    ulong new_len = fd_ulong_sat_add(old_len, (ulong)additional_bytes);

    if (new_len > MAX_PERMITTED_DATA_LENGTH) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
    }

    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( &clock, ctx.slot_ctx );
    ulong clock_slot = clock.slot;

    fd_bpf_upgradeable_loader_state_t programdata_acc_state;
    err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, programdata_acc, &programdata_acc_state, &err ))
      return err;

    if (!fd_bpf_upgradeable_loader_state_is_program_data( &programdata_acc_state )) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if (clock_slot == programdata_acc_state.inner.program_data.slot) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    if (!programdata_acc_state.inner.program_data.upgrade_authority_address) {
      return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
    }

    fd_pubkey_t * upgrade_authority_address = programdata_acc_state.inner.program_data.upgrade_authority_address;

    ulong min_balance = fd_rent_exempt_minimum_balance(ctx.slot_ctx, new_len);
    if (min_balance < 1)
      min_balance = 1;

    ulong required_payment = fd_ulong_sat_sub(min_balance, programdata_acc_rec->const_meta->info.lamports);
    if (required_payment > 0) {
      fd_pubkey_t const * payer_key = &txn_accs[instr_acc_idxs[OPTIONAL_PAYER_ACCOUNT_INDEX]];
      (void) payer_key;
      // invoke_context.native_invoke(
      //     system_instruction::transfer(&payer_key, &programdata_key, required_payment)
      //         .into(),
      //     &[],
      // )?;
      fd_system_program_instruction_t instr = {0};
      instr.discriminant = fd_system_program_instruction_enum_transfer;
      instr.inner.transfer = required_payment;

      FD_SCRATCH_SCOPE_BEGIN {
        fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t*)
                                                  fd_scratch_alloc( FD_VM_RUST_ACCOUNT_META_ALIGN, 2 * sizeof(fd_vm_rust_account_meta_t) );
        fd_native_cpi_create_account_meta( payer_key,       1, 1, &acct_metas[0] );
        fd_native_cpi_create_account_meta( programdata_acc, 0, 1, &acct_metas[1] );

        fd_pubkey_t signers[1];
        ulong signers_cnt = 1;
        signers[0] = *payer_key;

        err = fd_native_cpi_execute_system_program_instruction(
          &ctx,
          &instr,
          acct_metas,
          2,
          signers,
          signers_cnt
        );
        if ( err ) {
          return err;
        }
      } FD_SCRATCH_SCOPE_END;
    }

    result = fd_instr_borrowed_account_modify(&ctx, programdata_acc, new_len, &programdata_acc_rec);
    if (result != 0)
      return result;

    err = 0;
    if (!fd_account_set_data_length2(&ctx, programdata_acc_rec->meta, programdata_acc, new_len, 0, &err)) {
      return err;
    }

    result = setup_program(&ctx, programdata_acc_rec->data, fd_ulong_sat_add(SIZE_OF_PROGRAM, new_len));

    programdata_acc_state.discriminant = fd_bpf_upgradeable_loader_state_enum_program_data;
    programdata_acc_state.inner.program_data.slot = clock_slot;
    program_acc_state.inner.program_data.upgrade_authority_address = upgrade_authority_address;


    return write_bpf_upgradeable_loader_state( &ctx, programdata_acc, &programdata_acc_state );
  } else {
    FD_LOG_WARNING(( "unsupported bpf upgradeable loader program instruction: discriminant: %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
}
