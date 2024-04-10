#include "fd_bpf_upgradeable_loader_program.h"

#include "../fd_account.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../vm/fd_vm_syscalls.h"
#include "../../vm/fd_vm_interp.h"
#include "../../vm/fd_vm_disasm.h"
#include "fd_bpf_loader_serialization.h"
#include "../../../util/scratch/fd_scratch.h"
#include "fd_bpf_program_util.h"

#include <stdio.h>

static char * trace_buf;

static void __attribute__((constructor)) make_buf(void) {
  trace_buf = (char*)malloc(256*1024);
}

static void __attribute__((destructor)) free_buf(void) {
  free(trace_buf);
}

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
int fd_executor_bpf_upgradeable_loader_program_is_executable_program_account( fd_exec_slot_ctx_t * slot_ctx, fd_pubkey_t const * pubkey ) {
  int err = 0;
  fd_account_meta_t const * m = fd_acc_mgr_view_raw(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *) pubkey, NULL, &err);
  if (FD_UNLIKELY( !fd_acc_exists( m ) ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  if( memcmp( m->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t)) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

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

  if( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  /* Check if programdata is closed */
  fd_account_meta_t const * programdata_meta = (fd_account_meta_t const *) fd_acc_mgr_view_raw(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *) &loader_state.inner.program.programdata_address, NULL, &err);
  if (FD_UNLIKELY(!fd_acc_exists(programdata_meta)))
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  fd_bincode_destroy_ctx_t ctx_d = { .valloc = slot_ctx->valloc };
  fd_bpf_upgradeable_loader_state_destroy( &loader_state, &ctx_d );


  return 0;
}

int fd_executor_bpf_upgradeable_loader_program_execute_program_instruction( fd_exec_instr_ctx_t ctx ) {
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

  // FD_LOG_DEBUG(("Starting CUs %lu", ctx.txn_ctx->compute_meter));
  fd_vm_exec_context_t vm_ctx = {
    .entrypoint          = (long)prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .compute_meter       = ctx.txn_ctx->compute_meter,
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( fd_sbpf_validated_program_rodata( prog ) + (prog->text_off) ),
    .instrs_sz           = prog->text_cnt,
    .instrs_offset       = prog->text_off,
    .syscall_map         = syscalls,
    .calldests           = prog->calldests,
    .input               = input,
    .input_sz            = input_sz,
    .read_only           = fd_sbpf_validated_program_rodata( prog ),
    .read_only_sz        = prog->rodata_sz,
    /* TODO configure heap allocator */
    .instr_ctx           = &ctx,
    .heap_sz = ctx.txn_ctx->heap_size,
    .due_insn_cnt = 0,
    .previous_instruction_meter = ctx.txn_ctx->compute_meter,
    .alloc               = {.offset = 0}
  };

  ulong trace_sz = 4 * 1024 * 1024;
  fd_vm_trace_entry_t * trace = NULL;
  fd_vm_trace_context_t trace_ctx;
  (void) trace_sz;
  (void) trace;
  (void) trace_ctx;

#ifdef FD_DEBUG_SBPF_TRACES

uchar * signature = (uchar*)vm_ctx.instr_ctx->txn_ctx->_txn_raw->raw + vm_ctx.instr_ctx->txn_ctx->txn_descriptor->signature_off;
uchar sig[64];
fd_base58_decode_64("4HydfWFZwN67UWTXQWBShcPLofLEePTekfzb1k8CwfiN3RN5hWgHRkDqq4D81aMZYkWgwnDDXMk3Uuhxxcgct8Z6", sig);
if (FD_UNLIKELY(memcmp(signature, sig, 64) == 0)) {

  trace = (fd_vm_trace_entry_t *)fd_valloc_malloc( ctx.txn_ctx->valloc, 8UL, trace_sz * sizeof(fd_vm_trace_entry_t));
  // trace = (fd_vm_trace_entry_t *)malloc(trace_sz * sizeof(fd_vm_trace_entry_t));
  trace_ctx.trace_entries_used = 0;
  trace_ctx.trace_entries_sz = trace_sz;
  trace_ctx.trace_entries = trace;
  trace_ctx.valloc = ctx.txn_ctx->valloc;
  vm_ctx.trace_ctx = &trace_ctx;
}

#endif

  memset(vm_ctx.register_file, 0, sizeof(vm_ctx.register_file));
  vm_ctx.register_file[1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm_ctx.register_file[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;


  // ulong validate_result = fd_vm_context_validate( &vm_ctx );
  // if (validate_result != FD_VM_SBPF_VALIDATE_SUCCESS) {
  //   FD_LOG_ERR(( "fd_vm_context_validate() failed: %lu", validate_result ));
  // }

  // FD_LOG_WARNING(( "fd_vm_context_validate() success" ));
  ulong interp_res;

#ifdef FD_DEBUG_SBPF_TRACES
  if (FD_UNLIKELY(memcmp(signature, sig, 64) == 0)) {
    interp_res = fd_vm_interp_instrs_trace( &vm_ctx );
  } else {
    interp_res = fd_vm_interp_instrs( &vm_ctx );
  }
#else
  interp_res = fd_vm_interp_instrs( &vm_ctx );
#endif
  if( interp_res != 0 ) {
    FD_LOG_ERR(( "fd_vm_interp_instrs() failed: %lu", interp_res ));
  }

#ifdef FD_DEBUG_SBPF_TRACES
  // FILE * trace_fd = fopen("trace.log", "w");
if (FD_UNLIKELY(memcmp(signature, sig, 64) == 0)) {
  ulong prev_cus = 0;
  for( ulong i = 0; i < trace_ctx.trace_entries_used; i++ ) {
    fd_vm_trace_entry_t trace_ent = trace[i];
    char * trace_buf_out = trace_buf;

    trace_buf_out += sprintf(trace_buf_out, "%5lu [%016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX] %5lu: ",
      trace_ent.ic,
      trace_ent.register_file[0],
      trace_ent.register_file[1],
      trace_ent.register_file[2],
      trace_ent.register_file[3],
      trace_ent.register_file[4],
      trace_ent.register_file[5],
      trace_ent.register_file[6],
      trace_ent.register_file[7],
      trace_ent.register_file[8],
      trace_ent.register_file[9],
      trace_ent.register_file[10],
      trace_ent.pc
    );
    ulong out_len = 0;
    fd_vm_disassemble_instr(&vm_ctx.instrs[trace[i].pc], trace[i].pc, vm_ctx.syscall_map, trace_buf_out, &out_len);
    trace_buf_out += out_len;
    trace_buf_out += sprintf(trace_buf_out, " %lu %lu\n", trace[i].cus, prev_cus - trace[i].cus);
    prev_cus = trace[i].cus;

    fd_vm_trace_mem_entry_t * mem_ent = trace_ent.mem_entries_head;
    ulong j = 0;
    while( j < trace_ent.mem_entries_used ) {
      j++;
      if( mem_ent->type == FD_VM_TRACE_MEM_ENTRY_TYPE_READ ) {
        ulong prev_mod = 0;
        // for( long k = (long)i-1; k >= 0; k-- ) {
        //   fd_vm_trace_entry_t prev_trace_ent = trace[k];
        //   if (prev_trace_ent.mem_entries_used > 0) {
        //     fd_vm_trace_mem_entry_t * prev_mem_ent = prev_trace_ent.mem_entries_head;
        //     for( ulong l = 0; l < prev_trace_ent.mem_entries_used; l++ ) {
        //       // fd_vm_trace_mem_entry_t prev_mem_ent = prev_trace_ent.mem_entries[l];
        //       if( prev_mem_ent->type == FD_VM_TRACE_MEM_ENTRY_TYPE_WRITE ) {
        //         if ((prev_mem_ent->addr <= mem_ent->addr && mem_ent->addr < prev_mem_ent->addr + prev_mem_ent->sz)
        //             || (mem_ent->addr <= prev_mem_ent->addr && prev_mem_ent->addr < mem_ent->addr + mem_ent->sz)) {
        //           prev_mod = (ulong)k;
        //           break;
        //         }
        //       }
        //       prev_mem_ent = prev_mem_ent->next;
        //     }
        //   }
        //   if (prev_mod != 0) {
        //     break;
        //   }
        // }

        trace_buf_out += sprintf(trace_buf_out, "        R: vm_addr: 0x%016lX, sz: %8lu, prev_ic: %8lu, data: ", mem_ent->addr, mem_ent->sz, prev_mod);
      } else {
        trace_buf_out += sprintf(trace_buf_out, "        W: vm_addr: 0x%016lX, sz: %8lu, data: ", mem_ent->addr, mem_ent->sz);
      }

      if (mem_ent->sz < 10*1024) {
        for( ulong k = 0; k < mem_ent->sz; k++ ) {
          trace_buf_out += sprintf(trace_buf_out, "%02X ", mem_ent->data[k]);
        }
      }


      fd_valloc_free(ctx.txn_ctx->valloc, mem_ent->data);

      trace_buf_out += sprintf(trace_buf_out, "\n");
      mem_ent = mem_ent->next;
    }
    trace_buf_out += sprintf(trace_buf_out, "\0");
    fputs(trace_buf, stderr);
  }
  // fclose(trace_fd);
  // free(trace);
  fd_vm_trace_context_destroy( &trace_ctx );
  fd_valloc_free( ctx.txn_ctx->valloc, trace);
  }
#endif

  ctx.txn_ctx->compute_meter = vm_ctx.compute_meter;

  #ifdef VLOG
  if (ctx.txn_ctx->slot_ctx->slot_bank.slot == 250555489) {
    FD_LOG_WARNING(( "fd_vm_interp_instrs() success: %lu, ic: %lu, pc: %lu, ep: %lu, r0: %lu, fault: %lu, cus: %lu", interp_res, vm_ctx.instruction_counter, vm_ctx.program_counter, vm_ctx.entrypoint, vm_ctx.register_file[0], vm_ctx.cond_fault, vm_ctx.compute_meter ));
  }
  #endif

  // FD_LOG_WARNING(( "log coll - len: %lu %s", vm_ctx.log_collector.buf ));

  if( vm_ctx.register_file[0]!=0 ) {
    fd_valloc_free( ctx.valloc, input);
    //FD_LOG_WARNING((" register_file[0] fail "));
    // TODO: vm should report this error
    return -1;
  }

  if( vm_ctx.cond_fault ) {
    fd_valloc_free( ctx.valloc, input);
    //FD_LOG_WARNING(("cond_fault fail"));
    // TODO: vm should report this error
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
    FD_LOG_HEXDUMP_WARNING(("Program data hexdumpppp", program_data, program_data_len));
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

  fd_vm_exec_context_t vm_ctx = {
    .entrypoint          = (long)prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( prog->text ),
    .instrs_sz           = prog->text_cnt,
    .instrs_offset       = prog->text_off,
    .syscall_map         = syscalls,
    .calldests           = prog->calldests,
    .input               = NULL,
    .input_sz            = 0,
    .read_only           = (uchar *)fd_type_pun_const(prog->rodata),
    .read_only_sz        = prog->rodata_sz,
    .heap_sz = ctx->txn_ctx->heap_size,
    /* TODO configure heap allocator */
    .instr_ctx           = ctx,
  };

  ulong validate_result = fd_vm_context_validate( &vm_ctx );
  if (validate_result != FD_VM_SBPF_VALIDATE_SUCCESS) {
    FD_LOG_ERR(( "fd_vm_context_validate() failed: %lu", validate_result ));
  }

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
                      uchar const *                       instr_acc_idxs,
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

  if (instr_acc_idxs[2] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  recipient_acc_metadata->info.lamports += close_acc_metadata->info.lamports;
  close_acc_metadata->info.lamports = 0;

  loader_state->discriminant = fd_bpf_upgradeable_loader_state_enum_uninitialized;

  return write_bpf_upgradeable_loader_state( &ctx, close_acc, loader_state );
}

int fd_executor_bpf_upgradeable_loader_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {
  /* Deserialize the Stake instruction */
  uchar const * data            = ctx.instr->data;

  fd_bpf_upgradeable_loader_program_instruction_t instruction;
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.valloc  = ctx.valloc;

  int decode_err;
  if ( ( decode_err = fd_bpf_upgradeable_loader_program_instruction_decode( &instruction, &decode_ctx ) ) ) {
    FD_LOG_DEBUG(("fd_bpf_upgradeable_loader_program_instruction_decode failed: err code: %d, %ld", decode_err, ctx.instr->data_sz));
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

    if(instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
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
    result = fd_instr_borrowed_account_view(&ctx, buffer_acc, &buffer_rec);
    if( FD_UNLIKELY( result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
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

    if( instr_acc_idxs[7] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    ulong buffer_data_len = fd_ulong_sat_sub(buffer_rec->const_meta->dlen, BUFFER_METADATA_SIZE);
    ulong programdata_len = fd_ulong_sat_add(PROGRAMDATA_METADATA_SIZE, instruction.inner.deploy_with_max_data_len.max_data_len);
    if (buffer_rec->const_meta->dlen < BUFFER_METADATA_SIZE || buffer_data_len == 0) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if (instruction.inner.deploy_with_max_data_len.max_data_len < buffer_data_len) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    if (programdata_len > MAX_PERMITTED_DATA_LENGTH) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    // let (derived_address, bump_seed) =
    //             Pubkey::find_program_address(&[new_program_id.as_ref()], program_id);
    //         if derived_address != programdata_key {
    //             ic_logger_msg!(log_collector, "ProgramData address is not derived");
    //             return Err(InstructionError::InvalidArgument);
    //         }

    // Drain buffer lamports to payer
    int write_result = fd_instr_borrowed_account_modify( &ctx, buffer_acc,0UL, &buffer_rec);
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

    // FIXME: Do checked addition
    ulong buffer_lamports = buffer_rec->meta->info.lamports;
    payer->meta->info.lamports += buffer_lamports;
    // TODO: Does this mean this account is dead?
    buffer_rec->meta->info.lamports  = 0;

    // TODO: deploy program
    err = setup_program(&ctx, buffer_rec->data + BUFFER_METADATA_SIZE, buffer_data_len);
    if (err != 0) {
      return err;
    }

    // Create program data account
    // fd_funk_rec_t * program_data_rec = NULL;
    ulong sz2 = PROGRAMDATA_METADATA_SIZE + instruction.inner.deploy_with_max_data_len.max_data_len;
    fd_borrowed_account_t * programdata_rec = NULL;
    int modify_err = fd_instr_borrowed_account_modify( &ctx, programdata_acc, sz2, &programdata_rec);
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

    // payer->meta->info.lamports += buffer_rec->meta->info.lamports;
    payer->meta->info.lamports -= buffer_lamports;
    buffer_data_len = fd_ulong_sat_sub(buffer_rec->meta->dlen, BUFFER_METADATA_SIZE);

    err = fd_instr_borrowed_account_view(&ctx, buffer_acc, &buffer_rec);
    fd_memcpy( acct_data+PROGRAMDATA_METADATA_SIZE, buffer_rec->const_data+BUFFER_METADATA_SIZE, buffer_data_len );
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

    err = fd_account_set_executable( &ctx, program_acc, program_rec->meta, 1 );
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

    if( instr_acc_idxs[6] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
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
      // TODO Log: "Invalid ProgramData account"
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if (FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_program_redeployment_cooldown) && clock.slot == programdata_loader_state.inner.program_data.slot) {
      // TODO Log: "Program was deployed in this block already"
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    if (!programdata_loader_state.inner.program_data.upgrade_authority_address) {
      // TODO Log: "Program not upgradeable"
      return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
    }

    if (memcmp(programdata_loader_state.inner.program_data.upgrade_authority_address, authority_acc, sizeof(fd_pubkey_t)) != 0) {
      // TODO Log: "Incorrect upgrade authority provided"
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if (instr_acc_idxs[6] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
      // TODO Log: "Upgrade authority did not sign"
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
    fd_memcpy(programdata_content, buffer_content, buffer_data_len);
    fd_memset(programdata_content + buffer_data_len, 0, programdata_acc_metadata->dlen-buffer_data_len);

    spill_acc_metadata->info.lamports += programdata_acc_metadata->info.lamports + buffer_lamports - programdata_balance_required;
    buffer_acc_metadata_new->info.lamports = 0;
    programdata_acc_metadata->info.lamports = programdata_balance_required;

    if (FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_program_redeployment_cooldown)) {
      int err;
      if (!fd_account_set_data_length(&ctx, buffer_acc_metadata_new, buffer_acc, BUFFER_METADATA_SIZE, 0, &err)) {
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
      new_authority_acc = fd_alloca(1, sizeof(fd_pubkey_t));
      *new_authority_acc = txn_accs[instr_acc_idxs[2]];
    }

    fd_pubkey_t const * loader_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t const * present_authority_acc = &txn_accs[instr_acc_idxs[1]];

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, loader_acc, &loader_state, &err)) {
      // FIXME: HANDLE ERRORS!
      return err;
    }

    if( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( new_authority_acc==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if( loader_state.inner.buffer.authority_address==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if ( memcmp( loader_state.inner.buffer.authority_address, present_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if( instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      loader_state.inner.buffer.authority_address = new_authority_acc;
      return write_bpf_upgradeable_loader_state( &ctx, loader_acc, &loader_state );
    } else if( fd_bpf_upgradeable_loader_state_is_program_data( &loader_state ) ) {
      if( loader_state.inner.program_data.upgrade_authority_address==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if ( memcmp( loader_state.inner.program_data.upgrade_authority_address, present_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if(instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
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

    if ( memcmp( close_acc, recipient_acc, sizeof(fd_pubkey_t) )==0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if (!read_bpf_upgradeable_loader_state( &ctx, close_acc, &loader_state, &err ))
      return err;

    fd_borrowed_account_t * close_acc_rec = NULL;
    int write_result = fd_instr_borrowed_account_modify( &ctx, close_acc, 0UL, &close_acc_rec);
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    if (FD_FEATURE_ACTIVE(ctx.slot_ctx, enable_program_redeployment_cooldown)) {
      if (!fd_account_set_data_length(&ctx, close_acc_rec->meta, close_acc, SIZE_OF_UNINITIALIZED, 0, &err)) {
        return err;
      }
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
      close_acc_rec->meta->info.lamports = 0;

      return FD_EXECUTOR_INSTR_SUCCESS;
    } else if ( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( ctx.instr->acct_cnt < 3 ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      fd_pubkey_t const * authority_acc = &txn_accs[instr_acc_idxs[2]];

      return common_close_account(ctx, authority_acc, close_acc_rec->meta, recipient_acc_rec->meta, instr_acc_idxs, &loader_state, close_acc);
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

      err = common_close_account(ctx, authority_acc, close_acc_rec->meta, recipient_acc_rec->meta, instr_acc_idxs, &loader_state, close_acc);
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

      if(instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      if(instr_acc_idxs[2] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
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

      if (instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      if (instr_acc_idxs[2] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
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
      if (!fd_account_set_data_length(&ctx, close_acc_rec->meta, close_acc, SIZE_OF_UNINITIALIZED, 0, &err)) {
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

      return common_close_account(ctx, authority_acc, close_acc_rec->meta, recipient_acc_rec->meta, instr_acc_idxs, &loader_state, close_acc);
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

      err = common_close_account(ctx, authority_acc, close_acc_rec->meta, recipient_acc_rec->meta, instr_acc_idxs, &loader_state, close_acc);
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
    }

    result = fd_instr_borrowed_account_modify(&ctx, programdata_acc, new_len, &programdata_acc_rec);
    if (result != 0)
      return result;

    err = 0;
    if (!fd_account_set_data_length(&ctx, programdata_acc_rec->meta, programdata_acc, new_len, 0, &err)) {
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
