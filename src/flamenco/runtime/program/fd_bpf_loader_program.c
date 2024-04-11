#include "fd_bpf_loader_program.h"

#include "../fd_account.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../vm/fd_vm_syscalls.h"
#include "../../vm/fd_vm_interp.h"
#include "../../vm/fd_vm_disasm.h"
#include "fd_bpf_loader_serialization.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../context/fd_exec_instr_ctx.h"

#include <stdio.h>

static char * trace_buf;

static void __attribute__((constructor)) make_buf(void) {
  trace_buf = (char*)malloc(256*1024);
}

static void __attribute__((destructor)) free_buf(void) {
  free(trace_buf);
}

int
fd_executor_bpf_loader_program_is_executable_program_account( fd_exec_slot_ctx_t * slot_ctx,
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

static int
setup_program(fd_exec_instr_ctx_t * ctx, uchar * program_data, ulong program_data_len) {
  fd_sbpf_elf_info_t elf_info;
  if (fd_sbpf_elf_peek( &elf_info, program_data, program_data_len ) == NULL) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate rodata segment */
  void * rodata = fd_valloc_malloc( ctx->valloc, 32UL, elf_info.rodata_footprint );
  if (!rodata) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate program buffer */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( ctx->valloc, prog_align, prog_footprint ), &elf_info, rodata );
  FD_TEST( prog );

  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( ctx->valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_ctx( syscalls, ctx->slot_ctx );
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
    /* TODO configure heap allocator */
    .instr_ctx           = ctx,
    .heap_sz = ctx->txn_ctx->heap_size,
  };

  ulong validate_result = fd_vm_context_validate( &vm_ctx );
  if (validate_result != FD_VM_SBPF_VALIDATE_SUCCESS) {
    FD_LOG_ERR(( "fd_vm_context_validate() failed: %lu", validate_result ));
  }

  fd_valloc_free( ctx->valloc,  fd_sbpf_program_delete( prog ) );
  fd_valloc_free( ctx->valloc,  fd_sbpf_syscalls_delete( syscalls ) );
  fd_valloc_free( ctx->valloc, rodata);
  return 0;
}


int fd_executor_bpf_loader_program_execute_program_instruction( fd_exec_instr_ctx_t ctx ) {
  // FIXME: the program account is not in the instruction accounts?
  fd_borrowed_account_t * program_acc_view = NULL;
  int read_result = fd_txn_borrowed_account_view_idx( ctx.txn_ctx, ctx.instr->program_id, &program_acc_view );
  if (FD_UNLIKELY(read_result != FD_ACC_MGR_SUCCESS)) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_account_meta_t const * metadata = program_acc_view->const_meta;
  uchar const * program_data               = program_acc_view->const_data;
  ulong program_data_len = metadata->dlen;

  long dt = -fd_log_wallclock();
  fd_sbpf_elf_info_t elf_info;
  if (fd_sbpf_elf_peek( &elf_info, program_data, program_data_len ) == NULL) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate rodata segment */

  void * rodata = fd_valloc_malloc( ctx.valloc, 32UL,  elf_info.rodata_footprint );
  FD_TEST( rodata );

  /* Allocate program buffer */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( ctx.valloc, prog_align, prog_footprint ), &elf_info, rodata );
  FD_TEST( prog );

  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( ctx.valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls );
  /* Load program */

  if(  0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls ) ) {
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
  }
  dt += fd_log_wallclock();
  (void)dt;
  // FD_LOG_WARNING(( "sbpf load: %32J - time: %6.6f ms", ctx.instr->program_id_pubkey.key, (double)dt*1e-6 ));

  ulong input_sz = 0;
  ulong pre_lens[256];
  uchar * input;
  if (FD_UNLIKELY(memcmp(metadata->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t)) == 0)) {
    input = fd_bpf_loader_input_serialize_unaligned(ctx, &input_sz, pre_lens);
  } else {
    input = fd_bpf_loader_input_serialize_aligned(ctx, &input_sz, pre_lens);
  }

  if( input==NULL ) {
    fd_valloc_free( ctx.valloc,  fd_sbpf_program_delete( prog ) );
    fd_valloc_free( ctx.valloc,  fd_sbpf_syscalls_delete( syscalls ) );
    fd_valloc_free( ctx.valloc, rodata);
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_vm_exec_context_t vm_ctx = {
    .entrypoint          = (long)prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .compute_meter       = ctx.txn_ctx->compute_meter,
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( prog->text ),
    .instrs_sz           = prog->text_cnt,
    .instrs_offset       = prog->text_off,
    .syscall_map         = syscalls,
    .calldests           = prog->calldests,
    .input               = input,
    .input_sz            = input_sz,
    .read_only           = (uchar *)fd_type_pun_const(prog->rodata),
    .read_only_sz        = prog->rodata_sz,
    .heap_sz = FD_VM_DEFAULT_HEAP_SZ,
    /* TODO configure heap allocator */
    .instr_ctx           = &ctx,
    .due_insn_cnt        = 0,
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
fd_base58_decode_64( "4HydfWFZwN67UWTXQWBShcPLofLEePTekfzb1k8CwfiN3RN5hWgHRkDqq4D81aMZYkWgwnDDXMk3Uuhxxcgct8Z6", sig);
if (memcmp(signature, sig, 64) == 0) {
  trace = (fd_vm_trace_entry_t *)fd_valloc_malloc( ctx.txn_ctx->valloc, 8UL, trace_sz * sizeof(fd_vm_trace_entry_t));
  // trace = (fd_vm_trace_entry_t *)malloc( trace_sz * sizeof(fd_vm_trace_entry_t));
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
  if (memcmp(signature, sig, 64) == 0) {
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
if (memcmp(signature, sig, 64) == 0) {
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

      if (mem_ent->sz < 10*1024) {
        for( ulong k = 0; k < mem_ent->sz; k++ ) {
          trace_buf_out += sprintf(trace_buf_out, "%02X ", mem_ent->data[k]);
        }
      }


      fd_valloc_free(ctx.txn_ctx->valloc, mem_ent->data);

      trace_buf_out += sprintf(trace_buf_out, "\n");
      mem_ent = mem_ent->next;
    }

    }
    trace_buf_out += sprintf(trace_buf_out, "\0");
    fputs(trace_buf, stderr);
  // fclose(trace_fd);
  // free(trace);
  }
  fd_vm_trace_context_destroy( &trace_ctx );
  fd_valloc_free( ctx.txn_ctx->valloc, trace);
}
#endif
  ctx.txn_ctx->compute_meter = vm_ctx.compute_meter;

  fd_valloc_free( ctx.valloc,  fd_sbpf_program_delete( prog ) );
  fd_valloc_free( ctx.valloc,  fd_sbpf_syscalls_delete( syscalls ) );
  fd_valloc_free( ctx.valloc, rodata);

#ifdef VLOG
  FD_LOG_WARNING(( "fd_vm_interp_instrs() success: %lu, ic: %lu, pc: %lu, ep: %lu, r0: %lu, fault: %lu, cus: %lu", interp_res, vm_ctx.instruction_counter, vm_ctx.program_counter, vm_ctx.entrypoint, vm_ctx.register_file[0], vm_ctx.cond_fault, vm_ctx.compute_meter ));
#endif
  // FD_LOG_WARNING(( "log coll: %s", vm_ctx.log_collector.buf ));

  if( vm_ctx.register_file[0]!=0 ) {
    fd_valloc_free( ctx.valloc, input);
    return -1;
  }

  if( vm_ctx.cond_fault ) {
    fd_valloc_free( ctx.valloc, input);
    return -1;
  }

  if (FD_UNLIKELY(memcmp(metadata->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t)) == 0)) {
    fd_bpf_loader_input_deserialize_unaligned(ctx, pre_lens, input, input_sz);
  } else {
    fd_bpf_loader_input_deserialize_aligned(ctx, pre_lens, input, input_sz);
  }

  return 0;
}

int fd_executor_bpf_loader_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {
  if( ctx.instr->acct_cnt < 1 ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  uchar * data            = ctx.instr->data;

  /* Deserialize the BPF Program instruction */
  fd_bpf_loader_program_instruction_t instruction;
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data    = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.valloc  = ctx.valloc;


  if( fd_bpf_loader_program_instruction_decode( &instruction, &decode_ctx ) ) {
    FD_LOG_DEBUG(("fd_bpf_loader_program_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs = ctx.txn_ctx->accounts;

  /* Check that Instruction Account 0 is a signer */
  if( instr_acc_idxs[0] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

   /* FIXME: will need to actually find last program_acct in this instruction but practically no one does this. Yet another
       area where there seems to be a lot of overhead... See solana_runtime::Accounts::load_transaction_accounts */
  // fd_pubkey_t * bpf_loader_acc = &txn_accs[ctx.txn_ctx->txn_descriptor->acct_addr_cnt - 1];
  // if ( memcmp( bpf_loader_acc, ctx.global->solana_bpf_loader_program, sizeof(fd_pubkey_t) ) != 0 ) {
  //   return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  // }

  fd_pubkey_t const * program_acc = &txn_accs[instr_acc_idxs[0]];

  fd_borrowed_account_t * acc = NULL;
  int read_result = fd_instr_borrowed_account_view( &ctx, program_acc, &acc );
  if (FD_UNLIKELY(!fd_acc_exists(acc->const_meta))) {
    FD_LOG_WARNING(( "failed to read account metadata, err: %d", read_result ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }
  fd_account_meta_t const * program_acc_metadata = acc->const_meta;
  if ( memcmp(program_acc_metadata->info.owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) {
    FD_LOG_WARNING(("A"));
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  if( fd_bpf_loader_program_instruction_is_write( &instruction ) ) {
    ulong write_end = fd_ulong_sat_add( instruction.inner.write.offset, instruction.inner.write.bytes_len );
    if( program_acc_metadata->dlen < write_end ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    fd_borrowed_account_t * modify_acc = NULL;
    int err = fd_instr_borrowed_account_modify( &ctx, program_acc, 0, &modify_acc );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to get writable handle to program data" ));
      return err;
    }

    uchar *             program_acc_data = modify_acc->data;

    fd_memcpy( program_acc_data + instruction.inner.write.offset, instruction.inner.write.bytes, instruction.inner.write.bytes_len );

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if( fd_bpf_loader_program_instruction_is_finalize( &instruction ) ) {
    /* Check that Instruction Account 0 is a signer */
    if( instr_acc_idxs[0] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    fd_pubkey_t const * program_acc = &txn_accs[instr_acc_idxs[0]];

    fd_borrowed_account_t * modify_acc = NULL;
    int err = fd_instr_borrowed_account_modify(&ctx, program_acc, 0, &modify_acc);
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to get writable handle to program data" ));
      return err;
    }

    fd_account_meta_t * metadata_mut     = modify_acc->meta;
    uchar *             program_acc_data = modify_acc->data;

    // TODO: deploy program properly
    err = setup_program(&ctx, program_acc_data, metadata_mut->dlen);
    if (err != FD_EXECUTOR_INSTR_SUCCESS) {
      return err;
    }

    err = fd_account_set_executable2( &ctx, program_acc, metadata_mut, 1 );
    if (err != FD_EXECUTOR_INSTR_SUCCESS) {
      return err;
    }
    // ???? what does this do
    //fd_acc_mgr_set_metadata(ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, program_acc_metadata);

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else {
    FD_LOG_WARNING(( "unsupported bpf loader program instruction: discriminant: %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
}
