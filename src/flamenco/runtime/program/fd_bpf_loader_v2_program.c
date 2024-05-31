#include "fd_bpf_loader_v2_program.h"

#include "../fd_account.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../vm/fd_vm.h"
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

int
fd_bpf_loader_v2_user_execute( fd_exec_instr_ctx_t ctx ) {
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
fd_base58_decode_64( "2f3MQXT1hPA28DCrF7Rdr9XcYfUzUDWqTL2mNmTSG5ZeVzpQo5nhzfAm2ZAY6kS81NRrHGwEocz3EbGvzK8caDjW", sig);
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

int
fd_bpf_loader_v2_program_execute( fd_exec_instr_ctx_t ctx ) {
  do {
    int err = fd_exec_consume_cus( ctx.txn_ctx, 570UL );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}
