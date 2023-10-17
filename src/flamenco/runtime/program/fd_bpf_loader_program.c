#include "fd_bpf_loader_program.h"

#include "../fd_account.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../../ballet/sbpf/fd_sbpf_maps.h"
#include "../../vm/fd_vm_syscalls.h"
#include "../../vm/fd_vm_interp.h"
#include "../../vm/fd_vm_disasm.h"
#include "fd_bpf_loader_serialization.h"

#include <stdio.h>

int
fd_executor_bpf_loader_program_is_executable_program_account( fd_exec_slot_ctx_t * slot_ctx,
                                                              fd_pubkey_t const *  pubkey ) {

  FD_BORROWED_ACCOUNT_DECL(rec);
  int read_result = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, pubkey, rec );
  if (read_result != FD_ACC_MGR_SUCCESS)
    return -1;

  if( memcmp( rec->const_meta->info.owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t)) ) {
    return -1;
  }

  if( rec->const_meta->info.executable != 1) {
    return -1;
  }

  return 0;
}

static int
setup_program(fd_exec_instr_ctx_t ctx, uchar * program_data, ulong program_data_len) {
  fd_sbpf_elf_info_t elf_info;
  fd_sbpf_elf_peek( &elf_info, program_data, program_data_len );

  /* Allocate rodata segment */
  void * rodata = fd_valloc_malloc( ctx.valloc, 1UL,  elf_info.rodata_footprint );
  if (!rodata) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate program buffer */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( ctx.valloc, prog_align, prog_footprint ), &elf_info, rodata );
  FD_TEST( prog );

  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( ctx.valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_ctx( syscalls, ctx.slot_ctx );
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
    .local_call_map      = prog->calldests,
    .input               = NULL,
    .input_sz            = 0,
    .read_only           = (uchar *)fd_type_pun_const(prog->rodata),
    .read_only_sz        = prog->rodata_sz,
    /* TODO configure heap allocator */
    .instr_ctx           = ctx,
  };

  ulong validate_result = fd_vm_context_validate( &vm_ctx );
  if (validate_result != FD_VM_SBPF_VALIDATE_SUCCESS) {
    FD_LOG_ERR(( "fd_vm_context_validate() failed: %lu", validate_result ));
  }

  fd_valloc_free( ctx.valloc,  fd_sbpf_program_delete( prog ) );
  fd_valloc_free( ctx.valloc,  fd_sbpf_syscalls_delete( syscalls ) );
  fd_valloc_free( ctx.valloc, rodata);
  return 0;
}


int fd_executor_bpf_loader_program_execute_program_instruction( fd_exec_instr_ctx_t ctx ) {
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  fd_pubkey_t * program_acc = &txn_accs[ctx.instr->program_id];

  FD_LOG_NOTICE(("BPF V2 PROG INSTR RUN! - slot: %lu, addr: %32J", ctx.slot_ctx->bank.slot, program_acc));

  int read_result = 0;
  uchar * raw_program_acc_data = (uchar *)fd_acc_mgr_view_raw(ctx.acc_mgr, ctx.funk_txn, program_acc, NULL, &read_result);
  if (FD_UNLIKELY(!FD_RAW_ACCOUNT_EXISTS(raw_program_acc_data))) {
    FD_LOG_WARNING(( "HELLO !!!!"));
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_account_meta_t * metadata = (fd_account_meta_t *)raw_program_acc_data;
  uchar * program_data = fd_account_get_data( metadata );
  ulong program_data_len = metadata->dlen;


  fd_sbpf_elf_info_t elf_info;
  fd_sbpf_elf_peek( &elf_info, program_data, program_data_len );

  /* Allocate rodata segment */

  void * rodata = fd_valloc_malloc( ctx.valloc, 1UL,  elf_info.rodata_footprint );
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
  FD_LOG_WARNING(( "fd_sbpf_program_load() success: %s", fd_sbpf_strerror() ));

  ulong input_sz = 0;
  ulong pre_lens[256];
  uchar * input = fd_bpf_loader_input_serialize_aligned(ctx, &input_sz, pre_lens);
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
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( prog->text ),
    .instrs_sz           = prog->text_cnt,
    .instrs_offset       = prog->text_off,
    .syscall_map         = syscalls,
    .local_call_map      = prog->calldests,
    .input               = input,
    .input_sz            = input_sz,
    .read_only           = (uchar *)fd_type_pun_const(prog->rodata),
    .read_only_sz        = prog->rodata_sz,
    /* TODO configure heap allocator */
    .instr_ctx           = ctx,
  };

  ulong trace_sz = 16 * 1024 * 1024;
  ulong trace_used = 0;
  fd_vm_trace_entry_t * trace = (fd_vm_trace_entry_t *)fd_valloc_malloc( ctx.valloc, 1UL, trace_sz * sizeof(fd_vm_trace_entry_t));

  memset(vm_ctx.register_file, 0, sizeof(vm_ctx.register_file));
  vm_ctx.register_file[1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm_ctx.register_file[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;


  // ulong validate_result = fd_vm_context_validate( &vm_ctx );
  // if (validate_result != FD_VM_SBPF_VALIDATE_SUCCESS) {
  //   FD_LOG_ERR(( "fd_vm_context_validate() failed: %lu", validate_result ));
  // }

  // FD_LOG_WARNING(( "fd_vm_context_validate() success" ));

  ulong interp_res = fd_vm_interp_instrs_trace( &vm_ctx, trace, trace_sz, &trace_used );
  if( interp_res != 0 ) {
    FD_LOG_ERR(( "fd_vm_interp_instrs() failed: %lu", interp_res ));
  }

  // TODO: make tracing an option!
  // FILE * trace_fd = fopen("trace.log", "w");

  for( ulong i = 0; i < trace_used; i++ ) {
    fd_vm_trace_entry_t trace_ent = trace[i];
    fprintf(stderr, "%5lu [%016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX] %5lu: ",
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
        trace_ent.pc+29 // FIXME: THIS OFFSET IS FOR TESTING ONLY
      );
    fd_vm_disassemble_instr(&vm_ctx.instrs[trace[i].pc], trace[i].pc, vm_ctx.syscall_map, vm_ctx.local_call_map, stderr);

    fprintf(stderr, "\n");
  }

  // fclose(trace_fd);
  fd_valloc_free( ctx.valloc, trace);

  fd_valloc_free( ctx.valloc,  fd_sbpf_program_delete( prog ) );
  fd_valloc_free( ctx.valloc,  fd_sbpf_syscalls_delete( syscalls ) );
  fd_valloc_free( ctx.valloc, rodata);

  FD_LOG_WARNING(( "fd_vm_interp_instrs() success: %lu, ic: %lu, pc: %lu, ep: %lu, r0: %lu, fault: %lu", interp_res, vm_ctx.instruction_counter, vm_ctx.program_counter, vm_ctx.entrypoint, vm_ctx.register_file[0], vm_ctx.cond_fault ));
  // FD_LOG_WARNING(( "log coll: %s", vm_ctx.log_collector.buf ));

  if( vm_ctx.register_file[0]!=0 ) {
    fd_valloc_free( ctx.valloc, input);
    // TODO: vm should report this error
    return -1;
  }

  if( vm_ctx.cond_fault ) {
    fd_valloc_free( ctx.valloc, input);
    // TODO: vm should report this error
    return -1;
  }

  fd_bpf_loader_input_deserialize_aligned(ctx, pre_lens, input, input_sz);

  return 0;
}

int fd_executor_bpf_loader_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {
  /* Deserialize the BPF Program instruction */
  uchar * data            = ctx.instr->data;

  fd_bpf_loader_program_instruction_t instruction;
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data    = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.valloc  = ctx.valloc;

  if( fd_bpf_loader_program_instruction_decode( &instruction, &decode_ctx ) ) {
    FD_LOG_DEBUG(("fd_bpf_loader_program_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  if( ctx.instr->acct_cnt < 1 ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
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

  fd_funk_rec_t const * con_rec = NULL;
  int read_result = 0;
  uchar const * raw = fd_acc_mgr_view_raw( ctx.acc_mgr, ctx.funk_txn, program_acc, &con_rec, &read_result );
  if (FD_UNLIKELY(!FD_RAW_ACCOUNT_EXISTS(raw))) {
    FD_LOG_WARNING(( "failed to read account metadata" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }
  fd_account_meta_t const * program_acc_metadata = (fd_account_meta_t const *)raw;
  if ( memcmp(program_acc_metadata->info.owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  if( fd_bpf_loader_program_instruction_is_write( &instruction ) ) {
    ulong write_end = fd_ulong_sat_add( instruction.inner.write.offset, instruction.inner.write.bytes_len );
    if( program_acc_metadata->dlen < write_end ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    int err = 0;
    uchar * raw_mut = fd_acc_mgr_modify_raw( ctx.acc_mgr, ctx.funk_txn, program_acc, 0, 0UL, con_rec, NULL, &err );
    if( FD_UNLIKELY( !raw_mut ) ) {
      FD_LOG_WARNING(( "failed to get writable handle to program data" ));
      return err;
    }

    fd_account_meta_t * metadata_mut     = (fd_account_meta_t *)raw_mut;
    uchar *             program_acc_data = raw_mut + metadata_mut->hlen;

    fd_memcpy( program_acc_data + instruction.inner.write.offset, instruction.inner.write.bytes, instruction.inner.write.bytes_len );

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if( fd_bpf_loader_program_instruction_is_finalize( &instruction ) ) {
    /* Check that Instruction Account 0 is a signer */
    if( instr_acc_idxs[0] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    fd_pubkey_t const * program_acc = &txn_accs[instr_acc_idxs[0]];

    int err = 0;
    uchar * raw_mut = fd_acc_mgr_modify_raw( ctx.acc_mgr, ctx.funk_txn, program_acc, 0, 0UL, con_rec, NULL, &err );
    if( FD_UNLIKELY( !raw_mut ) ) {
      FD_LOG_WARNING(( "failed to get writable handle to program data" ));
      return err;
    }

    fd_account_meta_t * metadata_mut     = (fd_account_meta_t *)raw_mut;
    uchar *             program_acc_data = fd_account_get_data(metadata_mut);

    // TODO: deploy program properly
    err = setup_program(ctx, program_acc_data, metadata_mut->dlen);
    if (err != FD_EXECUTOR_INSTR_SUCCESS) {
      return err;
    }

    err = fd_account_set_executable( &ctx, program_acc, metadata_mut, 1 );
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
