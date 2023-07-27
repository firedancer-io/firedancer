#include "fd_bpf_loader_program.h"

#include "../fd_account.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../../ballet/sbpf/fd_sbpf_maps.h"
#include "../../vm/fd_vm_syscalls.h"
#include "../../vm/fd_vm_interp.h"
#include "../../vm/fd_vm_disasm.h"

#include <stdio.h>

int fd_executor_bpf_loader_program_is_executable_program_account( fd_global_ctx_t * global, fd_pubkey_t * pubkey ) {
  fd_account_meta_t metadata;
  int read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, pubkey, &metadata );

  if (read_result != FD_ACC_MGR_SUCCESS) {
    return -1;
  }

  if( memcmp( metadata.info.owner, global->solana_bpf_loader_program_with_jit, sizeof(fd_pubkey_t)) ) {
    return -1;
  }

  if( metadata.info.executable != 1) {
    return -1;
  }

  return 0;
}

uchar *
serialize_unaligned( instruction_ctx_t ctx, ulong * sz ) {
  ulong serialized_size = 0;
  uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

  uchar acc_idx_seen[256];
  ushort dup_acc_idx[256];
  memset(acc_idx_seen, 0, sizeof(acc_idx_seen));
  memset(dup_acc_idx, 0, sizeof(dup_acc_idx));

  serialized_size += sizeof(ulong);
  for( ushort i = 0; i < ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];

    // fd_pubkey_t * acc = &txn_accs[acc_idx];
    // FD_LOG_WARNING(( "START OF ACC: %32J %x", acc, serialized_size ));

    serialized_size++; // dup byte
    if( FD_LIKELY( !acc_idx_seen[acc_idx] ) ) {
      acc_idx_seen[acc_idx] = 1;
      dup_acc_idx[acc_idx] = i;

      fd_pubkey_t * acc = &txn_accs[acc_idx];
      int read_result = FD_ACC_MGR_SUCCESS;
      uchar * raw_acc_data = (uchar *)fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, acc, NULL, &read_result);
      fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;
      // FD_LOG_WARNING(( "START OF ACC 2: %d %d %d %d", !fd_account_is_sysvar( &ctx, acc ), fd_account_is_writable_idx(&ctx, i), i, instr_acc_idxs[i]));

      ulong acc_data_len = 0;
      if ( FD_LIKELY( read_result == FD_ACC_MGR_SUCCESS ) ) {
        acc_data_len = metadata->dlen;
      } else if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
        // FD_LOG_WARNING(( "START OF ACC 3: %d %d %d %d", !fd_account_is_sysvar( &ctx, acc ), fd_account_is_writable_idx(&ctx, i), i, instr_acc_idxs[i]));
        acc_data_len = 0;
      } else {
        FD_LOG_WARNING(( "failed to read account data - pubkey: %32J, err: %d", acc, read_result ));
        return NULL;
      }

      serialized_size += sizeof(uchar)  // is_signer
          + sizeof(uchar)               // is_writable
          + sizeof(fd_pubkey_t)         // key
          + sizeof(ulong)               // lamports
          + sizeof(ulong)               // data_len
          + acc_data_len
          + sizeof(fd_pubkey_t)         // owner
          + sizeof(uchar)               // is_executable
          + sizeof(ulong);              // rent_epoch
    }
  }

  serialized_size += sizeof(ulong)
      + ctx.instr->data_sz
      + sizeof(fd_pubkey_t);

  uchar * serialized_params = fd_valloc_malloc( ctx.global->valloc, 1UL, serialized_size);
  uchar * serialized_params_start = serialized_params;

  FD_STORE( ulong, serialized_params, ctx.instr->acct_cnt );
  serialized_params += sizeof(ulong);

  for( ushort i = 0; i < ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];
    fd_pubkey_t * acc = &txn_accs[acc_idx];

    if( FD_UNLIKELY( acc_idx_seen[acc_idx] && dup_acc_idx[acc_idx] != i ) ) {
      // Duplicate
      FD_STORE( ulong, serialized_params, 0 );
      FD_STORE( uchar, serialized_params, (uchar)dup_acc_idx[acc_idx] );
      serialized_params += sizeof(ulong);
    } else {
      FD_STORE( uchar, serialized_params, 0xFF );
      serialized_params += sizeof(uchar);

      int read_result = FD_ACC_MGR_SUCCESS;
      uchar * raw_acc_data = (uchar *)fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, acc, NULL, &read_result);
      fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;
      if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
          fd_memset( serialized_params, 0, sizeof(uchar)  // is_signer
          + sizeof(uchar));              // is_writable
          
          serialized_params +=sizeof(uchar)  // is_signer
          + sizeof(uchar);               // is_writable
          
          fd_pubkey_t key = *acc;
          FD_STORE( fd_pubkey_t, serialized_params, key );
          serialized_params += sizeof(fd_pubkey_t);

          fd_memset( serialized_params, 0, sizeof(ulong)               // lamports
          + sizeof(ulong)               // data_len
          + 0
          + sizeof(fd_pubkey_t)         // owner
          + sizeof(uchar)               // is_executable
          + sizeof(ulong));              // rent_epoch
          serialized_params += sizeof(ulong)               // lamports
          + sizeof(ulong)               // data_len
          + 0
          + sizeof(fd_pubkey_t)         // owner
          + sizeof(uchar)               // is_executable
          + sizeof(ulong);              // rent_epoch
        continue;
      } else if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account data - pubkey: %32J, err: %d", acc, read_result ));
        return NULL;
      }

      uchar * acc_data = fd_account_get_data( metadata );

      uchar is_signer = (uchar)fd_account_is_signer( &ctx, acc );
      FD_STORE( uchar, serialized_params, is_signer );
      serialized_params += sizeof(uchar);

      uchar is_writable = (uchar)(fd_account_is_writable_idx( &ctx, acc_idx ) && !fd_account_is_sysvar( &ctx, acc ));
      FD_STORE( uchar, serialized_params, is_writable );
      serialized_params += sizeof(uchar);

      fd_pubkey_t key = *acc;
      FD_STORE( fd_pubkey_t, serialized_params, key );
      serialized_params += sizeof(fd_pubkey_t);

      ulong lamports = metadata->info.lamports;
      FD_STORE( ulong, serialized_params, lamports );
      serialized_params += sizeof(ulong);

      ulong acc_data_len = metadata->dlen;
      FD_STORE( ulong, serialized_params, acc_data_len );
      serialized_params += sizeof(ulong);

      fd_memcpy( serialized_params, acc_data, acc_data_len);
      serialized_params += acc_data_len;

      fd_pubkey_t owner = *(fd_pubkey_t *)&metadata->info.owner;
      FD_STORE( fd_pubkey_t, serialized_params, owner );
      serialized_params += sizeof(fd_pubkey_t);

      uchar is_executable = (uchar)metadata->info.executable;
      FD_STORE( uchar, serialized_params, is_executable );
      serialized_params += sizeof(uchar);

      ulong rent_epoch = metadata->info.rent_epoch;
      FD_STORE( ulong, serialized_params, rent_epoch );
      serialized_params += sizeof(ulong);
    }
  }

  ulong instr_data_len = ctx.instr->data_sz;
  FD_STORE( ulong, serialized_params, instr_data_len );
  serialized_params += sizeof(ulong);

  uchar * instr_data = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off;
  fd_memcpy( serialized_params, instr_data, instr_data_len );
  serialized_params += instr_data_len;

  FD_STORE( fd_pubkey_t, serialized_params, txn_accs[ctx.instr->program_id] );
  serialized_params += sizeof(fd_pubkey_t);

  // FD_LOG_NOTICE(( "SERIALIZE (UNALIGNED) - sz: %lu, diff: %lu", serialized_size, serialized_params - serialized_params_start ));
  *sz = serialized_size;
  return serialized_params_start;
}

int
deserialize_unaligned( instruction_ctx_t ctx, uchar * input, FD_FN_UNUSED ulong input_sz ) {
  uchar * input_cursor = input;

  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, sizeof(acc_idx_seen));

  uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

  input_cursor += sizeof(ulong);

  for( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];
    fd_pubkey_t * acc = &txn_accs[instr_acc_idxs[i]];

    input_cursor++;
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      input_cursor += 7;
    } else {
      fd_funk_rec_t * acc_data_rec = NULL;
      int modify_err;

      input_cursor += sizeof(uchar) + sizeof(uchar) + sizeof(fd_pubkey_t);


      ulong lamports = FD_LOAD(ulong, input_cursor);
      input_cursor += sizeof(ulong);

      /* Consume data_len */
      input_cursor += sizeof(ulong);

      uchar * post_data = input_cursor;

      void * raw_acc_data = fd_acc_mgr_modify_data(ctx.global->acc_mgr, ctx.global->funk_txn, acc, 0, NULL, NULL, &acc_data_rec, &modify_err);
      fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;
      uchar * acc_data = fd_account_get_data( metadata );

      input_cursor += metadata->dlen;

      fd_pubkey_t * owner = (fd_pubkey_t *)input_cursor;
      input_cursor += sizeof(fd_pubkey_t);

      /* Consume executable flag */
      input_cursor += sizeof(ulong);

      metadata->info.lamports = lamports;
      fd_memcpy(metadata->info.owner, owner, sizeof(fd_pubkey_t));

      fd_memcpy( acc_data, post_data, metadata->dlen );

      fd_acc_mgr_commit_data(ctx.global->acc_mgr, acc_data_rec, acc, raw_acc_data, ctx.global->bank.slot, 0);

      input_cursor += sizeof(ulong);
    }
  }

  fd_valloc_free( ctx.global->valloc, input);

  return 0;
}

int fd_executor_bpf_loader_program_execute_program_instruction( instruction_ctx_t ctx ) {
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
  fd_pubkey_t * program_acc = &txn_accs[ctx.instr->program_id];

  FD_LOG_NOTICE(("BPF V2 PROG INSTR RUN! - slot: %lu, addr: %32J", ctx.global->bank.slot, program_acc));

  int read_result = 0;
  uchar * raw_program_acc_data = (uchar *)fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, NULL, &read_result);
  if (read_result != FD_ACC_MGR_SUCCESS) {
    FD_LOG_WARNING(( "HELLO !!!!"));
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_account_meta_t * metadata = (fd_account_meta_t *)raw_program_acc_data;
  uchar * program_data = fd_account_get_data( metadata );
  ulong program_data_len = metadata->dlen;


  fd_sbpf_elf_info_t elf_info;
  fd_sbpf_elf_peek( &elf_info, program_data, program_data_len );

  /* Allocate rodata segment */

  void * rodata = fd_valloc_malloc( ctx.global->valloc, 1UL,  elf_info.rodata_footprint );
  FD_TEST( rodata );

  /* Allocate program buffer */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( ctx.global->valloc, prog_align, prog_footprint ), &elf_info, rodata );
  FD_TEST( prog );

  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( ctx.global->valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls );
  /* Load program */

  if(  0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls ) ) {
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
  }
  FD_LOG_WARNING(( "fd_sbpf_program_load() success: %s", fd_sbpf_strerror() ));

  ulong input_sz = 0;
  uchar * input = serialize_unaligned(ctx, &input_sz);
  if( input==NULL ) {
    fd_valloc_free( ctx.global->valloc,  fd_sbpf_program_delete( prog ) );
    fd_valloc_free( ctx.global->valloc,  fd_sbpf_syscalls_delete( syscalls ) );
    fd_valloc_free( ctx.global->valloc, rodata);
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }
  uchar * input_cpy = fd_valloc_malloc( ctx.global->valloc, 8UL, input_sz);
  fd_memcpy(input_cpy, input, input_sz);
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
  fd_vm_trace_entry_t * trace = (fd_vm_trace_entry_t *) fd_valloc_malloc( ctx.global->valloc, 1UL, trace_sz * sizeof(fd_vm_trace_entry_t));

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
  
  // for( ulong i = 0; i < trace_used; i++ ) {
  //   fd_vm_trace_entry_t trace_ent = trace[i];
  //   fprintf(stderr, "%5lu [%016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX] %5lu: ",
  //       trace_ent.ic,
  //       trace_ent.register_file[0],
  //       trace_ent.register_file[1],
  //       trace_ent.register_file[2],
  //       trace_ent.register_file[3],
  //       trace_ent.register_file[4],
  //       trace_ent.register_file[5],
  //       trace_ent.register_file[6],
  //       trace_ent.register_file[7],
  //       trace_ent.register_file[8],
  //       trace_ent.register_file[9],
  //       trace_ent.register_file[10],
  //       trace_ent.pc+29 // FIXME: THIS OFFSET IS FOR TESTING ONLY
  //     );
  //   fd_vm_disassemble_instr(&vm_ctx.instrs[trace[i].pc], trace[i].pc, vm_ctx.syscall_map, vm_ctx.local_call_map, stderr);

  //   fprintf(stderr, "\n");
  // }
  
  // fclose(trace_fd);
  fd_valloc_free( ctx.global->valloc, trace);

  fd_valloc_free( ctx.global->valloc,  fd_sbpf_program_delete( prog ) );
  fd_valloc_free( ctx.global->valloc,  fd_sbpf_syscalls_delete( syscalls ) );
  fd_valloc_free( ctx.global->valloc, rodata);

  FD_LOG_WARNING(( "fd_vm_interp_instrs() success: %lu, ic: %lu, pc: %lu, ep: %lu, r0: %lu, fault: %lu", interp_res, vm_ctx.instruction_counter, vm_ctx.program_counter, vm_ctx.entrypoint, vm_ctx.register_file[0], vm_ctx.cond_fault ));
  FD_LOG_WARNING(( "log coll: %s", vm_ctx.log_collector.buf ));

  if( vm_ctx.register_file[0]!=0 ) {
    fd_valloc_free( ctx.global->valloc, input);
    // TODO: vm should report this error
    return -1;
  }

  if( vm_ctx.cond_fault ) {
    fd_valloc_free( ctx.global->valloc, input);
    // TODO: vm should report this error
    return -1;
  }

  deserialize_unaligned(ctx, input, input_sz);

  return 0;
}

int fd_executor_bpf_loader_program_execute_instruction( instruction_ctx_t ctx ) {
  /* Deserialize the Stake instruction */
  uchar * data            = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off;

  fd_bpf_loader_program_instruction_t instruction;
  fd_bpf_loader_program_instruction_new( &instruction );
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.valloc  = ctx.global->valloc;

  if( fd_bpf_loader_program_instruction_decode( &instruction, &decode_ctx ) ) {
    FD_LOG_WARNING(("fd_bpf_loader_program_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  if( ctx.instr->acct_cnt < 1 ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

  /* Check that Instruction Account 0 is a signer */
  if( instr_acc_idxs[0] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

   /* FIXME: will need to actually find last program_acct in this instruction but practically no one does this. Yet another
       area where there seems to be a lot of overhead... See solana_runtime::Accounts::load_transaction_accounts */
  fd_pubkey_t * bpf_loader_acc = &txn_accs[ctx.txn_ctx->txn_descriptor->acct_addr_cnt - 1];
  if ( memcmp( bpf_loader_acc, ctx.global->solana_bpf_loader_program_with_jit, sizeof(fd_pubkey_t) ) != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  }

  fd_pubkey_t * program_acc = &txn_accs[instr_acc_idxs[0]];
  fd_account_meta_t program_acc_metadata;
  int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata );
  if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to read account metadata" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  if ( memcmp(program_acc_metadata.info.owner, bpf_loader_acc, sizeof(fd_pubkey_t) ) != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  if( fd_bpf_loader_program_instruction_is_write( &instruction ) ) {
    ulong write_end = fd_ulong_sat_add( instruction.inner.write.offset, instruction.inner.write.bytes_len );
    if( program_acc_metadata.dlen < write_end ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    /* Read the current data in the account */
    uchar * program_acc_data = fd_valloc_malloc( ctx.global->valloc, 8UL, program_acc_metadata.dlen );
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, (uchar*)program_acc_data, sizeof(fd_account_meta_t), program_acc_metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    fd_memcpy( program_acc_data + instruction.inner.write.offset, instruction.inner.write.bytes, instruction.inner.write.bytes_len );

    int write_result = fd_acc_mgr_write_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata, sizeof(program_acc_metadata), program_acc_data, program_acc_metadata.dlen, 0 );
    if ( write_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write account data" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if( fd_bpf_loader_program_instruction_is_finalize( &instruction ) ) {
    // TODO: check for rent exemption
    // TODO: check for writable

    fd_acc_mgr_set_metadata(ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata);

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else {
    FD_LOG_WARNING(( "unsupported bpf loader program instruction: discriminant: %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
}
