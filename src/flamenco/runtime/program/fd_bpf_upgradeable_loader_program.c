#include "fd_bpf_upgradeable_loader_program.h"

#include "../fd_account.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../../ballet/sbpf/fd_sbpf_maps.h"
#include "../../vm/fd_vm_syscalls.h"
#include "../../vm/fd_vm_interp.h"
#include "../../vm/fd_vm_disasm.h"

#include <stdio.h>

#define BUFFER_METADATA_SIZE  (37)
#define PROGRAMDATA_METADATA_SIZE (45UL)
#define MAX_PERMITTED_DATA_INCREASE (10 * 1024)

char *
read_bpf_upgradeable_loader_state( fd_global_ctx_t* global, fd_pubkey_t* program_acc, fd_bpf_upgradeable_loader_state_t * result, int *opt_err) {
  int err = 0;
  char * raw_acc_data = (char*) fd_acc_mgr_view_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) program_acc, NULL, &err);
  if (NULL == raw_acc_data) {
    if (NULL != opt_err)
      *opt_err = err;
    return NULL;
  }
  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

  fd_bincode_decode_ctx_t ctx = {
    .data = raw_acc_data + m->hlen,
    .dataend = (char *) ctx.data + m->dlen,
    .valloc  = global->valloc,
  };

  fd_bpf_upgradeable_loader_state_new(result);

  if ( fd_bpf_upgradeable_loader_state_decode( result, &ctx ) ) {
    FD_LOG_WARNING(("fd_bpf_upgradeable_loader_state_decode failed"));
    return NULL;
  }

  return raw_acc_data;
}

int write_bpf_upgradeable_loader_state(fd_global_ctx_t* global, fd_pubkey_t* program_acc, fd_bpf_upgradeable_loader_state_t * loader_state) {
  int err = 0;
  ulong encoded_loader_state_size = fd_bpf_upgradeable_loader_state_size( loader_state );
  ulong acc_sz = sizeof(fd_account_meta_t) + encoded_loader_state_size;
  fd_funk_rec_t * acc_data_rec = NULL;

  char *raw_acc_data = fd_acc_mgr_modify_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *)  program_acc, 1, &acc_sz, NULL, &acc_data_rec, &err);
  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

  fd_bincode_encode_ctx_t ctx;
  ctx.data = raw_acc_data + m->hlen;
  ctx.dataend = (char*)ctx.data + encoded_loader_state_size;

  if ( fd_bpf_upgradeable_loader_state_encode( loader_state, &ctx ) ) {
    FD_LOG_ERR(("fd_bpf_upgradeable_loader_state_encode failed"));
  }

  ulong lamps = (encoded_loader_state_size + 128) * ((ulong) ((double)global->bank.rent.lamports_per_uint8_year * global->bank.rent.exemption_threshold));
  if (m->info.lamports < lamps) {
    FD_LOG_ERR(("topped up the lamports.. was this needed?"));
    m->info.lamports = lamps;
  }

  if (encoded_loader_state_size > m->dlen)
    m->dlen = encoded_loader_state_size;

  return fd_acc_mgr_commit_data(global->acc_mgr, acc_data_rec, (fd_pubkey_t *) program_acc, raw_acc_data, global->bank.slot, 0);
}

// This is literally called before every single instruction execution... To make it fast we are duplicating some code
int fd_executor_bpf_upgradeable_loader_program_is_executable_program_account( fd_global_ctx_t * global, fd_pubkey_t * pubkey ) {
  int err = 0;
  char * raw_acc_data = (char*) fd_acc_mgr_view_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) pubkey, NULL, &err);
  if (NULL == raw_acc_data)
    return -1;

  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

  if( memcmp( m->info.owner, global->solana_bpf_loader_upgradeable_program_with_jit, sizeof(fd_pubkey_t)) )
    return -1;

  if( m->info.executable != 1)
    return -1;

  fd_bincode_decode_ctx_t ctx = {
    .data = raw_acc_data + m->hlen,
    .dataend = (char *) ctx.data + m->dlen,
    .valloc  = global->valloc,
  };

  fd_bpf_upgradeable_loader_state_t loader_state;
  fd_bpf_upgradeable_loader_state_new(&loader_state);
  if ( fd_bpf_upgradeable_loader_state_decode( &loader_state, &ctx ) ) {
    FD_LOG_WARNING(("fd_bpf_upgradeable_loader_state_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  if( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) )
    return -1;

  fd_bincode_destroy_ctx_t ctx_d = { .valloc = global->valloc };
  fd_bpf_upgradeable_loader_state_destroy( &loader_state, &ctx_d );

  return 0;
}

/**
 * num accounts
 * serialized accounts
 * instr data len
 * instr data
 * program id public key
*/
// 64-bit aligned
uchar *
serialize_aligned( instruction_ctx_t ctx, ulong * sz ) {
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

    fd_pubkey_t * acc = &txn_accs[acc_idx];
    FD_LOG_WARNING(( "START OF ACC: %32J %x", acc, serialized_size ));

    serialized_size++; // dup byte
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      serialized_size += 7; // pad to 64-bit alignment
    } else {
      acc_idx_seen[acc_idx] = 1;
      dup_acc_idx[acc_idx] = i;
      fd_pubkey_t * acc = &txn_accs[acc_idx];
      int read_result = 0;
      uchar * raw_acc_data = (uchar *)fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, acc, NULL, &read_result);
      fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;
      FD_LOG_WARNING(( "START OF ACC 2: %d %d %d %d", !fd_account_is_sysvar( &ctx, acc ), fd_account_is_writable_idx(&ctx, i), i, instr_acc_idxs[i]));
      if ( NULL == raw_acc_data ) {
        FD_LOG_WARNING(( "failed to read account data - pubkey: %32J, err: %d", acc, read_result ));
        return NULL;
      }

      ulong acc_data_len = metadata->dlen;
      ulong aligned_acc_data_len = fd_ulong_align_up(acc_data_len, 8);

      serialized_size += sizeof(uchar)  // is_signer
          + sizeof(uchar)               // is_writable
          + sizeof(uchar)               // is_executable
          + sizeof(uint)                // original_data_len
          + sizeof(fd_pubkey_t)         // key
          + sizeof(fd_pubkey_t)         // owner
          + sizeof(ulong)               // lamports
          + sizeof(ulong)               // data_len
          + aligned_acc_data_len
          + MAX_PERMITTED_DATA_INCREASE
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

      int read_result;
      uchar * raw_acc_data = (uchar *)fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, acc, NULL, &read_result);
      fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;
      uchar * acc_data = fd_account_get_data( metadata );

      uchar is_signer = (uchar)fd_account_is_signer( &ctx, acc );
      FD_STORE( uchar, serialized_params, is_signer );
      serialized_params += sizeof(uchar);

      uchar is_writable = (uchar)(fd_account_is_writable_idx( &ctx, acc_idx ) && !fd_account_is_sysvar( &ctx, acc ));
      FD_STORE( uchar, serialized_params, is_writable );
      serialized_params += sizeof(uchar);

      uchar is_executable = (uchar)metadata->info.executable;
      FD_STORE( uchar, serialized_params, is_executable );
      serialized_params += sizeof(uchar);

      uint padding_0 = 0;
      FD_STORE( uint, serialized_params, padding_0 );
      serialized_params += sizeof(uint);

      fd_pubkey_t key = *acc;
      FD_STORE( fd_pubkey_t, serialized_params, key );
      serialized_params += sizeof(fd_pubkey_t);

      fd_pubkey_t owner = *(fd_pubkey_t *)&metadata->info.owner;
      FD_STORE( fd_pubkey_t, serialized_params, owner );
      serialized_params += sizeof(fd_pubkey_t);

      ulong lamports = metadata->info.lamports;
      FD_STORE( ulong, serialized_params, lamports );
      serialized_params += sizeof(ulong);

      ulong acc_data_len = metadata->dlen;
      ulong aligned_acc_data_len = fd_ulong_align_up(acc_data_len, 8);
      ulong alignment_padding_len = aligned_acc_data_len - acc_data_len;

      ulong data_len = acc_data_len;
      FD_STORE( ulong, serialized_params, data_len );
      serialized_params += sizeof(ulong);

      fd_memcpy( serialized_params, acc_data, acc_data_len);
      serialized_params += acc_data_len;

      fd_memset( serialized_params, 0, MAX_PERMITTED_DATA_INCREASE + alignment_padding_len);
      serialized_params += MAX_PERMITTED_DATA_INCREASE + alignment_padding_len;

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

  FD_LOG_NOTICE(( "SERIALIZE - sz: %lu, diff: %lu", serialized_size, serialized_params - serialized_params_start ));
  *sz = serialized_size;
  return serialized_params_start;
}

int
deserialize_aligned( instruction_ctx_t ctx, uchar * input, FD_FN_UNUSED ulong input_sz ) {
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

      input_cursor += sizeof(uchar) + sizeof(uchar) + sizeof(uchar) + sizeof(uint) + sizeof(fd_pubkey_t);
      fd_pubkey_t * owner = (fd_pubkey_t *)input_cursor;
      input_cursor += sizeof(fd_pubkey_t);

      ulong lamports = FD_LOAD(ulong, input_cursor);
      input_cursor += sizeof(ulong);

      ulong post_data_len = FD_LOAD(ulong, input_cursor);
      input_cursor += sizeof(ulong);

      uchar * post_data = input_cursor;

      ulong acc_sz = sizeof(fd_account_meta_t) + post_data_len;

      void * raw_acc_data = fd_acc_mgr_modify_data(ctx.global->acc_mgr, ctx.global->funk_txn, acc, 0, &acc_sz, NULL, &acc_data_rec, &modify_err);
      fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;
      uchar * acc_data = fd_account_get_data( metadata );

      input_cursor += fd_ulong_align_up(metadata->dlen, 8) + MAX_PERMITTED_DATA_INCREASE;
      metadata->dlen = post_data_len;
      metadata->info.lamports = lamports;
      fd_memcpy(metadata->info.owner, owner, sizeof(fd_pubkey_t));

      fd_memcpy( acc_data, post_data, post_data_len );

      fd_acc_mgr_commit_data(ctx.global->acc_mgr, acc_data_rec, acc, raw_acc_data, ctx.global->bank.slot, 0);

      input_cursor += sizeof(ulong);
    }
  }

  fd_valloc_free( ctx.global->valloc, input );

  return 0;
}

int fd_executor_bpf_upgradeable_loader_program_execute_program_instruction( instruction_ctx_t ctx ) {
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
  fd_pubkey_t * program_acc = &txn_accs[ctx.instr->program_id];

  fd_bpf_upgradeable_loader_state_t program_loader_state;
  int err = 0;
  if (FD_UNLIKELY(NULL == read_bpf_upgradeable_loader_state( ctx.global, program_acc, &program_loader_state, &err )))
    return err;

  fd_bincode_destroy_ctx_t ctx_d = { .valloc = ctx.global->valloc };

  if( !fd_bpf_upgradeable_loader_state_is_program( &program_loader_state ) ) {
    fd_bpf_upgradeable_loader_state_destroy( &program_loader_state, &ctx_d );
    return -1;
  }

  fd_pubkey_t * programdata_acc = &program_loader_state.inner.program.programdata_address;

  fd_bpf_upgradeable_loader_state_t programdata_loader_state;

  err = 0;
  uchar *ptr = (uchar *) read_bpf_upgradeable_loader_state( ctx.global, programdata_acc, &programdata_loader_state, &err );
  if (NULL == ptr)
    return err;
  fd_account_meta_t *programdata_metadata = (fd_account_meta_t *) ptr;

  FD_LOG_NOTICE(("BPF PROG INSTR RUN! - slot: %lu, addr: %32J", ctx.global->bank.slot, &txn_accs[ctx.instr->program_id]));

  if( !fd_bpf_upgradeable_loader_state_is_program_data( &programdata_loader_state ) ) {
    fd_bpf_upgradeable_loader_state_destroy( &program_loader_state, &ctx_d );
    return -1;
  }

  ulong program_data_len = programdata_metadata->dlen - PROGRAMDATA_METADATA_SIZE;
  uchar * program_data = ptr + programdata_metadata->hlen + PROGRAMDATA_METADATA_SIZE;

  fd_bpf_upgradeable_loader_state_destroy( &program_loader_state, &ctx_d );

  fd_sbpf_elf_info_t elf_info;
  fd_sbpf_elf_peek( &elf_info, program_data, program_data_len );

  /* Allocate rodata segment */

  void * rodata = fd_valloc_malloc( ctx.global->valloc, 1UL,  elf_info.rodata_footprint );
  FD_TEST( rodata );

  /* Allocate program buffer */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( aligned_alloc( prog_align, prog_footprint ), &elf_info, rodata );
  FD_TEST( prog );

  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new(
      aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls );
  /* Load program */

  if(  0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls ) ) {
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
  }
  FD_LOG_WARNING(( "fd_sbpf_program_load() success: %s", fd_sbpf_strerror() ));

  ulong input_sz = 0;
  uchar * input = serialize_aligned(ctx, &input_sz);
  if( input==NULL ) {
    fd_valloc_free( ctx.global->valloc, fd_sbpf_program_delete( prog ) );
    fd_valloc_free( ctx.global->valloc, fd_sbpf_syscalls_delete( syscalls ) );
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

  ulong trace_sz = 1024 * 1024;
  ulong trace_used = 0;
  fd_vm_trace_entry_t * trace = (fd_vm_trace_entry_t *) fd_valloc_malloc( ctx.global->valloc, 1UL, trace_sz * sizeof(fd_vm_trace_entry_t));

  memset(vm_ctx.register_file, 0, sizeof(vm_ctx.register_file));
  vm_ctx.register_file[1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm_ctx.register_file[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;


  ulong validate_result = fd_vm_context_validate( &vm_ctx );
  if (validate_result != FD_VM_SBPF_VALIDATE_SUCCESS) {
    FD_LOG_ERR(( "fd_vm_context_validate() failed: %lu", validate_result ));
  }

  FD_LOG_WARNING(( "fd_vm_context_validate() success" ));

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
  fd_valloc_free( ctx.global->valloc, trace);

  fd_valloc_free( ctx.global->valloc, fd_sbpf_program_delete( prog ) );
  fd_valloc_free( ctx.global->valloc, fd_sbpf_syscalls_delete( syscalls ) );
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

  deserialize_aligned(ctx, input, input_sz);

  return 0;
}


int fd_executor_bpf_upgradeable_loader_program_execute_instruction( instruction_ctx_t ctx ) {
  /* Deserialize the Stake instruction */
  uchar * data            = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off;

  fd_bpf_upgradeable_loader_program_instruction_t instruction;
  fd_bpf_upgradeable_loader_program_instruction_new( &instruction );
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.valloc  = ctx.global->valloc;

  int decode_err;
  if ( ( decode_err = fd_bpf_upgradeable_loader_program_instruction_decode( &instruction, &decode_ctx ) ) ) {
    FD_LOG_WARNING(("fd_bpf_upgradeable_loader_program_instruction_decode failed: err code: %d, %d %x", decode_err, ctx.instr->data_sz, ((uint*)data)[0]));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }


  uchar* instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t* txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);


  FD_LOG_NOTICE(("BPF INSTR RUN! - addr: %32J, disc: %u", &txn_accs[ctx.instr->program_id], instruction.discriminant));

  if( fd_bpf_upgradeable_loader_program_instruction_is_initialize_buffer( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_bpf_upgradeable_loader_state_t loader_state;
    fd_pubkey_t * buffer_acc = &txn_accs[instr_acc_idxs[0]];

    int err = 0;
    if (FD_UNLIKELY(NULL == read_bpf_upgradeable_loader_state( ctx.global, buffer_acc, &loader_state, &err ))) {
      // TODO: Fix leaks...
      return err;
    }

    if( !fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[1]];
    loader_state.discriminant = fd_bpf_upgradeable_loader_state_enum_buffer;
    loader_state.inner.buffer.authority_address = authority_acc;

    write_bpf_upgradeable_loader_state( ctx.global, buffer_acc, &loader_state );

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_write( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    // FIXME: Do we need to check writable?

    fd_pubkey_t * buffer_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[1]];

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if (NULL == read_bpf_upgradeable_loader_state( ctx.global, buffer_acc, &loader_state, &err)) {
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

    fd_account_meta_t buffer_acc_metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, &buffer_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    ulong offset = fd_ulong_sat_add(fd_bpf_upgradeable_loader_state_size( &loader_state ), instruction.inner.write.offset);
    ulong write_end = fd_ulong_sat_add( offset, instruction.inner.write.bytes_len );
    if( buffer_acc_metadata.dlen < write_end ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    /* Read the current data in the account */
    uchar * buffer_acc_data = fd_valloc_malloc( ctx.global->valloc, 8UL, buffer_acc_metadata.dlen );
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, (uchar*)buffer_acc_data, sizeof(fd_account_meta_t), buffer_acc_metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    fd_memcpy( buffer_acc_data + offset, instruction.inner.write.bytes, instruction.inner.write.bytes_len );

    int write_result = fd_acc_mgr_write_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, &buffer_acc_metadata, sizeof(buffer_acc_metadata), buffer_acc_data, buffer_acc_metadata.dlen, 0 );
    if ( write_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write account data" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;

  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_deploy_with_max_data_len( &instruction ) ) {
    if( ctx.instr->acct_cnt < 4 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t * payer_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * programdata_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t * program_acc = &txn_accs[instr_acc_idxs[2]];
    fd_pubkey_t * buffer_acc = &txn_accs[instr_acc_idxs[3]];
    fd_pubkey_t * rent_acc = &txn_accs[instr_acc_idxs[4]];
    fd_pubkey_t * clock_acc = &txn_accs[instr_acc_idxs[5]];

    if( ctx.instr->acct_cnt < 8 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[7]];

    // Drain buffer lamports to payer
    fd_account_meta_t payer_acc_metadata;
    fd_account_meta_t buffer_acc_metadata;

    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, &buffer_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, payer_acc, &payer_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    // FIXME: Do checked addition
    FD_LOG_WARNING(("EEEEE: %lu", buffer_acc_metadata.info.lamports ));
    payer_acc_metadata.info.lamports += buffer_acc_metadata.info.lamports;
    buffer_acc_metadata.info.lamports = 0;

    int write_result = fd_acc_mgr_set_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, &buffer_acc_metadata );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to write account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    // Create program data account
    fd_funk_rec_t * program_data_rec = NULL;
    int modify_err;
    ulong sz = PROGRAMDATA_METADATA_SIZE + instruction.inner.deploy_with_max_data_len.max_data_len + sizeof(fd_account_meta_t);
    void * program_data_raw = fd_acc_mgr_modify_data(ctx.global->acc_mgr, ctx.global->funk_txn, programdata_acc, 1, &sz, NULL, &program_data_rec, &modify_err);
    fd_account_meta_t * meta = (fd_account_meta_t *)program_data_raw;
    uchar * acct_data = fd_account_get_data(meta);

    fd_bpf_upgradeable_loader_state_t program_data_acc_loader_state = {
      .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
      .inner.program_data.slot = ctx.global->bank.slot,
      .inner.program_data.upgrade_authority_address = authority_acc
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
    fd_memcpy(&meta->info.owner, &ctx.global->solana_bpf_loader_upgradeable_program_with_jit, sizeof(fd_pubkey_t));
    meta->info.lamports = fd_rent_exempt_minimum_balance(ctx.global, meta->dlen);
    meta->info.rent_epoch = 0;

    FD_LOG_WARNING(("FFFFF: %lu", buffer_acc_metadata.info.lamports ));

    payer_acc_metadata.info.lamports += buffer_acc_metadata.info.lamports;
    payer_acc_metadata.info.lamports -= meta->info.lamports;
    ulong buffer_data_len = fd_ulong_sat_sub(buffer_acc_metadata.dlen, BUFFER_METADATA_SIZE);

    uchar * raw_acc_data = (uchar *)fd_acc_mgr_view_data(ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, NULL, &read_result);
    fd_memcpy( acct_data+PROGRAMDATA_METADATA_SIZE, raw_acc_data+BUFFER_METADATA_SIZE+sizeof(fd_account_meta_t), buffer_data_len );
    // fd_memset( acct_data+PROGRAMDATA_METADATA_SIZE+buffer_data_len, 0, instruction.inner.deploy_with_max_data_len.max_data_len-buffer_data_len );
    FD_LOG_WARNING(("QQQQQQ: %lu %lu %lu %lu %32J %32J", buffer_data_len, instruction.inner.deploy_with_max_data_len.max_data_len, fd_bpf_upgradeable_loader_state_size(&program_data_acc_loader_state), PROGRAMDATA_METADATA_SIZE, payer_acc, buffer_acc));
      // FD_LOG_WARNING(("AAA: %x", *(acct_data+meta->dlen-3)));
    fd_acc_mgr_commit_data(ctx.global->acc_mgr, program_data_rec, programdata_acc, program_data_raw, ctx.global->bank.slot, 0);

    fd_account_meta_t program_acc_metadata;

    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    program_acc_metadata.info.executable = 1;

    write_result = fd_acc_mgr_set_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to write account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    fd_bpf_upgradeable_loader_state_t program_acc_loader_state;
    // FIXME: HANDLE ERRORS!
    int err = 0;
    if (NULL == read_bpf_upgradeable_loader_state( ctx.global, program_acc, &program_acc_loader_state, &err ))
      return err;

    program_acc_loader_state.discriminant = fd_bpf_upgradeable_loader_state_enum_program;
    fd_memcpy(&program_acc_loader_state.inner.program.programdata_address, programdata_acc, sizeof(fd_pubkey_t));

    write_bpf_upgradeable_loader_state( ctx.global, program_acc, &program_acc_loader_state );

    write_result = fd_acc_mgr_set_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, payer_acc, &payer_acc_metadata );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to write account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    (void)clock_acc;
    (void)rent_acc;

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_upgrade( &instruction ) ) {
    if( ctx.instr->acct_cnt < 7 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t * programdata_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * program_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t * buffer_acc = &txn_accs[instr_acc_idxs[2]];
    fd_pubkey_t * rent_acc = &txn_accs[instr_acc_idxs[4]];
    fd_pubkey_t * clock_acc = &txn_accs[instr_acc_idxs[5]];
    fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[6]];

    fd_account_meta_t program_acc_metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    // Is program executable?
    if( !program_acc_metadata.info.executable ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE;
    }

    // Is program writable?
    if( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[1] ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    // Is program owner the BPF upgradeable loader?
    if ( memcmp( program_acc_metadata.info.owner, ctx.global->solana_bpf_loader_upgradeable_program_with_jit, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    fd_bpf_upgradeable_loader_state_t program_acc_loader_state;
    int err = 0;
    if (NULL == read_bpf_upgradeable_loader_state( ctx.global, program_acc, &program_acc_loader_state, &err)) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
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
    if (NULL == read_bpf_upgradeable_loader_state( ctx.global, buffer_acc, &buffer_acc_loader_state, &err )) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
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

    fd_account_meta_t buffer_acc_metadata;

    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, &buffer_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    ulong buffer_data_len = fd_ulong_sat_sub(buffer_acc_metadata.dlen, BUFFER_METADATA_SIZE);

    if( buffer_acc_metadata.dlen < BUFFER_METADATA_SIZE || buffer_data_len==0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    // TODO: A lot of checks need to be added from Solana code

    ulong sz = PROGRAMDATA_METADATA_SIZE + instruction.inner.deploy_with_max_data_len.max_data_len + sizeof(fd_account_meta_t);
    err = 0;
    void * program_data_raw = fd_acc_mgr_modify_data(ctx.global->acc_mgr, ctx.global->funk_txn, programdata_acc, 1, &sz, NULL, NULL, &err);
    fd_account_meta_t * programdata_acc_metadata = (fd_account_meta_t *)program_data_raw;
    uchar * programdata_acc_data = fd_account_get_data(programdata_acc_metadata);

    fd_bpf_upgradeable_loader_state_t program_data_acc_loader_state = {
      .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
      .inner.program_data.slot = ctx.global->bank.slot,
      .inner.program_data.upgrade_authority_address = authority_acc,
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

    /* Read the current data in the account */
    uchar * buffer_acc_data = fd_valloc_malloc( ctx.global->valloc, 8UL, buffer_acc_metadata.dlen );
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, (uchar*)buffer_acc_data, sizeof(fd_account_meta_t), buffer_acc_metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    uchar * buffer_content = buffer_acc_data + BUFFER_METADATA_SIZE;
    uchar * programdata_content = programdata_acc_data + PROGRAMDATA_METADATA_SIZE;
    fd_memcpy(programdata_content, buffer_content, buffer_data_len);
    fd_memset(programdata_content + buffer_data_len, 0, programdata_acc_metadata->dlen-buffer_data_len);

    (void)clock_acc;
    (void)rent_acc;

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_set_authority( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t * new_authority_acc = NULL;
    if( ctx.instr->acct_cnt >= 3 ) {
      new_authority_acc = &txn_accs[instr_acc_idxs[2]];
    }

    fd_pubkey_t * loader_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * present_authority_acc = &txn_accs[instr_acc_idxs[1]];

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if (NULL == read_bpf_upgradeable_loader_state( ctx.global, loader_acc, &loader_state, &err)) {
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

      if(instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      loader_state.inner.buffer.authority_address = new_authority_acc;
      write_bpf_upgradeable_loader_state( ctx.global, loader_acc, &loader_state );

      return FD_EXECUTOR_INSTR_SUCCESS;
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

      write_bpf_upgradeable_loader_state( ctx.global, loader_acc, &loader_state );

      return FD_EXECUTOR_INSTR_SUCCESS;
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_close( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t * close_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * recipient_acc = &txn_accs[instr_acc_idxs[1]];

    if ( memcmp( close_acc, recipient_acc, sizeof(fd_pubkey_t) )==0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_bpf_upgradeable_loader_state_t loader_state;
    int err = 0;
    if (NULL == read_bpf_upgradeable_loader_state( ctx.global, close_acc, &loader_state, &err ))
      return err;

    if( fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) {
      fd_account_meta_t close_acc_metadata;
      fd_account_meta_t recipient_acc_metdata;

      int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, close_acc, &close_acc_metadata );
      if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, recipient_acc, &recipient_acc_metdata );
      if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      // FIXME: Do checked addition
      recipient_acc_metdata.info.lamports += close_acc_metadata.info.lamports;
      close_acc_metadata.info.lamports = 0;

      int write_result = fd_acc_mgr_set_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, close_acc, &close_acc_metadata );
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to write account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }

      write_result = fd_acc_mgr_set_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, recipient_acc, &recipient_acc_metdata );
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to write account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }

      return FD_EXECUTOR_INSTR_SUCCESS;
    } else if ( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( ctx.instr->acct_cnt < 3 ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[2]];

      (void)authority_acc;
    } else if( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_extend_program( &instruction ) ) {


    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } else {
    FD_LOG_WARNING(( "unsupported bpf upgradeable loader program instruction: discriminant: %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
}
