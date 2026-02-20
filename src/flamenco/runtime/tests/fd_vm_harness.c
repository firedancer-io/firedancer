#include "fd_instr_harness.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../../log_collector/fd_log_collector.h"
#include "../program/fd_bpf_loader_serialization.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../vm/fd_vm.h"
#include "../../vm/test_vm_util.h"
#include "generated/vm.pb.h"
#include "../fd_bank.h"

static fd_sbpf_syscalls_t *
fd_solfuzz_vm_syscall_lookup_func( fd_sbpf_syscalls_t * syscalls,
                                   const char *         syscall_name,
                                   size_t               len) {
  ulong i;

  if (!syscall_name) return NULL;

  for (i = 0; i < fd_sbpf_syscalls_slot_cnt(); ++i) {
    if (!fd_sbpf_syscalls_key_inval(syscalls[i].key) && syscalls[i].name && strlen(syscalls[i].name) == len) {
      if (!memcmp(syscalls[i].name, syscall_name, len)) {
        return syscalls + i;
      }
    }
  }

  return NULL;
}

static ulong
fd_solfuzz_vm_load_from_input_regions( fd_vm_input_region_t const *        input,
                                       uint                                input_count,
                                       fd_exec_test_input_data_region_t ** output,
                                       pb_size_t *                         output_count,
                                       void *                              output_buf,
                                       ulong                               output_bufsz ) {
  /* pre-flight checks on output buffer size*/
  ulong input_regions_total_sz = 0;
  for( ulong i=0; i<input_count; i++ ) {
    input_regions_total_sz += input[i].region_sz;
  }

  if( FD_UNLIKELY(   input_regions_total_sz == 0
                  || output_bufsz < input_regions_total_sz ) ) {
    *output = NULL;
    *output_count = 0;
    return 0;
  }

  FD_SCRATCH_ALLOC_INIT( l, output_buf );
  *output = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_input_data_region_t),
                                      input_count * sizeof (fd_exec_test_input_data_region_t) );
  FD_TEST( *output );
  *output_count = input_count;

  for( ulong i=0; i<input_count; i++ ) {
    fd_vm_input_region_t const * vm_region = &input[i];
    fd_exec_test_input_data_region_t * out_region = &(*output)[i];
    out_region->is_writable = vm_region->is_writable;
    out_region->offset = vm_region->vaddr_offset;

    if( vm_region->region_sz > 0 ) {
      out_region->content = FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                                 PB_BYTES_ARRAY_T_ALLOCSIZE(vm_region->region_sz) );
      FD_TEST( out_region->content );
      out_region->content->size = vm_region->region_sz;
      fd_memcpy( out_region->content->bytes, (void *)vm_region->haddr, vm_region->region_sz );
    } else {
      out_region->content = NULL;
    }
  }

  ulong end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  return end - (ulong)output_buf; /* return the number of bytes written */
}


ulong
fd_solfuzz_pb_syscall_run( fd_solfuzz_runner_t * runner,
                           void const *          input_,
                           void **               output_,
                           void *                output_buf,
                           ulong                 output_bufsz ) {
  fd_exec_test_syscall_context_t const * input =  fd_type_pun_const( input_ );
  fd_exec_test_syscall_effects_t **      output = fd_type_pun( output_ );

  /* Create execution context */
  const fd_exec_test_instr_context_t * input_instr_ctx = &input->instr_ctx;
  fd_exec_instr_ctx_t ctx[1];
  // Skip extra checks for non-CPI syscalls
  int is_cpi            = !strncmp( (const char *)input->syscall_invocation.function_name.bytes, "sol_invoke_signed", 17 );
  int skip_extra_checks = !is_cpi;

  fd_solfuzz_pb_instr_ctx_create( runner, ctx, input_instr_ctx, skip_extra_checks );

  ctx->txn_out->err.exec_err = 0;
  ctx->txn_out->err.exec_err_kind = FD_EXECUTOR_ERR_KIND_NONE;
  ctx->bank = runner->bank;

  /* Capture outputs */
  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );
  fd_exec_test_syscall_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_syscall_effects_t),
                                sizeof (fd_exec_test_syscall_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    goto error;
  }

  if( input->vm_ctx.return_data.program_id && input->vm_ctx.return_data.program_id->size == sizeof(fd_pubkey_t) ) {
    fd_memcpy( ctx->txn_out->details.return_data.program_id.uc, input->vm_ctx.return_data.program_id->bytes, sizeof(fd_pubkey_t) );
  }

  if( input->vm_ctx.return_data.data && input->vm_ctx.return_data.data->size>0U ) {
    ctx->txn_out->details.return_data.len = input->vm_ctx.return_data.data->size;
    fd_memcpy( ctx->txn_out->details.return_data.data, input->vm_ctx.return_data.data->bytes, ctx->txn_out->details.return_data.len );
  }

  *effects = (fd_exec_test_syscall_effects_t) FD_EXEC_TEST_SYSCALL_EFFECTS_INIT_ZERO;

  /* Set up the VM instance */
  fd_spad_t * spad = runner->spad;
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_spad_alloc_check( spad, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  fd_vm_syscall_register_all( syscalls, 0 );

  /* Pull out the memory regions */
  if( !input->has_vm_ctx ) {
    goto error;
  }

  ulong rodata_sz = input->vm_ctx.rodata ? input->vm_ctx.rodata->size : 0UL;
  uchar * rodata = fd_spad_alloc_check( spad, 8UL, rodata_sz );
  if ( input->vm_ctx.rodata != NULL ) {
    fd_memcpy( rodata, input->vm_ctx.rodata->bytes, rodata_sz );
  }

  if( input->vm_ctx.heap_max > FD_VM_HEAP_MAX ) {
    goto error;
  }

  fd_vm_t * vm = fd_vm_join( fd_vm_new( fd_spad_alloc_check( spad, fd_vm_align(), fd_vm_footprint() ) ) );
  if ( !vm ) {
    goto error;
  }

  /* If the program ID account owner is the v1 BPF loader, then alignment is disabled (controlled by
     the `is_deprecated` flag) */

  ulong                   input_sz                               = 0UL;
  ulong                   pre_lens[256]                          = {0};
  fd_vm_input_region_t    input_mem_regions[1000]                = {0}; /* We can have a max of (3 * num accounts + 1) regions */
  fd_vm_acc_region_meta_t acc_region_metas[256]                  = {0}; /* instr acc idx to idx */
  uint                    input_mem_regions_cnt                  = 0U;
  int                     direct_mapping                         = FD_FEATURE_ACTIVE_BANK( ctx->bank, account_data_direct_mapping );
  int                     stricter_abi_and_runtime_constraints   = FD_FEATURE_ACTIVE_BANK( ctx->bank, stricter_abi_and_runtime_constraints );

  uchar               program_id_idx = ctx->instr->program_id;
  fd_account_meta_t * program_acc    = ctx->txn_out->accounts.account[program_id_idx].meta;
  uchar               is_deprecated  = ( program_id_idx < ctx->txn_out->accounts.cnt ) &&
                                      ( !memcmp( program_acc->owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) );

  /* Push the instruction onto the stack. This may also modify the sysvar instructions account, if its present. */
  int stack_push_err = fd_instr_stack_push( ctx->runtime, ctx->txn_in, ctx->txn_out, (fd_instr_info_t *)ctx->instr );
  if( FD_UNLIKELY( stack_push_err ) ) {
      FD_LOG_WARNING(( "instr stack push err" ));
      goto error;
  }

  ulong instr_data_offset = 0UL;
  int err = fd_bpf_loader_input_serialize_parameters( ctx,
                                                      pre_lens,
                                                      input_mem_regions,
                                                      &input_mem_regions_cnt,
                                                      acc_region_metas,
                                                      stricter_abi_and_runtime_constraints,
                                                      direct_mapping,
                                                      is_deprecated,
                                                      &instr_data_offset,
                                                      &input_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "bpf loader input serialize parameters err" ));
    goto error;
  }

  fd_vm_init( vm,
              ctx,
              input->vm_ctx.heap_max,
              ctx->txn_out->details.compute_budget.compute_meter,
              rodata,
              rodata_sz,
              NULL, // TODO
              0, // TODO
              0, // TODO
              0, // TODO, text_sz
              0, // TODO
              NULL, // TODO
              TEST_VM_DEFAULT_SBPF_VERSION,
              syscalls,
              NULL, // TODO
              sha,
              input_mem_regions,
              input_mem_regions_cnt,
              acc_region_metas,
              is_deprecated,
              direct_mapping,
              stricter_abi_and_runtime_constraints,
              0 /* dump_syscall_to_pb */,
              0UL /* r2 is set by the fuzzer below */ );

  // Override some execution state values from the syscall fuzzer input
  // This is so we can test if the syscall mutates any of these erroneously
  vm->reg[0] = input->vm_ctx.r0;
  vm->reg[1] = input->vm_ctx.r1;
  vm->reg[2] = input->vm_ctx.r2;
  vm->reg[3] = input->vm_ctx.r3;
  vm->reg[4] = input->vm_ctx.r4;
  vm->reg[5] = input->vm_ctx.r5;
  vm->reg[6] = input->vm_ctx.r6;
  vm->reg[7] = input->vm_ctx.r7;
  vm->reg[8] = input->vm_ctx.r8;
  vm->reg[9] = input->vm_ctx.r9;
  vm->reg[10] = input->vm_ctx.r10;
  vm->reg[11] = input->vm_ctx.r11;

  // Override initial part of the heap, if specified the syscall fuzzer input
  if( input->syscall_invocation.heap_prefix ) {
    fd_memcpy( vm->heap, input->syscall_invocation.heap_prefix->bytes,
               fd_ulong_min(input->syscall_invocation.heap_prefix->size, vm->heap_max) );
  }

  // Override initial part of the stack, if specified the syscall fuzzer input
  if( input->syscall_invocation.stack_prefix ) {
    fd_memcpy( vm->stack, input->syscall_invocation.stack_prefix->bytes,
               fd_ulong_min(input->syscall_invocation.stack_prefix->size, FD_VM_STACK_MAX) );
  }

  // Look up the syscall to execute
  char * syscall_name = (char *)input->syscall_invocation.function_name.bytes;
  fd_sbpf_syscalls_t const * syscall = fd_solfuzz_vm_syscall_lookup_func(syscalls, syscall_name, input->syscall_invocation.function_name.size);
  if( !syscall ) {
    goto error;
  }

  /* There's an instr ctx struct embedded in the txn ctx instr stack. */
  fd_exec_instr_ctx_t * instr_ctx = &ctx->runtime->instr.stack[ ctx->runtime->instr.stack_sz - 1 ];
  *instr_ctx = (fd_exec_instr_ctx_t) {
    .instr   = ctx->instr,
    .txn_out = ctx->txn_out,
    .runtime = ctx->runtime,
  };

  /* Actually invoke the syscall */
  int syscall_err = syscall->func( vm, vm->reg[1], vm->reg[2], vm->reg[3], vm->reg[4], vm->reg[5], &vm->reg[0] );
  int stack_pop_err = fd_instr_stack_pop( ctx->runtime, ctx->txn_out, ctx->instr );
  if( FD_UNLIKELY( stack_pop_err ) ) {
      FD_LOG_WARNING(( "instr stack pop err" ));
      goto error;
  }
  if( syscall_err ) {
    fd_log_collector_program_failure( vm->instr_ctx );
  }

  /* Capture the effects */
  int exec_err = vm->instr_ctx->txn_out->err.exec_err;
  effects->error = 0;
  if( syscall_err ) {
    if( exec_err==0 ) {
      FD_LOG_WARNING(( "TODO: syscall returns error, but exec_err not set. this is probably missing a log." ));
      effects->error = -1;
    } else {
      effects->error = (exec_err <= 0) ? -exec_err : -1;

      /* Map error kind, equivalent to:
          effects->error_kind = (fd_exec_test_err_kind_t)(vm->instr_ctx->txn_ctx->err.exec_err_kind); */
      switch (vm->instr_ctx->txn_out->err.exec_err_kind) {
        case FD_EXECUTOR_ERR_KIND_EBPF:
          effects->error_kind = FD_EXEC_TEST_ERR_KIND_EBPF;
          break;
        case FD_EXECUTOR_ERR_KIND_SYSCALL:
          effects->error_kind = FD_EXEC_TEST_ERR_KIND_SYSCALL;
          break;
        case FD_EXECUTOR_ERR_KIND_INSTR:
          effects->error_kind = FD_EXEC_TEST_ERR_KIND_INSTRUCTION;
          break;
        default:
          effects->error_kind = FD_EXEC_TEST_ERR_KIND_UNSPECIFIED;
          break;
      }
    }
  }
  effects->r0 = syscall_err ? 0 : vm->reg[0]; // Save only on success
  effects->cu_avail = (ulong)vm->cu;

  if( vm->heap_max ) {
    effects->heap = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(uint), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->heap_max ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      goto error;
    }
    effects->heap->size = (uint)vm->heap_max;
    fd_memcpy( effects->heap->bytes, vm->heap, vm->heap_max );
  } else {
    effects->heap = NULL;
  }

  effects->stack = FD_SCRATCH_ALLOC_APPEND(
    l, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( FD_VM_STACK_MAX ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      goto error;
    }
  effects->stack->size = (uint)FD_VM_STACK_MAX;
  fd_memcpy( effects->stack->bytes, vm->stack, FD_VM_STACK_MAX );

  if( vm->rodata_sz ) {
    effects->rodata = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( rodata_sz ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      goto error;
    }
    effects->rodata->size = (uint)rodata_sz;
    fd_memcpy( effects->rodata->bytes, vm->rodata, rodata_sz );
  } else {
    effects->rodata = NULL;
  }

  effects->frame_count = vm->frame_cnt;

  fd_log_collector_t * log = vm->instr_ctx->runtime->log.log_collector;
  /* Only collect log on valid errors (i.e., != -1). Follows
     https://github.com/firedancer-io/solfuzz-agave/blob/99758d3c4f3a342d56e2906936458d82326ae9a8/src/utils/err_map.rs#L148 */
  if( effects->error != -1 && log->buf_sz ) {
    effects->log = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( log->buf_sz ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      goto error;
    }
    effects->log->size = (uint)fd_log_collector_debug_sprintf( log, (char *)effects->log->bytes, 0 );
  } else {
    effects->log = NULL;
  }

  /* Capture input regions */
  ulong tmp_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  ulong input_regions_size = fd_solfuzz_vm_load_from_input_regions(
      vm->input_mem_regions,
      vm->input_mem_regions_cnt,
      &effects->input_data_regions,
      &effects->input_data_regions_count,
      (void *)tmp_end,
      fd_ulong_sat_sub( output_end, tmp_end )
  );

  if( !!vm->input_mem_regions_cnt && !effects->input_data_regions ) {
    goto error;
  }

  /* Return the effects */
  ulong actual_end = tmp_end + input_regions_size;
  fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );

  *output = effects;
  return actual_end - (ulong)output_buf;

error:
  fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
  return 0;
}
