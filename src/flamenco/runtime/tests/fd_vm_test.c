#include "fd_vm_test.h"
#include "fd_exec_instr_test.h"
#include "../fd_system_ids.h"
#include "generated/vm.pb.h"
#include "../program/fd_bpf_loader_serialization.h"


int
fd_vm_syscall_noop( void * _vm,
                    ulong arg0,
                    ulong arg1,
                    ulong arg2,
                    ulong arg3,
                    ulong arg4,
                    ulong* _ret){
  /* TODO: have input message determine CUs to deduct?
  fd_vm_t * vm = (fd_vm_t *) _vm;
  vm->cu = vm->cu - 5;
  */

  (void) _vm;
  (void) arg0;
  (void) arg1;
  (void) arg2;
  (void) arg3;
  (void) arg4;
  *_ret = 0;
  return 0;
}

void
fd_setup_vm_acc_region_metas( fd_vm_acc_region_meta_t * acc_regions_meta,
                              fd_vm_t *                 vm,
                              fd_exec_instr_ctx_t *     instr_ctx ) {
  /* cur_region is used to figure out what acc region index the account
     corresponds to. */
  uint cur_region = 0UL;
  for( ulong i=0UL; i<instr_ctx->instr->acct_cnt; i++ ) {
    cur_region++;
    fd_txn_account_t const * acc = instr_ctx->instr->accounts[i];
    acc_regions_meta[i].region_idx          = cur_region;
    acc_regions_meta[i].has_data_region     = acc->const_meta->dlen>0UL;
    acc_regions_meta[i].has_resizing_region = !vm->is_deprecated;
    if( acc->const_meta->dlen>0UL ) {
      cur_region++;
    }
    if( vm->is_deprecated ) {
      cur_region--;
    }
  }
}

ulong
fd_exec_vm_interp_test_run( fd_exec_instr_test_runner_t *         runner,
                            void const *                          input_,
                            void **                               output_,
                            void *                                output_buf,
                            ulong                                 output_bufsz ) {
  fd_exec_test_syscall_context_t const * input = fd_type_pun_const( input_ );
  fd_exec_test_syscall_effects_t      ** output = fd_type_pun( output_ );

  /* Create execution context */
  const fd_exec_test_instr_context_t * input_instr_ctx = &input->instr_ctx;
  fd_exec_instr_ctx_t instr_ctx[1];
  if( !fd_exec_test_instr_context_create( runner, instr_ctx, input_instr_ctx, true /* is_syscall avoids certain checks we don't want */ ) ) {
    fd_exec_test_instr_context_destroy( runner, instr_ctx );
    return 0UL;
  }

  if( !( input->has_vm_ctx ) ) {
    fd_exec_test_instr_context_destroy( runner, instr_ctx );
    return 0UL;
  }

  fd_spad_t * spad   = fd_exec_instr_test_runner_get_spad( runner );
  fd_valloc_t valloc = fd_spad_virtual( spad );

  /* Create effects */
  ulong output_end = (ulong) output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );
  fd_exec_test_syscall_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_syscall_effects_t),
                                sizeof (fd_exec_test_syscall_effects_t) );
  *effects = (fd_exec_test_syscall_effects_t) FD_EXEC_TEST_SYSCALL_EFFECTS_INIT_ZERO;

  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_exec_test_instr_context_destroy( runner, instr_ctx );
    return 0UL;
  }

do{
  /* Setup regions */
  if ( !input->vm_ctx.rodata ) {
    break;
  }
  ulong   rodata_sz = input->vm_ctx.rodata->size;
  uchar * rodata = fd_spad_alloc_debug( spad, 8UL, rodata_sz );
  memcpy( rodata, input->vm_ctx.rodata->bytes, rodata_sz );

  /* Enable direct_mapping for SBPF version >= v1 */
  if( input->vm_ctx.sbpf_version >= FD_SBPF_V1 ) {
    ((fd_exec_txn_ctx_t *)(instr_ctx->txn_ctx))->features.bpf_account_data_direct_mapping = 0UL;
  }

  /* Setup input region */
  ulong                   input_sz                = 0UL;
  ulong                   pre_lens[256]           = {0};
  fd_vm_input_region_t    input_mem_regions[1000] = {0}; /* We can have a max of (3 * num accounts + 1) regions */
  fd_vm_acc_region_meta_t acc_region_metas[256]   = {0}; /* instr acc idx to idx */
  uint                    input_mem_regions_cnt   = 0U;
  int                     direct_mapping          = FD_FEATURE_ACTIVE( instr_ctx->txn_ctx->slot_bank->slot, instr_ctx->txn_ctx->features, bpf_account_data_direct_mapping );

  uchar * input_ptr      = NULL;
  uchar   program_id_idx = instr_ctx->instr->program_id;
  uchar   is_deprecated  = ( program_id_idx < instr_ctx->txn_ctx->accounts_cnt ) &&
                           ( !memcmp( instr_ctx->txn_ctx->accounts[program_id_idx].const_meta->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) );

  /* TODO: Check for an error code. Probably unlikely during fuzzing though */
  fd_bpf_loader_input_serialize_parameters( instr_ctx,
                                            &input_sz,
                                            pre_lens,
                                            input_mem_regions,
                                            &input_mem_regions_cnt,
                                            acc_region_metas,
                                            direct_mapping,
                                            is_deprecated,
                                            &input_ptr );

  if( input->vm_ctx.heap_max>FD_VM_HEAP_DEFAULT ) {
    break;
  }

  /* Setup calldests from call_whitelist.
     Alloc calldests with the expected size (1 bit per ix, rounded up to ulong) */
  ulong max_pc = (rodata_sz + 7) / 8;
  ulong calldests_sz = ((max_pc + 63) / 64) * 8;
  ulong * calldests = fd_valloc_malloc( valloc, fd_sbpf_calldests_align(), calldests_sz );
  memset( calldests, 0, calldests_sz );
  if( input->vm_ctx.call_whitelist && input->vm_ctx.call_whitelist->size > 0 ) {
    memcpy( calldests, input->vm_ctx.call_whitelist->bytes, input->vm_ctx.call_whitelist->size );
    /* Make sure bits over max_pc are all 0s. */
    ulong mask = (1UL << (max_pc % 64)) - 1UL;
    calldests[ max_pc / 64 ] &= mask;
  }
  ulong entry_pc = fd_ulong_min( input->vm_ctx.entry_pc, rodata_sz / 8UL - 1UL );
  if( input->vm_ctx.sbpf_version >= FD_SBPF_V3 ) {
    /* in v3 we have to enable the entrypoint */
    calldests[ entry_pc / 64UL ] |= ( 1UL << ( entry_pc % 64UL ) );
  }

  /* Setup syscalls. Have them all be no-ops */
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  fd_vm_syscall_register_slot( syscalls,
                               instr_ctx->txn_ctx->slot_bank->slot,
                               &instr_ctx->txn_ctx->features,
                               0 );

  for( ulong i=0; i< fd_sbpf_syscalls_slot_cnt(); i++ ){
    fd_sbpf_syscalls_t * syscall = fd_sbpf_syscalls_query( syscalls, syscalls[i].key, NULL );
    if ( !syscall ) {
      continue;
    }
    syscall->func = fd_vm_syscall_noop;
  }

  /* Setup trace */
  const uint DUMP_TRACE = 0; // Set to 1 to dump trace to stdout
  uint tracing_enabled = input->vm_ctx.tracing_enabled;
  fd_vm_trace_t * trace = NULL;
  ulong event_max = 1UL<<20;
  ulong event_data_max = 2048UL;

  if (!!tracing_enabled) {
    trace = fd_vm_trace_new( fd_valloc_malloc( valloc, fd_vm_trace_align(), fd_vm_trace_footprint( event_max, event_data_max ) ), event_max, event_data_max );
  }

  /* Setup vm */
  fd_vm_t * vm = fd_vm_join( fd_vm_new( fd_valloc_malloc( valloc, fd_vm_align(), fd_vm_footprint() ) ) );
  FD_TEST( vm );

  fd_vm_init(
    vm,
    instr_ctx,
    input->vm_ctx.heap_max,
    input->has_instr_ctx ? input->instr_ctx.cu_avail : 0,
    rodata,
    rodata_sz,
    (ulong *) rodata, /* text*, same as rodata */
    rodata_sz / 8, /* text_cnt */
    0, /* text_off */
    rodata_sz, /* text_sz */
    entry_pc,
    calldests,
    input->vm_ctx.sbpf_version,
    syscalls,
    trace, /* trace */
    NULL, /* sha */
    input_mem_regions,
    input_mem_regions_cnt,
    acc_region_metas, /* vm_acc_region_meta*/
    is_deprecated, /* is deprecated */
    direct_mapping /* direct mapping */
  );

  /* Setup registers.
     r1, r10, r11 are initialized by EbpfVm::new (r10) or EbpfVm::execute_program (r1, r11),
     or equivalently by fd_vm_init and fd_vm_setup_state_for_execution.
     Modifying them will most like break execution.
     In syscalls we allow override them (especially r1) because that simulates the fact
     that a program partially executed before reaching the syscall.
     Here we want to test what happens when the program starts from the beginning. */
  vm->reg[0]  = input->vm_ctx.r0;
  // vm->reg[1]  = input->vm_ctx.r1; // do not override
  vm->reg[2]  = input->vm_ctx.r2;
  vm->reg[3]  = input->vm_ctx.r3;
  vm->reg[4]  = input->vm_ctx.r4;
  vm->reg[5]  = input->vm_ctx.r5;
  vm->reg[6]  = input->vm_ctx.r6;
  vm->reg[7]  = input->vm_ctx.r7;
  vm->reg[8]  = input->vm_ctx.r8;
  vm->reg[9]  = input->vm_ctx.r9;
  // vm->reg[10]  = input->vm_ctx.r10; // do not override
  // vm->reg[11]  = input->vm_ctx.r11; // do not override

  // Validate the vm
  if( fd_vm_validate( vm ) != FD_VM_SUCCESS ) {
    // custom error, avoid -1 because we use it for "unknown error" in solfuzz-agave
    effects->error = -2;
    break;
  }

  if( input->syscall_invocation.stack_prefix ) {
    uchar * stack    = input->syscall_invocation.stack_prefix->bytes;
    ulong   stack_sz = fd_ulong_min(input->syscall_invocation.stack_prefix->size, FD_VM_STACK_MAX);
    fd_memcpy( vm->stack, stack, stack_sz );
  }

  if( input->syscall_invocation.heap_prefix ) {
    uchar * heap    = input->syscall_invocation.heap_prefix->bytes;
    ulong   heap_sz = fd_ulong_min(input->syscall_invocation.heap_prefix->size, FD_VM_HEAP_MAX);
    fd_memcpy( vm->heap, heap, heap_sz );
  }

  /* Run vm */
  int exec_res = 0;
  if (!!tracing_enabled) {
    exec_res = fd_vm_exec_trace( vm );
    if( DUMP_TRACE ) fd_vm_trace_printf( trace, syscalls );
    fd_vm_trace_delete( fd_vm_trace_leave( trace ) );
  } else {
    exec_res = fd_vm_exec_notrace( vm );
  }

  /* Agave does not have a SIGCALL error, and instead throws SIGILL */
  if( exec_res == FD_VM_ERR_SIGCALL ) exec_res = FD_VM_ERR_SIGILL;
  effects->error = -1 * exec_res;

  /* Capture outputs */
  effects->cu_avail    = vm->cu;
  effects->frame_count = vm->frame_cnt;
  /* Only capture registers if no error */;
  effects->r0          = exec_res ? 0 : vm->reg[0];
  effects->r1          = exec_res ? 0 : vm->reg[1];
  effects->r2          = exec_res ? 0 : vm->reg[2];
  effects->r3          = exec_res ? 0 : vm->reg[3];
  effects->r4          = exec_res ? 0 : vm->reg[4];
  effects->r5          = exec_res ? 0 : vm->reg[5];
  effects->r6          = exec_res ? 0 : vm->reg[6];
  effects->r7          = exec_res ? 0 : vm->reg[7];
  effects->r8          = exec_res ? 0 : vm->reg[8];
  effects->r9          = exec_res ? 0 : vm->reg[9];
  effects->r10         = exec_res ? 0 : vm->reg[10];

  /* skip logs since syscalls are stubbed */

  /* CU error is difficult to properly compare as there may have been
     valid writes to the memory regions prior to capturing the error. And
     the pc might be well past (by an arbitrary amount) the instruction
     where the CU error occurred. */
  if( exec_res == FD_VM_ERR_SIGCOST ) break;

  effects->pc = vm->pc;

  if( vm->heap_max > 0 ) {
    effects->heap       = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->heap_max ) );
    effects->heap->size = (uint)vm->heap_max;
    fd_memcpy( effects->heap->bytes, vm->heap, vm->heap_max );
  }

  /* Compress stack by removing right-most 0s.
     This reduces the total size of effects/fixtures when stack is not used,
     otherwise each would waste 256kB. */
  int rtrim_sz;
  for( rtrim_sz=FD_VM_STACK_MAX-1; rtrim_sz>=0; rtrim_sz-- ) {
    if( vm->stack[rtrim_sz] != 0 ) break;
  }
  if( rtrim_sz > 0 || (vm->stack[0] != 0) ) {
    effects->stack       = FD_SCRATCH_ALLOC_APPEND(
      l, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( FD_VM_STACK_MAX ) );
    effects->stack->size = (uint)rtrim_sz+1;
    fd_memcpy( effects->stack->bytes, vm->stack, (ulong)rtrim_sz+1 );
  }

  effects->rodata       = FD_SCRATCH_ALLOC_APPEND(
    l, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( rodata_sz ) );
  effects->rodata->size = (uint)rodata_sz;
  fd_memcpy( effects->rodata->bytes, rodata, rodata_sz );

  /* Capture input data regions */
  ulong tmp_end = FD_SCRATCH_ALLOC_FINI(l, 1UL);
  ulong input_data_regions_size = load_from_vm_input_regions( vm->input_mem_regions,
                                                              vm->input_mem_regions_cnt,
                                                              &effects->input_data_regions,
                                                              &effects->input_data_regions_count,
                                                              (void *) tmp_end,
                                                              fd_ulong_sat_sub( output_end, tmp_end) );
  FD_SCRATCH_ALLOC_APPEND( l, 1UL, input_data_regions_size );

} while(0);

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  *output = effects;
  fd_exec_test_instr_context_destroy( runner, instr_ctx );
  return actual_end - (ulong)output_buf;
}


uint
fd_setup_vm_input_regions( fd_vm_input_region_t *                   input,
                           fd_exec_test_input_data_region_t const * test_input,
                           ulong                                    test_input_count,
                           fd_spad_t *                              spad ) {
  ulong offset = 0UL;
  uint input_idx = 0UL;
  for( ulong i=0; i<test_input_count; i++ ) {
    fd_exec_test_input_data_region_t const * region = &test_input[i];
    pb_bytes_array_t * array = region->content;
    if( !array ) {
      continue; /* skip empty regions https://github.com/anza-xyz/agave/blob/3072c1a72b2edbfa470ca869f1ea891dfb6517f2/programs/bpf_loader/src/serialization.rs#L136 */
    }

    uchar * haddr = fd_spad_alloc_debug( spad, 8UL, array->size );
    fd_memcpy( haddr, array->bytes, array->size );
    input[input_idx].vaddr_offset     = offset;
    input[input_idx].haddr            = (ulong)haddr;
    input[input_idx].region_sz        = array->size;
    input[input_idx].is_writable      = region->is_writable;

    input_idx++;
    offset += array->size;
  }
  return input_idx; /* return the number of populated regions */
}


ulong
load_from_vm_input_regions( fd_vm_input_region_t const *        input,
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

    out_region->content = FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                               PB_BYTES_ARRAY_T_ALLOCSIZE(vm_region->region_sz) );
    FD_TEST( out_region->content );
    out_region->content->size = vm_region->region_sz;
    fd_memcpy( out_region->content->bytes, (void *)vm_region->haddr, vm_region->region_sz );
  }

  ulong end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  return end - (ulong)output_buf; /* return the number of bytes written */
}
