#include "fd_vm_test.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../../vm/test_vm_util.h"
#include "fd_exec_instr_test.h"

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

ulong
fd_exec_vm_validate_test_run( fd_exec_instr_test_runner_t * runner,
                              void const *                  input_,
                              void **                       output_,
                              void *                        output_buf,
                              ulong                         output_bufsz ) {
  (void) runner;
  fd_exec_test_full_vm_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_validate_vm_effects_t **  output = fd_type_pun( output_ );

  if( FD_UNLIKELY( !input->has_vm_ctx ) ) {
    return 0UL;
  }

  fd_exec_instr_ctx_t * ctx = test_vm_minimal_exec_instr_ctx( fd_libc_alloc_virtual() );

  FD_TEST( output_bufsz >= sizeof(fd_exec_test_validate_vm_effects_t) );

  /* Capture outputs */
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_validate_vm_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_validate_vm_effects_t),
                                sizeof (fd_exec_test_validate_vm_effects_t) );
  FD_SCRATCH_ALLOC_FINI( l, 1UL );

  fd_valloc_t valloc = fd_scratch_virtual();
  do{
    fd_exec_test_vm_context_t const * vm_ctx = &input->vm_ctx;

    /* Follows prost/solfuzz-agave behavior for empty bytes field */
    uchar * rodata = NULL;
    ulong rodata_sz = 0UL;
    if( FD_LIKELY( vm_ctx->rodata ) ) {
      rodata = vm_ctx->rodata->bytes;
      rodata_sz = vm_ctx->rodata->size;
    }

    ulong * text = (ulong *) (rodata + vm_ctx->rodata_text_section_offset);
    ulong text_cnt = vm_ctx->rodata_text_section_length / 8UL;

    fd_vm_t * vm = fd_vm_join( fd_vm_new( fd_valloc_malloc( valloc, fd_vm_align(), fd_vm_footprint() ) ) );
    FD_TEST( vm );

    fd_vm_init(
      vm,
      ctx,
      0, /* heap_max */
      0, /* cu_avail */
      rodata,
      rodata_sz,
      text,
      text_cnt,
      vm_ctx->rodata_text_section_offset,
      vm_ctx->rodata_text_section_length,
      0, /* entry_pc, not used in validate at the moment */
      NULL, /* calldests */
      NULL, /* syscalls */
      NULL, /* trace */
      NULL, /* sha */
      NULL, /* mem regions */
      0,    /* mem regions count */
      NULL, /* mem regions accs */
      0     /* is deprecated */
    );
    effects->result = fd_vm_validate( vm );

    fd_valloc_free( valloc, fd_vm_delete( fd_vm_leave( vm ) ) );

  } while(0);


  /* Run vm validate and capture result */

  effects->success = (effects->result == FD_VM_SUCCESS);
  *output = effects;

  test_vm_exec_instr_ctx_delete( ctx );
  return sizeof (fd_exec_test_validate_vm_effects_t);
}

void
setup_vm_acc_region_metas( fd_vm_acc_region_meta_t * acc_regions_meta,
                           fd_vm_t *                 vm,
                           fd_exec_instr_ctx_t *     instr_ctx ) {
  /* cur_region is used to figure out what acc region index the account
     corresponds to. */
  uint cur_region = 0UL;
  for( ulong i=0UL; i<instr_ctx->instr->acct_cnt; i++ ) {
    cur_region++;
    fd_borrowed_account_t const * acc = instr_ctx->instr->borrowed_accounts[i];
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
                            fd_exec_test_syscall_context_t const *input,
                            fd_exec_test_syscall_effects_t      **output,
                            void *                                output_buf,
                            ulong                                 output_bufsz ) {
  fd_wksp_t  * wksp  = fd_wksp_attach( "wksp" );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );

  /* Create execution context */
  const fd_exec_test_instr_context_t * input_instr_ctx = &input->instr_ctx;
  fd_exec_instr_ctx_t instr_ctx[1];
  if( !fd_exec_test_instr_context_create( runner, instr_ctx, input_instr_ctx, alloc, true /* is_syscall avoids certain checks we don't want */ ) ) {
    fd_exec_test_instr_context_destroy( runner, instr_ctx, wksp, alloc );
    return 0UL;
  }

  if( !( input->has_vm_ctx && input->has_syscall_invocation ) ) {
    fd_exec_test_instr_context_destroy( runner, instr_ctx, wksp, alloc );
    return 0UL;
  }

  fd_valloc_t valloc = fd_scratch_virtual();

  /* Create effects */
  ulong output_end = (ulong) output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );
  fd_exec_test_syscall_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_syscall_effects_t),
                                sizeof (fd_exec_test_syscall_effects_t) );
  *effects = (fd_exec_test_syscall_effects_t) FD_EXEC_TEST_SYSCALL_EFFECTS_INIT_ZERO;

  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_exec_test_instr_context_destroy( runner, instr_ctx, wksp, alloc );
    return 0UL;
  }

do{
  /* Setup regions */
  if ( !input->vm_ctx.rodata ) {
    break;
  }
  uchar * rodata = input->vm_ctx.rodata->bytes;
  ulong   rodata_sz = input->vm_ctx.rodata->size;

  /* Load input data regions */
  fd_vm_input_region_t * input_regions     = fd_valloc_malloc( valloc, alignof(fd_vm_input_region_t), sizeof(fd_vm_input_region_t) * input->vm_ctx.input_data_regions_count );
  uint                   input_regions_cnt = setup_vm_input_regions( input_regions, input->vm_ctx.input_data_regions, input->vm_ctx.input_data_regions_count );

  if (input->vm_ctx.heap_max > FD_VM_HEAP_DEFAULT) {
    break;
  }

  /* Setup calldests from call_whitelist */
  ulong * calldests = (ulong *) input->vm_ctx.call_whitelist->bytes;

  /* Setup syscalls. Have them all be no-ops */
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  fd_vm_syscall_register_all( syscalls, 0 );

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

  /* Override some execution state values from the interp fuzzer input
     This is so we can test if the interp (or vm setup) mutates any of
     these erroneously */
  vm->reg[0]  = input->vm_ctx.r0;
  vm->reg[1]  = input->vm_ctx.r1;
  vm->reg[2]  = input->vm_ctx.r2;
  vm->reg[3]  = input->vm_ctx.r3;
  vm->reg[4]  = input->vm_ctx.r4;
  vm->reg[5]  = input->vm_ctx.r5;
  vm->reg[6]  = input->vm_ctx.r6;
  vm->reg[7]  = input->vm_ctx.r7;
  vm->reg[8]  = input->vm_ctx.r8;
  vm->reg[9]  = input->vm_ctx.r9;
  vm->reg[10] = input->vm_ctx.r10;
  vm->reg[11] = input->vm_ctx.r11;

  fd_vm_init(
    vm,
    instr_ctx,
    FD_VM_HEAP_MAX,
    input->has_instr_ctx ? input->instr_ctx.cu_avail : 0,
    rodata,
    rodata_sz,
    (ulong *) rodata, /* text*, same as rodata */
    rodata_sz / 8, /* text_cnt */
    0, /* text_off */
    rodata_sz, /* text_sz */
    input->vm_ctx.entry_pc,
    calldests,
    syscalls,
    trace, /* trace */
    NULL, /* sha */
    input_regions,
    input_regions_cnt,
    NULL, /* vm_acc_region_meta*/
    0 /* is deprecated */
  );

  // Propagate the acc_regions_meta to the vm
  vm->acc_region_metas = fd_valloc_malloc( valloc, alignof(fd_vm_acc_region_meta_t), sizeof(fd_vm_acc_region_meta_t) * input->vm_ctx.input_data_regions_count );
  setup_vm_acc_region_metas( vm->acc_region_metas, vm, vm->instr_ctx );

  // Validate the vm
  if ( fd_vm_validate( vm ) != FD_VM_SUCCESS ) {
    effects->error = -1;
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
  effects->error = -1 * exec_res;

  /* Capture outputs */
  effects->cu_avail    = vm->cu;
  effects->frame_count = vm->frame_cnt;
  effects->r0          = exec_res ? 0 : vm->reg[0]; /* Only capture r0 if no error */

  /* skip logs since syscalls are stubbed */

  /* CU error is difficult to properly compare as there may have been
     valid writes to the memory regions prior to capturing the error. And
     the pc might be well past (by an arbitrary amount) the instruction
     where the CU error occurred. */
  if( exec_res == FD_VM_ERR_SIGCOST ) break;

  effects->pc = vm->pc;

  effects->heap       = FD_SCRATCH_ALLOC_APPEND(
    l, alignof(uchar), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->heap_max ) );
  effects->heap->size = (uint)vm->heap_max;
  fd_memcpy( effects->heap->bytes, vm->heap, vm->heap_max );

  effects->stack       = FD_SCRATCH_ALLOC_APPEND(
    l, alignof(uchar), PB_BYTES_ARRAY_T_ALLOCSIZE( FD_VM_STACK_MAX ) );
  effects->stack->size = (uint)FD_VM_STACK_MAX;
  fd_memcpy( effects->stack->bytes, vm->stack, FD_VM_STACK_MAX );

  effects->rodata       = FD_SCRATCH_ALLOC_APPEND(
    l, alignof(uchar), PB_BYTES_ARRAY_T_ALLOCSIZE( rodata_sz ) );
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
  fd_exec_test_instr_context_destroy( runner, instr_ctx, wksp, alloc );
  return actual_end - (ulong)output_buf;
}


uint
setup_vm_input_regions( fd_vm_input_region_t *                   input,
                        fd_exec_test_input_data_region_t const * test_input,
                        ulong                                    test_input_count ) {
  ulong offset = 0UL;
  uint input_idx = 0UL;
  for( ulong i=0; i<test_input_count; i++ ) {
    fd_exec_test_input_data_region_t const * region = &test_input[i];
    pb_bytes_array_t * array = region->content;
    if( !array ) {
      continue; /* skip empty regions https://github.com/anza-xyz/agave/blob/3072c1a72b2edbfa470ca869f1ea891dfb6517f2/programs/bpf_loader/src/serialization.rs#L136 */
    }

    input[input_idx].vaddr_offset     = offset;
    input[input_idx].haddr            = (ulong)array->bytes;
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
