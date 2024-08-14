#include "fd_vm_test.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../../vm/test_vm_util.h"

ulong
fd_exec_vm_validate_test_run( fd_exec_instr_test_runner_t * runner,
                              void const *                  input_,
                              void **                       output_,
                              void *                        output_buf,
                              ulong                         output_bufsz ) {
  (void) runner; /* unused, for wrapper compat */
  fd_exec_test_full_vm_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_validate_vm_effects_t **  output = fd_type_pun( output_ );

  if( FD_UNLIKELY( !input->has_vm_ctx ) ) {
    return 0UL;
  }

  int rej_callx_r10 = 0;
  if( input->has_features ) {
    for( ulong i=0UL; i < input->features.features_count; i++ ) {
      if( input->features.features[i] == TEST_VM_REJECT_CALLX_R10_FEATURE_PREFIX ) {
        rej_callx_r10 = 1;
        break;
      }
    }
  }
  fd_exec_instr_ctx_t * ctx = test_vm_minimal_exec_instr_ctx( fd_libc_alloc_virtual(), rej_callx_r10 );

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
