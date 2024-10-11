#include "fd_vm_syscall.h"

#include "../../../ballet/base64/fd_base64.h"
#include "../../../ballet/utf8/fd_utf8.h"
#include "../../runtime/sysvar/fd_sysvar.h"
#include "../../runtime/sysvar/fd_sysvar_clock.h"
#include "../../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../runtime/sysvar/fd_sysvar_fees.h"
#include "../../runtime/context/fd_exec_txn_ctx.h"
#include "../../runtime/context/fd_exec_instr_ctx.h"
#include "../../runtime/fd_account.h"

int
fd_vm_syscall_abort( FD_PARAM_UNUSED void *  _vm,
                     FD_PARAM_UNUSED ulong   r1,
                     FD_PARAM_UNUSED ulong   r2,
                     FD_PARAM_UNUSED ulong   r3,
                     FD_PARAM_UNUSED ulong   r4,
                     FD_PARAM_UNUSED ulong   r5,
                     FD_PARAM_UNUSED ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/mod.rs#L630 */
  fd_vm_t * vm = (fd_vm_t *)_vm;
  FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_ERR_SYSCALL_ABORT );
  return FD_VM_ERR_ABORT;
}

/* FD_TRANSLATE_STRING returns a read only pointer to the host address of
   a valid utf8 string, or it errors.

   Analogous of Agave's translate_string_and_do().
   https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/mod.rs#L601

   As of v0.2.6, the only two usages are in syscall panic and syscall log. */
#define FD_TRANSLATE_STRING( vm, vaddr, msg_sz ) (__extension__({                          \
    char const * msg = FD_VM_MEM_SLICE_HADDR_LD( vm, vaddr, FD_VM_ALIGN_RUST_U8, msg_sz ); \
    if( FD_UNLIKELY( !fd_utf8_verify( msg, msg_sz ) ) ) {                                  \
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_ERR_SYSCALL_INVALID_STRING );                   \
      return FD_VM_ERR_SYSCALL_INVALID_STRING;                                             \
    }                                                                                      \
    msg;                                                                                   \
}))

int
fd_vm_syscall_sol_panic( /**/            void *  _vm,
                         /**/            ulong   file_vaddr,
                         /**/            ulong   file_sz,
                         /**/            ulong   line,
                         /**/            ulong   column,
                         FD_PARAM_UNUSED ulong   r5,
                         FD_PARAM_UNUSED ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/mod.rs#L637

     Note: this syscall is not used by the Rust SDK, only by the C SDK.
     Rust transforms `panic!()` into a log, followed by an abort.
     It's unclear if this syscall actually makes any sense... */
  FD_VM_CU_UPDATE( vm, file_sz );

  /* Validate string */
  FD_TRANSLATE_STRING( vm, file_vaddr, file_sz );

  /* Note: we truncate the log, ignoring file, line, column.
     As mentioned above, it's unclear if anyone is even using this syscall,
     so dealing with the complexity of Agave's log is a waste of time. */
  (void)line;
  (void)column;

  FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_ERR_SYSCALL_PANIC );
  return FD_VM_ERR_PANIC;
}

int
fd_vm_syscall_sol_log( /**/            void *  _vm,
                       /**/            ulong   msg_vaddr,
                       /**/            ulong   msg_sz,
                       FD_PARAM_UNUSED ulong   r2,
                       FD_PARAM_UNUSED ulong   r3,
                       FD_PARAM_UNUSED ulong   r4,
                       /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L5 */

  FD_VM_CU_UPDATE( vm, fd_ulong_max( msg_sz, FD_VM_SYSCALL_BASE_COST ) );

  /* Note: when msg_sz==0, msg can be undefined. fd_log_collector_program_log() handles it. */
  fd_log_collector_program_log( vm->instr_ctx, FD_TRANSLATE_STRING( vm, msg_vaddr, msg_sz ), msg_sz );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_log_64( void *  _vm,
                          ulong   r1,
                          ulong   r2,
                          ulong   r3,
                          ulong   r4,
                          ulong   r5,
                          ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L37 */

  FD_VM_CU_UPDATE( vm, FD_VM_LOG_64_UNITS );

  /* Max msg_sz: 46 - 15 + 16*5 = 111 < 127 => we can use printf */
  fd_log_collector_printf_dangerous_max_127( vm->instr_ctx,
    "Program log: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx", r1, r2, r3, r4, r5 );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_log_compute_units( /**/            void *  _vm,
                                     FD_PARAM_UNUSED ulong   r1,
                                     FD_PARAM_UNUSED ulong   r2,
                                     FD_PARAM_UNUSED ulong   r3,
                                     FD_PARAM_UNUSED ulong   r4,
                                     FD_PARAM_UNUSED ulong   r5,
                                     /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L60 */

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  /* Max msg_sz: 40 - 3 + 20 = 57 < 127 => we can use printf */
  fd_log_collector_printf_dangerous_max_127( vm->instr_ctx,
    "Program consumption: %lu units remaining", vm->cu );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_log_pubkey( /**/            void *  _vm,
                              /**/            ulong   pubkey_vaddr,
                              FD_PARAM_UNUSED ulong   r2,
                              FD_PARAM_UNUSED ulong   r3,
                              FD_PARAM_UNUSED ulong   r4,
                              FD_PARAM_UNUSED ulong   r5,
                              /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L84 */

  FD_VM_CU_UPDATE( vm, FD_VM_LOG_PUBKEY_UNITS );

  void const * pubkey = FD_VM_MEM_HADDR_LD( vm, pubkey_vaddr, FD_VM_ALIGN_RUST_PUBKEY, sizeof(fd_pubkey_t) );

  char msg[ FD_BASE58_ENCODED_32_SZ ]; ulong msg_sz;
  if( FD_UNLIKELY( fd_base58_encode_32( pubkey, &msg_sz, msg )==NULL ) ) {
    return FD_VM_ERR_INVAL;
  }

  fd_log_collector_program_log( vm->instr_ctx, msg, msg_sz );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_log_data( /**/            void *  _vm,
                            /**/            ulong   slice_vaddr,
                            /**/            ulong   slice_cnt,
                            FD_PARAM_UNUSED ulong   r3,
                            FD_PARAM_UNUSED ulong   r4,
                            FD_PARAM_UNUSED ulong   r5,
                            /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L109

     Note: this is implemented following Agave's perverse behavior.
     We need to loop the slice multiple times to match the exact error,
     first compute budget, then memory mapping.
     And finally we can loop to log. */

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L121 */

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L123-L128 */

  fd_vm_vec_t const * slice = (fd_vm_vec_t const *)FD_VM_MEM_HADDR_LD( vm, slice_vaddr, FD_VM_ALIGN_RUST_SLICE_U8_REF,
    fd_ulong_sat_mul( slice_cnt, sizeof(fd_vm_vec_t) ) );

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L130-L135 */

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_mul( FD_VM_SYSCALL_BASE_COST, slice_cnt ) );

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L136-L141 */

  for( ulong i=0UL; i<slice_cnt; i++ ) {
    FD_VM_CU_UPDATE( vm, slice[i].len );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L145-L152 */

  ulong msg_sz = 14UL; /* "Program data: ", with space */
  for( ulong i=0UL; i<slice_cnt; i++ ) {
    ulong cur_len = slice[i].len;
    /* This fails the syscall in case of memory mapping issues */
    FD_VM_MEM_SLICE_HADDR_LD( vm, slice[i].addr, FD_VM_ALIGN_RUST_U8, cur_len );
    /* Every buffer will be base64 encoded + space separated */
    msg_sz += (slice[i].len + 2)/3*4 + (i > 0);
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.6/programs/bpf_loader/src/syscalls/logging.rs#L156 */

  char msg[ FD_LOG_COLLECTOR_MAX ];
  ulong bytes_written = fd_log_collector_check_and_truncate( &vm->instr_ctx->txn_ctx->log_collector, msg_sz );
  if( FD_LIKELY( bytes_written < ULONG_MAX ) ) {
    fd_memcpy( msg, "Program data: ", 14 );
    char * buf = msg + 14;

    for( ulong i=0UL; i<slice_cnt; i++ ) {
      ulong cur_len = slice[i].len;
      void const * bytes = FD_VM_MEM_SLICE_HADDR_LD( vm, slice[i].addr, FD_VM_ALIGN_RUST_U8, cur_len );

      if( i ) { *buf = ' '; ++buf; } /* skip first */
      buf += fd_base64_encode( buf, bytes, cur_len );
    }
    FD_TEST( (ulong)(buf-msg)==msg_sz );

    fd_log_collector_msg( vm->instr_ctx, msg, msg_sz );
  }

  *_ret = 0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_alloc_free( /**/            void *  _vm,
                              /**/            ulong   sz,
                              /**/            ulong   free_vaddr,
                              FD_PARAM_UNUSED ulong   r3,
                              FD_PARAM_UNUSED ulong   r4,
                              FD_PARAM_UNUSED ulong   r5,
                              /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L666 */

  /* This syscall is ... uh ... problematic.  But the community has
     already recognized this and deprecated it:

     https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/feature_set.rs#L846

     Unfortunately, old code never dies so, practically, this will need
     to be supported until the heat death of the universe.

     The most serious issue is that there is nothing to stop VM code
     making a decision based on the _location_ of the returned
     allocation.  If different validator implementations use different
     allocator algorithms, though each implementation would behave
     functionally correct in isolation, the VM code that uses it would
     actually break consensus.

     As a result, every validator needs to use a bit-for-bit identical
     allocation algorithm.  Fortunately, Solana is just using a basic
     bump allocator:

     https://github.com/solana-labs/solana/blob/v1.17.23/program-runtime/src/invoke_context.rs#L122-L148

     vm->heap_{sz,max} and the below replicate this exactly.

     Another major issue is that this alloc doesn't always conform
     typical malloc/free semantics (e.g. C/C++ requires malloc to have
     an alignment safe for primitive types ... 8 for the Solana machine
     model).  This is clearly to support backward compat with older VM
     code (though ideally a malloc syscall should have behaved like ...
     well ... malloc from day 1).  So the alignment behavior below is a
     bug-for-bug replication of that:

     https://github.com/solana-labs/solana/blob/v1.17.23/programs/bpf_loader/src/syscalls/mod.rs#L645-L681
     https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/entrypoint.rs#L265-L266

     More generally and already ranted about elsewhere, any code that
     uses malloc/free style dynamic allocation is inherently broken.  So
     this syscall should have never existed in the first place ... it
     just feeds the trolls.  The above is just additional implementation
     horror because people consistent think malloc/free is much simpler
     than it actually is.  This is also an example of how quickly
     mistakes fossilize and become a thorn-in-the-side forever.

     IMPORTANT SAFETY TIP!  heap_start must be non zero and both
     heap_start and heap_end should have an alignment of at least 8.
     This existing runtime policies around heap implicitly satisfy this.

     IMPORTANT SAFETY TIP!  The specification for Rust's align_offset
     doesn't seem to provide a strong guarantee that it will return the
     minimal positive offset necessary to align pointers.  It is
     possible for a "conforming" Rust compiler to break consensus by
     using a different align_offset implementation that aligned pointer
     between different compilations of the Solana validator and the
     below. */

  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L676-L680 */

  ulong align = fd_vm_is_check_align_enabled( vm ) ? 8UL : FD_VM_ALIGN_RUST_U8;

  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L681-L683
     Nothing to do. This section can't error, see:
     https://doc.rust-lang.org/1.81.0/src/core/alloc/layout.rs.html#70
     https://doc.rust-lang.org/1.81.0/src/core/alloc/layout.rs.html#100 */


  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L684
     Nothing to do.
     TODO: unclear if it throw InstructionError::CallDepth
     https://github.com/anza-xyz/agave/blob/v2.0.8/program-runtime/src/invoke_context.rs#L662 */

  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L685-L693 */

  /* Non-zero free address implies that this is a free() call.  Since
     this is a bump allocator, free is a no-op. */
  if( FD_UNLIKELY( free_vaddr ) ) {
    *_ret = 0UL;
    return FD_VM_SUCCESS;
  }


  ulong heap_sz    = fd_ulong_align_up( vm->heap_sz, align                           );
  ulong heap_vaddr = fd_ulong_sat_add ( heap_sz,     FD_VM_MEM_MAP_HEAP_REGION_START );
  /**/  heap_sz    = fd_ulong_sat_add ( heap_sz,     sz                              );

  if( FD_UNLIKELY( heap_sz > vm->heap_max ) ) { /* Not enough free memory */
    *_ret = 0UL;
    return FD_VM_SUCCESS;
  }

  vm->heap_sz = heap_sz;

  *_ret = heap_vaddr;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_memcpy( /**/            void *  _vm,
                          /**/            ulong   dst_vaddr,
                          /**/            ulong   src_vaddr,
                          /**/            ulong   sz,
                          FD_PARAM_UNUSED ulong   r4,
                          FD_PARAM_UNUSED ulong   r5,
                          /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mem_ops.rs#L18 */

  /* FIXME: confirm exact handling matches Solana for the NULL, sz==0
     and/or dst==src cases (see other mem syscalls ... they don't all
     fault in the same way though in principle that shouldn't break
     consensus).  Except for fixing the overflow risk from wrapping
     ranges (the below is computed as though the ranges are in exact
     math and don't overlap), the below handling matches the original
     implementation. */
  /* FIXME: use overlap logic from runtime? */

  FD_VM_CU_MEM_OP_UPDATE( vm, sz );

  /* https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/mem_ops.rs#L31 */
  FD_VM_MEM_CHECK_NON_OVERLAPPING( vm, src_vaddr, sz, dst_vaddr, sz );

  if( FD_UNLIKELY( !sz ) ) {
    *_ret = 0;
    return FD_VM_SUCCESS;
  }

  if( !FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, bpf_account_data_direct_mapping ) ) {
    void *       dst = FD_VM_MEM_HADDR_ST( vm, dst_vaddr, FD_VM_ALIGN_RUST_U8, sz );
    void const * src = FD_VM_MEM_HADDR_LD( vm, src_vaddr, FD_VM_ALIGN_RUST_U8, sz );

    fd_memcpy( dst, src, sz );

    *_ret = 0;
    return FD_VM_SUCCESS;
  } else {

    /* Lookup host address chunks.  Try to do a standard memcpy if the regions
       do not cross memory regions. */
    ulong   dst_region              = dst_vaddr >> 32;
    ulong   dst_offset              = dst_vaddr & 0xffffffffUL;
    ulong   dst_region_idx          = 0UL;
    ulong   dst_bytes_in_cur_region = sz;
    uchar * dst_haddr               = NULL;
    if( dst_region==4UL ) {
      dst_region_idx          = fd_vm_get_input_mem_region_idx( vm, dst_offset );
      dst_haddr               = (uchar*)(vm->input_mem_regions[ dst_region_idx ].haddr + dst_offset - vm->input_mem_regions[ dst_region_idx ].vaddr_offset);
      dst_bytes_in_cur_region = fd_ulong_min( sz, fd_ulong_sat_sub( vm->input_mem_regions[ dst_region_idx ].region_sz, 
                                                                    ((ulong)dst_haddr - vm->input_mem_regions[ dst_region_idx ].haddr) ) );
      if( FD_UNLIKELY( !vm->input_mem_regions[ dst_region_idx ].is_writable ) ) {
        *_ret = 1;
        return FD_VM_ERR_ABORT;
      }
      if( FD_UNLIKELY( dst_region_idx+1UL==vm->input_mem_regions_cnt && dst_bytes_in_cur_region<sz ) ) {
        *_ret = 1;
        return FD_VM_ERR_ABORT;
      }

    } else {
      dst_haddr = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, dst_vaddr, FD_VM_ALIGN_RUST_U8, sz );
    }

    ulong src_region              = src_vaddr >> 32;
    ulong src_offset              = src_vaddr & 0xffffffffUL;
    ulong src_region_idx          = 0UL;
    ulong src_bytes_in_cur_region = sz;
    uchar * src_haddr             = NULL;
    if( src_region==4UL ) {
      src_region_idx          = fd_vm_get_input_mem_region_idx( vm, src_offset );
      src_haddr               = (uchar*)(vm->input_mem_regions[ src_region_idx ].haddr + src_offset - vm->input_mem_regions[ src_region_idx ].vaddr_offset);
      src_bytes_in_cur_region = fd_ulong_min( sz, fd_ulong_sat_sub( vm->input_mem_regions[ src_region_idx ].region_sz, 
                                                                    ((ulong)src_haddr - vm->input_mem_regions[ src_region_idx ].haddr) ) );
      if( FD_UNLIKELY( src_region_idx+1UL==vm->input_mem_regions_cnt && src_bytes_in_cur_region<sz ) ) {
        *_ret = 1;
        return FD_VM_ERR_ABORT;
      }

    } else {
      src_haddr           = (uchar *)FD_VM_MEM_SLICE_HADDR_LD( vm, src_vaddr, FD_VM_ALIGN_RUST_U8, sz );
    }

    /* Do a normal memcpy if regions do not overlap */
    if( FD_LIKELY( src_bytes_in_cur_region==dst_bytes_in_cur_region && src_bytes_in_cur_region==sz ) ) {
      fd_memcpy( dst_haddr, src_haddr, sz );
      *_ret = 0;
      return FD_VM_SUCCESS;
    }
  
    /* Case where the operation spans multiple regions. Copy over the bytes
       from each region while iterating to the next one. */
    /* TODO: An optimization would be to memcpy chunks at once */
    ulong dst_idx = 0UL;
    ulong src_idx = 0UL;
    for( ulong i=0UL; i<sz; i++ ) {
      if( FD_UNLIKELY( !dst_bytes_in_cur_region ) ) {
        /* Go to next one */
        if( FD_UNLIKELY( ++dst_region_idx>=vm->input_mem_regions_cnt ) ) {
          *_ret = 1;
          return FD_VM_ERR_ABORT;
        }
        if( FD_UNLIKELY( !vm->input_mem_regions[ dst_region_idx ].is_writable ) ) {
          *_ret = 1;
          return FD_VM_ERR_ABORT;
        }
        dst_haddr               = (uchar*)vm->input_mem_regions[ dst_region_idx ].haddr;
        dst_bytes_in_cur_region = vm->input_mem_regions[ dst_region_idx ].region_sz;
        dst_idx                 = 0UL;
      }
      if( FD_UNLIKELY( !src_bytes_in_cur_region ) ) {
        /* Go to next one */
        if( FD_UNLIKELY( ++src_region_idx>=vm->input_mem_regions_cnt ) ) {
          *_ret = 1;
          return FD_VM_ERR_ABORT;
        }
        src_haddr               = (uchar*)vm->input_mem_regions[ src_region_idx ].haddr;
        src_bytes_in_cur_region = vm->input_mem_regions[ src_region_idx ].region_sz;
        src_idx                 = 0UL;
      }

      dst_haddr[ dst_idx ] = src_haddr[ src_idx ];

      dst_bytes_in_cur_region--;
      src_bytes_in_cur_region--;
      dst_idx++;
      src_idx++;
    }
    *_ret = 0;
    return FD_VM_SUCCESS;
  }
}

int
fd_vm_syscall_sol_memcmp( /**/            void *  _vm,
                          /**/            ulong   m0_vaddr,
                          /**/            ulong   m1_vaddr,
                          /**/            ulong   sz,
                          /**/            ulong   out_vaddr,
                          FD_PARAM_UNUSED ulong   r5,
                          /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/mem_ops.rs#L59 */

  FD_VM_CU_MEM_OP_UPDATE( vm, sz );

  /* Note: though this behaves like a normal C-style memcmp, we can't
     use the compilers / libc memcmp directly because the specification
     doesn't provide strong enough guarantees about the return value (it
     only promises the sign). */

  if( !FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, bpf_account_data_direct_mapping ) ) {
    uchar const * m0 = (uchar const *)FD_VM_MEM_SLICE_HADDR_LD( vm, m0_vaddr, FD_VM_ALIGN_RUST_U8, sz );
    uchar const * m1 = (uchar const *)FD_VM_MEM_SLICE_HADDR_LD( vm, m1_vaddr, FD_VM_ALIGN_RUST_U8, sz );

    /* Silly that this doesn't use r0 to return ... slower, more edge
      case, different from libc style memcmp, harder to callers to use,
      etc ... probably too late to do anything about it now ... sigh */

    void * _out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_I32, 4UL );

    int out = 0;
    for( ulong i=0UL; i<sz; i++ ) {
      int i0 = (int)m0[i];
      int i1 = (int)m1[i];
      if( i0!=i1 ) {
        out = i0 - i1;
        break;
      }
    }

    fd_memcpy( _out, &out, 4UL ); /* Sigh ... see note above (and might be unaligned ... double sigh) */

    *_ret = 0;
    return FD_VM_SUCCESS;
  } else {
    void * _out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_I32, 4UL );

    int    out  = 0;
    /* Lookup host address chunks.  Try to do a standard memcpy if the regions
       do not cross memory regions. */
    ulong   m0_region              = m0_vaddr >> 32;
    ulong   m0_offset              = m0_vaddr & 0xffffffffUL;
    ulong   m0_region_idx          = 0UL;
    ulong   m0_bytes_in_cur_region = sz;
    uchar * m0_haddr               = NULL;
    if( m0_region==4UL ) {
      m0_region_idx          = fd_vm_get_input_mem_region_idx( vm, m0_offset );
      m0_haddr               = (uchar*)(vm->input_mem_regions[ m0_region_idx ].haddr + m0_offset - vm->input_mem_regions[ m0_region_idx ].vaddr_offset);
      m0_bytes_in_cur_region = fd_ulong_min( sz, fd_ulong_sat_sub( vm->input_mem_regions[ m0_region_idx ].region_sz,
                                                                   ((ulong)m0_haddr - vm->input_mem_regions[ m0_region_idx ].haddr) ) );
      if( FD_UNLIKELY( m0_region_idx+1UL==vm->input_mem_regions_cnt && m0_bytes_in_cur_region<sz ) ) {
        *_ret = 1;
        return FD_VM_ERR_ABORT;
      }
    } else {
      m0_haddr = (uchar *)FD_VM_MEM_SLICE_HADDR_LD( vm, m0_vaddr, FD_VM_ALIGN_RUST_U8, sz );
    }

    ulong   m1_region              = m1_vaddr >> 32;
    ulong   m1_offset              = m1_vaddr & 0xffffffffUL;
    ulong   m1_region_idx          = 0UL;
    ulong   m1_bytes_in_cur_region = sz;
    uchar * m1_haddr               = NULL;
    if( m1_region==4UL ) {
      m1_region_idx          = fd_vm_get_input_mem_region_idx( vm, m1_offset );
      m1_haddr               = (uchar*)(vm->input_mem_regions[ m1_region_idx ].haddr + m1_offset - vm->input_mem_regions[ m1_region_idx ].vaddr_offset);
      m1_bytes_in_cur_region = fd_ulong_min( sz, fd_ulong_sat_sub( vm->input_mem_regions[ m1_region_idx ].region_sz,
                                                                   ((ulong)m1_haddr - vm->input_mem_regions[ m1_region_idx ].haddr) ) );
      if( FD_UNLIKELY( m1_region_idx+1UL==vm->input_mem_regions_cnt && m1_bytes_in_cur_region<sz ) ) {
        *_ret = 1;
        return FD_VM_ERR_ABORT;
      }
    } else {
      m1_haddr = (uchar *)FD_VM_MEM_SLICE_HADDR_LD( vm, m1_vaddr, FD_VM_ALIGN_RUST_U8, sz );
    }

    /* Case where the operation spans multiple regions. Copy over the bytes
       from each region while iterating to the next one. */
    /* TODO: An optimization would be to memcmp chunks at once */
    ulong m0_idx = 0UL;
    ulong m1_idx = 0UL;
    for( ulong i=0UL; i<sz; i++ ) {
      if( FD_UNLIKELY( !m0_bytes_in_cur_region ) ) {
        /* Go to next one */
        if( FD_UNLIKELY( ++m0_region_idx>=vm->input_mem_regions_cnt ) ) {
          *_ret = 1;
          return FD_VM_ERR_ABORT;
        }
        m0_haddr = (uchar*)vm->input_mem_regions[ m0_region_idx ].haddr;
        m0_idx = 0UL;
        m0_bytes_in_cur_region = vm->input_mem_regions[ m0_region_idx ].region_sz;
      }
      if( FD_UNLIKELY( !m1_bytes_in_cur_region ) ) {
        /* Go to next one */
        if( FD_UNLIKELY( ++m1_region_idx>=vm->input_mem_regions_cnt ) ) {
          *_ret = 1;
          return FD_VM_ERR_ABORT;
        }
        m1_haddr = (uchar*)vm->input_mem_regions[ m1_region_idx ].haddr;
        m1_idx = 0UL;
        m1_bytes_in_cur_region = vm->input_mem_regions[ m1_region_idx ].region_sz;
      }

      int i0 = (int)m0_haddr[ m0_idx ];
      int i1 = (int)m1_haddr[ m1_idx ];
      if( i0!=i1 ) {
        out = i0 - i1;
        break;
      }

      m0_bytes_in_cur_region--;
      m1_bytes_in_cur_region--;
      m0_idx++;
      m1_idx++;
    }
    fd_memcpy( _out, &out, 4UL ); /* Sigh ... see note above (and might be unaligned ... double sigh) */
    *_ret = 0;
    return FD_VM_SUCCESS;
  }
}

int
fd_vm_syscall_sol_memset( /**/            void *  _vm,
                          /**/            ulong   dst_vaddr,
                          /**/            ulong   c,
                          /**/            ulong   sz,
                          FD_PARAM_UNUSED ulong   r4,
                          FD_PARAM_UNUSED ulong   r5,
                          /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/mem_ops.rs#L115 */

  FD_VM_CU_MEM_OP_UPDATE( vm, sz );

  ulong FD_FN_UNUSED dst_region = dst_vaddr >> 32;
  int b = (int)(c & 255UL);

  if( dst_region!=4UL || !FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, bpf_account_data_direct_mapping ) ) {
    void * dst = FD_VM_MEM_SLICE_HADDR_ST( vm, dst_vaddr, 1UL, sz );
    fd_memset( dst, b, sz );
  } else {
    /* Syscall manages the pointer accesses directly and will report in the 
       case of bad memory accesses. */
    ulong sz_left              = sz;
    ulong dst_offset           = dst_vaddr & 0xffffffffUL;
    ulong region_idx           = fd_vm_get_input_mem_region_idx( vm, dst_offset );
    ulong region_offset        = dst_offset - vm->input_mem_regions[region_idx].vaddr_offset;
    ulong bytes_left_in_region = fd_ulong_sat_sub(vm->input_mem_regions[region_idx].region_sz, region_offset);
    uchar * haddr              = (uchar*)(vm->input_mem_regions[region_idx].haddr + region_offset);

    if( FD_UNLIKELY( !bytes_left_in_region ) ) {
      *_ret = 1UL;
      return FD_VM_ERR_INVAL;
    }

    while( sz_left ) {
      if( FD_UNLIKELY( region_idx>=vm->input_mem_regions_cnt ) ) {
        *_ret = 1UL;
        return FD_VM_ERR_INVAL;
      }
      if( FD_UNLIKELY( !vm->input_mem_regions[region_idx].is_writable ) ) {
        *_ret = 1UL;
        return FD_VM_ERR_INVAL;
      }

      ulong bytes_to_write = fd_ulong_min( sz_left, bytes_left_in_region );
      memset( haddr, b, bytes_to_write );

      sz_left = fd_ulong_sat_sub( sz_left, bytes_to_write );
      region_idx++;

      if( region_idx!=vm->input_mem_regions_cnt ) {
        haddr                = (uchar*)vm->input_mem_regions[region_idx].haddr;
        bytes_left_in_region = vm->input_mem_regions[region_idx].region_sz;
      }
    }
  }

  *_ret = 0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_memmove( /**/            void *  _vm,
                           /**/            ulong   dst_vaddr,
                           /**/            ulong   src_vaddr,
                           /**/            ulong   sz,
                           FD_PARAM_UNUSED ulong   r4,
                           FD_PARAM_UNUSED ulong   r5,
                           /**/            ulong * _ret ) {

  fd_vm_t * vm = (fd_vm_t *)_vm;

  FD_VM_CU_MEM_OP_UPDATE( vm, sz );

  if( !FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, bpf_account_data_direct_mapping ) ) {
    void *       dst = FD_VM_MEM_SLICE_HADDR_ST( vm, dst_vaddr, FD_VM_ALIGN_RUST_U8, sz );
    void const * src = FD_VM_MEM_SLICE_HADDR_LD( vm, src_vaddr, FD_VM_ALIGN_RUST_U8, sz );
    if( FD_LIKELY( sz > 0 ) ) {
      memmove( dst, src, sz );
    }
  } else {
    /* Lookup host address chunks.  Try to do a standard memcpy if the regions
       do not cross memory regions. */
    ulong   dst_region              = dst_vaddr >> 32;
    ulong   dst_offset              = dst_vaddr & 0xffffffffUL;
    ulong   dst_region_idx          = 0UL;
    ulong   dst_bytes_in_cur_region = sz;
    uchar * dst_haddr               = NULL;
    if( dst_region==4UL ) {
      dst_region_idx          = fd_vm_get_input_mem_region_idx( vm, dst_offset );
      dst_haddr               = (uchar*)(vm->input_mem_regions[ dst_region_idx ].haddr + dst_offset - vm->input_mem_regions[ dst_region_idx ].vaddr_offset);
      dst_bytes_in_cur_region = fd_ulong_min( sz, fd_ulong_sat_sub( vm->input_mem_regions[ dst_region_idx ].region_sz,
                                                                    ((ulong)dst_haddr - vm->input_mem_regions[ dst_region_idx ].haddr) ) );
      if( FD_UNLIKELY( !vm->input_mem_regions[ dst_region_idx ].is_writable ) ) {
        *_ret = 1;
        return FD_VM_ERR_ABORT;
      }
      if( FD_UNLIKELY( dst_region_idx+1UL==vm->input_mem_regions_cnt && dst_bytes_in_cur_region<sz ) ) {
        *_ret = 1;
        return FD_VM_ERR_ABORT;
      }

    } else {
      dst_haddr = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, dst_vaddr, 1UL, sz );
    }

    ulong src_region              = src_vaddr >> 32;
    ulong src_offset              = src_vaddr & 0xffffffffUL;
    ulong src_region_idx          = 0UL;
    ulong src_bytes_in_cur_region = sz;
    uchar * src_haddr             = NULL;
    if( src_region==4UL ) {
      src_region_idx          = fd_vm_get_input_mem_region_idx( vm, src_offset );
      src_haddr               = (uchar*)(vm->input_mem_regions[ src_region_idx ].haddr + src_offset - vm->input_mem_regions[ src_region_idx ].vaddr_offset);
      src_bytes_in_cur_region = fd_ulong_min( sz, fd_ulong_sat_sub( vm->input_mem_regions[ src_region_idx ].region_sz,
                                                                    ((ulong)src_haddr - vm->input_mem_regions[ src_region_idx ].haddr) ) );

      if( FD_UNLIKELY( src_region_idx+1UL==vm->input_mem_regions_cnt && src_bytes_in_cur_region<sz ) ) {
        *_ret = 1;
        return FD_VM_ERR_ABORT;
      }
    } else {
      src_haddr = (uchar *)FD_VM_MEM_SLICE_HADDR_LD( vm, src_vaddr, 1UL, sz );
    }

    /* Do a normal memcpy if regions do not overlap */
    if( FD_LIKELY( src_bytes_in_cur_region==dst_bytes_in_cur_region && src_bytes_in_cur_region==sz ) ) {
      memmove( dst_haddr, src_haddr, sz );
      *_ret = 0;
      return FD_VM_SUCCESS;
    }
  
    /* Case where the operation spans multiple regions. Copy over the bytes
       from each region while iterating to the next one. */
    /* TODO: An optimization would be to memcpy chunks at once */
    ulong dst_idx = 0UL;
    ulong src_idx = 0UL;
    for( ulong i=0UL; i<sz; i++ ) {
      if( FD_UNLIKELY( !dst_bytes_in_cur_region ) ) {
        /* Go to next one */
        if( FD_UNLIKELY( ++dst_region_idx>=vm->input_mem_regions_cnt ) ) {
          *_ret = 1;
          return FD_VM_ERR_ABORT;
        }
        if( FD_UNLIKELY( !vm->input_mem_regions[ dst_region_idx ].is_writable ) ) {
          *_ret = 1;
          return FD_VM_ERR_ABORT;
        }
        dst_haddr               = (uchar*)vm->input_mem_regions[ dst_region_idx ].haddr;
        dst_bytes_in_cur_region = vm->input_mem_regions[ dst_region_idx ].region_sz;
        dst_idx                 = 0UL;
      }
      if( FD_UNLIKELY( !src_bytes_in_cur_region ) ) {
        /* Go to next one */
        if( FD_UNLIKELY( ++src_region_idx>=vm->input_mem_regions_cnt ) ) {
          *_ret = 1;
          return FD_VM_ERR_ABORT;
        }
        src_haddr               = (uchar*)vm->input_mem_regions[ src_region_idx ].haddr;
        src_bytes_in_cur_region = vm->input_mem_regions[ src_region_idx ].region_sz;
        src_idx                 = 0UL;
      }

      dst_haddr[ dst_idx ] = src_haddr[ src_idx ];

      dst_bytes_in_cur_region--;
      src_bytes_in_cur_region--;
      dst_idx++;
      src_idx++;
    }
  }

  *_ret = 0;
  return FD_VM_SUCCESS;
}
