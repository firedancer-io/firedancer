#include "fd_vm_syscall.h"

#include "../../../ballet/base64/fd_base64.h"
#include "../../runtime/sysvar/fd_sysvar.h"

int
fd_vm_syscall_abort( FD_PARAM_UNUSED void *  _vm,
                     FD_PARAM_UNUSED ulong   arg0,
                     FD_PARAM_UNUSED ulong   arg1,
                     FD_PARAM_UNUSED ulong   arg2,
                     FD_PARAM_UNUSED ulong   arg3,
                     FD_PARAM_UNUSED ulong   arg4,
                     /**/            ulong * _ret ) {
  *_ret = 0; /* FIXME: SHOULD ABORT SET _RET 0 (SEEMS TO BE ONLY SYSCALL THAT SETS *_RET ON FAILURE) */
  return FD_VM_ERR_ABORT;
}

int
fd_vm_syscall_sol_panic( /**/            void *  _vm,
                         /**/            ulong   msg_vaddr,
                         /**/            ulong   msg_sz,
                         FD_PARAM_UNUSED ulong   arg2,
                         FD_PARAM_UNUSED ulong   arg3,
                         FD_PARAM_UNUSED ulong   arg4,
                         FD_PARAM_UNUSED ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, msg_sz );
  if( FD_UNLIKELY( err ) ) return err;

  /* Here, Solana Labs charges compute units, does UTF-8 validation,
     and checks for a cstr terminating NUL.  We skip all of this since
     this syscall always aborts the transaction.  The type of error
     does not matter. */

  /* FIXME: write to log collector instead of writing to fd_log */

  /* FIXME: WHO CALLS PANIC AND WHY AND WHAT HAPPENS AFTERWARD?
     E.G. MALICIOUS CODE CALLING PANIC TO STOP A VALIDATOR OR CAUSE THE
     VALIDATOR TO GENERATE LOTS OF LOGGING IS A POTENTIAL DOS ATTACK
     VECTOR (PROBABLY RELATED TO THE PREEXISTING "TODO" HERE) */

  char const * msg_haddr = fd_vm_translate_vm_to_host_const( vm, msg_vaddr, msg_sz, alignof(uchar) );
  if( FD_UNLIKELY( !msg_haddr ) ) {
    FD_LOG_WARNING(( "sol_panic_ called with invalid string (addr=%#lx, len=%#lx)", msg_vaddr, msg_sz ));
    return FD_VM_ERR_MEM_OVERLAP; /* FIXME: ALMOST CERTAINLY SHOULD BE ERR_PERM */
  }

  /* FIXME: FD_LOG_HEXDUMP ALREADY PROVIDES ENOUGH CONTEXT TO DIAGNOSE
     TRUNCATION SO NOT CLEAR WHY THE EXTRA LOGGING HERE */

  /* FIXME: WHY 1024?  IS THIS MAX_RETURN_DATA OR SOME OTHER PROTOCOL
     DEFINED VALUE? */

  if( FD_UNLIKELY( msg_sz > 1024UL ) ) FD_LOG_WARNING(( "Truncating sol_panic_ message (orig %#lx bytes)", msg_sz ));
  FD_LOG_HEXDUMP_DEBUG(( "sol_panic", msg_haddr, msg_sz ));

  return FD_VM_ERR_PANIC;
}

int
fd_vm_syscall_sol_log( /**/            void *  _vm,
                       /**/            ulong   msg_vaddr,
                       /**/            ulong   msg_sz,
                       FD_PARAM_UNUSED ulong   arg2,
                       FD_PARAM_UNUSED ulong   arg3,
                       FD_PARAM_UNUSED ulong   arg4,
                       /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, fd_ulong_max( msg_sz, vm_compute_budget.syscall_base_cost ) );
  if( FD_UNLIKELY( err ) ) return err;

  void const * msg_haddr = fd_vm_translate_vm_to_host_const( vm, msg_vaddr, msg_sz, alignof(uchar) );
  if( FD_UNLIKELY( !msg_haddr ) ) return FD_VM_ERR_PERM;

  /* FIXME: SHOULD THERE BE SANITIZATION FIRST? */
  /* FIXME: SHOULD TRUNCATION BE SILENT? */

  fd_vm_log_collector_append( vm->log_collector, msg_haddr, msg_sz );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_log_64( void *  _vm,
                          ulong   arg0,
                          ulong   arg1,
                          ulong   arg2,
                          ulong   arg3,
                          ulong   arg4,
                          ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.log_64_units );
  if( FD_UNLIKELY( err ) ) return err;

  /* FIXME: Consider using faster fd_cstr semantics here.  This would
     cleanup that sprintf isn't getting error trapped here (sprintf
     _shouldn't_ ever fail for this format string but there is no actual
     guarantee of this provided by the API ... fd_cstr could give that
     guarantee while being faster). */
  /* FIXME: SHOULD TRUNCATION BE SILENT? */

  char msg[1024];
  int msg_len = sprintf( msg, "Program log: %lx %lx %lx %lx %lx", arg0, arg1, arg2, arg3, arg4 );
  fd_vm_log_collector_append( vm->log_collector, msg, (ulong)msg_len );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_log_pubkey( /**/            void *  _vm,
                              /**/            ulong   pubkey_vaddr,
                              FD_PARAM_UNUSED ulong   arg1,
                              FD_PARAM_UNUSED ulong   arg2,
                              FD_PARAM_UNUSED ulong   arg3,
                              FD_PARAM_UNUSED ulong   arg4,
                              /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.log_pubkey_units );
  if( FD_UNLIKELY( err ) ) return err;

  void * pubkey_haddr = fd_vm_translate_vm_to_host( vm, pubkey_vaddr, sizeof(fd_pubkey_t), alignof(uchar) );
  if( FD_UNLIKELY( !pubkey_haddr ) ) return FD_VM_ERR_PERM;

  char pubkey_cstr[ FD_BASE58_ENCODED_32_SZ ]; /* 44+1 */
  fd_base58_encode_32( pubkey_haddr, NULL, pubkey_cstr );

  /* FIXME: See note above about sprintf error trapping and fd_cstr
     instead of sprintf here.  Probably even faster still to just call
     log_collector append twice (once with "Program log: " and then
     again with pubkey_cstr).  E.g.

       fd_vm_log_collector_append( vm->log_collector, "Program log: ", 13UL                     );
       fd_vm_log_collector_append( vm->log_collector, pubkey_cstr,     FD_BASE58_ENCODED_32_LEN );

     Could go even faster still by doing zero copy encode_32 in-place
     into the log_collector (would need to check truncation upfront) */

  char msg[128]; /* >>13+44+1 */
  int msg_len = sprintf( msg, "Program log: %s", pubkey_cstr );
  fd_vm_log_collector_append( vm->log_collector, msg, (ulong)msg_len );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_log_compute_units( /**/            void *  _vm,
                                     FD_PARAM_UNUSED ulong   arg0,
                                     FD_PARAM_UNUSED ulong   arg1,
                                     FD_PARAM_UNUSED ulong   arg2,
                                     FD_PARAM_UNUSED ulong   arg3,
                                     FD_PARAM_UNUSED ulong   arg4,
                                     /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;
  if( FD_UNLIKELY( !vm ) ) return FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.syscall_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  /* FIXME: See note above about sprintf error trapping and fd_cstr
     usage above */

  char msg[1024];
  int msg_len = sprintf( msg, "Program consumption: %lu units remaining\n", vm->compute_meter );
  fd_vm_log_collector_append( vm->log_collector, msg, (ulong)msg_len );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

/* FIXME: SOL_LOG_DATA IS NOT IN GOOD SHAPE.  PROBABLY SHOULD JUST
   INCREMENTALLY CALL LOG_COLLECTOR APPEND. */

int
fd_vm_syscall_sol_log_data( /**/            void *  _vm,
                            /**/            ulong   slice_vaddr,
                            /**/            ulong   slice_cnt,
                            FD_PARAM_UNUSED ulong   arg2,
                            FD_PARAM_UNUSED ulong   arg3,
                            FD_PARAM_UNUSED ulong   arg4,
                            /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.syscall_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  ulong slice_sz = slice_cnt*sizeof(fd_vm_vec_t); /* FIXME: OVERFLOW TRAPPING */
  fd_vm_vec_t const * slice_haddr = fd_vm_translate_slice_vm_to_host_const( vm, slice_vaddr, slice_sz, FD_VM_VEC_ALIGN );
  if( FD_UNLIKELY( !slice_haddr ) ) return FD_VM_ERR_PERM;

  err = fd_vm_consume_compute( vm, fd_ulong_sat_mul( vm_compute_budget.syscall_base_cost, slice_cnt ) );
  if( FD_UNLIKELY( err ) ) return err;

  char msg[102400]; /* FIXME: MAGIC NUMBER (AND PROBABLY SHOULD NOT BE ON THE STACK IF NEEDS TO BE MADE LARGER ... PROBABLY SHOULD USE BATCHING HERE) */

  ulong msg_len = (ulong)sprintf( msg, "Program data: " ); /* FIXME: GROSS */

  ulong cost = 0UL;
  for( ulong i=0UL; i<slice_cnt; i++ ) {
    ulong mem_sz = slice_haddr[i].len; /* FIXME: RENAME THIS FIELD SZ?  (IT ALMOST CERTAINLY ISN'T A LEN) */
    cost += mem_sz; /* FIXME: OVERFLOW RISK HERE */

    void const * mem_haddr = fd_vm_translate_vm_to_host_const( vm, slice_haddr[i].addr, mem_sz, alignof(uchar) );
    if( FD_UNLIKELY( !mem_haddr ) ) return FD_VM_ERR_PERM;

    char encoded[1500];
    ulong encoded_len = fd_base64_encode( encoded, mem_haddr, mem_sz );

    /* FIXME: OVERFLOW RISK HERE */
    memcpy( msg + msg_len, encoded, encoded_len );
    msg_len += encoded_len;

    /* Append a space if more fields */

    if( i!=(slice_cnt-1UL) ) {
      sprintf( msg + msg_len, " " ); /* FIXME: OVER RISK HERE AND GROSS */
      msg_len++;
    }
  }

  /* FIXME: DOS VECTOR ... SHOULD TRY TO BILL FOR COMPUTE UPFRONT SO WE
     DON'T DO ALL THE BASE64 ENCODING WORK.  COULD DO A MINIMAL BOUND TO
     ELIMINATE DOS RISK AND THEN DECREMENT PRECISELY. */

  err = fd_vm_consume_compute( vm, cost );
  if( FD_UNLIKELY( err ) ) return err;

  fd_vm_log_collector_append( vm->log_collector, msg, msg_len );

  *_ret = 0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_alloc_free( /**/            void *  _vm,
                              /**/            ulong   sz,
                              /**/            ulong   free_vaddr,
                              FD_PARAM_UNUSED ulong   arg2,
                              FD_PARAM_UNUSED ulong   arg3,
                              FD_PARAM_UNUSED ulong   arg4,
                              /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* This syscall is ... uh ... problematic.  But the community has
     already recognized this and deprecated it:

     https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/feature_set.rs#L846

     Unfortunately, old code never dies so, practically, this will need
     to be supported until the heat death of the universe.

     The most serious issue is that there is nothing to stop VM code
     making a decision based on the _location_ of the returned
     allocation.  If different validator implementations use different
     allocator algorithms, though each implemementation would behave
     functionally correct in isolation, the VM code that uses it would
     actually break consensus.

     As a result, every validator needs to use a bit-for-bit identical
     allocation algorithm.  Fortunately, Solana is just using a basic
     bump allocator:

     https://github.com/solana-labs/solana/blob/v1.17.23/program-runtime/src/invoke_context.rs#L122-L148

     fd_vm_heap_allocator_t and the below replicate this exactly.

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
     horror because people consistent think malloc/free is much simplier
     than it actually is.  This is also an example of how quickly
     mistakes fossilize and become a thorn-in-the-side forever.

     IMPORANT SAFETY TIP!  heap_start must be non zero and both
     heap_start and heap_end should have an alignment of at least 8.
     This existing runtime policies around heap implicitly satisfy this.

     IMPORANT SAFETY TIP!  The specification for Rust's align_offset
     doesn't seem to be provide a strong guarantee that it will return
     the minimal positive offset necessary to align pointers.  It is
     possible for a "conforming" Rust compiler to break consensus by
     using a different align_offset implementation that aligned pointer
     between different compilations of the Solana validator and the
     below. */

  /* Non-zero free address implies that this is a free() call.  Since
     this is a bump allocator, free is a no-op. */

  if( FD_UNLIKELY( free_vaddr ) ) {
    *_ret = 0UL;
    return FD_VM_SUCCESS;
  }

  fd_vm_heap_allocator_t * alloc = vm->alloc;

  ulong align = vm->check_align ? 8UL : 1UL;

  ulong pos         = fd_ulong_align_up( alloc->offset, align );
  ulong alloc_vaddr = fd_ulong_sat_add ( pos,           FD_VM_MEM_MAP_HEAP_REGION_START );
  /**/  pos         = fd_ulong_sat_add ( pos,           sz    );

  if( FD_UNLIKELY( pos > vm->heap_sz ) ) { /* Not enough free memory */
    *_ret = 0UL;
    return FD_VM_SUCCESS;
  }

  alloc->offset = pos;

  *_ret = alloc_vaddr;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_memcpy( /**/            void *  _vm,
                          /**/            ulong   dst_vaddr,
                          /**/            ulong   src_vaddr,
                          /**/            ulong   sz,
                          FD_PARAM_UNUSED ulong   arg3,
                          FD_PARAM_UNUSED ulong   arg4,
                          /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_mem( vm, sz );
  if( FD_UNLIKELY( err ) ) return err;

  /* Check for overlap */
  /* FIXME: DOES THIS LOGIC WORK IF DST_VADDR+SZ OR SRC_VADDR+SZ
     OVERFLOW?  SEE THE LOGIC USED FOR GET/SET_RETURN_DATA. */

  if( FD_UNLIKELY( ( (dst_vaddr<=src_vaddr) & (src_vaddr<(dst_vaddr+sz)) ) |
                   ( (src_vaddr<=dst_vaddr) & (dst_vaddr<(src_vaddr+sz)) ) ) ) return FD_VM_ERR_MEM_OVERLAP;

  /* FIXME: CONSIDER MOVING THIS SHORT-CIRCUIT ABOVE THE OVERLAPPING
     SHORTCUT (AND MAYBE THE COST MODEL AS SZ==0 COSTS NOTHING IN THE
     CURRENT COST MODEL). */

  if( FD_UNLIKELY( !sz ) ) {
    *_ret = 0;
    return FD_VM_SUCCESS;
  }

  void *       dst_haddr = fd_vm_translate_vm_to_host      ( vm, dst_vaddr, sz, alignof(uchar) );
  if( FD_UNLIKELY( !dst_haddr ) ) return FD_VM_ERR_PERM;

  void const * src_haddr = fd_vm_translate_vm_to_host_const( vm, src_vaddr, sz, alignof(uchar) );
  if( FD_UNLIKELY( !src_haddr ) ) return FD_VM_ERR_PERM;

  memcpy( dst_haddr, src_haddr, sz );

  *_ret = 0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_memcmp( /**/            void *  _vm,
                          /**/            ulong   m0_vaddr,
                          /**/            ulong   m1_vaddr,
                          /**/            ulong   sz,
                          /**/            ulong   out_vaddr,
                          FD_PARAM_UNUSED ulong   arg4,
                          /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_mem( vm, sz );
  if( FD_UNLIKELY( err ) ) return err;

  uchar const * m0_haddr = fd_vm_translate_vm_to_host_const( vm, m0_vaddr, sz, alignof(uchar) );
  if( FD_UNLIKELY( !m0_haddr ) ) return FD_VM_ERR_PERM;

  uchar const * m1_haddr = fd_vm_translate_vm_to_host_const( vm, m1_vaddr, sz, alignof(uchar) );
  if( FD_UNLIKELY( !m1_haddr ) ) return FD_VM_ERR_PERM;

  int * out_haddr = fd_vm_translate_vm_to_host( vm, out_vaddr, sizeof(int), alignof(int) );
  if( FD_UNLIKELY( !out_haddr ) ) return FD_VM_ERR_PERM;

  /* Note: though this behaves like a normal C-style memcmp, we can't
     use the compilers / libc memcmp directly because the specification
     doesn't provide strong enough guarantees about the return value (it
     only promises the sign). */

  int out = 0;
  for( ulong i=0UL; i<sz; i++ ) {
    int i0 = (int)m0_haddr[i];
    int i1 = (int)m1_haddr[i];
    if( i0!=i1 ) {
      out = i0 - i1;
      break;
    }
  }

  *out_haddr = out; /* Sigh ... silly that this doesn't use ret (like other syscalls) for this ... Slower and more edge cases. */
  *_ret = 0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_memset( /**/            void *  _vm,
                          /**/            ulong   dst_vaddr,
                          /**/            ulong   c,
                          /**/            ulong   sz,
                          FD_PARAM_UNUSED ulong   arg3,
                          FD_PARAM_UNUSED ulong   arg4,
                          /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_mem( vm, sz );
  if( FD_UNLIKELY( err ) ) return err;

  void * dst_haddr = fd_vm_translate_vm_to_host( vm, dst_vaddr, sz, alignof(uchar) );
  if( FD_UNLIKELY( !dst_haddr ) ) return FD_VM_ERR_PERM;

  int b = (int)(c & 255UL);
  if( FD_LIKELY( sz ) ) memset( dst_haddr, b, sz ); /* Sigh ... avoid UB around sz==0 */

  *_ret = 0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_memmove( /**/            void *  _vm,
                           /**/            ulong   dst_vaddr,
                           /**/            ulong   src_vaddr,
                           /**/            ulong   sz,
                           FD_PARAM_UNUSED ulong   arg3,
                           FD_PARAM_UNUSED ulong   arg4,
                           /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_mem( vm, sz );
  if( FD_UNLIKELY( err ) ) return err;

  void *       dst_haddr = fd_vm_translate_vm_to_host      ( vm, dst_vaddr, sz, alignof(uchar) );
  if( FD_UNLIKELY( !dst_haddr ) ) return FD_VM_ERR_PERM;

  void const * src_haddr = fd_vm_translate_vm_to_host_const( vm, src_vaddr, sz, alignof(uchar) );
  if( FD_UNLIKELY( !src_haddr ) ) return FD_VM_ERR_PERM;

  if( FD_LIKELY( sz ) ) memmove( dst_haddr, src_haddr, sz ); /* Sigh ... avoid UB around sz==0 */

  *_ret = 0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_clock_sysvar( /**/            void *  _vm,
                                    /**/            ulong   out_vaddr,
                                    FD_PARAM_UNUSED ulong   arg1,
                                    FD_PARAM_UNUSED ulong   arg2,
                                    FD_PARAM_UNUSED ulong   arg3,
                                    FD_PARAM_UNUSED ulong   arg4,
                                    /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* FIXME: DON'T USE FD_TEST HERE ... SHOULD ONLY BE FOR UNIT TESTS,
     NOT SURE WHAT THIS IS */
  FD_TEST( vm->instr_ctx->instr );

  /* FIXME: IS SAT ADD REALLY NEEDED HERE? */
  int err = fd_vm_consume_compute( vm, fd_ulong_sat_add( vm_compute_budget.sysvar_base_cost, sizeof(fd_sol_sysvar_clock_t) ) );
  if( FD_UNLIKELY( err ) ) return err;

  /* FIXME: IF NEW IS CALLED, IMPLIES THERE SHOULD BE DELETE (AND, IF A
     DISTIBUTED OBJECT AS JOIN/LEAVE PAIR). */
  fd_sol_sysvar_clock_t clock[1];
  fd_sol_sysvar_clock_new( clock );
  fd_sysvar_clock_read( clock, vm->instr_ctx->slot_ctx );

  void * out_haddr = fd_vm_translate_vm_to_host( vm, out_vaddr, sizeof(fd_sol_sysvar_clock_t), FD_SOL_SYSVAR_CLOCK_ALIGN );
  if( FD_UNLIKELY( !out_haddr ) ) return FD_VM_ERR_PERM;

  /* FIXME: SHOULD THE ADDRESS CHECK BE BEFORE THE READ?  AND MAYBE JUST
     DO THE READ DIRECTLY INTO OUT_HADDR TO AVOID THE EXTRA MEMCPY? */
  memcpy( out_haddr, clock, sizeof(fd_sol_sysvar_clock_t ) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_epoch_schedule_sysvar( /**/            void *  _vm,
                                             /**/            ulong   out_vaddr,
                                             FD_PARAM_UNUSED ulong   arg1,
                                             FD_PARAM_UNUSED ulong   arg2,
                                             FD_PARAM_UNUSED ulong   arg3,
                                             FD_PARAM_UNUSED ulong   arg4,
                                             /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* FIXME: DON'T USE FD_TEST HERE ... SHOULD ONLY BE FOR UNIT TESTS,
     NOT SURE WHAT THIS IS */
  FD_TEST( vm->instr_ctx->instr );

  /* FIXME: IS SAT ADD REALLY NEEDED HERE? */
  int err = fd_vm_consume_compute( vm, fd_ulong_sat_add( vm_compute_budget.sysvar_base_cost, sizeof(fd_epoch_schedule_t) ) );
  if( FD_UNLIKELY( err ) ) return err;

  /* FIXME: IF NEW IS CALLED, IMPLIES THERE SHOULD BE DELETE (AND, IF A
     DISTIBUTED OBJECT AS JOIN/LEAVE PAIR) */
  fd_epoch_schedule_t schedule[1]; /* FIXME: RENAME SOL_SYSVAR_SCHEDULE_T? */
  fd_epoch_schedule_new( schedule );
  fd_sysvar_epoch_schedule_read( schedule, vm->instr_ctx->slot_ctx );

  void * out_haddr = fd_vm_translate_vm_to_host( vm, out_vaddr, sizeof(fd_epoch_schedule_t), FD_EPOCH_SCHEDULE_ALIGN );
  if( FD_UNLIKELY( !out_haddr ) ) return FD_VM_ERR_PERM;

  /* FIXME: SHOULD THE ADDRESS CHECK BE BEFORE THE READ?  AND MAYBE JUST
     DO THE READ DIRECTLY INTO OUT_HADDR TO AVOID THE EXTRA MEMCPY? */
  memcpy( out_haddr, schedule, sizeof(fd_epoch_schedule_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_fees_sysvar( /**/            void *  _vm,
                                   /**/            ulong   out_vaddr,
                                   FD_PARAM_UNUSED ulong   arg1,
                                   FD_PARAM_UNUSED ulong   arg2,
                                   FD_PARAM_UNUSED ulong   arg3,
                                   FD_PARAM_UNUSED ulong   arg4,
                                   /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* FIXME: DON'T USE FD_TEST HERE ... SHOULD ONLY BE FOR UNIT TESTS,
     NOT SURE WHAT THIS IS */
  FD_TEST( vm->instr_ctx->instr );

  /* FIXME: IS SAT ADD REALLY NEEDED HERE? */
  int err = fd_vm_consume_compute( vm, fd_ulong_sat_add( vm_compute_budget.sysvar_base_cost, sizeof(fd_sysvar_fees_t) ) );
  if( FD_UNLIKELY( err ) ) return err;

  /* FIXME: IF NEW IS CALLED, IMPLIES THERE SHOULD BE DELETE (AND, IF A
     DISTIBUTED OBJECT AS JOIN/LEAVE PAIR) */
  fd_sysvar_fees_t fees[1]; /* FIXME: RENAME FD_SOL_SYSVAR_FEES_T? */
  fd_sysvar_fees_new( fees );
  fd_sysvar_fees_read( fees, vm->instr_ctx->slot_ctx );

  /* FIXME: SHOULD THE ADDRESS CHECK BE BEFORE THE READ?  AND MAYBE JUST
     DO THE READ DIRECTLY INTO OUT_HADDR TO AVOID THE EXTRA MEMCPY? */
  void * out_haddr = fd_vm_translate_vm_to_host( vm, out_vaddr, sizeof(fd_sysvar_fees_t), FD_SYSVAR_FEES_ALIGN );
  if( FD_UNLIKELY( !out_haddr ) ) return FD_VM_ERR_PERM;

  memcpy( out_haddr, fees, sizeof(fd_sysvar_fees_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_rent_sysvar( /**/            void *  _vm,
                                   /**/            ulong   out_vaddr,
                                   FD_PARAM_UNUSED ulong   arg1,
                                   FD_PARAM_UNUSED ulong   arg2,
                                   FD_PARAM_UNUSED ulong   arg3,
                                   FD_PARAM_UNUSED ulong   arg4,
                                   /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* FIXME: DON'T USE FD_TEST HERE ... SHOULD ONLY BE FOR UNIT TESTS,
     NOT SURE WHAT THIS IS */
  FD_TEST( vm->instr_ctx->instr );

  /* FIXME: IS SAT ADD REALLY NEEDED HERE? */
  int err = fd_vm_consume_compute( vm, fd_ulong_sat_add( vm_compute_budget.sysvar_base_cost, sizeof(fd_rent_t) ) );
  if( FD_UNLIKELY( err ) ) return err;

  /* FIXME: IF NEW IS CALLED, IMPLIES THERE SHOULD BE DELETE (AND, IF A
     DISTIBUTED OBJECT AS JOIN/LEAVE PAIR) */
  fd_rent_t rent[1]; /* FIXME: RENAME FD_SOL_SYSVAR_RENT_T? */
  fd_rent_new( rent );
  fd_sysvar_rent_read( rent, vm->instr_ctx->slot_ctx );

  /* FIXME: SHOULD THE ADDRESS CHECK BE BEFORE THE READ?  AND MAYBE JUST
     DO THE READ DIRECTLY INTO OUT_HADDR TO AVOID THE EXTRA MEMCPY? */
  void * out_haddr = fd_vm_translate_vm_to_host( vm, out_vaddr, sizeof(fd_rent_t), FD_RENT_ALIGN );
  if( FD_UNLIKELY( !out_haddr ) ) return FD_VM_ERR_PERM;

  memcpy( out_haddr, rent, sizeof(fd_rent_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_stack_height( /**/            void *  _vm,
                                    FD_PARAM_UNUSED ulong   arg0,
                                    FD_PARAM_UNUSED ulong   arg1,
                                    FD_PARAM_UNUSED ulong   arg2,
                                    FD_PARAM_UNUSED ulong   arg3,
                                    FD_PARAM_UNUSED ulong   arg4,
                                    /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.syscall_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  *_ret = vm->instr_ctx->txn_ctx->instr_stack_sz;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_processed_sibling_instruction( FD_PARAM_UNUSED void *  _vm,
                                                     FD_PARAM_UNUSED ulong   arg0,
                                                     FD_PARAM_UNUSED ulong   arg1,
                                                     FD_PARAM_UNUSED ulong   arg2,
                                                     FD_PARAM_UNUSED ulong   arg3,
                                                     FD_PARAM_UNUSED ulong   arg4,
                                                     FD_PARAM_UNUSED ulong * _ret ) {
  return FD_VM_ERR_UNSUP;
}
