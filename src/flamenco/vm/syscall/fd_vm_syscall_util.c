#include "fd_vm_syscall.h"

#include "../../../ballet/base64/fd_base64.h"
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

  /* FIXME: this originally cleared *_ret, which would change r0 to 0 as
     part of the abort.  This is commented out below to preserve VM
     state at precisely the time of the abort (including the updaets to
     ic and cu for the syscall itself).  It is trivial to flip back if
     desired by uncommenting the below. */

//*_ret = 0;

  return FD_VM_ERR_ABORT;
}

int
fd_vm_syscall_sol_panic( /**/            void *  _vm,
                         /**/            ulong   msg_vaddr,
                         /**/            ulong   msg_sz,
                         FD_PARAM_UNUSED ulong   r3,
                         FD_PARAM_UNUSED ulong   r4,
                         FD_PARAM_UNUSED ulong   r5,
                         FD_PARAM_UNUSED ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: this originally checked compute units and then did a hex
     dump to at FD_LOG_WARNING level (which is very very expensive).  To
     avoid a DOS attack from the transactions calling panic with large
     messages, we just append the message to the log caller (like
     suggested in a pre-belt sanding TODO).  As before, we defer to any
     runtime handler of the syscall log UTF-8 validation, checking for
     proper cstr termination, etc.  While we don't strictly need to
     check the compute units here, it is a fast O(1) and can thus avoid
     a large memcpy to further keep performance reasonable. */

  FD_VM_CU_UPDATE( vm, msg_sz ); /* FIXME: FD_VM_CU_MEM_UPDATE? */
  fd_vm_log_append( vm, FD_VM_MEM_HADDR_LD( vm, msg_vaddr, 1UL, msg_sz ), msg_sz );

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

  /* FIXME: should this do things like UTF validation or what not and
     fail the transaction for syscall cases that currently otherwise
     return success? */

  FD_VM_CU_UPDATE( vm, fd_ulong_max( msg_sz, FD_VM_SYSCALL_BASE_COST ) ); /* FIXME: FD_VM_CU_MEM_UPDATE? */
  fd_vm_log_append( vm, FD_VM_MEM_HADDR_LD( vm, msg_vaddr, 1UL, msg_sz ), msg_sz );

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

  FD_VM_CU_UPDATE( vm, FD_VM_LOG_64_UNITS );

  /* Note: The original version of this use sprintf to a stack buffer
     and then copied the result into the log, not including the '\0'
     termination.  This does the printf directly into the log buffer.
     The tail region is large enough (128) to handle the worst case msg
     (13+16*5+4+1).  Since only the strlen bytes of the message is
     actually published to the log and the log API explicitly allows
     message producers to clobber the entire log preparation region,
     this replicates the old log behavior exactly published message
     bytes but potentially has different bytes in the clobber region. */

  /* FIXME: consider even lower overhead pretty printing? */
  char * msg     = (char *)fd_vm_log_prepare( vm );
  ulong  msg_max = fd_vm_log_prepare_max( vm );
  ulong  msg_len;

  fd_cstr_printf( msg, msg_max, &msg_len, "Program log: %lx %lx %lx %lx %lx", r1, r2, r3, r4, r5 );

  fd_vm_log_publish( vm, msg_len );

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

  FD_VM_CU_UPDATE( vm, FD_VM_LOG_PUBKEY_UNITS );
  void const * pubkey = FD_VM_MEM_HADDR_LD( vm, pubkey_vaddr, 1UL, sizeof(fd_pubkey_t) );

  /* Note that prepare_max is guaranteed large enough (128) to handle
     the worst case len here (13+44+1).  See note in sol_log above about
     tail clobbering. */

  char * msg = (char *)fd_vm_log_prepare( vm );
  ulong  msg_len;

  char * p = fd_cstr_init( msg );
  p = fd_cstr_append_text( p, "Program log: ", 13UL );
  ulong  pubkey_len; fd_base58_encode_32( pubkey, &pubkey_len, p ); p += pubkey_len;
  msg_len = (ulong)(p - msg);
  fd_cstr_fini( p );

  fd_vm_log_publish( vm, msg_len );

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

  /* FIXME: THIS CHECK PROBABLY SHOULD BE MOVED OUT OF THE SYSCALL AND
     INTO THE CPI STUFF THAT INVOKES IT?  THE VM INTERPRETER WILL NEVER
     CALL WITH A NULL VM AT LEAST. */
  if( FD_UNLIKELY( !vm ) ) return FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED;

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  /* At this point, vm->cu is the remaining compute units between this
     syscall and the following instruction. */

  /* See note in sol_log above about tail clobbering. */

  char * msg     = (char *)fd_vm_log_prepare( vm );
  ulong  msg_max = fd_vm_log_prepare_max( vm );
  ulong  msg_len;

  /* FIXME: SHOULD THIS HAVE A NEWLINE? */
  fd_cstr_printf( msg, msg_max, &msg_len, "Program consumption: %lu units remaining\n", vm->cu );

  fd_vm_log_publish( vm, msg_len );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_log_data( /**/            void *  _vm,
                            /**/            ulong   slice_vaddr,
                            /**/            ulong   slice_cnt,
                            FD_PARAM_UNUSED ulong   r2,
                            FD_PARAM_UNUSED ulong   r3,
                            FD_PARAM_UNUSED ulong   r4,
                            /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* Make sure we have enough compute budget and every address range is
     valid before we do any work to avoid DOS risk from a malicious
     syscall that has a big slice count, a bunch of valid slices to
     trigger a lot of work but then faults on the last slice.

     FIXME: in the current implementation under slice_cnt==0, this will
     charge BASE_COST, try to map an empty address range (which is
     always successful) and then return success as the remaining loops
     will do no iterations.  CHECK THAT THIS BEHAVIOR MATCHES SOLANA! */

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  if( FD_UNLIKELY( slice_cnt>(ULONG_MAX/sizeof(fd_vm_vec_t)) ) ) return FD_VM_ERR_SIGSEGV; /* FIXME: SIGOVERFLOW maybe? */
  ulong slice_sz = slice_cnt*sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slice = (fd_vm_vec_t const *)FD_VM_MEM_HADDR_LD( vm, slice_vaddr, FD_VM_VEC_ALIGN, slice_sz );

  for( ulong slice_idx=0UL; slice_idx<slice_cnt; slice_idx++ ) {
    FD_VM_CU_UPDATE( vm, slice[slice_idx].len );
    FD_VM_MEM_HADDR_LD( vm, slice[slice_idx].addr, 1UL, slice[slice_idx].len );
  }

  /* Call is guaranteed to succeed at this point */

  fd_vm_log_append( vm, "Program data: ", 14UL );

  for( ulong slice_idx=0UL; slice_idx<slice_cnt; slice_idx++ ) {
    if( FD_UNLIKELY( !fd_vm_log_rem( vm ) ) ) break; /* If the log is at limit, don't waste time on fully discarded messages */

    /* Note that buf_sz requires:

         FD_BASE64_ENC_SZ( buf_sz ) == 4 ceil( buf_sz/3 )

       to encode.  This might be larger than msg_max-1 (note that we
       also usually need to encode a space after the message).  We thus
       want a safe maximum we can encode into msg_max-1 space; this is
       similar to but not quite the same as FD_BASE64_DEC_SZ(msg_max-1).

       That is, we want a buf_lim such that:

            4 ceil( buf_lim/3 ) <= (msg_max-1)
         ->   ceil( buf_lim/3 ) <= (msg_max-1)/4

       Noting that, for integral buf_lim:

         ceil( buf_lim/3 ) == floor( (buf_lim+2)/3 ) <= (buf_lim+2)/3

       Thus, buf_lim is guaranteed safe if:

            (buf_lim+2)/3 <= (msg_max-1)/4
         -> buf_lim <= (3*(msg_max-1)/4)-2 == (3*msg_max-11)/4

       Since buf_lim is integral, this implies a safe maximum to encode
       is:

             floor( (3*msg_max-11)/4 )

       This is not necessarily the largest possible value but it will
       be really close and the tail clobbering region in msg_max will
       naturally give enough margin such that all buffer bytes that can
       be encoded into the log will be whether or not this is tight
       and/or we need to append a space.  We don't have to worry about
       overflow with the multiplication because msg_max<<ULONG_MAX.  We
       likewise don't have to worry about underflow from the
       subtractions because msg_max>>4 due to LOG_TAIL. */

    char * msg     = (char *)fd_vm_log_prepare( vm );
    ulong  msg_max = fd_vm_log_prepare_max( vm );
    ulong  msg_len = fd_base64_encode( msg, FD_VM_MEM_HADDR_LD_FAST( vm, slice[ slice_idx ].addr ),
                                       fd_ulong_min( slice[ slice_idx ].len, (3UL*msg_max-11UL)/4UL ) );
    msg[ msg_len ] = ' ';
    msg_len += (ulong)( slice_idx < (slice_cnt-1UL) ); /* Note that slice cnt is at least 1 here */
    fd_vm_log_publish( vm, msg_len );
  }

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

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

  ulong align = vm->check_align ? 8UL : 1UL;

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
                          FD_PARAM_UNUSED ulong   arg3,
                          FD_PARAM_UNUSED ulong   arg4,
                          /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: DON'T USE FD_TEST HERE ... SHOULD ONLY BE FOR UNIT TESTS,
     NOT SURE WHAT THIS IS */
  FD_TEST( vm->instr_ctx->instr );

  /* FIXME: IS SAT ADD REALLY NEEDED HERE? */
  int err = fd_vm_consume_compute( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sol_sysvar_clock_t) ) );
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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: DON'T USE FD_TEST HERE ... SHOULD ONLY BE FOR UNIT TESTS,
     NOT SURE WHAT THIS IS */
  FD_TEST( vm->instr_ctx->instr );

  /* FIXME: IS SAT ADD REALLY NEEDED HERE? */
  int err = fd_vm_consume_compute( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_epoch_schedule_t) ) );
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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: DON'T USE FD_TEST HERE ... SHOULD ONLY BE FOR UNIT TESTS,
     NOT SURE WHAT THIS IS */
  FD_TEST( vm->instr_ctx->instr );

  /* FIXME: IS SAT ADD REALLY NEEDED HERE? */
  int err = fd_vm_consume_compute( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sysvar_fees_t) ) );
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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: DON'T USE FD_TEST HERE ... SHOULD ONLY BE FOR UNIT TESTS,
     NOT SURE WHAT THIS IS */
  FD_TEST( vm->instr_ctx->instr );

  /* FIXME: IS SAT ADD REALLY NEEDED HERE? */
  int err = fd_vm_consume_compute( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_rent_t) ) );
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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  int err = fd_vm_consume_compute( vm, FD_VM_SYSCALL_BASE_COST );
  if( FD_UNLIKELY( err ) ) return err;

  *_ret = vm->instr_ctx->txn_ctx->instr_stack_sz;
  return FD_VM_SUCCESS;
}

/* FIXME: PREFIX? */
/* FIXME: BRANCHLESS? */
/* FIXME: SEE MEMCPY ABOVE? */

static inline int
is_nonoverlapping( ulong src, ulong src_sz,    /* Assumes src_sz>0 and [src,src+src_sz) does not wrap */
                   ulong dst, ulong dst_sz ) { /* Assumes dst_sz>0 and [dst,dst+dst_sz) does not wrap */
  if( src>dst ) return (src-dst)>=dst_sz;
  else          return (dst-src)>=src_sz;
}

int
fd_vm_syscall_sol_get_return_data( /**/            void *  _vm,
                                   /**/            ulong   dst_vaddr,
                                   /**/            ulong   dst_max,
                                   /**/            ulong   program_id_vaddr,
                                   FD_PARAM_UNUSED ulong   arg3,
                                   FD_PARAM_UNUSED ulong   arg4,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  int err = fd_vm_consume_compute( vm, FD_VM_SYSCALL_BASE_COST );
  if( FD_UNLIKELY( err ) ) return err;

  fd_txn_return_data_t const * return_data = &vm->instr_ctx->txn_ctx->return_data;

  ulong return_data_sz = return_data->len;

  ulong cpy_sz = fd_ulong_min( return_data_sz, dst_max );
  if( FD_LIKELY( cpy_sz ) ) {

    /* FIXME: Assumes non-zero denom */
    ulong cost = fd_ulong_sat_add( cpy_sz, sizeof(fd_pubkey_t) ) / FD_VM_CPI_BYTES_PER_UNIT;
    err = fd_vm_consume_compute( vm, cost );
    if( FD_UNLIKELY( err ) ) return err;

    uchar * dst_haddr = fd_vm_translate_vm_to_host( vm, dst_vaddr, cpy_sz, alignof(uchar) );
    if( FD_UNLIKELY( !dst_haddr ) ) return FD_VM_ERR_PERM;

    memcpy( dst_haddr, return_data->data, cpy_sz );

    /* FIXME: CHECK alignof(fd_pubkey_t)==1 IS CORRECT */
    fd_pubkey_t * program_id_haddr = fd_vm_translate_vm_to_host( vm, program_id_vaddr, sizeof(fd_pubkey_t), alignof(fd_pubkey_t) );
    if( FD_UNLIKELY( !program_id_haddr) ) return FD_VM_ERR_PERM;

    /* At this point, cpy_sz>0, sizeof(fd_pubkey_t)>0 and ranges do not
       wrap (FIXME: ASSUMES FD_VM_XLAT HAS THE PROPERTY IT FAILS
       OVERLAPPING RANGES) */
    if( FD_UNLIKELY( !is_nonoverlapping( (ulong)dst_haddr, cpy_sz, (ulong)program_id_haddr, sizeof(fd_pubkey_t) ) ) )
      return FD_VM_ERR_MEM_OVERLAP; /* FIXME: Error code? */

    memcpy( program_id_haddr->uc, return_data->program_id.uc, sizeof(fd_pubkey_t) );

  }

  *_ret = return_data_sz;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_set_return_data( /**/            void *  _vm,
                                   /**/            ulong   src_vaddr,
                                   /**/            ulong   src_sz,
                                   FD_PARAM_UNUSED ulong   arg2,
                                   FD_PARAM_UNUSED ulong   arg3,
                                   FD_PARAM_UNUSED ulong   arg4,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: Assumes non-zero denom */
  ulong cost = fd_ulong_sat_add( src_sz / FD_VM_CPI_BYTES_PER_UNIT, FD_VM_SYSCALL_BASE_COST );
  int   err  = fd_vm_consume_compute( vm, cost );
  if( FD_UNLIKELY( err ) ) return err;

  if( FD_UNLIKELY( src_sz>FD_VM_RETURN_DATA_MAX ) ) return FD_VM_ERR_RETURN_DATA_TOO_LARGE;

  uchar const * src_haddr = fd_vm_translate_vm_to_host_const( vm, src_vaddr, src_sz, alignof(uchar) );
  if( FD_UNLIKELY( !src_haddr ) ) return FD_VM_ERR_PERM;

  fd_exec_instr_ctx_t * instr_ctx = vm->instr_ctx;

  fd_pubkey_t const    * program_id  = &instr_ctx->instr->program_id_pubkey;
  fd_txn_return_data_t * return_data = &instr_ctx->txn_ctx->return_data;

  memcpy( return_data->program_id.uc, program_id->uc, sizeof(fd_pubkey_t) );

  return_data->len = src_sz;
  if( FD_LIKELY( src_sz ) ) memcpy( return_data->data, src_haddr, src_sz );

  *_ret = 0;
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
