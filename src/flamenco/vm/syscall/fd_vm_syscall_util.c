#include "fd_vm_syscall.h"

#include "../../../ballet/base64/fd_base64.h"

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
                         /**/            ulong   msg_len,
                         FD_PARAM_UNUSED ulong   arg2,
                         FD_PARAM_UNUSED ulong   arg3,
                         FD_PARAM_UNUSED ulong   arg4,
                         FD_PARAM_UNUSED ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, msg_len );
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

  char const * str = fd_vm_translate_vm_to_host_const( vm, msg_vaddr, msg_len, alignof(uchar) );
  if( FD_UNLIKELY( !str ) ) {
    FD_LOG_WARNING(( "sol_panic_ called with invalid string (addr=%#lx, len=%#lx)", msg_vaddr, msg_len ));
    return FD_VM_ERR_MEM_OVERLAP; /* FIXME: ALMOST CERTAINLY SHOULD BE ERR_PERM */
  }

  /* FIXME: FD_LOG_HEXDUMP ALREADY PROVIDES ENOUGH CONTEXT TO DIAGNOSE
     TRUNCATION SO NOT CLEAR WHY THE EXTRA LOGGING HERE */

  /* FIXME: WHY 1024?  IS THIS MAX_RETURN_DATA OR SOME OTHER PROTOCOL
     DEFINED VALUE? */

  if( FD_UNLIKELY( msg_len > 1024UL ) ) FD_LOG_WARNING(( "Truncating sol_panic_ message (orig %#lx bytes)", msg_len ));
  FD_LOG_HEXDUMP_DEBUG(( "sol_panic", str, msg_len ));

  return FD_VM_ERR_PANIC;
}

int
fd_vm_syscall_sol_log( /**/            void *  _vm,
                       /**/            ulong   msg_vaddr,
                       /**/            ulong   msg_len,
                       FD_PARAM_UNUSED ulong   arg2,
                       FD_PARAM_UNUSED ulong   arg3,
                       FD_PARAM_UNUSED ulong   arg4,
                       /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, fd_ulong_max( msg_len, vm_compute_budget.syscall_base_cost ) );
  if( FD_UNLIKELY( err ) ) return err;

  void const * msg_haddr = fd_vm_translate_vm_to_host_const( vm, msg_vaddr, msg_len, alignof(uchar) );
  if( FD_UNLIKELY( !msg_haddr ) ) return FD_VM_ERR_PERM;

  /* FIXME: SHOULD THERE BE SANITIZATION FIRST? */
  /* FIXME: SHOULD TRUNCATION BE SILENT? */

  fd_vm_log_collector_append( vm->log_collector, msg_haddr, msg_len );

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
                            /**/            ulong   vaddr,
                            /**/            ulong   cnt,
                            FD_PARAM_UNUSED ulong   arg2,
                            FD_PARAM_UNUSED ulong   arg3,
                            FD_PARAM_UNUSED ulong   arg4,
                            /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.syscall_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  ulong sz = cnt*sizeof(fd_vm_vec_t); /* FIXME: OVERFLOW TRAPPING */
  fd_vm_vec_t const * untranslated_fields = fd_vm_translate_slice_vm_to_host_const( vm, vaddr, sz, FD_VM_VEC_ALIGN );
  /* FIXME: TRAP TRANSLATED ADDR */

  err = fd_vm_consume_compute( vm, fd_ulong_sat_mul( vm_compute_budget.syscall_base_cost, cnt ) );
  if( FD_UNLIKELY( err ) ) return err;

  char msg[102400]; /* FIXME: MAGIC NUMBER (AND PROBABLY SHOULD NOT BE ON THE STACK IF NEEDS TO BE MADE LARGER ... PROBABLY SHOULD USE BATCHING HERE) */

  ulong msg_len = (ulong)sprintf( msg, "Program data: " ); /* FIXME: GROSS */

  ulong cost = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    cost += untranslated_fields[i].len; /* FIXME: RENAME THIS FIELD SZ?  (IT ALMOST CERTAINLY ISN'T A LEN) */

    void const * translated_addr =
      fd_vm_translate_vm_to_host_const( vm, untranslated_fields[i].addr, untranslated_fields[i].len, alignof(uchar) );
    /* FIXME: TRAP TRANSLATED ADDR */

    char encoded[1500];
    ulong encoded_len = fd_base64_encode( encoded, (uchar const *) translated_addr, untranslated_fields[i].len );

    /* Append a space if more fields */

    if( i!=(cnt-1UL) ) {
      sprintf( msg + msg_len, " " ); /* FIXME: OVER RISK HERE AND GROSS */
      msg_len++;
    }

    /* FIXME: OVERFLOW RISK HERE */
    memcpy( msg + msg_len, encoded, encoded_len );
    msg_len += encoded_len;
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
