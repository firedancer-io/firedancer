#ifndef HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h
#define HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h

#include "../fd_vm_context.h"

/* FIXME: CONSIDER NOT PREFIXING SYSCALLS WITH SOL_? (OR MAYBE THIS
   IS NECESSARY TO DISAMBIGUATE SOLANA SYSCALLS FROM NON-SOLANA?
   SYSCALLS? */

#define MAX_RETURN_DATA (1024UL) /* FIXME: NAME */

#define FD_VM_SYSCALL_DECL(name)     \
int                                  \
fd_vm_syscall_##name ( void *  _vm,  \
                       ulong   arg0, \
                       ulong   arg1, \
                       ulong   arg2, \
                       ulong   arg3, \
                       ulong   arg4, \
                       ulong * _ret )

FD_PROTOTYPES_BEGIN

/* FIXME: MOVE THESE TO SOMETHING LIKE VM_CONTEXT */
/* FIXME: MOVE FD_SBPF_SYSCALLS_T INTO VM_CONTEXT */

/* Registers a syscall by name to an execution context. */

void
fd_vm_register_syscall( fd_sbpf_syscalls_t *   syscalls,
                        char const *           name,
                        fd_sbpf_syscall_func_t func );

/* fd_vm_syscall_register all reigsters all syscalls implemented.
   May change between Firedancer versions without warning. */

void
fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls );

/* fd_vm_syscall_register_ctx registers all syscalls appropriate for
   slot context. */

void
fd_vm_syscall_register_ctx( fd_sbpf_syscalls_t *       syscalls,
                            fd_exec_slot_ctx_t const * slot_ctx );

/* fd_vm_syscall_util *************************************************/

/* syscall(b6fc1a11) "abort"
   Abort program execution and fail transaction.

   Inputs:

     arg0 - ignored
     arg1 - ignored
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_ABORT: *_ret 0. (FIXME: SHOULD IT DO THIS?)

   FIXME: SHOULD THIS BE NAMED "SOL_ABORT"? */

FD_VM_SYSCALL_DECL( abort );

/* syscall(686093bb) "sol_panic_"
   Log panic message, abort program execution, and fail transaction.

   Inputs:

     arg0 - message cstr VM address, indexed [0,arg1), FIXME: WHEN IS NULL OKAY?
     arg1 - message cstr strlen, FIXME: IS 0 OKAY (PROBABLY)?
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_MEM_OVERLAP: bad address range.  *_ret unchanged.
     Compute budget decremented.  (FIXME: PROBABLY SHOULD BE ERR_PERM TO
     BE CONSISTENT WITH OTHER SYSCALLS).

     FD_VM_ERR_PANIC: *_ret unchanged.  Compute budget decremented.

   IMPORANT SAFETY TIP!  All VM_ERR cases fail the transaction so it is
   okay for a PANIC to return non-panic error codes (such might be
   useful for additional disambiguation of error cases). */

FD_VM_SYSCALL_DECL( sol_panic );

/* syscall(207559bd) "sol_log_"
   Write message to log.

   Inputs:

     arg0 - message cstr VM address, indexed [0,arg1), FIXME: WHEN IS NULL OKAY?
     arg1 - message cstr strlen, FIXME: IS 0 OKAY (PROBABLY)?
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range.  *_ret unchanged.  Compute
     budget decremented.

     FD_VM_SUCCESS: success.  *_ret 0.  Compute budget decremented.
     IMPORANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the log collector
     when called (FIXME: CHECK THIS IS CORRECT BEHAVIOR ... LIKEWISE
     SEEMS LIKE THERE MIGHT BE OTHER ERROR CASES LIKE NON-PRINTABLE
     CHARACTERS, NO CSTR '\0'-TERMINATION AND/OR OTHER STRING
     SANTIZATION NEEDED GIVEN THE COMMENT IN LOG_PANIC). */

FD_VM_SYSCALL_DECL( sol_log );

/* syscall(5c2a3178) "sol_log_64_"
   Write args0:4 to the log as a hexadecimal

   Inputs:

     arg0 - ulong
     arg1 - ulong
     arg2 - ulong
     arg3 - ulong
     arg4 - ulong

   Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range.  *_ret unchanged.  Compute
     budget decremented.

     FD_VM_SUCCESS: success.  *_ret 0.  Compute budget decremented.
     IMPORANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the log collector
     when called (FIXME: CHECK THIS IS CORRECT BEHAVIOR) */

FD_VM_SYSCALL_DECL( sol_log_64 );

/* syscall(7ef088ca) "sol_log_pubkey"
   Write Base58 encoding of 32 byte array to log.

   Inputs:

     arg0 - pubkey VM address, indexed [0,32), FIXME: IS NULL ERR_PERM?
     arg1 - ignored
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range.  *_ret unchanged.  Compute
     budget decremented.

     FD_VM_SUCCESS: success.  *_ret 0.  Compute budget decremented.
     IMPORANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the log collector
     when called (FIXME: CHECK THIS IS CORRECT BEHAVIOR) */

FD_VM_SYSCALL_DECL( sol_log_pubkey );

/* syscall(52ba5096) "sol_log_compute_units_"
   Write remaining compute unit count to log.

   Inputs:

     arg0 - ignored
     arg1 - ignored
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED: NULL vm handle passed.
     (FIXME: WHY DON'T OTHER SYSCALLS NEED TO CHECK VM?)

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret 0.  Compute budget decremented.
     IMPORANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the log collector
     when called (FIXME: CHECK THIS IS CORRECT BEHAVIOR) */

FD_VM_SYSCALL_DECL( sol_log_compute_units );

/* syscall(FIXME) "sol_log_data"
   Write Base64 encoded bytes to log.

   Inputs:

     arg0 - gather vector VM address, indexed [0,cnt), FIXME: WHEN IS NULL OKAY?
     arg1 - gather vector cnt, FIXME: IS 0 OKAY (PROBABLY)
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Note a gather vector element is a pair:
     ulong vaddr ... holds the viritual address of the region, indexed [0,sz)
     ulong sz    ... holds the size of the region (FIXME: IS 0 OKAY ... PROBABLY)?

   Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret 0.  Compute budget decremented.
     IMPORANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the log collector
     when called (FIXME: CHECK THIS IS CORRECT BEHAVIOR ... SEEMS LIKE
     THERE MIGHT BE OTHER ERROR CASES LIKE NON-PRINTABLE CHARACTERS, NO
     CSTR '\0'-TERMINATION AND/OR OTHER STRING SANTIZATION NEEDED GIVEN
     THE COMMENT IN LOG_PANIC). */

FD_VM_SYSCALL_DECL( sol_log_data );

/* syscall(FIXME) "sol_memcpy"
   Copy sz bytes from src to dst.  src and dst should not overlap.

   Inputs:

     arg0 - dst VM address, indexed [0,sz)
     arg1 - src VM address, indexed [0,sz)
     arg2 - sz, 0 okay
     arg3 - ignored
     arg4 - ignored

  Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for src (an empty address range
     is considered valid ... FIXME: CHECK THIS IS DESIRED) and/or bad
     address range for dst (an empty address range is considered valid
     ... FIXME: CHECK THIS IS DESIRED).  *_ret unchanged.  Compute
     budget decremented.

     FD_VM_ERR_MEM_OVERLAP: address ranges for src and dst overlap
     (either partially or fully ... FIXME: CHECK IF EXACT OVERLAP IS
     PERMITTED).  Empty address ranges are considered to never overlap
     (FIXME: CHECK THIS IS DESIRED).  *_ret unchanged.  Compute budget
     decremented.  FIXME: CONSIDER MERGING THIS ERR CODE WITH PERM?

     FD_VM_SUCCESS: success.  *_ret = 0.  On return, dst[i]==src[i] for
     i in [0,sz).  Compute budget decremented.  IMPORTANT SAFETY TIP!
     The current Solana cost model has sz 0 at zero cost so sz==0 always
     succeeds. */

FD_VM_SYSCALL_DECL( sol_memcpy );

/* syscall(FIXME) "sol_memcmp"
   Compare sz bytes at addr0 to addr1

   Inputs:

     arg0 - addr0 VM address, treated as a uchar array indexed [0,sz)
     arg1 - addr1 VM address, treated as a uchar array indexed [0,sz)
     arg2 - sz, FIXME: IS SZ 0 OKAY?
     arg3 - out VM address, pointer to a 32-bit int
     arg4 - ignored

  Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_out and *_ret
     unchanged.  Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for addr0, bad address range for
     addr1 or bad address range for out (including 32-bit integer
     alignment if check_align is enabled).  *_out and *_ret unchanged.
     Compute budget decremented.

     FD_VM_SUCCESS: success.  *_out will hold a positive / zero /
     negative number if the region at addr0 lexicographically compares
     strictly greater than / equal to / strictly less than the region at
     addr1.  The specific value will exactly match the value from the
     existing Solana validator.  Compute budget decremented. */

FD_VM_SYSCALL_DECL( sol_memcmp );

/* syscall(FIXME) "sol_memset"
   Set sz bytes at dst to the byte value c.

   Inputs:

     arg0 - dst VM address, indexed [0,sz)
     arg1 - c, bits [8,64) are ignored
     arg2 - sz, FIXME: IS SZ 0 OKAY?
     arg3 - ignored
     arg4 - ignored

  Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for dst.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret = 0.  Compute budget decremented.
     On return, dst[i]==(c & 255UL) for i in [0,sz). */

FD_VM_SYSCALL_DECL( sol_memset );

/* syscall(FIXME) "sol_memmove"
   Copy sz bytes from src to dst.  src and dst can overlap.

   Inputs:

     arg0 - dst VM address, indexed [0,sz)
     arg1 - src VM address, indexed [0,sz)
     arg2 - sz, FIXME: IS SZ 0 OKAY?
     arg3 - ignored
     arg4 - ignored

  Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for src and/or bad address range
     for dst.  *_ret unchanged.  Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret = 0.  On return,
     dst[i]==src_as_it_was_before_the_call[i] for i in [0,sz).  Compute
     budget decremented. */

FD_VM_SYSCALL_DECL( sol_memmove );

/* syscall(FIXME) "sol_alloc_free"
   DEPRECATED ... dynamic heap allocation support

   Inputs:

     arg0 - sz, ignored if vaddr is not 0
     arg1 - vaddr VM address
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     All cases return FD_VM_SUCCESS.

     If vaddr is 0, this is "malloc"-like:

       Let the VM heap region cover bytes [heap_start,heap_end) with
       heap_start<=heap_end.  If the request was satisfied, on return,
       *_ret will point to a range of heap bytes [*_ret,*_ret+sz) that
       does not overlap with any other current allocation such that
       heap_start<=*_ret<=*_ret+sz<=heap_end.  This includes the zero sz
       case (note that the zero sz case might return the same value as a
       previous zero sz case and/or return the exact value of heap_end).

       If the request cannot be satisfied, *_ret = 0 on return and the
       heap unchanged.

       IMPORTANT SAFETY TIP!  If the VM has check_align set, this
       location will have an alignment of at least 8.  Otherwise, this
       location will have no particular alignment.  Note that this
       implies allocations done by this syscall do not conform to the
       usual alignment requirements of a standard malloc call for older
       VM code.

     If vaddr is not-zero, this is "free"-like.  Since the underlying
     implementation is necessarily a bump allocator (see implementation
     for more details), the specific value is ignored and *_ret = 0 on
     return.

   FIXME: SHOULD THIS NOT DECREMENT THE COMPUTE BUDGET?  E.G. SZ = 0
   INFINITE LOOP) */

FD_VM_SYSCALL_DECL(sol_alloc_free);

/* syscall(FIXME) "sol_get_clock_sysvar"
   syscall(FIXME) "sol_get_epoch_schedule_sysvar"
   syscall(FIXME) "sol_get_fees_sysvar"
   syscall(FIXME) "sol_get_rent_sysvar"
   Get various sysvar values

   Inputs:

     arg0 - out VM address
     arg1 - ignored
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for out.  *_ret unchanged.
     Compute budget decremented.  out should have:
                      | align | sz
       clock          |     8 | 40
       epoch_schedule |     1 | 40 ... FIXME: HMMM
       fees           |     8 |  8
       rent           |     8 | 24
     Strict alignment is only required if the VM has check_align set.

     FD_VM_SUCCESS: success.  *_ret = 0.  On return, out_addr[i] for i
     in [0,sz) will hold the value of the appropriate sysvar.  Compute
     budget decremented. */

FD_VM_SYSCALL_DECL(sol_get_clock_sysvar);
FD_VM_SYSCALL_DECL(sol_get_epoch_schedule_sysvar);
FD_VM_SYSCALL_DECL(sol_get_fees_sysvar);
FD_VM_SYSCALL_DECL(sol_get_rent_sysvar);

/* syscall(FIXME) "sol_get_stack_height"

   Inputs:

     arg0 - ignored
     arg1 - ignored
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_BUDGET: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret = stack_height.  Compute budget
     decremented. */

FD_VM_SYSCALL_DECL(sol_get_stack_height);

/* FIXME: NOT IMPLENTED YET (IGNORES ALL ARGUMENTS AND RETRNS
   FD_VM_ERR_UNSUP).  */

FD_VM_SYSCALL_DECL(sol_get_processed_sibling_instruction);

FD_VM_SYSCALL_DECL(sol_get_return_data);
FD_VM_SYSCALL_DECL(sol_set_return_data);

/*** PDA (program derived address) syscalls ***************************/

/* syscall(9377323c) "sol_create_program_address"
   Compute SHA-256 hash of `<program ID> .. &[&[u8]] .. <PDA Marker>`,
   and check whether result is an Ed25519 curve point. */

FD_VM_SYSCALL_DECL( sol_create_program_address );

/* syscall(48504a38) "sol_try_find_program_address"
   Repeatedly derive program address while incrementing nonce in seed
   list until a point is found that is not a valid Ed25519 curve point.  */

FD_VM_SYSCALL_DECL( sol_try_find_program_address );

/* CPI syscalls *******************************************************/

/* Represents an account for a CPI*/

struct fd_instruction_account {
  ushort index_in_transaction;
  ushort index_in_caller;
  ushort index_in_callee;
  uint is_signer;
  uint is_writable;
};
typedef struct fd_instruction_account fd_instruction_account_t;

// Prepare instruction method

int
fd_vm_prepare_instruction( fd_instr_info_t const *  caller_instr,
                           fd_instr_info_t *        callee_instr,
                           fd_exec_instr_ctx_t *    instr_ctx,
                           fd_instruction_account_t instruction_accounts[256],
                           ulong *                  instruction_accounts_cnt,
                           fd_pubkey_t const *      signers,
                           ulong                    signers_cnt );

/* syscall(a22b9c85) "sol_invoke_signed_c"
   Dispatch a cross program invocation.  Inputs are in C ABI. */

FD_VM_SYSCALL_DECL(cpi_c);

/* syscall(d7449092) "sol_invoke_signed_rust"
   Dispatch a cross program invocation.  Inputs are in Rust ABI. */

FD_VM_SYSCALL_DECL(cpi_rust);

/* Crypto syscalls ****************************************************/

/* FD_VM_SYSCALL_SOL_CURVE_ECC_{...} specifies the curve IDs and
   FD_VM_SYSCALL_SOL_CURVE_ECC_G_{...} declares IDs of operations on
   elliptic curve groups for the sol_curve syscalls. */

#define FD_VM_SYSCALL_SOL_CURVE_ECC_ED25519      (0UL)
#define FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255 (1UL)

#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_ADD        (0UL)  /* add */
#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_SUB        (1UL)  /* add inverse */
#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_MUL        (2UL)  /* scalar mult */

FD_VM_SYSCALL_DECL( sol_alt_bn128_group_op    );
FD_VM_SYSCALL_DECL( sol_alt_bn128_compression );
FD_VM_SYSCALL_DECL( sol_blake3                );
FD_VM_SYSCALL_DECL( sol_curve_validate_point  );
FD_VM_SYSCALL_DECL( sol_curve_group_op        );
FD_VM_SYSCALL_DECL( sol_curve_multiscalar_mul );
FD_VM_SYSCALL_DECL( sol_keccak256             );
FD_VM_SYSCALL_DECL( sol_poseidon              ); /* Light protocol flavor */
FD_VM_SYSCALL_DECL( sol_secp256k1_recover     );
FD_VM_SYSCALL_DECL( sol_sha256                );

FD_PROTOTYPES_END

#endif /*HEADER_src_flamenco_vm_syscall_fd_vm_syscall_h */
