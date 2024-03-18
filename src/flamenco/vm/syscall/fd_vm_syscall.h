#ifndef HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h
#define HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h

#include "../fd_vm_private.h"
#include "fd_vm_cpi.h"                /* FIXME: REFINE THIS MORE */
#include "../../runtime/fd_runtime.h" /* FIXME: REFINE THIS MORE */

#define FD_VM_RETURN_DATA_MAX  (1024UL) /* FIXME: DOCUMENT AND DOES THIS BELONG HERE? */
#define FD_VM_CPI_SEED_MAX     (16UL)   /* FIXME: DOCUMENT AND DOES THIS BELONG HERE? */
#define FD_VM_CPI_SEED_MEM_MAX (32UL)   /* FIXME: DOCUMENT AND DOES THIS BELONG HERE? */

/* FIXME: CONSIDER NOT PREFIXING SYSCALLS WITH SOL_? (OR MAYBE THIS
   IS NECESSARY TO DISAMBIGUATE SOLANA SYSCALLS FROM NON-SOLANA?
   SYSCALLS? */

/* FD_VM_SYSCALL_DECL declares a prototype of a syscall.  When a
   syscall implementation is called, the syscall will see a precise
   reporting VM's state at time of the syscall.  Notably:

   - vm->pc will be at the syscall instruction
   - vm->ic will include the syscall instruction
   - vm->cu will include the 1 cu cost of the syscall instruction.
     Further, it will be positive.

   r1,r2,r3,r4,r5 are the values in r1,r2,r3,r4,r5 at time of the
   syscall.

   When a syscall implementation returns FD_VM_SUCCESS, *_r0 should hold
   the application return error value it wants to place in r0.

   When an syscall implementation returns FD_VM_ERR, the syscall is
   considered to have faulted the VM.  It ideally should not have set
   *_r0 or updated vm->cu (or changed any other vm state though that
   often isn't practical).

   It is the syscall's responsibility to deduct from vm->cu its specific
   cost model (not including the syscall instruction itself).  As such,
   when a syscall returns SIGCOST, ideally, it should also have set
   vm->cu to zero.  When it returns anything else, it should have set cu
   to something in [1,cu_at_function_entry].

   To mitigate risks of from syscall implementations that do not
   strictly enforce this and other similar risks that can affect
   bookkeeping, on return from a syscall, the VM will:

   FIXME: ADD NO SETTING OF R0 ON FAILURE TO VM_INTERP.

   - Ignore updates to pc, ic and frame_cnt.
   - Ignore updates to cu that increase it.
   - Treat updates to cu that zero it as SIGCOST.
   - Treat SIGCOST returns that didn't update cu to zero as zeroing it. */

#define FD_VM_SYSCALL_DECL(name)   \
int                                \
fd_vm_syscall_##name( void *  _vm, \
                      ulong   r1,  \
                      ulong   r2,  \
                      ulong   r3,  \
                      ulong   r4,  \
                      ulong   r5,  \
                      ulong * _ret )

FD_PROTOTYPES_BEGIN

/* fd_vm_syscall_util *************************************************/

/* syscall(b6fc1a11) "abort"
   Abort program execution and fail transaction.

   Inputs:

     r1 - ignored
     r2 - ignored
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_ERR_ABORT: *_ret unchanged.  vm state unchanged.

   FIXME: SHOULD THIS BE NAMED "SOL_ABORT"? */

FD_VM_SYSCALL_DECL( abort );

/* syscall(686093bb) "sol_panic_"
   Log panic message, abort program execution, and fail transaction.

   Inputs:

     r1 - msg, byte VM pointer, indexed [0,msg_sz), FIXME: WHEN IS NULL OKAY?
     r2 - msg_sz, FIXME: IS 0 OKAY?
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     vm->cu==0.

     FD_VM_ERR_SIGSEGV: bad address range.  *_ret unchanged. vm->cu
     decremented and positive.

     FD_VM_ERR_PANIC: *_ret unchanged. *_ret unchanged. vm->cu
     decremented and positive.

   IMPORTANT SAFETY TIP!  All VM_ERR cases fail the transaction so it is
   okay for a PANIC to return non-panic error codes (such might be
   useful for additional disambiguation of error cases). */

FD_VM_SYSCALL_DECL( sol_panic );

/* syscall(207559bd) "sol_log_"
   Write message to log.

   Inputs:

     r1 - msg, byte VM pointer, indexed [0,msg_sz), FIXME: WHEN IS NULL OKAY?
     r2 - msg_sz, FIXME: IS 0 OKAY?
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     vm->cu==0.

     FD_VM_ERR_SIGSEGV: bad address range.  *_ret unchanged.  vm->cu
     decremented and positive.

     FD_VM_SUCCESS: success.  *_ret=0. vm->cu decremented and positive.

     IMPORTANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log );

/* syscall(5c2a3178) "sol_log_64_"
   Write args0:4 to the log as a hexadecimal

   Inputs:

     r1 - ulong
     r2 - ulong
     r3 - ulong
     r4 - ulong
     r5 - ulong

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     vm->cu==0.

     FD_VM_SUCCESS: success.  *_ret=0. vm->cu decremented and positive.

     IMPORTANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log_64 );

/* syscall(7ef088ca) "sol_log_pubkey"
   Write Base58 encoding of 32 byte array to log.

   Inputs:

     r1 - pubkey, byte VM pointer, indexed [0,32)
     r2 - ignored
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     vm->cu==0.

     FD_VM_ERR_SIGSEGV: bad address range.  *_ret unchanged.  vm->cu
     decremented and positive.

     FD_VM_SUCCESS: success.  *_ret=0. vm->cu decremented and positive.

     IMPORTANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log_pubkey );

/* syscall(52ba5096) "sol_log_compute_units_"
   Write remaining compute unit count to log.

   Inputs:

     r1 - ignored
     r2 - ignored
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     vm->cu==0.

     FD_VM_SUCCESS: success.  *_ret=0.  Compute budget decremented.  The
     value logged will be the value of cu when between when the syscall
     completed and the next interation starts and will be positive.

     IMPORTANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log_compute_units );

/* syscall(FIXME) "sol_log_data"
   Write Base64 encoded bytes to log.

   Inputs:

     r0 - slice, ulong pair VM pointer, indexed [0,cnt), FIXME: WHEN IS NULL OKAY?
     r1 - cnt, FIXME: IS 0 OKAY?
     r2 - ignored
     r3 - ignored
     r4 - ignored

     slice[i] holds the ulong pair:
       mem, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
       sz, FIXME: IS 0 OKAY?

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     vm->cu==0.

     FD_VM_ERR_SIGSEGV: bad address range.  *_ret unchanged.  vm->cu
     decremented and positive.

     FD_VM_SUCCESS: success.  *_ret=0. vm->cu decremented and positive.

     IMPORTANT SAFETY TIP!  The log message might have been silently
     truncated if not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log_data );

/* syscall(FIXME) "sol_alloc_free"
   DEPRECATED ... dynamic heap allocation support

   Inputs:

     arg0 - sz, ignored if vaddr is not 0
     arg1 - free_vaddr, byte VM pointer
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     All cases return FD_VM_SUCCESS.

     If free_vaddr is 0, this is "malloc"-like:

       Let the VM heap region cover bytes [heap_start,heap_end) with
       heap_start<=heap_end.  If the request was satisfied, on return,
       *_ret will point to a range of heap bytes [*_ret,*_ret+sz) that
       does not overlap with any other current allocation such that
       heap_start<=*_ret<=*_ret+sz<=heap_end.  This includes the zero sz
       case (note that the zero sz case might return the same value as a
       previous zero sz case and/or return the exact value of heap_end).

       If the request cannot be satisfied, *_ret=0 on return and the
       heap unchanged.

       IMPORTANT SAFETY TIP!  If the VM has check_align set, this
       location will have at least 8 byte alignment.  Otherwise, this
       location will have no particular alignment.  Note that this
       implies allocations done by this syscall do not conform to the
       usual alignment requirements of a standard malloc call for older
       VM code.

     If vaddr is not-zero, this is "free"-like.  Since the underlying
     implementation is necessarily a bump allocator (see implementation
     for more details), the specific value is ignored and *_ret=0 on
     return.

   FIXME: SHOULD THIS NOT DECREMENT THE VM->CU?  E.G. SZ=0
   INFINITE LOOP) */

FD_VM_SYSCALL_DECL( sol_alloc_free );

/* syscall(FIXME) "sol_memcpy"
   Copy sz bytes from src to dst.  src and dst should not overlap.

   Inputs:

     arg0 - dst, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     arg1 - src, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     arg2 - sz, FIXME: IS 0 okay?
     arg3 - ignored
     arg4 - ignored

  Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for src and/or bad address range
     for dst.  *_ret unchanged.  Compute budget decremented.

     FD_VM_ERR_MEM_OVERLAP: address ranges for src and dst overlap
     (either partially or fully ... FIXME: CHECK IF EXACT OVERLAP IS
     PERMITTED).  Empty address ranges are considered to never overlap
     (FIXME: CHECK THIS IS DESIRED).  *_ret unchanged.  Compute budget
     decremented.  FIXME: CONSIDER MERGING THIS ERR CODE WITH PERM?

     FD_VM_SUCCESS: success.  *_ret=0.  On return, dst[i]==src[i] for i
     in [0,sz).  Compute budget decremented.  IMPORTANT SAFETY TIP!  The
     current Solana cost model has sz==0 at zero cost so sz==0 always
     succeeds. */

FD_VM_SYSCALL_DECL( sol_memcpy );

/* syscall(FIXME) "sol_memcmp"
   Compare sz bytes at m0 to m1

   Inputs:

     arg0 - m0, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     arg1 - m1, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     arg2 - sz, FIXME: IS SZ 0 OKAY?
     arg3 - out, int VM pointer
     arg4 - ignored

  Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_out and *_ret
     unchanged.  Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for m0, m1 and/or out (including
     out not 4 byte aligned if the VM has check_align set).  *_out and
     *_ret unchanged.  Compute budget decremented.

     FD_VM_SUCCESS: success.  *_out will hold a positive / zero /
     negative number if the region at m0 lexicographically compares
     strictly greater than / equal to / strictly less than the region at
     m1.  Specifically, if the regions different, *_out will be
     (int)m0[i] - (int)m1[i] where i is the first differing byte.
     Compute budget decremented. */

FD_VM_SYSCALL_DECL( sol_memcmp );

/* syscall(FIXME) "sol_memset"
   Set sz bytes at dst to the byte value c.

   Inputs:

     arg0 - dst, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     arg1 - c, bits [8,64) ignored
     arg2 - sz, FIXME: IS SZ 0 OKAY?
     arg3 - ignored
     arg4 - ignored

  Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for dst.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret=0.  Compute budget decremented.
     On return, dst[i]==(c & 255UL) for i in [0,sz). */

FD_VM_SYSCALL_DECL( sol_memset );

/* syscall(FIXME) "sol_memmove"
   Copy sz bytes from src to dst.  src and dst can overlap.

   Inputs:

     arg0 - dst, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     arg1 - src, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     arg2 - sz, FIXME: IS SZ 0 OKAY?
     arg3 - ignored
     arg4 - ignored

  Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for src and/or dst.  *_ret
     unchanged.  Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret=0.  On return,
     dst[i]==src_as_it_was_before_the_call[i] for i in [0,sz).  Compute
     budget decremented. */

FD_VM_SYSCALL_DECL( sol_memmove );

/* syscall(FIXME) "sol_get_clock_sysvar"
   syscall(FIXME) "sol_get_epoch_schedule_sysvar"
   syscall(FIXME) "sol_get_fees_sysvar"
   syscall(FIXME) "sol_get_rent_sysvar"
   Get various sysvar values

   Inputs:

     arg0 - out, {clock,schedule,fees,rent} VM pointer
     arg1 - ignored
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for out.  *_ret unchanged.
     Compute budget decremented.  out should have:
                | align | sz
       clock    |     8 | 40
       schedule |     1 | 40 ... FIXME: CHECK THIS IS CORRECT!
       fees     |     8 |  8
       rent     |     8 | 24
     Strict alignment is only required when the VM has check_align set.

     FD_VM_SUCCESS: success.  *_ret=0.  On return, *out will hold the
     value of the appropriate sysvar.  Compute budget decremented. */

FD_VM_SYSCALL_DECL( sol_get_clock_sysvar          );
FD_VM_SYSCALL_DECL( sol_get_epoch_schedule_sysvar );
FD_VM_SYSCALL_DECL( sol_get_fees_sysvar           );
FD_VM_SYSCALL_DECL( sol_get_rent_sysvar           );

/* syscall(FIXME) "sol_get_stack_height"

   Inputs:

     arg0 - ignored
     arg1 - ignored
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret=stack_height.  Compute budget
     decremented. */

FD_VM_SYSCALL_DECL( sol_get_stack_height );

/* FIXME: NOT IMPLEMENTED YET ... IGNORES ALL ARGUMENTS AND RETURNS
   FD_VM_ERR_UNSUP.  (MAYBE GROUP WITH CPI OR PDA?)*/

FD_VM_SYSCALL_DECL( sol_get_processed_sibling_instruction );

/* syscall(FIXME) "sol_get_return_data"
   Get the return data and program id associated with it.

   Inputs:

     arg0 - dst, byte VM pointer, indexed [0,dst_max), FIXME: WHEN IS NULL OKAY? (PROBABLY "ignored when dst_max==0")
     arg1 - dst_max, FIXME: IS 0 OKAY? (PROBABLY)
     arg2 - program_id, byte VM pointer, indexed [0,32), FIXME: PROBABLY "ignored when dst_max==0"
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for dst and/or program_id.  *_ret
     unchanged.  Compute budget decremented.

     FD_VM_ERR_MEM_OVERLAP: dst and program_id address ranges overlap.
     *_ret unchanged.  Compute budget decremented.  (FIXME: ERR CODE)

     FD_VM_SUCCESS: success.  *_ret=return_data_sz.  Compute budget
     decremented.  If dst_max was non-zero, dst holds
     min(return_data_sz,dst_max) bytes of return data (as such, if
     return_data_sz>dst_max, the value returned in the buffer was
     truncated).  Any trailing bytes of dst are unchanged.  program_id
     holds the program_id associated with the return data.

     If dst_max was zero, dst and program_id are untouched.  (FIXME: IS
     THIS CORRECT BEHAVIOR FOR PROGRAM_ID?)

   FIXME: MAYBE GROUP WITH CPI OR PDA? */

FD_VM_SYSCALL_DECL( sol_get_return_data );

/* syscall(FIXME) "sol_set_return_data"
   Set the return data.  The return data will be associated with the
   caller's program ID.

   Inputs:

     arg0 - src, byte VM pointer, indexed [0,src_sz), FIXME: WHEN IS NULL OKAY?
     arg1 - src_sz, FIXME: IS 0 OKAY?
     arg2 - ignored
     arg3 - ignored
     arg4 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_RETURN_DATA_TOO_LARGE: src_sz too large.  *_ret
     unchanged.  Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for src.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret=0.  Compute budget decremented.

   FIXME: MAYBE GROUP WITH CPI OR PDA? */

FD_VM_SYSCALL_DECL( sol_set_return_data );

/* fd_vm_syscall_pda **************************************************/

/* syscall(9377323c) "sol_create_program_address"

   Compute SHA-256 hash of <program ID> .. &[&[u8]] .. <PDA Marker>
   and check whether result is an Ed25519 curve point.

   Inputs:

     arg0 - seed, ulong pair (FIXME: TRIPLE?) VM pointer, indexed [0,seed_cnt), FIXME: WHEN IS NULL OKAY?
     arg1 - seed_cnt, FIXME: IS 0 OKAY?
     arg2 - program_id, byte VM pointer, indexed [0,32) (FIXME: DOUBLE CHECK SIZE / ALIGN REQ)
     arg3 - out, byte VM pointer, indexed [0,32) (FIXME: DOUBLE CHECK SIZE)
     arg4 - ignored

     seed[i] holds the ulong pair (FIXME: TRIPLE?):
       mem, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
       sz, FIXME: IS 0 OKAY?

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: seed_cnt and/or seed[i].sz too large (FIXME: USE
     DIFFERENT ERR CODE), bad address range for program_id, seed,
     seed[i].mem and/or out (including 8-byte alignment for seed if the
     VM has check_align set). *_ret unchanged.  Compute budget
     decremented.

     FD_VM_SUCCESS: success.  If *_ret==0, a PDA was created and
     stored at out.  If *_ret==1, create failed and out was unchanged.
     Compute budget decremented. */

FD_VM_SYSCALL_DECL( sol_create_program_address );

/* syscall(48504a38) "sol_try_find_program_address"

   Repeatedly derive program address while incrementing nonce in seed
   list until a point is found that is not a valid Ed25519 curve point.

   Inputs:

     arg0 - seed, ulong pair (FIXME: TRIPLE?) VM pointer, indexed [0,seed_cnt), FIXME: WHEN IS NULL OKAY?
     arg1 - seed_cnt, FIXME: IS 0 OKAY?
     arg2 - program_id, byte VM pointer, indexed [0,32) (FIXME: DOUBLE CHECK SIZE / ALIGN REQ)
     arg3 - out, byte VM pointer, indexed [0,32) (FIXME: DOUBLE CHECK SIZE)
     arg4 - bump_seed, byte VM pointer, indexed [0,1)

     seed[i] holds the ulong pair (FIXME: TRIPLE?):
       mem, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
       sz, FIXME: IS 0 OKAY?

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: seed_cnt and/or seed[i].sz too large (FIXME: USE
     DIFFERENT ERR CODE), bad address range for program_id, seed,
     seed[i].mem, out and/or bump_seed (including 8-byte alignment for
     seed if the VM has check_align set). *_ret unchanged.  Compute
     budget decremented.

     FD_VM_SUCCESS: success.  If *_ret==0, a PDA was found and stored at
     out and the suffix stored at bump_seed.  If *_ret==1, no PDA was
     found and out and bump_seed were unchanged.  Compute budget
     decremented. */

FD_VM_SYSCALL_DECL( sol_try_find_program_address );

/* fd_vm_syscall_cpi **************************************************/

/* Represents an account for a CPI */
/* FIXME: DOES THIS GO HERE?  MAYBE GROUP WITH ADMIN OR OUTSIDE SYSCALL? */

struct fd_instruction_account {
  ushort index_in_transaction;
  ushort index_in_caller;
  ushort index_in_callee;
  uint is_signer;
  uint is_writable;
};

typedef struct fd_instruction_account fd_instruction_account_t;

/* Prepare instruction method */
/* FIXME: DOES THIS GO HERE?  MAYBE GROUP WITH ADMIN OR OUTSIDE SYSCALL? */

int
fd_vm_prepare_instruction( fd_instr_info_t const *  caller_instr,
                           fd_instr_info_t *        callee_instr,
                           fd_exec_instr_ctx_t *    instr_ctx,
                           fd_instruction_account_t instruction_accounts[256],
                           ulong *                  instruction_accounts_cnt,
                           fd_pubkey_t const *      signers,
                           ulong                    signers_cnt );

/* syscall(a22b9c85) "sol_invoke_signed_c"
   Dispatch a cross program invocation.  Inputs are in C ABI.

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( cpi_c );

/* syscall(d7449092) "sol_invoke_signed_rust"
   Dispatch a cross program invocation.  Inputs are in Rust ABI.

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( cpi_rust );

/* fd_vm_syscall_crypto ***********************************************/

/* syscall(FIXME) sol_alt_bn128_group_op
   syscall(FIXME) sol_alt_bn128_compression

   FIXME: NOT IMPLEMENTED YET, IGNORES ALL ARGUMENTS AND RETURNS INVAL
   (MAYBE SHOULD RETURN UNSUP)? */

FD_VM_SYSCALL_DECL( sol_alt_bn128_group_op    );
FD_VM_SYSCALL_DECL( sol_alt_bn128_compression );

/* syscall(FIXME) "sol_blake3"
   syscall(FIXME) "sol_keccak256"
   syscall(FIXME) "sol_sha256"

   Inputs:

     arg0 - slice, ulong pair VM pointer, indexed [0,cnt), FIXME: WHEN IS NULL OKAY?
     arg1 - cnt, FIXME: IS 0 OKAY?
     arg2 - hash, byte VM pointer, indexed [0,32)
     arg3 - ignored
     arg4 - ignored

     slice[i] holds the ulong pair:
       mem, byte vector VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
       sz, FIXME: IS 0 OKAY?

   Return:

     FD_VM_ERR_INVAL: cnt too large.  *_ret unchanged.

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     Compute budget decremented.

     FD_VM_ERR_PERM: bad address range for slice, hash and/or
     slice[i].addr (including slice not 8 byte aligned if the VM has
     check_align set).  *_ret unchanged.  Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret=0 and hash[i] holds the hash of the
     concatentation of the slices.  Compute budget decremented. */

FD_VM_SYSCALL_DECL( sol_blake3    );
FD_VM_SYSCALL_DECL( sol_keccak256 );
FD_VM_SYSCALL_DECL( sol_sha256    );

/* syscall(FIXME) "sol_poseidon"

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_poseidon ); /* Light protocol flavor */

/* syscall(FIXME) "sol_secp256k1_recover"

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_secp256k1_recover );

/* fd_vm_syscall_curve ************************************************/

/* FD_VM_SYSCALL_SOL_CURVE_ECC_{...} specifies the curve IDs and
   FD_VM_SYSCALL_SOL_CURVE_ECC_G_{...} declares IDs of operations on
   elliptic curve groups for the sol_curve syscalls. */

#define FD_VM_SYSCALL_SOL_CURVE_ECC_ED25519      (0UL)
#define FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255 (1UL)

#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_ADD (0UL) /* add */
#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_SUB (1UL) /* add inverse */
#define FD_VM_SYSCALL_SOL_CURVE_ECC_G_MUL (2UL) /* scalar mult */

/* syscall(FIXME) sol_curve_validate_point

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_curve_validate_point  );

/* syscall(FIXME) sol_curve_validate_point

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_curve_group_op );

/* syscall(FIXME) sol_curve_validate_point

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_curve_multiscalar_mul );

FD_PROTOTYPES_END

#endif /* HEADER_src_flamenco_vm_syscall_fd_vm_syscall_h */
