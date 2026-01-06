#ifndef HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h
#define HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h

#include "../fd_vm_private.h"
#include "fd_vm_syscall_macros.h"
#include "fd_vm_cpi.h"                /* FIXME: REFINE THIS MORE */
#include "../../runtime/fd_runtime.h" /* FIXME: REFINE THIS MORE */
#include "../../runtime/context/fd_exec_instr_ctx.h"
#include "../../log_collector/fd_log_collector.h"

#define FD_VM_RETURN_DATA_MAX  (1024UL) /* FIXME: DOCUMENT AND DOES THIS BELONG HERE? */

/* The maximum number of seeds a PDA can have
   https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/sdk/program/src/pubkey.rs#L21 */
#define FD_VM_PDA_SEEDS_MAX    (16UL)
/* The maximum length of a PDA seed
   https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/sdk/program/src/pubkey.rs#L19 */
#define FD_VM_PDA_SEED_MEM_MAX (32UL)

/* PYTHON3 CODE FOR COMPUTING THE SYSCALL MURMUR3 HASH (e.g. sol_get_epoch_stake):
  ```
  import mmh3
  import ctypes

  def compute_murmur3_hash(input_string):
      # Compute the Murmur3 hash of the input string
      hash_value = mmh3.hash(input_string)
      # Convert the hash value to a 32-bit unsigned integer
      u32_hash_value = ctypes.c_uint32(hash_value).value
      return u32_hash_value

  input_string = b"sol_get_epoch_stake"
  hash_value = compute_murmur3_hash(input_string)
  print(f"The Murmur3 hash of '{input_string}' as u32 is: {hex(hash_value)}")

  Output:
  The Murmur3 hash of 'b'sol_get_epoch_stake'' as u32 is: 0x5be92f4a
  ```
*/

/* https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/sdk/program/src/pubkey.rs#L22 */

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

   When an syscall implementation returns FD_VM_SYSCALL_ERR*, the
   syscall is considered to have faulted the VM.  It ideally should not
   have set *_r0 (or changed any vm state, except vm->cu, though that
   often isn't practical, and not critical to consensus).

   It is the syscall's responsibility to deduct from vm->cu its specific
   cost model (not including the syscall instruction itself).  As such,
   when a syscall returns COMPUTE_BUDGET_EXCEEDED, it should have set
   vm->cu to zero. When it returns anything else, it should have set cu
   to something in [0,cu_at_function_entry] (upper bound inclusive,
   despite most syscalls deducing base CUs first thing, some don't,
   e.g., sol_sha256).

   To mitigate risks of from syscall implementations that do not
   strictly enforce this and other similar risks that can affect
   bookkeeping, on return from a syscall, the VM will:

   - Ignore updates to pc, ic and frame_cnt.
   - Ignore updates to cu that increase it.
   - Treat updates to cu that zero it as SIGCOST.
   - Treat SIGCOST returns that didn't update cu to zero as zeroing it.

   FIXME: ADD NO SETTING OF R0 ON VM_ERR IN VM_INTERP. */

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

     FD_VM_SYSCALL_ERR_ABORT: *_ret unchanged.  vm->cu unchanged.

   FIXME: SHOULD THIS BE NAMED "SOL_ABORT"? */

FD_VM_SYSCALL_DECL( abort );

/* syscall(686093bb) "sol_panic_"
   Log panic message, abort program execution, and fail transaction.

   Inputs:

     r1 - msg, byte VM pointer, indexed [0,msg_sz), msg doesn't have to
     be \0 terminated and can contain \0 within,
     r2 - msg_sz, may be 0,
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_INVALID_STRING: Bad filepath string, msg is not
     a valid sequence of utf8 bytes.  *_ret unchanged and vm->cu>=0.

     FD_VM_SYSCALL_ERR_PANIC: *_ret unchanged.  *_ret unchanged.  vm->cu
     decremented and vm->cu>=0. */

FD_VM_SYSCALL_DECL( sol_panic );

/* syscall(207559bd) "sol_log_"
   Write message encoded as (msg, msg_sz) to log, prefixed with
   "Program log: ".

   Inputs:

     r1 - msg, byte VM pointer, indexed [0,msg_sz),
     r2 - msg_sz, may be 0,
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_INVALID_STRING: bad message string.  *_ret
     unchanged. vm->cu decremented and vm->cu>=0.

     FD_VM_SUCCESS: success.  *_ret==0.  vm->cu decremented and
     vm->cu>=0.

     IMPORTANT SAFETY TIP!  The log message will be silently truncated
     if there was not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log );

/* syscall(5c2a3178) "sol_log_64_"
   Write r1:5 to the log as a hexadecimal

   Inputs:

     r1 - ulong
     r2 - ulong
     r3 - ulong
     r4 - ulong
     r5 - ulong

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SUCCESS: success.  *_ret=0.  vm->cu decremented and
     vm->cu>=0.

     IMPORTANT SAFETY TIP!  The log message will be silently truncated
     if there was not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log_64 );

/* syscall(7ef088ca) "sol_log_pubkey"
   Write the base58 encoding of 32 byte array to the log.

   Inputs:

     r1 - pubkey, byte VM pointer, indexed [0,32)
     r2 - ignored
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret unchanged.
     vm->cu decremented and vm->cu>=0.

     FD_VM_SUCCESS: success.  *_ret==0.  vm->cu decremented and
     vm->cu>=0.

     IMPORTANT SAFETY TIP!  The log message will be silently truncated
     if there was not enough room for the message in the syscall log
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

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SUCCESS: success.  *_ret=0.  vm->cu decremented
     and vm->cu>=0.  The value logged will be the value of cu when
     between when the syscall completed and the next interation starts
     and will be >=0.

     IMPORTANT SAFETY TIP!  The log message will be silently truncated
     if there was not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log_compute_units );

/* syscall(7317b434) "sol_log_data"
   Write the base64 encoded cnt data slices to the log.

   Inputs:

     r1 - slice, ulong pair VM pointer, indexed [0,cnt),
     r2 - cnt, may be 0,
     r3 - ignored
     r4 - ignored
     r5 - ignored

     slice[i] holds the ulong pair:
       mem, byte VM pointer, indexed [0,sz),
       sz, may be 0

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute budget.
     *_ret unchanged. vm->cu==0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret unchanged.  vm->cu
     decremented and vm->cu>0.

     FD_VM_SUCCESS: success.  *_ret=0.  vm->cu decremented and vm->cu>0.

     IMPORTANT SAFETY TIP!  The log message will be silently truncated
     if there was not enough room for the message in the syscall log
     when called. */

FD_VM_SYSCALL_DECL( sol_log_data );

/* syscall(83f00e8f) "sol_alloc_free_"
   DEPRECATED ... dynamic heap allocation support

   Inputs:

     r1 - sz, ignored if vaddr is not 0
     r2 - free_vaddr, byte VM pointer
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     All cases return FD_VM_SUCCESS and leave vm->cu unchanged.

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
     return. */

FD_VM_SYSCALL_DECL( sol_alloc_free );

/* syscall(717cc4a3) "sol_memcpy_"
   Copy sz bytes from src to dst.  src and dst should not overlap.

   Inputs:

     r1 - dst, byte VM pointer, indexed [0,sz),
     r2 - src, byte VM pointer, indexed [0,sz),
     r3 - sz,
     r4 - ignored
     r5 - ignored

  Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_COPY_OVERLAPPING: address ranges for src and dst
     overlap (either partially or fully).  Empty address ranges are
     considered to **never** overlap.  *_ret==0.  vm->cu decremented and
     vm->cu>=0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret==0.  vm->cu
     decremented and vm->cu>=0.

     FD_VM_SUCCESS: success.  *_ret==0.  vm->cu decremented and
     vm->cu>=0. On return, dst[i]==src[i] for i in [0,sz). */

FD_VM_SYSCALL_DECL( sol_memcpy );

/* syscall(5fdcde31) "sol_memcmp_"
   Compare sz bytes at m0 to m1

   Inputs:

     r1 - m0, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     r2 - m1, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     r3 - sz, FIXME: IS SZ 0 OKAY?
     r4 - out, int VM pointer
     r5 - ignored

  Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute budget.
     *_ret unchanged. vm->cu==0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range (including out not 4 byte
     aligned).  *_ret unchanged.  vm->cu decremented and vm->cu>0.
     Strict alignment is only required when the VM has check_align set.

     FD_VM_SUCCESS: success.  *_ret=0.  vm->cu decremented and vm->cu>0.
     On return, *_out will hold a positive / zero / negative number if
     the region at m0 lexicographically compares strictly greater than /
     equal to / strictly less than the region at m1 when treated as
     uchars.  Specifically, if the regions are different, *_out will be
     (int)m0[i] - (int)m1[i] where i is the first differing byte.

     IMPORANT SAFETY TIP!  Note that, strangely, this returns the result
     in memory instead via *_ret like a libc-style memcmp would. */

FD_VM_SYSCALL_DECL( sol_memcmp );

/* syscall(3770fb22) "sol_memset_"
   Set sz bytes at dst to the byte value c.

   Inputs:

     r1 - dst, byte VM pointer, indexed [0,sz), FIXME: WHEN IS NULL OKAY?
     r2 - c, bits [8,64) ignored (FIXME: CHECK SOLANA DOES THIS)
     r3 - sz, may be 0,
     r4 - ignored
     r5 - ignored

  Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute budget.
     *_ret unchanged. vm->cu==0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret unchanged.  vm->cu
     decremented and vm->cu>0.

     FD_VM_SUCCESS: success.  *_ret=0.  vm->cu decremented and vm->cu>0.
     On return, dst[i]==(uchar)(c & 255UL) for i in [0,sz). */

FD_VM_SYSCALL_DECL( sol_memset );

/* syscall(434371f8) "sol_memmove_"
   Copy sz bytes from src to dst.  src and dst can overlap.

   Inputs:

     r1 - dst, byte VM pointer, indexed [0,sz),
     r2 - src, byte VM pointer, indexed [0,sz),
     r3 - sz, may be 0,
     r4 - ignored
     r5 - ignored

  Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute budget.
     *_ret unchanged. vm->cu==0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret unchanged.  vm->cu
     decremented and vm->cu>0.

     FD_VM_SUCCESS: success.  *_ret=0.  vm->cu decremented and vm->cu>0.
     On return, dst[i]==src_as_it_was_before_the_call[i] for i in
     [0,sz). */

FD_VM_SYSCALL_DECL( sol_memmove );

/* fd_vm_syscall_runtime **********************************************/

/* syscall(d56b5fe9) "sol_get_clock_sysvar"
   syscall(23a29a61) "sol_get_epoch_schedule_sysvar"
   syscall(bf7188f6) "sol_get_rent_sysvar"
   syscall(77f9b9d0) "sol_get_last_restart_slot_sysvar"
   Get various sysvar values

   Inputs:

     r1 - out, {clock,schedule,fees,rent,last_restart_slot} VM pointer
     r2 - ignored
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME: the VM is not running within the
     Solana runtime.  *_ret unchanged.  vm->cu unchanged.

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret unchanged.
     vm->cu decremented and vm->cu>=0.  out should have:
                          | align | sz
       clock              |     8 | 40
       schedule           |     8 | 40
       rent               |     8 | 24
       last restart slot  |     8 | 8
     Strict alignment is only required when the VM has check_align set.

     FD_VM_SUCCESS: success.  *_ret=0.  vm->cu decremented and vm->cu>0.
     On return, *out will hold the value of the appropriate sysvar. */

FD_VM_SYSCALL_DECL( sol_get_clock_sysvar             );
FD_VM_SYSCALL_DECL( sol_get_epoch_schedule_sysvar    );
FD_VM_SYSCALL_DECL( sol_get_rent_sysvar              );
FD_VM_SYSCALL_DECL( sol_get_last_restart_slot_sysvar );
FD_VM_SYSCALL_DECL( sol_get_epoch_rewards_sysvar     );

/* syscall(13c1b505) "sol_get_sysvar"

   Get a slice of a sysvar account's data.

   Inputs:

     r1 - sysvar_id_vaddr, sysvar pubkey VM pointer
     r2 - out_vaddr, byte VM pointer
     r3 - offset, ulong
     r4 - sz, num bytes to store
     r5 - ignored

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad sysvar_id_vaddr, bad out_vaddr,
     requested slice outside of sysvar data buffer.  _ret unchanged.
     vm->cu decremented and vm->cu>=0.

     FD_VM_SYSCALL_ERR_ABORT: offset+sz overflow.  *_ret unchanged.
     vm->cu decremented and vm->cu>=0.

     FD_VM_SUCCESS: success. vm->cu decremented and vm->cu>=0.
      - *_ret = 2 if sysvar id is not in {clock,schedule,rewards,rent,
                  slot hashes,stake history, last restart slot}
                  OR sysvar account does not exist.
      - *_ret = 1 if [offset,offset+sz) is outside of sysvar data
                  buffer.
      - *_ret = 0 if success.

     On return, sz bytes of appropriate offset sysvar data will be
     copied into haddr belonging to out_vaddr. */
FD_VM_SYSCALL_DECL( sol_get_sysvar );

/* syscall(5be92f4a) "sol_get_epoch_stake"

   This syscall is meant to return the latest frozen stakes at an epoch
   boundary.  So for instance, when we are executing in epoch 7, this
   should return the stakes at the end of epoch 6.  Note that this is
   also the stakes that determined the leader schedule for the upcoming
   epoch, namely epoch 8.

   Inputs:

     r1 - var_addr, vote pubkey VM pointer, or zero to get the total
          active stake on the cluster.
     r2 - ignored
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_ERR_SIGCOST: insufficient compute budget.  *_ret unchanged.
     vm->cu==0.

     FD_VM_ERR_SIGSEGV: bad var_addr.  _ret unchanged.  vm->cu
     decremented and vm->cu>=0.

     FD_VM_ERR_ABORT: offset+sz overflow.  *_ret unchanged.

     FD_VM_SUCCESS: success. vm->cu decremented and vm->cu>=0.
      If var_addr == 0, *_ret is the total active stake on the
      cluster.  Else, it is the vote account's delegated stake if
      var_addr is an existing vote account, and 0 otherwise. */

FD_VM_SYSCALL_DECL( sol_get_epoch_stake );

/* syscall(85532d94) "sol_get_stack_height"

   Inputs:

     r1 - ignored
     r2 - ignored
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret unchanged.
     vm->cu decremented and vm->cu>=0.

     FD_VM_SUCCESS: success.  *_ret==stack_height.  vm->cu decremented
     and vm->cu>=0. */

FD_VM_SYSCALL_DECL( sol_get_stack_height );

/* syscall(5d2245e4) "sol_get_return_data"
   Get the return data and program id associated with it.

   Inputs:

     r1 - dst, byte VM pointer, indexed [0,dst_max),
     r2 - dst_max, may be 0,
     r3 - program_id, byte VM pointer, indexed [0,32)
     r4 - ignored
     r5 - ignored

   Return:

     FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME: the VM is not running within
     the Solana runtime.  *_ret unchanged.  vm->cu unchanged.

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged. vm->cu==0.

     FD_VM_SYSCALL_ERR_COPY_OVERLAPPING: dst and program_id address
     ranges overlap.  *_ret unchanged.   vm->cu decremented and
     vm->cu>=0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range for dst and/or
     program_id. *_ret unchanged.  Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret=return_data_sz.  vm->cu decremented
     and vm->cu>=0.  On return, if dst_max was non-zero, dst holds the
     leading min(return_data_sz,dst_max) bytes of return data (as such,
     if return_data_sz>dst_max, the value returned in the buffer was
     truncated).  Any trailing bytes of dst are unchanged.  program_id
     holds the program_id associated with the return data.

     If dst_max was zero, dst and program_id are untouched. */

FD_VM_SYSCALL_DECL( sol_get_return_data );

/* syscall(a226d3eb) "sol_set_return_data"
   Set the return data.  The return data will be associated with the
   caller's program ID.

   Inputs:

     r1 - src, byte VM pointer, indexed [0,src_sz),
     r2 - src_sz, may be 0,
     r3 - ignored
     r4 - ignored
     r5 - ignored

   Return:
     FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME: the VM is not running within the
     Solana runtime.  *_ret unchanged.  vm->cu unchanged.

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE: src_sz too large.  *_ret
     unchanged.  vm->cu decremented and vm->cu>0.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range for src.  *_ret unchanged.
     vm->cu decremented and vm->cu>=0.

     FD_VM_SUCCESS: success.  *_ret=0.  vm->cu decremented and vm->cu>0. */

FD_VM_SYSCALL_DECL( sol_set_return_data );

/* syscall(adb8efc8) "sol_get_processed_sibling_instruction"
   Returns the last element from a reverse-ordered list of successfully
   processed sibling instructions: the "processed sibling instruction
   list".

   For example, given the call flow:
   A
   B -> C -> D
   B -> E
   B -> F      (current execution point)

   B's processed sibling instruction list is [A]
   F's processed sibling instruction list is [E, C]

   This allows the current instruction to know what the last processed
   sibling instruction was.  This is useful to check that critical
   preceding instructions have actually executed: for example, ensuring
   that an assert instruction has successfully executed.

   Inputs:

     r1 - index
     r2 - result_meta_vaddr, byte VM pointer of the object where
          metadata about the last processed sibling instruction will be
          stored upon successful execution (the length of the arrays in
          the result). Has the type
          solana_program::instruction::ProcessedSiblingInstruction
          https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/sdk/program/src/instruction.rs#L672-L681
     r3 - result_program_id_vaddr, byte VM pointer where the pubkey of
          the program ID of the last processed sibling instruction will
          be stored upon successful execution
     r4 - result_data_vaddr, byte VM pointer where the instruction
          data of the last processed sibling instruction will be stored
          upon successful execution. The length of the data will be
          stored in ProcessedSiblingInstruction.data_len
     r5 - result_accounts_vaddr, byte VM pointer where an array of
          account meta structures will be stored into upon successful
          execution.  The length of the data will be stored in
          ProcessedSiblingInstruction.accounts_len.  Each account meta
          has the type solana_program::instruction::AccountMeta
          https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/sdk/program/src/instruction.rs#L525-L548

    Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SUCCESS: *_ret==1 if the instruction was found and, *_ret==0
     otherwise.  vm->cu decremented and vm->cu>=0. */


FD_VM_SYSCALL_DECL( sol_get_processed_sibling_instruction );

/* fd_vm_syscall_pda **************************************************/

/* syscall(9377323c) "sol_create_program_address"

   Compute SHA-256 hash of <program ID> .. &[&[u8]] .. <PDA Marker>
   and check whether result is an Ed25519 curve point.

   Inputs:

     r1 - seeds, bytes VM pointer, indexed [0,seed_cnt),
     r2 - seed_cnt, may be 0,
     r3 - program_id, byte VM pointer, indexed [0,32), FD_PUBKEY_ALIGN
          aligned
     r4 - out, byte VM pointer, indexed [0,32), FD_PUBKEY_ALIGN aligned
     r5 - ignored

     seed[i] holds the ulong pair
       mem, byte VM pointer, indexed [0,sz),
       sz, may be 0

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_BAD_SEEDS: seed_cnt and/or seed[i].sz too large,
     bad address range for program_id, seed,
     seed[i].mem and/or out (including 8-byte alignment for seed if the
     VM has check_align set). *_ret unchanged.  Compute budget
     decremented.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret unchanged.
     vm->cu decremented and vm->cu>=0.

     FD_VM_SUCCESS: success.  If *_ret==0, a PDA was created and
     stored at out.  If *_ret==1, create failed and out was unchanged.
     Compute budget decremented. */

FD_VM_SYSCALL_DECL( sol_create_program_address );

/* syscall(48504a38) "sol_try_find_program_address"

   Repeatedly derive program address while incrementing nonce in seed
   list until a point is found that is not a valid Ed25519 curve point.

   Inputs:

     r1 - seed, ulong pair VM pointer, indexed [0,seed_cnt),
     r2 - seed_cnt, may be 0,
     r3 - program_id, byte VM pointer, indexed [0,32), FD_PUBKEY_ALIGN
          aligned
     r4 - out, byte VM pointer, indexed [0,32), FD_PUBKEY_ALIGN aligned
     r5 - bump_seed, byte VM pointer, indexed [0,1)

     seed[i] holds the ulong pair
       mem, byte VM pointer, indexed [0,sz),
       sz, may be 0

   Return:

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute
     budget.  *_ret unchanged.  vm->cu==0.

     FD_VM_SYSCALL_ERR_BAD_SEEDS: seed_cnt and/or seed[i].sz too large,
     bad address range for program_id, seed,
     seed[i].mem, out and/or bump_seed (including 8-byte alignment for
     seed if the VM has check_align set). *_ret unchanged.  Compute
     budget decremented.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range.  *_ret unchanged.
     vm->cu decremented and vm->cu>=0.

     FD_VM_SUCCESS: success.  If *_ret==0, a PDA was found and stored at
     out and the suffix stored at bump_seed.  If *_ret==1, no PDA was
     found and out and bump_seed were unchanged.  Compute budget
     decremented. */

FD_VM_SYSCALL_DECL( sol_try_find_program_address );

/* fd_vm_syscall_cpi **************************************************/

/* Prepare instruction method */
/* FIXME: DOES THIS GO HERE?  MAYBE GROUP WITH ADMIN OR OUTSIDE SYSCALL? */

int
fd_vm_prepare_instruction( fd_instr_info_t *        callee_instr,
                           fd_exec_instr_ctx_t *    instr_ctx,
                           fd_pubkey_t const *      callee_program_id_pubkey,
                           fd_pubkey_t const        instr_acct_keys[ FD_INSTR_ACCT_MAX ],
                           fd_instruction_account_t instruction_accounts[ FD_INSTR_ACCT_MAX ],
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

/* FD_VM_SYSCALL_SOL_ALT_BN128_{ADD,SUB,MUL,PAIRING} specifies the curve operation. */

#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_ADD_BE           (  0UL) /* add */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_SUB_BE           (  1UL) /* add inverse */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_MUL_BE           (  2UL) /* scalar mult */
#define FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING_BE          (  3UL) /* pairing */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_ADD_BE           (  4UL) /* add */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_SUB_BE           (  5UL) /* add inverse */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_MUL_BE           (  6UL) /* scalar mult */
#define FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG  ( 0x80) /* little endian (SIMD-0284) */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_ADD_LE           ( FD_VM_SYSCALL_SOL_ALT_BN128_G1_ADD_BE  | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_SUB_LE           ( FD_VM_SYSCALL_SOL_ALT_BN128_G1_SUB_BE  | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_MUL_LE           ( FD_VM_SYSCALL_SOL_ALT_BN128_G1_MUL_BE  | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING_LE          ( FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING_BE | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_ADD_LE           ( FD_VM_SYSCALL_SOL_ALT_BN128_G2_ADD_BE  | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_SUB_LE           ( FD_VM_SYSCALL_SOL_ALT_BN128_G2_SUB_BE  | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_MUL_LE           ( FD_VM_SYSCALL_SOL_ALT_BN128_G2_MUL_BE  | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )

/* FD_VM_SYSCALL_SOL_ALT_BN128_{...}COMPRESS specifies the (de)compress operation. */

#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_COMPRESS_BE      (  0UL) /* compress point in G1 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_DECOMPRESS_BE    (  1UL) /* decompress point in G1 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_COMPRESS_BE      (  2UL) /* compress point in G2 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_DECOMPRESS_BE    (  3UL) /* decompress point in G2 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_COMPRESS_LE      ( FD_VM_SYSCALL_SOL_ALT_BN128_G1_COMPRESS_BE   | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_DECOMPRESS_LE    ( FD_VM_SYSCALL_SOL_ALT_BN128_G1_DECOMPRESS_BE | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_COMPRESS_LE      ( FD_VM_SYSCALL_SOL_ALT_BN128_G2_COMPRESS_BE   | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_DECOMPRESS_LE    ( FD_VM_SYSCALL_SOL_ALT_BN128_G2_DECOMPRESS_BE | FD_VM_SYSCALL_SOL_ALT_BN128_LITTLE_ENDIAN_FLAG )

/* FD_VM_SYSCALL_SOL_ALT_BN128_{...}_SZ specifies the size of inputs/outputs for the Alt_BN128 curve. */

#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_SZ               ( 64UL) /* size of a point in G1 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G1_COMPRESSED_SZ    ( 32UL) /* size of a compressed point in G2 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_SZ               (128UL) /* size of a point in G2 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_G2_COMPRESSED_SZ    ( 64UL) /* size of a compressed point in G2 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_SCALAR_SZ           ( 32UL) /* size of a scalar */
#define FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING_INPUT_EL_SZ (192UL) /* size of G1 + G2 */
#define FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING_OUTPUT_SZ   ( 32UL) /* size of pairing syscall result, i.e. 0 or 1 as 256-bit int ¯\_(ツ)_/¯ */

/* syscall(ae0c318b) sol_alt_bn128_group_op computes operations on the Alt_BN128 curve,
   including point addition in G1, scalar multiplication in G1, and pairing.
   See SIMD-0129.

   FIXME: DOCUMENT */

FD_VM_SYSCALL_DECL( sol_alt_bn128_group_op    );

/* syscall(334fd5ed) sol_alt_bn128_compression allows to compress or decompress points
   in G1 or G2 groups over the Alt_BN128 curve.
   See SIMD-0129.

   FIXME: DOCUMENT */

FD_VM_SYSCALL_DECL( sol_alt_bn128_compression );

/* syscall(174c5122) "sol_blake3"
   syscall(d7793abb) "sol_keccak256"
   syscall(11f49d86) "sol_sha256"

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

     FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED: insufficient compute budget.
     *_ret unchanged. Compute budget decremented.

     FD_VM_SYSCALL_ERR_SEGFAULT: bad address range for slice, hash and/or
     slice[i].addr (including slice not 8 byte aligned if the VM has
     check_align set).  *_ret unchanged.  Compute budget decremented.

     FD_VM_SUCCESS: success.  *_ret=0 and hash[i] holds the hash of the
     concatentation of the slices.  Compute budget decremented. */

FD_VM_SYSCALL_DECL( sol_blake3    );
FD_VM_SYSCALL_DECL( sol_keccak256 );
FD_VM_SYSCALL_DECL( sol_sha256    );

/* syscall(c4947c21) sol_poseidon computes the Poseidon hash on an array of input values.
   See SIMD-0129.

   FIXME: DOCUMENT */

#define FD_VM_SYSCALL_SOL_POSEIDON_MAX_VALS 12UL

FD_VM_SYSCALL_DECL( sol_poseidon ); /* Light protocol flavor */

/* syscall(17e40350) "sol_secp256k1_recover"

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_secp256k1_recover );

/* fd_vm_syscall_curve ************************************************/

/* FD_VM_SYSCALL_SOL_CURVE_CURVE25519_{...} specifies the curve ID */

#define FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS   ( 0UL) /* ed25519 */
#define FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO ( 1UL) /* ristretto255 */

/* FD_VM_SYSCALL_SOL_CURVE_{...} specifies the curve operation */

#define FD_VM_SYSCALL_SOL_CURVE_ADD                  ( 0UL) /* add */
#define FD_VM_SYSCALL_SOL_CURVE_SUB                  ( 1UL) /* add inverse */
#define FD_VM_SYSCALL_SOL_CURVE_MUL                  ( 2UL) /* scalar mul */

/* FD_VM_SYSCALL_SOL_CURVE_CURVE25519_{...}_SZ specifies the size of inputs/outputs. */

#define FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ  (32UL) /* point (compressed) */
#define FD_VM_SYSCALL_SOL_CURVE_CURVE25519_SCALAR_SZ (32UL) /* scalar */

/* syscall(aa2607ca) sol_curve_validate_point

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_curve_validate_point  );

/* syscall(dd1c41a6) sol_curve_validate_point

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_curve_group_op );

/* syscall(60a40880) sol_curve_validate_point

   FIXME: BELT SAND AND DOCUMENT */

FD_VM_SYSCALL_DECL( sol_curve_multiscalar_mul );

int
fd_vm_derive_pda( fd_vm_t *           vm,
                  fd_pubkey_t const * program_id,
                  void const * *      seed_haddrs,
                  ulong *             seed_szs,
                  ulong               seeds_cnt,
                  uchar *             bump_seed,
                  fd_pubkey_t *       out );

int
fd_vm_translate_and_check_program_address_inputs( fd_vm_t *             vm,
                                                  ulong                 seeds_vaddr,
                                                  ulong                 seeds_cnt,
                                                  ulong                 program_id_vaddr,
                                                  void const * *        out_seed_haddrs,
                                                  ulong *               out_seed_szs,
                                                  fd_pubkey_t const * * out_program_id,
                                                  uchar                 is_syscall );
FD_PROTOTYPES_END

#endif /* HEADER_src_flamenco_vm_syscall_fd_vm_syscall_h */
