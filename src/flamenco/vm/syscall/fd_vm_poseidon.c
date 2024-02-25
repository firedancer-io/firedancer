#include "fd_vm_poseidon.h"

static int
poseidon_cost( ulong   input_cnt,
               ulong   cost_coefficient,
               ulong * cost_out ) {
  ulong input_sq;
  if( FD_UNLIKELY( __builtin_umull_overflow( input_cnt, input_cnt, &input_sq ) ) ) return 0;

  ulong mul_result;
  if( FD_UNLIKELY( __builtin_umull_overflow( cost_coefficient, input_sq, &mul_result ) ) ) return 0;

  if( FD_UNLIKELY( __builtin_uaddl_overflow( mul_result, input_cnt, cost_out ) ) ) return 0;

  return 1;
}

int
fd_vm_syscall_sol_poseidon( void *  _ctx,
                            ulong   params,
                            ulong   endianness,
                            ulong   vals_addr,
                            ulong   vals_len,
                            ulong   result_addr,
                            ulong * _ret ) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  *_ret = 0UL;

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1731 */

  if( FD_UNLIKELY( params!=0UL ) ) {
    /* TODO What is the implicit conversion form PoseidonSyscallError to SyscallError? */
    *_ret = 1UL;  /* PoseidonSyscallError::InvalidParameters */
    return FD_VM_SYSCALL_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1732 */

  switch( endianness ) {
  case 0:
  case 1:
    break;
  default:
    /* TODO What is the implicit conversion form PoseidonSyscallError to SyscallError? */
    *_ret = 2UL;  /* PoseidonSyscallError::InvalidEndianness */
    return FD_VM_SYSCALL_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1734-L1741 */

  if( FD_UNLIKELY( vals_len > 12UL ) ) {
    /* TODO Log: "Poseidon hashing {} sequences is not supported" */
    return FD_VM_SYSCALL_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1743-L1750 */

  ulong cost;
  if( FD_UNLIKELY( !poseidon_cost( vals_len, 1UL, &cost ) ) ) {
    /* TODO Log: "Overflow while calculating the compute cost" */
    return FD_VM_SYSCALL_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1751 */

  int err = fd_vm_consume_compute( ctx, cost );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1753-L1759 */

  void * hash_result =
      fd_vm_translate_vm_to_host( ctx, result_addr, 32UL, 1UL );
  if( FD_UNLIKELY( !hash_result ) ) return FD_VM_ERR_ACC_VIO;

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1760-L1766 */

  /* TODO check vals_len for overflow */

  ulong               slices_sz = vals_len * sizeof(fd_vm_vec_t);
  fd_vm_vec_t const * slices =
      fd_vm_translate_vm_to_host_const( ctx, vals_addr, slices_sz, FD_VM_VEC_ALIGN );
  if( FD_UNLIKELY( !slices ) ) return FD_VM_ERR_ACC_VIO;

  /* At this point, Solana Labs allocates a vector of translated slices.
     Ideally, we'd do this in O(1) allocs by doing incremental hashing
     and translating as we go (see sha256 syscall).  However, the
     poseidon API in ballet doesn't support incremental hashing yet.

     TODO Implement! */

  FD_LOG_WARNING(( "Poseidon input parsing not yet implemented" ));

  return FD_VM_SYSCALL_ERR_INVAL;
}
