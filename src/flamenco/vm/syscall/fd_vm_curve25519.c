#include "fd_vm_curve25519.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/ed25519/fd_ristretto255.h"

ulong
fd_vm_syscall_sol_curve_validate_point(
    void *  _ctx,
    ulong   curve_id,
    ulong   point_addr,
    ulong   r3 FD_PARAM_UNUSED,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pret
) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong ret;
  switch( curve_id ) {
  case FD_FLAMENCO_CURVE_25519_EDWARDS: {
    /* TODO consume CU
       https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L967  */

    uchar const * point = fd_vm_translate_vm_to_host_const( ctx, point_addr, 32UL, 1UL );
    if( FD_UNLIKELY( !point ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    ret = !!fd_ed25519_validate_public_key( point );  /* 1 if ok, 0 if not */
    break;
  }
  case FD_FLAMENCO_CURVE_25519_RISTRETTO: {
    /* TODO consume CU
       https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L985 */

    uchar const * point = fd_vm_translate_vm_to_host_const( ctx, point_addr, 32UL, 1UL );
    if( FD_UNLIKELY( !point ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    ret = !!fd_ristretto255_validate_point( point );  /* 1 if ok, 0 if not */
    break;
  }
  default:
    ret = 1UL;
    return FD_VM_SYSCALL_SUCCESS;
  }
  *pret = ret;
  return FD_VM_SYSCALL_SUCCESS;
}

