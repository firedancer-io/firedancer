#include "fd_vm_secp256k1.h"

#if !FD_HAS_SECP256K1
ulong
fd_vm_syscall_sol_secp256k1_recover(
  FD_PARAM_UNUSED void * _ctx,
  FD_PARAM_UNUSED ulong hash_vaddr,
  FD_PARAM_UNUSED ulong recovery_id_val,
  FD_PARAM_UNUSED ulong signature_vaddr,
  FD_PARAM_UNUSED ulong result_vaddr,
  FD_PARAM_UNUSED ulong arg4 FD_PARAM_UNUSED,
  FD_PARAM_UNUSED ulong * pr0
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}
#else

#include "../../../ballet/secp256k1/fd_secp256k1.h"

ulong
fd_vm_syscall_sol_secp256k1_recover(
    void * _ctx,
    ulong hash_vaddr,
    ulong recovery_id_val,
    ulong signature_vaddr,
    ulong result_vaddr,
    ulong arg4 FD_PARAM_UNUSED,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.secp256k1_recover_cost);
  if ( FD_UNLIKELY( err ) ) return err;

  void const * hash = fd_vm_translate_vm_to_host_const(
    ctx,
    hash_vaddr,
    sizeof(fd_hash_t),
    alignof(uchar) );
  if( FD_UNLIKELY( !hash ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void const * signature = fd_vm_translate_vm_to_host_const(
    ctx,
    signature_vaddr,
    64,
    alignof(uchar) );
  if( FD_UNLIKELY( !hash ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void * pubkey_result = fd_vm_translate_vm_to_host(
    ctx,
    result_vaddr,
    64,
    alignof(uchar) );
  if( FD_UNLIKELY( !pubkey_result ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  if( recovery_id_val > 4 ) {
    *pr0 = 1; // Secp256k1RecoverError::InvalidRecoveryId
    return FD_VM_SYSCALL_SUCCESS;
  }

  uchar secp256k1_pubkey[64];
  if( !fd_secp256k1_recover(secp256k1_pubkey, hash, signature, (int)recovery_id_val) ) {
    *pr0 = 2; // Secp256k1RecoverError::InvalidSignature
    return FD_VM_SYSCALL_SUCCESS;
  }

  fd_memcpy(pubkey_result, secp256k1_pubkey, 64);
  *pr0 = 0;

  return FD_VM_SYSCALL_SUCCESS;
}

#endif
