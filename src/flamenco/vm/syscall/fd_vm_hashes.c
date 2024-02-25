#include "fd_vm_hashes.h"

#include "../../../ballet/keccak256/fd_keccak256.h"

int
fd_vm_syscall_sol_sha256( /**/            void *  _ctx,
                          /**/            ulong   slices_vaddr,
                          /**/            ulong   slices_cnt,
                          /**/            ulong   res_vaddr,
                          FD_PARAM_UNUSED ulong   arg3,
                          FD_PARAM_UNUSED ulong   arg4,
                          /**/            ulong * _ret ) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) ) return FD_VM_SYSCALL_ERR_INVAL;

  int err = fd_vm_consume_compute( ctx, vm_compute_budget.sha256_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices = fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );
  void *              hash   = fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!slices) | (!hash) ) ) return FD_VM_ERR_ACC_VIO;

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  for( ulong i = 0; i < slices_cnt; i++ ) {
    uchar const * slice = fd_vm_translate_vm_to_host_const( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
    if( FD_UNLIKELY( !slice ) ) return FD_VM_ERR_ACC_VIO;

    ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len) / 2);
    int err = fd_vm_consume_compute( ctx, cost );
    if( FD_UNLIKELY( err ) ) return err;

    fd_sha256_append( &sha, slice, slices[i].len );
  }

  fd_sha256_fini( &sha, hash );
  *_ret = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

int
fd_vm_syscall_sol_keccak256( /**/            void *  _ctx,
                             /**/            ulong   slices_vaddr,
                             /**/            ulong   slices_cnt,
                             /**/            ulong   res_vaddr,
                             FD_PARAM_UNUSED ulong   arg3,
                             FD_PARAM_UNUSED ulong   arg4,
                             /**/            ulong * _ret ) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) )
    return FD_VM_SYSCALL_ERR_INVAL;

  int err = fd_vm_consume_compute( ctx, vm_compute_budget.sha256_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  void * hash = fd_vm_translate_vm_to_host( ctx, res_vaddr, 32UL, alignof(uchar) );
  if( FD_UNLIKELY( !hash ) ) return FD_VM_ERR_ACC_VIO;

  fd_keccak256_t sha;
  fd_keccak256_init(&sha);

  if ( FD_LIKELY( slices_cnt > 0 ) ) {
    ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

    fd_vm_vec_t const * slices =
        fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );

    if( FD_UNLIKELY( (!slices) ) ) {
      return FD_VM_ERR_ACC_VIO;
    }

    for (ulong i = 0; i < slices_cnt; i++) {
      void const * slice = fd_vm_translate_vm_to_host_const( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
      if( FD_UNLIKELY( !slice ) ) {
        FD_LOG_DEBUG(("Translate slice failed %lu %lu %lu", i, slices[i].addr, slices[i].len));
        return FD_VM_ERR_ACC_VIO;
      }

      ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len / 2));
      int err = fd_vm_consume_compute( ctx, cost );
      if( FD_UNLIKELY( err ) ) return err;

      fd_keccak256_append( &sha, slice, slices[i].len );
    }
  }

  fd_keccak256_fini(&sha, hash);
  *_ret = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

int
fd_vm_syscall_sol_blake3( /**/            void *  _ctx,
                          /**/            ulong   slices_vaddr,
                          /**/            ulong   slices_cnt,
                          /**/            ulong   res_vaddr,
                          FD_PARAM_UNUSED ulong   arg3,
                          FD_PARAM_UNUSED ulong   arg4,
                          /**/            ulong * _ret ) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  /* TODO don't hardcode limit */
  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) )
    return FD_VM_SYSCALL_ERR_INVAL;

  int err = fd_vm_consume_compute( ctx, vm_compute_budget.sha256_base_cost );
  if( FD_UNLIKELY( err ) ) return err;
  ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices =
      fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );
  void * hash =
      fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!slices) | (!hash) ) ) return FD_VM_ERR_ACC_VIO;

  fd_blake3_t b3;
  fd_blake3_init(&b3);

  for (ulong i = 0; i < slices_cnt; i++) {
    void const * slice = fd_vm_translate_vm_to_host( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
    if( FD_UNLIKELY( !slice ) ) return FD_VM_ERR_ACC_VIO;

    ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len) / 2);
    int err = fd_vm_consume_compute( ctx, cost );
    if( FD_UNLIKELY( err ) ) return err;

    fd_blake3_append( &b3, slice, slices[i].len );
  }

  fd_blake3_fini( &b3, hash );
  *_ret = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}
