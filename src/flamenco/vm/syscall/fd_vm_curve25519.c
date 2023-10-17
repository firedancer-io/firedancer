#include "fd_vm_curve25519.h"
#include "../../../ballet/ed25519/fd_ed25519_ge.h"
#include "../../../ballet/ed25519/fd_ristretto255_ge.h"

/* pointer constraints for input parameters */

#define POINT_SZ     (32UL)
#define POINT_ALIGN  ( 1UL)
#define SCALAR_SZ    (32UL)
#define SCALAR_ALIGN ( 1UL)

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

  ulong ret = 1UL;
  switch( curve_id ) {
  case FD_FLAMENCO_ECC_ED25519: {
    /* TODO consume CU
       https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L967  */

    uchar const * point = fd_vm_translate_vm_to_host_const( ctx, point_addr, POINT_SZ, POINT_ALIGN );
    if( FD_UNLIKELY( !point ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    ret = !!fd_ed25519_point_validate( point );  /* 1 if ok, 0 if not */
    break;
  }
  case FD_FLAMENCO_ECC_RISTRETTO255: {
    /* TODO consume CU
       https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L985 */

    uchar const * point = fd_vm_translate_vm_to_host_const( ctx, point_addr, POINT_SZ, POINT_ALIGN );
    if( FD_UNLIKELY( !point ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    ret = !!fd_ristretto255_point_validate( point );  /* 1 if ok, 0 if not */
    break;
  }
  default:
    break;
  }
  *pret = ret;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_curve_group_op(
    void *  _ctx,
    ulong   curve_id,
    ulong   group_op,
    ulong   in0_addr,
    ulong   in1_addr,
    ulong   out_addr,
    ulong * pret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong ret = 1UL;

  switch( curve_id ) {
  case FD_FLAMENCO_ECC_ED25519: {
    switch( group_op ) {
    case FD_FLAMENCO_ECC_G_ADD: {
      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1027 */

      uchar const * p0c = fd_vm_translate_vm_to_host_const( ctx, in0_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p0c ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
      uchar const * p1c = fd_vm_translate_vm_to_host_const( ctx, in1_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p1c ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

      fd_ed25519_point_t p0[1];
      fd_ed25519_point_t p1[1];
      int p0v = !!fd_ed25519_point_decompress( p0, p0c );
      int p1v = !!fd_ed25519_point_decompress( p0, p1c );

      if( FD_LIKELY( p0v && p1v ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( ctx, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

        fd_ed25519_point_t h[1];
        fd_ed25519_point_add( h, p0, p1 );
        fd_ed25519_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }
    case FD_FLAMENCO_ECC_G_SUB: {
      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1027 */

      uchar const * p0c = fd_vm_translate_vm_to_host_const( ctx, in0_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p0c ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
      uchar const * p1c = fd_vm_translate_vm_to_host_const( ctx, in1_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p1c ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

      fd_ed25519_point_t p0[1];
      fd_ed25519_point_t p1[1];
      int p0v = !!fd_ed25519_point_decompress( p0, p0c );
      int p1v = !!fd_ed25519_point_decompress( p0, p1c );

      if( FD_LIKELY( p0v && p1v ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( ctx, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

        fd_ed25519_point_t h[1];
        fd_ed25519_point_sub( h, p0, p1 );
        fd_ed25519_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }
    case FD_FLAMENCO_ECC_G_MUL: {
      FD_LOG_WARNING(( "TODO: ED25519 G_MUL" ));
      break;
    }
    }
    break;
  }
  case FD_FLAMENCO_ECC_RISTRETTO255: {
    switch( group_op ) {
    case FD_FLAMENCO_ECC_G_ADD: {
      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1115 */

      uchar const * p0c = fd_vm_translate_vm_to_host_const( ctx, in0_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p0c ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
      uchar const * p1c = fd_vm_translate_vm_to_host_const( ctx, in1_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p1c ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

      fd_ristretto255_point_t p0[1];
      fd_ristretto255_point_t p1[1];
      int p0v = !!fd_ristretto255_point_decompress( p0, p0c );
      int p1v = !!fd_ristretto255_point_decompress( p0, p1c );

      if( FD_LIKELY( p0v && p1v ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( ctx, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

        fd_ristretto255_point_t h[1];
        fd_ristretto255_point_add( h, p0, p1 );
        fd_ristretto255_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }
    case FD_FLAMENCO_ECC_G_SUB: {
      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1027 */

      uchar const * p0c = fd_vm_translate_vm_to_host_const( ctx, in0_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p0c ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
      uchar const * p1c = fd_vm_translate_vm_to_host_const( ctx, in1_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p1c ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

      fd_ristretto255_point_t p0[1];
      fd_ristretto255_point_t p1[1];
      int p0v = !!fd_ristretto255_point_decompress( p0, p0c );
      int p1v = !!fd_ristretto255_point_decompress( p0, p1c );

      if( FD_LIKELY( p0v && p1v ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( ctx, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

        fd_ristretto255_point_t h[1];
        fd_ristretto255_point_sub( h, p0, p1 );
        fd_ristretto255_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }
    case FD_FLAMENCO_ECC_G_MUL: {
      FD_LOG_WARNING(( "TODO: RISTRETTO255 G_MUL" ));
      break;
    }
    }
    break;
  }
  default:
    break;
  }

  *pret = ret;
  return FD_VM_SYSCALL_SUCCESS;
}
