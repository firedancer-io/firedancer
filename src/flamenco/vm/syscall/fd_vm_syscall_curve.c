#include "fd_vm_syscall.h"

#include "../../../ballet/ed25519/fd_ristretto255_ge.h"

/* pointer constraints for input parameters */
/* FIXME: PREFIX */

#define POINT_ALIGN   ( 1UL)
#define POINT_SZ      (32UL)
#define SCALAR_ALIGN  ( 1UL)
#define SCALAR_SZ     (32UL)

int
fd_vm_syscall_sol_curve_validate_point( /**/            void *  _vm,
                                        /**/            ulong   curve_id,
                                        /**/            ulong   point_addr,
                                        FD_PARAM_UNUSED ulong   arg2,
                                        FD_PARAM_UNUSED ulong   arg3,
                                        FD_PARAM_UNUSED ulong   arg4,
                                        /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  switch( curve_id ) {

  case FD_VM_SYSCALL_SOL_CURVE_ECC_ED25519: {

    /* TODO consume CU
       https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L967  */

    uchar const * point = fd_vm_translate_vm_to_host_const( vm, point_addr, POINT_SZ, POINT_ALIGN );
    if( FD_UNLIKELY( !point ) ) return FD_VM_ERR_PERM;

    *_ret = (ulong)!!fd_ed25519_point_validate( point );  /* 1 if ok, 0 if not */
    return FD_VM_SUCCESS;
  }

  case FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255: {

    /* TODO consume CU
       https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L985 */

    uchar const * point = fd_vm_translate_vm_to_host_const( vm, point_addr, POINT_SZ, POINT_ALIGN );
    if( FD_UNLIKELY( !point ) ) return FD_VM_ERR_PERM;

    *_ret = (ulong)!!fd_ristretto255_point_validate( point );  /* 1 if ok, 0 if not */
    return FD_VM_SUCCESS;
  }

  default:
    break;
  }

  *_ret = 1UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_curve_group_op( void *  _vm,
                                  ulong   curve_id,
                                  ulong   group_op,
                                  ulong   in0_addr,
                                  ulong   in1_addr,
                                  ulong   out_addr,
                                  ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* FIXME: consider flattening into a single switch */
  /* FIXME: do the out_addr translateion need to be after the expensive
     point decompresses? */

  ulong ret = 1UL;

  switch( curve_id ) {

  case FD_VM_SYSCALL_SOL_CURVE_ECC_ED25519: {

    switch( group_op ) {

    case FD_VM_SYSCALL_SOL_CURVE_ECC_G_ADD: {

      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1027 */

      uchar const * p0c = fd_vm_translate_vm_to_host_const( vm, in0_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p0c ) ) return FD_VM_ERR_PERM;

      uchar const * p1c = fd_vm_translate_vm_to_host_const( vm, in1_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p1c ) ) return FD_VM_ERR_PERM;

      fd_ed25519_point_t p0[1];
      fd_ed25519_point_t p1[1];
      int p0v = !!fd_ed25519_point_decompress( p0, p0c );
      int p1v = !!fd_ed25519_point_decompress( p1, p1c );

      if( FD_LIKELY( p0v & p1v ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( vm, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_ERR_PERM;

        fd_ed25519_point_t h[1];
        fd_ed25519_point_add( h, p0, p1 );
        fd_ed25519_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }

    case FD_VM_SYSCALL_SOL_CURVE_ECC_G_SUB: {

      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1055 */

      uchar const * p0c = fd_vm_translate_vm_to_host_const( vm, in0_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p0c ) ) return FD_VM_ERR_PERM;

      uchar const * p1c = fd_vm_translate_vm_to_host_const( vm, in1_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p1c ) ) return FD_VM_ERR_PERM;

      fd_ed25519_point_t p0[1];
      fd_ed25519_point_t p1[1];
      int p0v = !!fd_ed25519_point_decompress( p0, p0c );
      int p1v = !!fd_ed25519_point_decompress( p1, p1c );

      if( FD_LIKELY( p0v & p1v ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( vm, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_ERR_PERM;

        fd_ed25519_point_t h[1];
        fd_ed25519_point_sub( h, p0, p1 );
        fd_ed25519_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }

    case FD_VM_SYSCALL_SOL_CURVE_ECC_G_MUL: {

      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1083 */

      uchar const * s  = fd_vm_translate_vm_to_host_const( vm, in0_addr, SCALAR_SZ, SCALAR_ALIGN );
      if( FD_UNLIKELY( !s  ) ) return FD_VM_ERR_PERM;

      uchar const * pc = fd_vm_translate_vm_to_host_const( vm, in1_addr, POINT_SZ,  POINT_ALIGN  );
      if( FD_UNLIKELY( !pc ) ) return FD_VM_ERR_PERM;

      fd_ed25519_point_t p[1];
      int pv = !!fd_ed25519_point_decompress( p, pc );
      int sv = !!fd_ed25519_scalar_validate ( s );

      if( FD_LIKELY( pv & sv ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( vm, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_ERR_PERM;

        fd_ed25519_point_t h[1];
        fd_ed25519_point_scalarmult( h, s, p );
        fd_ed25519_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }

    default: break; /* Unknown curve op */
    }
    break;
  }

  case FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255: {

    switch( group_op ) {

    case FD_VM_SYSCALL_SOL_CURVE_ECC_G_ADD: {

      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1115 */

      uchar const * p0c = fd_vm_translate_vm_to_host_const( vm, in0_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p0c ) ) return FD_VM_ERR_PERM;

      uchar const * p1c = fd_vm_translate_vm_to_host_const( vm, in1_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p1c ) ) return FD_VM_ERR_PERM;

      fd_ristretto255_point_t p0[1];
      fd_ristretto255_point_t p1[1];
      int p0v = !!fd_ristretto255_point_decompress( p0, p0c );
      int p1v = !!fd_ristretto255_point_decompress( p1, p1c );

      if( FD_LIKELY( p0v && p1v ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( vm, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_ERR_PERM;

        fd_ristretto255_point_t h[1];
        fd_ristretto255_point_add( h, p0, p1 );
        fd_ristretto255_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }

    case FD_VM_SYSCALL_SOL_CURVE_ECC_G_SUB: {

      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1143 */

      uchar const * p0c = fd_vm_translate_vm_to_host_const( vm, in0_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p0c ) ) return FD_VM_ERR_PERM;

      uchar const * p1c = fd_vm_translate_vm_to_host_const( vm, in1_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !p1c ) ) return FD_VM_ERR_PERM;

      fd_ristretto255_point_t p0[1];
      fd_ristretto255_point_t p1[1];
      int p0v = !!fd_ristretto255_point_decompress( p0, p0c );
      int p1v = !!fd_ristretto255_point_decompress( p1, p1c );

      if( FD_LIKELY( p0v && p1v ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( vm, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_ERR_PERM;

        fd_ristretto255_point_t h[1];
        fd_ristretto255_point_sub( h, p0, p1 );
        fd_ristretto255_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }

    case FD_VM_SYSCALL_SOL_CURVE_ECC_G_MUL: {

      /* TODO consume CU
         https://github.com/solana-labs/solana/blob/c0fbfc6422fa5b739049c01bfda48a0da1bf6a46/programs/bpf_loader/src/syscalls/mod.rs#L1173 */

      uchar const * s  = fd_vm_translate_vm_to_host_const( vm, in0_addr, SCALAR_SZ, SCALAR_ALIGN );
      if( FD_UNLIKELY( !s  ) ) return FD_VM_ERR_PERM;

      uchar const * pc = fd_vm_translate_vm_to_host_const( vm, in1_addr, POINT_SZ,  POINT_ALIGN  );
      if( FD_UNLIKELY( !pc ) ) return FD_VM_ERR_PERM;

      fd_ristretto255_point_t p[1];
      int pv = !!fd_ristretto255_point_decompress( p, pc );
      int sv = !!fd_ristretto255_scalar_validate ( s );

      if( FD_LIKELY( pv && sv ) ) {
        uchar * hc = fd_vm_translate_vm_to_host( vm, out_addr, POINT_SZ, POINT_ALIGN );
        if( FD_UNLIKELY( !hc ) ) return FD_VM_ERR_PERM;

        fd_ristretto255_point_t h[1];
        fd_ristretto255_point_scalarmult( h, s, p );
        fd_ristretto255_point_compress( hc, h );
        ret = 0UL;
      }
      break;
    }

    default: break; /* unknown curve op */
    }
    break;
  }

  default: break; /* unknown curve */
  }

  *_ret = ret;
  return FD_VM_SUCCESS;
}

/* multiscalar_multiply_edwards computes a MSM on curve25519.

   This function is equivalent to
   zk-token-sdk::edwards::multiscalar_multiply_edwards

   https://github.com/solana-labs/solana/blob/v1.17.7/zk-token-sdk/src/curve25519/edwards.rs#L116

   Specifically it takes as input byte arrays and takes care of scalars
   validation and points decompression.  It then invokes ballet MSM
   function fd_ed25519_multiscalar_mul.  To avoid dynamic allocation,
   the full MSM is done in batches of MSM_BATCH_SZ. */

/* FIXME: WHY RETURN VOID * AND NOT POINT? */

#define BATCH_MAX (16UL) /* FIXME: CONSIDER LARGER BATCH CNT (low hundreds to a low thousands is quite reasonable here 128?) */

static void *
multiscalar_multiply_edwards( fd_ed25519_point_t * r,
                              uchar const *        a,
                              uchar const *        pc,
                              ulong                cnt ) {
  fd_ed25519_point_0( r );

  for( ulong i=0UL; i<cnt; i+=BATCH_MAX ) {
    ulong batch_cnt = fd_ulong_min( cnt-i, BATCH_MAX );

    fd_ed25519_point_t A[ BATCH_MAX ];
    for( ulong j=0UL; j<batch_cnt; j++ ) {
      /* FIXME: IS THIS ORDER OPTIMAL (E.G. ONE OR THE OTHER IS A LOT
         CHEAPER, DO THAT WHOLE BATCH FIRST) */
      if( FD_UNLIKELY( !fd_ed25519_point_decompress( &A[j], pc + j* POINT_SZ ) ) ) return NULL;
      if( FD_UNLIKELY( !fd_ed25519_scalar_validate ( a         + j*SCALAR_SZ ) ) ) return NULL;
    }

    fd_ed25519_point_t h[1];
    fd_ed25519_multiscalar_mul( h, a, A, batch_cnt );
    fd_ed25519_point_add( r, r, h );
    pc +=  POINT_SZ*batch_cnt;
    a  += SCALAR_SZ*batch_cnt;
  }

  return r;
}

/* multiscalar_multiply_ristretto computes a MSM on ristretto255.
   See multiscalar_multiply_edwards for details. */
/* FIXME: SAME AS EDWARDS */

static void *
multiscalar_multiply_ristretto( fd_ristretto255_point_t * r,
                                uchar const *             a,
                                uchar const *             pc,
                                ulong                     cnt ) {
  fd_ristretto255_point_0( r );

  for( ulong i=0UL; i<cnt; i+=BATCH_MAX ) {
    ulong batch_cnt = fd_ulong_min( cnt-i, BATCH_MAX );

    fd_ristretto255_point_t A[ BATCH_MAX ];
    for( ulong j=0UL; j<batch_cnt; j++ ) {
      if( FD_UNLIKELY( !fd_ristretto255_point_decompress( &A[j], pc + j* POINT_SZ ) ) ) return NULL;
      if( FD_UNLIKELY( !fd_ristretto255_scalar_validate ( a         + j*SCALAR_SZ ) ) ) return NULL;
    }

    fd_ristretto255_point_t h[1];
    fd_ristretto255_multiscalar_mul( h, a, A, batch_cnt );
    fd_ristretto255_point_add( r, r, h );

    pc +=  POINT_SZ*batch_cnt;
    a  += SCALAR_SZ*batch_cnt;
  }

  return r;
}

#undef BATCH_MAX

int
fd_vm_syscall_sol_curve_multiscalar_mul( void *  _vm,
                                         ulong   curve_id,
                                         ulong   scalar_addr,
                                         ulong   point_addr,
                                         ulong   point_cnt,
                                         ulong   result_point_addr,
                                         ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  ulong ret = 1UL;

  // TODO limit on point_cnt

  ulong scalar_list_sz = fd_ulong_sat_mul( point_cnt, SCALAR_SZ );
  ulong  point_list_sz = fd_ulong_sat_mul( point_cnt, POINT_SZ  );

  switch( curve_id ) {

  case FD_VM_SYSCALL_SOL_CURVE_ECC_ED25519: {

    /* TODO consume CU
       https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/bpf_loader/src/syscalls/mod.rs#L1233 */

    uchar const * s  = fd_vm_translate_vm_to_host_const( vm, scalar_addr, scalar_list_sz, SCALAR_ALIGN );
    if( FD_UNLIKELY( !s  ) ) return FD_VM_ERR_PERM;

    uchar const * pc = fd_vm_translate_vm_to_host_const( vm, point_addr,  point_list_sz,  POINT_ALIGN  );
    if( FD_UNLIKELY( !pc ) ) return FD_VM_ERR_PERM;

    fd_ed25519_point_t _r[1];
    fd_ed25519_point_t * r = multiscalar_multiply_edwards( _r, s, pc, point_cnt );

    if( FD_LIKELY( r ) ) {
      uchar * rc = fd_vm_translate_vm_to_host( vm, result_point_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !rc ) ) return FD_VM_ERR_PERM;

      fd_ed25519_point_compress( rc, r );
      ret = 0UL;
    }
    break;
  }

  case FD_VM_SYSCALL_SOL_CURVE_ECC_RISTRETTO255: {

    /* TODO consume CU
       https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/bpf_loader/src/syscalls/mod.rs#L1273 */

    uchar const * s  = fd_vm_translate_vm_to_host_const( vm, scalar_addr, scalar_list_sz, SCALAR_ALIGN );
    if( FD_UNLIKELY( !s  ) ) return FD_VM_ERR_PERM;

    uchar const * pc = fd_vm_translate_vm_to_host_const( vm, point_addr,  point_list_sz,  POINT_ALIGN  );
    if( FD_UNLIKELY( !pc ) ) return FD_VM_ERR_PERM;

    fd_ristretto255_point_t _r[1];
    fd_ristretto255_point_t * r = multiscalar_multiply_ristretto( _r, s, pc, point_cnt );
    if( FD_LIKELY( r ) ) {
      uchar * rc = fd_vm_translate_vm_to_host( vm, result_point_addr, POINT_SZ, POINT_ALIGN );
      if( FD_UNLIKELY( !rc ) ) return FD_VM_ERR_PERM;

      fd_ristretto255_point_compress( rc, r );
      ret = 0UL;
    }
    break;
  }

  default: /* unknown curve */
    break;
  }

  *_ret = ret;
  return FD_VM_SUCCESS;
}
