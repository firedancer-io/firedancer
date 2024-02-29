#include "fd_vm_syscall.h"

#include "../../../ballet/keccak256/fd_keccak256.h"
#include "../../../ballet/ed25519/fd_ristretto255_ge.h"
#if FD_HAS_SECP256K1
#include "../../../ballet/secp256k1/fd_secp256k1.h"
#endif

int
fd_vm_syscall_sol_alt_bn128_group_op( FD_PARAM_UNUSED void *  _vm,
                                      FD_PARAM_UNUSED ulong   params,
                                      FD_PARAM_UNUSED ulong   endianness,
                                      FD_PARAM_UNUSED ulong   vals_addr,
                                      FD_PARAM_UNUSED ulong   vals_len,
                                      FD_PARAM_UNUSED ulong   result_addr,
                                      FD_PARAM_UNUSED ulong * _ret ) {
  return FD_VM_ERR_INVAL; /* FIXME: UNSUP? */
}

int
fd_vm_syscall_sol_alt_bn128_compression( FD_PARAM_UNUSED void *  _vm,
                                         FD_PARAM_UNUSED ulong   params,
                                         FD_PARAM_UNUSED ulong   endianness,
                                         FD_PARAM_UNUSED ulong   vals_addr,
                                         FD_PARAM_UNUSED ulong   vals_len,
                                         FD_PARAM_UNUSED ulong   result_addr,
                                         FD_PARAM_UNUSED ulong * _ret ) {
  return FD_VM_ERR_INVAL; /* FIXME: UNSUP? */
}

int
fd_vm_syscall_sol_blake3( /**/            void *  _vm,
                          /**/            ulong   slice_vaddr,
                          /**/            ulong   slice_cnt,
                          /**/            ulong   hash_vaddr,
                          FD_PARAM_UNUSED ulong   arg3,
                          FD_PARAM_UNUSED ulong   arg4,
                          /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* Note: Solana uses the sha256 cost model currently for blake3.
     FIXME: PROVIDE LINK TO SOLANA CODE HERE */

  /* TODO don't hardcode limit */
  if( FD_UNLIKELY( slice_cnt>vm_compute_budget.sha256_max_slices ) ) return FD_VM_ERR_INVAL;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.sha256_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  ulong slice_sz = slice_cnt*sizeof(fd_vm_vec_t); /* Note: assumes sha256_max_slices <= ULONG_MAX/sizeof(fd_vm_vec_t) */

  /* FIXME: ONLY XLAT SLICE_HADDR IF SLICE_CNT!=0 (SEE KECCAK256)? */
  fd_vm_vec_t const * slice_haddr = fd_vm_translate_vm_to_host_const( vm, slice_vaddr, slice_sz, FD_VM_VEC_ALIGN );
  void *              hash_haddr  = fd_vm_translate_vm_to_host      ( vm, hash_vaddr,  32UL,      alignof(uchar) );
  if( FD_UNLIKELY( (!slice_haddr) | (!hash_haddr) ) ) return FD_VM_ERR_PERM;

  /* FIXME: CONSIDERING CONSUMING COMPUTE AND TESTING TRANSLATION BEFORE
     DOING ANY WORK TO MINIMIZE HOST COST ON FAILED CASES? */

  fd_blake3_t blake[1];
  fd_blake3_init( blake );

  for( ulong i=0UL; i<slice_cnt; i++ ) {
    ulong        mem_sz    = slice_haddr[i].len;
    void const * mem_haddr = fd_vm_translate_vm_to_host( vm, slice_haddr[i].addr, mem_sz, alignof(uchar) );
    if( FD_UNLIKELY( !mem_haddr ) ) return FD_VM_ERR_PERM;

    /* FIXME: WHERE DOES THE / 2UL GO? (SEE OTHER EXAMPLES) */
    ulong cost = fd_ulong_max( vm_compute_budget.mem_op_base_cost,
                               fd_ulong_sat_mul( vm_compute_budget.sha256_byte_cost, mem_sz ) / 2UL );
    int err = fd_vm_consume_compute( vm, cost );
    if( FD_UNLIKELY( err ) ) return err;

    fd_blake3_append( blake, mem_haddr, mem_sz );
  }

  fd_blake3_fini( blake, hash_haddr );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_keccak256( /**/            void *  _vm,
                             /**/            ulong   slice_vaddr,
                             /**/            ulong   slice_cnt,
                             /**/            ulong   res_vaddr,
                             FD_PARAM_UNUSED ulong   arg3,
                             FD_PARAM_UNUSED ulong   arg4,
                             /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* Note: Solana uses the sha256 cost model currently for blake3.
     FIXME: PROVIDE LINK TO SOLANA CODE HERE */

  /* FIXME: BLAKE3 HAS NOTE THAT SLICE_CNT SHOULDN'T BE HARDCODED */
  if( FD_UNLIKELY( slice_cnt > vm_compute_budget.sha256_max_slices ) ) return FD_VM_ERR_INVAL;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.sha256_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  void * hash_haddr = fd_vm_translate_vm_to_host( vm, res_vaddr, 32UL, alignof(uchar) );
  if( FD_UNLIKELY( !hash_haddr ) ) return FD_VM_ERR_PERM;

  /* FIXME: CONSIDERING CONSUMING COMPUTE AND TESTING TRANSLATION BEFORE
     DOING ANY WORK TO MINIMIZE HOST COST ON FAILED CASES? */

  fd_keccak256_t keccak[1];
  fd_keccak256_init( keccak );

  if( FD_LIKELY( slice_cnt ) ) {
    ulong slice_sz = slice_cnt*sizeof(fd_vm_vec_t); /* Note: assumes sha256_max_slices <= ULONG_MAX/sizeof(fd_vm_vec_t) */

    fd_vm_vec_t const * slice_haddr = fd_vm_translate_vm_to_host_const( vm, slice_vaddr, slice_sz, FD_VM_VEC_ALIGN );
    if( FD_UNLIKELY( !slice_haddr ) ) return FD_VM_ERR_PERM;

    for( ulong i=0UL; i<slice_cnt; i++ ) {
      ulong        mem_sz    = slice_haddr[i].len;
      void const * mem_haddr = fd_vm_translate_vm_to_host_const( vm, slice_haddr[i].addr, mem_sz, alignof(uchar) );
      if( FD_UNLIKELY( !mem_haddr ) ) return FD_VM_ERR_PERM;

      /* FIXME: WHERE DOES THE / 2UL GO? (SEE OTHER EXAMPLES) (THIS IS PROBABLY WRONG?) */
      ulong cost = fd_ulong_max( vm_compute_budget.mem_op_base_cost,
                                 fd_ulong_sat_mul( vm_compute_budget.sha256_byte_cost, mem_sz / 2UL ) );
      int err = fd_vm_consume_compute( vm, cost );
      if( FD_UNLIKELY( err ) ) return err;

      fd_keccak256_append( keccak, mem_haddr, mem_sz );
    }
  }

  fd_keccak256_fini( keccak, hash_haddr );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_sha256( /**/            void *  _vm,
                          /**/            ulong   slice_vaddr,
                          /**/            ulong   slice_cnt,
                          /**/            ulong   hash_vaddr,
                          FD_PARAM_UNUSED ulong   arg3,
                          FD_PARAM_UNUSED ulong   arg4,
                          /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  /* Note: Solana uses the sha256 cost model currently for blake3.
     FIXME: PROVIDE LINK TO SOLANA CODE HERE */

  /* FIXME: NOTE BLAKE3 HAS NOTE ABOUT NOT HARDCODED? */
  if( FD_UNLIKELY( slice_cnt > vm_compute_budget.sha256_max_slices ) ) return FD_VM_ERR_INVAL;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.sha256_base_cost );
  if( FD_UNLIKELY( err ) ) return err;

  ulong slice_sz = slice_cnt*sizeof(fd_vm_vec_t); /* Note: assumes sha256_max_slices <= ULONG_MAX/sizeof(fd_vm_vec_t) */

  /* FIXME: ONLY XLAT SLICE_HADDR IF SLICE_CNT!=0 (SEE KECCAK256)? */
  fd_vm_vec_t const * slice_haddr = fd_vm_translate_vm_to_host_const( vm, slice_vaddr, slice_sz, FD_VM_VEC_ALIGN );
  void *              hash_haddr  = fd_vm_translate_vm_to_host      ( vm, hash_vaddr,   32UL,      alignof(uchar)  );
  if( FD_UNLIKELY( (!slice_haddr) | (!hash_haddr) ) ) return FD_VM_ERR_PERM;

  /* FIXME: CONSIDERING CONSUMING COMPUTE AND TESTING TRANSLATION BEFORE
     DOING ANY WORK TO MINIMIZE HOST COST ON FAILED CASES? */

  fd_sha256_t sha[1];
  fd_sha256_init( sha );

  for( ulong i=0UL; i<slice_cnt; i++ ) {
    ulong         mem_sz    = slice_haddr[i].len;
    uchar const * mem_haddr = fd_vm_translate_vm_to_host_const( vm, slice_haddr[i].addr, slice_sz, alignof(uchar) );
    if( FD_UNLIKELY( !mem_haddr ) ) return FD_VM_ERR_PERM;

    /* FIXME: WHERE DOES THE / 2UL GO? (SEE OTHER EXAMPLES) */
    ulong cost = fd_ulong_max( vm_compute_budget.mem_op_base_cost,
                               fd_ulong_sat_mul( vm_compute_budget.sha256_byte_cost, mem_sz ) / 2UL );
    int err = fd_vm_consume_compute( vm, cost );
    if( FD_UNLIKELY( err ) ) return err;

    fd_sha256_append( sha, mem_haddr, mem_sz );
  }

  fd_sha256_fini( sha, hash_haddr );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

static inline int
fd_vm_syscall_sol_poseidon_cost( ulong   input_cnt,
                                 ulong   cost_coefficient,
                                 ulong * _cost_out ) {
  ulong input_sq;
  ulong mul_result;
  /* FIXME: USE FD_SAT? */
  if( FD_UNLIKELY( __builtin_umull_overflow( input_cnt,        input_cnt, &input_sq   ) ) ) return 0;
  if( FD_UNLIKELY( __builtin_umull_overflow( cost_coefficient, input_sq,  &mul_result ) ) ) return 0;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( mul_result,       input_cnt, _cost_out   ) ) ) return 0;
  return 1;
}

int
fd_vm_syscall_sol_poseidon( void *  _vm,
                            ulong   params,
                            ulong   endianness,
                            ulong   vals_addr,
                            ulong   vals_len,
                            ulong   result_addr,
                            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  *_ret = 0UL;

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1731 */

  if( FD_UNLIKELY( params!=0UL ) ) {
    /* TODO What is the implicit conversion form PoseidonSyscallError to SyscallError? */
    *_ret = 1UL;  /* PoseidonSyscallError::InvalidParameters */
    return FD_VM_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1732 */

  switch( endianness ) {
  case 0UL:
  case 1UL:
    break;

  default:
    /* TODO What is the implicit conversion form PoseidonSyscallError to SyscallError? */
    *_ret = 2UL;  /* PoseidonSyscallError::InvalidEndianness */
    return FD_VM_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1734-L1741 */

  if( FD_UNLIKELY( vals_len > 12UL ) ) {
    /* TODO Log: "Poseidon hashing {} sequences is not supported" */
    return FD_VM_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1743-L1750 */

  ulong cost;
  if( FD_UNLIKELY( !fd_vm_syscall_sol_poseidon_cost( vals_len, 1UL, &cost ) ) ) {
    /* TODO Log: "Overflow while calculating the compute cost" */
    return FD_VM_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1751 */

  int err = fd_vm_consume_compute( vm, cost );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1753-L1759 */

  void * hash_result = fd_vm_translate_vm_to_host( vm, result_addr, 32UL, 1UL );
  if( FD_UNLIKELY( !hash_result ) ) return FD_VM_ERR_PERM;

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/bpf_loader/src/syscalls/mod.rs#L1760-L1766 */

  /* TODO check vals_len for overflow */

  ulong slices_sz = vals_len*sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices = fd_vm_translate_vm_to_host_const( vm, vals_addr, slices_sz, FD_VM_VEC_ALIGN );
  if( FD_UNLIKELY( !slices ) ) return FD_VM_ERR_PERM;

  /* At this point, Solana Labs allocates a vector of translated slices.
     Ideally, we'd do this in O(1) allocs by doing incremental hashing
     and translating as we go (see sha256 syscall).  However, the
     poseidon API in ballet doesn't support incremental hashing yet.

     TODO Implement! */

  FD_LOG_WARNING(( "Poseidon input parsing not yet implemented" ));

  return FD_VM_ERR_INVAL;
}

#if FD_HAS_SECP256K1

int
fd_vm_syscall_sol_secp256k1_recover( /**/            void *  _vm,
                                     /**/            ulong   hash_vaddr,
                                     /**/            ulong   recovery_id_val,
                                     /**/            ulong   signature_vaddr,
                                     /**/            ulong   result_vaddr,
                                     FD_PARAM_UNUSED ulong   arg3,
                                     /**/            ulong * _ret ) {
  fd_vm_exec_context_t * vm = (fd_vm_exec_context_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.secp256k1_recover_cost );
  if( FD_UNLIKELY( err ) ) return err;

  /* FIXME: Consider fusing these branches? */

  void const * hash = fd_vm_translate_vm_to_host_const( vm, hash_vaddr, sizeof(fd_hash_t), alignof(uchar) );
  if( FD_UNLIKELY( !hash ) ) return FD_VM_ERR_PERM;

  void const * signature = fd_vm_translate_vm_to_host_const( vm, signature_vaddr, 64UL, alignof(uchar) );
  if( FD_UNLIKELY( !signature ) ) return FD_VM_ERR_PERM;

  void * pubkey_result = fd_vm_translate_vm_to_host( vm, result_vaddr, 64UL, alignof(uchar) );
  if( FD_UNLIKELY( !pubkey_result ) ) return FD_VM_ERR_PERM;

  if( FD_UNLIKELY( recovery_id_val > 4UL ) ) {
    *_ret = 1UL; // Secp256k1RecoverError::InvalidRecoveryId
    return FD_VM_SUCCESS;
  }

  uchar secp256k1_pubkey[64];
  if( FD_UNLIKELY( !fd_secp256k1_recover( secp256k1_pubkey, hash, signature, (int)recovery_id_val ) ) ) {
    *_ret = 2UL; // Secp256k1RecoverError::InvalidSignature
    return FD_VM_SUCCESS;
  }

  memcpy( pubkey_result, secp256k1_pubkey, 64UL );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

#else

int
fd_vm_syscall_sol_secp256k1_recover( FD_PARAM_UNUSED void *  _vm,
                                     FD_PARAM_UNUSED ulong   hash_vaddr,
                                     FD_PARAM_UNUSED ulong   recovery_id_val,
                                     FD_PARAM_UNUSED ulong   signature_vaddr,
                                     FD_PARAM_UNUSED ulong   result_vaddr,
                                     FD_PARAM_UNUSED ulong   arg3,
                                     FD_PARAM_UNUSED ulong * _ret ) {
  return FD_VM_ERR_UNSUP;
}

#endif

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
