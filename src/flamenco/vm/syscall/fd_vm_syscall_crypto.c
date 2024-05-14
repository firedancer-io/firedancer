#include "fd_vm_syscall.h"

#include "../../../ballet/bn254/fd_bn254.h"
#include "../../../ballet/bn254/fd_poseidon.h"
#include "../../../ballet/secp256k1/fd_secp256k1.h"

int
fd_vm_syscall_sol_alt_bn128_group_op( void *  _vm,
                                      ulong   group_op,
                                      ulong   input_addr,
                                      ulong   input_sz,
                                      ulong   result_addr,
                                      FD_PARAM_UNUSED ulong r4,
                                      ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1509 */
  fd_vm_t * vm  = (fd_vm_t *)_vm;
  ulong     ret = 1UL; /* by default return Ok(1) == error */

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1520-L1549 */
  ulong cost = 0UL;
  ulong output_sz = 0UL;
  switch( group_op ) {

  case FD_VM_SYSCALL_SOL_ALT_BN128_ADD:
    output_sz = FD_VM_SYSCALL_SOL_ALT_BN128_G1_SZ;
    cost = FD_VM_ALT_BN128_ADDITION_COST;
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_MUL:
    output_sz = FD_VM_SYSCALL_SOL_ALT_BN128_G1_SZ;
    cost = FD_VM_ALT_BN128_MULTIPLICATION_COST;
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING:
    output_sz = FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING_OUTPUT_SZ;
    ulong elements_len = input_sz / FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING_INPUT_EL_SZ;
    cost = FD_VM_ALT_BN128_PAIRING_ONE_PAIR_COST_FIRST
      + FD_VM_SHA256_BASE_COST
      + FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING_OUTPUT_SZ;
    cost = fd_ulong_sat_add( cost,
      fd_ulong_sat_mul( FD_VM_ALT_BN128_PAIRING_ONE_PAIR_COST_OTHER,
        fd_ulong_sat_sub( elements_len, 1 ) ) );
    cost = fd_ulong_sat_add( cost, input_sz );
    break;

  default:
    return FD_VM_ERR_INVAL; /* SyscallError::InvalidAttribute */
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1551 */

  FD_VM_CU_UPDATE( vm, cost );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1553-L1565 */

  uchar const * input = FD_VM_MEM_HADDR_LD( vm, input_addr,  FD_VM_ALIGN_RUST_U8, input_sz );
  uchar * call_result = FD_VM_MEM_HADDR_ST( vm, result_addr, FD_VM_ALIGN_RUST_U8, output_sz );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1567-L1598
     Note: this implementation is post SIMD-0129, we only support the simplified error codes. */
  switch( group_op ) {

  case FD_VM_SYSCALL_SOL_ALT_BN128_ADD:
    /* Compute add */
    if( FD_LIKELY( fd_bn254_g1_add_syscall( call_result, input, input_sz )==0 ) ) {
      ret = 0UL; /* success */
    }
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_MUL:
    /* Compute scalar mul */
    if( FD_LIKELY( fd_bn254_g1_scalar_mul_syscall( call_result, input, input_sz )==0 ) ) {
      ret = 0UL; /* success */
    }
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_PAIRING:
    /* Compute pairing */
    if( FD_LIKELY( fd_bn254_pairing_is_one_syscall( call_result, input, input_sz )==0 ) ) {
      ret = 0UL; /* success */
    }
    break;
  }

  *_ret = ret;
  return FD_VM_SUCCESS; /* Ok(SUCCESS) or Ok(ERROR) */
}

int
fd_vm_syscall_sol_alt_bn128_compression( void *  _vm,
                                         ulong   op,
                                         ulong   input_addr,
                                         ulong   input_sz,
                                         ulong   result_addr,
                                         FD_PARAM_UNUSED ulong r4,
                                         ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1776 */
  fd_vm_t * vm  = (fd_vm_t *)_vm;
  ulong     ret = 1UL; /* by default return Ok(1) == error */

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1791-L1811 */
  ulong cost = 0UL;
  ulong output_sz = 0UL;
  switch( op ) {

  case FD_VM_SYSCALL_SOL_ALT_BN128_G1_COMPRESS:
    output_sz = FD_VM_SYSCALL_SOL_ALT_BN128_G1_COMPRESSED_SZ;
    cost = FD_VM_ALT_BN128_G1_COMPRESS;
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_G1_DECOMPRESS:
    output_sz = FD_VM_SYSCALL_SOL_ALT_BN128_G1_SZ;
    cost = FD_VM_ALT_BN128_G1_DECOMPRESS;
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_G2_COMPRESS:
    output_sz = FD_VM_SYSCALL_SOL_ALT_BN128_G2_COMPRESSED_SZ;
    cost = FD_VM_ALT_BN128_G2_COMPRESS;
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_G2_DECOMPRESS:
    output_sz = FD_VM_SYSCALL_SOL_ALT_BN128_G2_SZ;
    cost = FD_VM_ALT_BN128_G2_DECOMPRESS;
    break;

  default:
    return FD_VM_ERR_INVAL; /* SyscallError::InvalidAttribute */
  }
  cost = fd_ulong_sat_add( cost, FD_VM_SYSCALL_BASE_COST );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1813 */

  FD_VM_CU_UPDATE( vm, cost );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1815-L1827 */

  void const * input = FD_VM_MEM_HADDR_LD( vm, input_addr,  FD_VM_ALIGN_RUST_U8, input_sz );
  void * call_result = FD_VM_MEM_HADDR_ST( vm, result_addr, FD_VM_ALIGN_RUST_U8, output_sz );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1829-L1891
     Note: this implementation is post SIMD-0129, we only support the simplified error codes. */
  switch( op ) {

  case FD_VM_SYSCALL_SOL_ALT_BN128_G1_COMPRESS:
    if( FD_UNLIKELY( input_sz!=FD_VM_SYSCALL_SOL_ALT_BN128_G1_SZ ) ) {
      goto soft_error;
    }
    if( FD_LIKELY( fd_bn254_g1_compress( fd_type_pun(call_result), fd_type_pun_const(input) ) ) ) {
      ret = 0UL; /* success */
    }
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_G1_DECOMPRESS:
    if( FD_UNLIKELY( input_sz!=FD_VM_SYSCALL_SOL_ALT_BN128_G1_COMPRESSED_SZ ) ) {
      goto soft_error;
    }
    if( FD_LIKELY( fd_bn254_g1_decompress( fd_type_pun(call_result), fd_type_pun_const(input) ) ) ) {
      ret = 0UL; /* success */
    }
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_G2_COMPRESS:
    if( FD_UNLIKELY( input_sz!=FD_VM_SYSCALL_SOL_ALT_BN128_G2_SZ ) ) {
      goto soft_error;
    }
    if( FD_LIKELY( fd_bn254_g2_compress( fd_type_pun(call_result), fd_type_pun_const(input) ) ) ) {
      ret = 0UL; /* success */
    }
    break;

  case FD_VM_SYSCALL_SOL_ALT_BN128_G2_DECOMPRESS:
    if( FD_UNLIKELY( input_sz!=FD_VM_SYSCALL_SOL_ALT_BN128_G2_COMPRESSED_SZ ) ) {
      goto soft_error;
    }
    if( FD_LIKELY( fd_bn254_g2_decompress( fd_type_pun(call_result), fd_type_pun_const(input) ) ) ) {
      ret = 0UL; /* success */
    }
    break;
  }

soft_error:
  *_ret = ret;
  return FD_VM_SUCCESS; /* Ok(SUCCESS) or Ok(ERROR) */
}

int
fd_vm_syscall_sol_poseidon( void *  _vm,
                            ulong   params,
                            ulong   endianness,
                            ulong   vals_addr,
                            ulong   vals_len,
                            ulong   result_addr,
                            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1678 */
  fd_vm_t * vm  = (fd_vm_t *)_vm;
  ulong     ret = 1UL; /* by default return Ok(1) == error */

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1688 */

  if( FD_UNLIKELY( params!=0UL ) ) {
    return FD_VM_ERR_INVAL; /* PoseidonSyscallError::InvalidParameters */
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1689 */

  if( FD_UNLIKELY(
       endianness!=0UL /* Big endian */
    && endianness!=1UL /* Little endian */
  ) ) {
    return FD_VM_ERR_INVAL; /* PoseidonSyscallError::InvalidEndianness */
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1691-L1698 */

  if( FD_UNLIKELY( vals_len > FD_VM_SYSCALL_SOL_POSEIDON_MAX_VALS ) ) {
    fd_vm_log_append_printf( vm, "Poseidon hashing %lu sequences is not supported", vals_len );
    return FD_VM_ERR_INVAL; /* SyscallError::InvalidLength */
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1700-L1707
     poseidon_cost(): https://github.com/solana-labs/solana/blob/v1.18.12/program-runtime/src/compute_budget.rs#L211 */

  /* vals_len^2 * A + C */
  ulong cost = fd_ulong_sat_add(
    fd_ulong_sat_mul(
      fd_ulong_sat_mul( vals_len, vals_len ),
      FD_VM_POSEIDON_COST_COEFFICIENT_A
    ),
    FD_VM_POSEIDON_COST_COEFFICIENT_C
  );

  /* The following can never happen, left as comment for completeness.
     if( FD_UNLIKELY( cost == ULONG_MAX ) ) {
       fd_vm_log_append_printf( vm, "Overflow while calculating the compute cost" );
       return FD_VM_ERR_INVAL; // SyscallError::ArithmeticOverflow
     }
  */

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1708 */

  FD_VM_CU_UPDATE( vm, cost );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1710-L1715 */

  void * hash_result = FD_VM_MEM_HADDR_ST( vm, result_addr, FD_VM_ALIGN_RUST_U8, 32UL );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1716-L1732 */

  /* Agave allocates a vector of translated slices (that can return a fatal
     error), and then computes Poseidon, returning a soft error in case of
     issues (e.g. invalid input).

     We must be careful in returning the correct fatal vs soft error.

     The special case of vals_len==0 returns success, so for simplicity
     we capture it explicitly. */

  if( FD_UNLIKELY( !vals_len ) ) {
    ret = 0;
    return FD_VM_SUCCESS;
  }

  /* First loop to memory map. This can return a fatal error. */
  fd_vm_vec_t const * input_vec_haddr = (fd_vm_vec_t const *)FD_VM_MEM_HADDR_LD( vm, vals_addr, FD_VM_VEC_ALIGN, vals_len*sizeof(fd_vm_vec_t) );
  void const * inputs_haddr[ FD_VM_SYSCALL_SOL_POSEIDON_MAX_VALS ];
  for( ulong i=0UL; i<vals_len; i++ ) {
    inputs_haddr[i] = FD_VM_MEM_HADDR_LD( vm, input_vec_haddr[i].addr, FD_VM_ALIGN_RUST_U8, input_vec_haddr[i].len );
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1734-L1750
     Note: this implementation is post SIMD-0129, we only support the simplified error codes. */

  /* Second loop to computed Poseidon. This can return a soft error. */
  int big_endian = endianness==0;
  fd_poseidon_t pos[1];
  fd_poseidon_init( pos, big_endian );

  for( ulong i=0UL; i<vals_len; i++ ) {
    if( FD_UNLIKELY( fd_poseidon_append( pos, inputs_haddr[ i ], input_vec_haddr[i].len )==NULL ) ) {
      goto soft_error;
    }
  }

  ret = !fd_poseidon_fini( pos, hash_result );

soft_error:
  *_ret = ret;
  return FD_VM_SUCCESS; /* Ok(1) == error */
}

int
fd_vm_syscall_sol_secp256k1_recover( /**/            void *  _vm,
                                     /**/            ulong   hash_vaddr,
                                     /**/            ulong   recovery_id_val,
                                     /**/            ulong   signature_vaddr,
                                     /**/            ulong   result_vaddr,
                                     FD_PARAM_UNUSED ulong   r4,
                                     /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L810 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L820-L821 */

  FD_VM_CU_UPDATE( vm, FD_VM_SECP256K1_RECOVER_COST );

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L823-L840 */

  uchar const * hash    = FD_VM_MEM_HADDR_LD( vm, hash_vaddr,      FD_VM_ALIGN_RUST_U8, 32UL );
  uchar const * sig     = FD_VM_MEM_HADDR_LD( vm, signature_vaddr, FD_VM_ALIGN_RUST_U8, 64UL );
  uchar * pubkey_result = FD_VM_MEM_HADDR_ST( vm, result_vaddr,    FD_VM_ALIGN_RUST_U8, 64UL );

  /* CRITICAL */

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L842-L853 */

  /* Secp256k1RecoverError::InvalidHash
     This can never happen, as `libsecp256k1::Message::parse_slice(hash)`
     only checks that hash is 32-byte long, and that's by construction.
     https://github.com/paritytech/libsecp256k1/blob/v0.6.0/src/lib.rs#L657-L665

     if( FD_UNLIKELY( 0 ) ) {
       *_ret = 1UL; // Secp256k1RecoverError::InvalidHash
       return FD_VM_SUCCESS;
     }
   */

  /* Secp256k1RecoverError::InvalidRecoveryId
     Agave code has 2 checks: the first is a cast from u64 to u8.
     The second is `libsecp256k1::RecoveryId::parse(adjusted_recover_id_val)` that
     checks if `adjusted_recover_id_val < 4`.
     https://github.com/paritytech/libsecp256k1/blob/v0.6.0/src/lib.rs#L674-L680
  */

  if( FD_UNLIKELY( recovery_id_val >= 4UL ) ) {
    *_ret = 2UL; /* Secp256k1RecoverError::InvalidRecoveryId */
    return FD_VM_SUCCESS;
  }

  /* Secp256k1RecoverError::InvalidSignature
     We omit this check, as this is done as part of fd_secp256k1_recover() below,
     and the return code is the same.

     In more details, this checks that the signature is valid, i.e. if the
     signature is represented as two scalars (r, s), it checks that both r
     and s are canonical scalars.

     Note the `?` at the end of this line:
     https://github.com/paritytech/libsecp256k1/blob/v0.6.0/src/lib.rs#L535
     And following the code, `scalar::check_overflow` is checks that the scalar is valid:
     https://github.com/paritytech/libsecp256k1/blob/master/core/src/scalar.rs#L70-L87 */

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L855-L860 */

  uchar secp256k1_pubkey[64];
  if( FD_UNLIKELY( !fd_secp256k1_recover( secp256k1_pubkey, hash, sig, (int)recovery_id_val ) ) ) {
    *_ret = 3UL; /* Secp256k1RecoverError::InvalidSignature */
    return FD_VM_SUCCESS;
  }

  memcpy( pubkey_result, secp256k1_pubkey, 64UL );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}
