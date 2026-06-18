#include "fd_vm_syscall.h"

#if FD_HAS_S2NBIGNUM

#include "../../../ballet/bigint/fd_big_mod_exp.h"

/* sol_big_mod_exp (SIMD-0529): result = (base ^ exponent) mod modulus.

   All operands and the result are little-endian unsigned integers; the
   modulus must be odd and > 1.  The computation lives in ballet
   (fd_big_mod_exp, wrapping s2n-bignum); this file handles the syscall
   ABI: reading params, validating, the compute-unit cost model, and
   writing the result.

   The syscall is gated behind the enable_big_mod_exp_syscall feature
   (registration in fd_vm_syscall.c); if it runs, the feature is active. */

/* SIMD-0529 cost-model constants. */
#define FD_BIG_MOD_EXP_BASE_CU                       (422UL)
#define FD_BIG_MOD_EXP_CU_DIVISOR                    (189UL)
#define FD_BIG_MOD_EXP_MIN_EXPONENT_LENGTH           ( 75UL)
#define FD_BIG_MOD_EXP_MOD_REDUCTION_COMPLEXITY_FACTOR (15UL)

/* BigModExpParams as laid out in VM memory (repr(C), 48 bytes, 8-byte
   aligned).  Pointers are VM virtual addresses. */
struct fd_vm_big_mod_exp_params {
  ulong base;          /* vaddr */
  ulong base_len;
  ulong exponent;      /* vaddr */
  ulong exponent_len;
  ulong modulus;       /* vaddr */
  ulong modulus_len;
};
typedef struct fd_vm_big_mod_exp_params fd_vm_big_mod_exp_params_t;

/* mult_complexity per SIMD-0529 (x is a byte length). */
static inline ulong
fd_big_mod_exp_mult_complexity( ulong x ) {
  if( x<= 64UL ) return x*x;
  if( x<=1024UL ) return x*x/4UL  +  96UL*x -   3072UL;
  return                x*x/16UL + 480UL*x - 199680UL;
}

/* adjusted_exponent_length per EIP-198, over the little-endian exponent
   exp[0,exp_len).  Equivalent to viewing the exponent most-significant
   byte first across exactly exp_len bytes. */
static ulong
fd_big_mod_exp_adjusted_exponent_length( uchar const * exp,
                                         ulong         exp_len ) {
  if( exp_len<=32UL ) {
    /* highest set bit index (0-based) over the whole value; 0 if zero */
    for( ulong i=exp_len; i-->0UL; ) {
      if( exp[i] ) return i*8UL + (ulong)fd_ulong_find_msb( (ulong)exp[i] );
    }
    return 0UL;
  }
  /* exp_len>32: 8*(exp_len-32) + highest set bit in the most significant
     32 bytes (bytes [exp_len-32, exp_len-1]); 0 for the bit term if those
     bytes are all zero. */
  ulong base_term = 8UL*( exp_len-32UL );
  ulong lo        = exp_len-32UL;
  for( ulong i=exp_len; i-->lo; ) {
    if( exp[i] ) return base_term + (i-lo)*8UL + (ulong)fd_ulong_find_msb( (ulong)exp[i] );
  }
  return base_term;
}

/* decoded exponent == 1 (little-endian) */
static inline int
fd_big_mod_exp_exponent_is_one( uchar const * exp,
                                ulong         exp_len ) {
  if( FD_UNLIKELY( exp_len==0UL ) ) return 0;
  if( exp[0]!=1U ) return 0;
  for( ulong i=1UL; i<exp_len; i++ ) if( exp[i] ) return 0;
  return 1;
}

/* SIMD-0529 compute-unit cost. */
static ulong
fd_big_mod_exp_cost( uchar const * exp,
                     ulong         exp_len,
                     ulong         base_len,
                     ulong         mod_len ) {
  ulong max_operand_len = fd_ulong_max( base_len, mod_len );
  ulong complexity;
  if( fd_big_mod_exp_exponent_is_one( exp, exp_len ) ) {
    complexity = fd_big_mod_exp_mult_complexity( max_operand_len )
               * FD_BIG_MOD_EXP_MOD_REDUCTION_COMPLEXITY_FACTOR;
  } else {
    ulong adj = fd_big_mod_exp_adjusted_exponent_length( exp, exp_len );
    ulong eff = fd_ulong_max( adj, FD_BIG_MOD_EXP_MIN_EXPONENT_LENGTH );
    complexity = fd_big_mod_exp_mult_complexity( max_operand_len ) * eff;
  }
  /* BASE_CU + ceil(complexity / DIVISOR); all terms fit comfortably in u64
     (complexity <= mult_complexity(512)*4095 < 2^29). */
  return FD_BIG_MOD_EXP_BASE_CU
       + (complexity + FD_BIG_MOD_EXP_CU_DIVISOR - 1UL) / FD_BIG_MOD_EXP_CU_DIVISOR;
}

int
fd_vm_syscall_sol_big_mod_exp( /**/  void *  _vm,
                               /**/  ulong   params_vaddr,
                               /**/  ulong   result_vaddr,
                               FD_PARAM_UNUSED ulong r3,
                               FD_PARAM_UNUSED ulong r4,
                               FD_PARAM_UNUSED ulong r5,
                               /**/  ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* Step 1: read the params record (48B, 8-byte aligned). */
  fd_vm_big_mod_exp_params_t const * params =
    (fd_vm_big_mod_exp_params_t const *)FD_VM_MEM_HADDR_LD(
        vm, params_vaddr, FD_VM_ALIGN_RUST_U64, sizeof(fd_vm_big_mod_exp_params_t) );

  ulong base_len = params->base_len;
  ulong exp_len  = params->exponent_len;
  ulong mod_len  = params->modulus_len;

  /* Step 2: length validation (max size, nonzero modulus). */
  if( FD_UNLIKELY( base_len>FD_BIG_MOD_EXP_MAX_BYTES ||
                   exp_len >FD_BIG_MOD_EXP_MAX_BYTES ||
                   mod_len >FD_BIG_MOD_EXP_MAX_BYTES ||
                   mod_len==0UL ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );
    return FD_VM_SYSCALL_ERR_INVALID_LENGTH;
  }

  /* Steps 3+4: translate input ranges (readable) and the output range
     (writable).  fd_vm_mem_haddr performs the pointer+len overflow and
     bounds checks.  Zero-length inputs need no memory.  The output range
     is validated now but written only after charging. */
  uchar const * base = base_len ? FD_VM_MEM_HADDR_LD( vm, params->base,     FD_VM_ALIGN_RUST_U8, base_len ) : (uchar const *)"";
  uchar const * exp  = exp_len  ? FD_VM_MEM_HADDR_LD( vm, params->exponent, FD_VM_ALIGN_RUST_U8, exp_len  ) : (uchar const *)"";
  uchar const * mod  =            FD_VM_MEM_HADDR_LD( vm, params->modulus,  FD_VM_ALIGN_RUST_U8, mod_len  );
  uchar *       out  =            FD_VM_MEM_HADDR_ST( vm, result_vaddr,     FD_VM_ALIGN_RUST_U8, mod_len  );

  /* Step 5: validate the modulus is odd and > 1 (before charging). */
  if( FD_UNLIKELY( !fd_big_mod_exp_modulus_is_valid( mod, mod_len ) ) ) {
    /* NOTE: exact abort code TBD vs final agave SIMD-0529 mapping. */
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
    return FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE;
  }

  /* Steps 6-8: determine cost; abort (without charging) if insufficient,
     else charge. */
  FD_VM_CU_UPDATE( vm, fd_big_mod_exp_cost( exp, exp_len, base_len, mod_len ) );

  /* Step 9: compute and write the result (modulus already validated, so
     this cannot fail).  fd_big_mod_exp buffers its inputs before writing,
     so out may alias the inputs. */
  int err = fd_big_mod_exp( out, base, base_len, exp, exp_len, mod, mod_len );
  if( FD_UNLIKELY( err!=FD_BIG_MOD_EXP_SUCCESS ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
    return FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE;
  }

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

#endif /* FD_HAS_S2NBIGNUM */
