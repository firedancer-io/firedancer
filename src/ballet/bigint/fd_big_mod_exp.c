#include "fd_big_mod_exp.h"

#if FD_HAS_S2NBIGNUM

#include <stdint.h>
#include <s2n-bignum.h>

/* Max operand size in 64-bit words (512 bytes / 8). */
#define FD_BIG_MOD_EXP_MAX_WORDS (FD_BIG_MOD_EXP_MAX_BYTES/8UL)

int
fd_big_mod_exp_modulus_is_valid( uchar const * mod,
                                 ulong         mod_len ) {
  if( FD_UNLIKELY( mod_len==0UL ) ) return 0;        /* zero */
  if( FD_UNLIKELY( !(mod[0] & 1U) ) ) return 0;      /* even (includes zero) */
  /* odd: the only remaining value <= 1 is exactly 1 */
  if( FD_UNLIKELY( mod[0]==1U ) ) {
    int is_one = 1;
    for( ulong i=1UL; i<mod_len; i++ ) if( mod[i] ) { is_one = 0; break; }
    if( is_one ) return 0;                           /* one */
  }
  return 1;
}

int
fd_big_mod_exp( uchar *       out,
                uchar const * base, ulong base_len,
                uchar const * exp,  ulong exp_len,
                uchar const * mod,  ulong mod_len ) {

  if( FD_UNLIKELY( !fd_big_mod_exp_modulus_is_valid( mod, mod_len ) ) )
    return FD_BIG_MOD_EXP_ERR_MODULUS;

  /* bignum_modexp operates on three k-word operands of equal width, where
     k is large enough to hold the widest operand.  Little-endian bytes map
     directly onto little-endian limbs, so decoding is a memcpy into a
     zero-extended word buffer. */

  ulong max_len = base_len;
  if( exp_len>max_len ) max_len = exp_len;
  if( mod_len>max_len ) max_len = mod_len;
  ulong k = (max_len + 7UL) / 8UL;   /* in [1,FD_BIG_MOD_EXP_MAX_WORDS] */

  ulong a[ FD_BIG_MOD_EXP_MAX_WORDS ];                    /* base     */
  ulong p[ FD_BIG_MOD_EXP_MAX_WORDS ];                    /* exponent */
  ulong m[ FD_BIG_MOD_EXP_MAX_WORDS ];                    /* modulus  */
  ulong z[ FD_BIG_MOD_EXP_MAX_WORDS ];                    /* result   */
  ulong t[ 3UL*FD_BIG_MOD_EXP_MAX_WORDS ];               /* scratch (>=3k) */

  fd_memset( a, 0, k*sizeof(ulong) );
  fd_memset( p, 0, k*sizeof(ulong) );
  fd_memset( m, 0, k*sizeof(ulong) );
  fd_memcpy( (uchar *)a, base, base_len );
  fd_memcpy( (uchar *)p, exp,  exp_len  );
  fd_memcpy( (uchar *)m, mod,  mod_len  );

  bignum_modexp( k, z, a, p, m, t );

  /* result < modulus <= 2^(8*mod_len), so it fits in mod_len little-endian
     bytes with the high bytes already zero (trailing-zero padded). */
  fd_memcpy( out, (uchar const *)z, mod_len );

  return FD_BIG_MOD_EXP_SUCCESS;
}

#endif /* FD_HAS_S2NBIGNUM */
