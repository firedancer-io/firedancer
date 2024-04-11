#include "fd_curve25519.h"

#if FD_HAS_AVX512
#include "avx512/fd_curve25519_secure.c"
#else
#include "ref/fd_curve25519_secure.c"
#endif

/* All the functions in this file are considered "secure", specifically:

   - Constant time in the input, i.e. the input can be a secret
   - Small and auditable code base, incl. simple types
   - Either, no local variables = no need to clear them before exit (most functions)
   - Or, only static allocation + clear local variable before exit (fd_ed25519_scalar_mul_base_const_time)
   - Clear registers via FD_FN_SENSITIVE
   - C safety
 */

FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_scalar_radix16( char        secret_e[ 64 ], /* ouput: 64-entry in [-8;8] */
                           uchar const secret_a[ 32 ], /* input: 32-byte, assumes valid scalar */
                           char *      tmp_secret_carry ) {
  (*tmp_secret_carry) = 0;

  for( int i=0; i<32; i++ ) {
    secret_e[2*i+0] = (char)((secret_a[i]     ) & 0xF);
    secret_e[2*i+1] = (char)((secret_a[i] >> 4) & 0xF);
  }

  /* At this point, e[0:62] are in [0:15], e[63] is in [0:7] */

  for( int i=0; i<63; i++ ) {
    secret_e[i] = (char)(secret_e[i] + (*tmp_secret_carry));
    (*tmp_secret_carry) = (char)((secret_e[i] + 8) >> 4);
    secret_e[i] = (char)(secret_e[i] - ((*tmp_secret_carry) << 4));
  }
  secret_e[63] = (char)(secret_e[63] + (*tmp_secret_carry));
}

/* const_time_eq returns a==b ? 1 : 0.
   Note: this is const time. */
FD_25519_INLINE uchar FD_FN_SENSITIVE
const_time_eq( const uchar secret_a, const uchar secret_b ) {
  return (uchar)((((uint)(secret_a ^ secret_b))-1U) >> 31);
}

/* fd_ed25519_table_select selects an element in the table of pre-computed
   points &fd_ed25519_base_point_const_time_table.

   Given (j, secret), j in 0..31, secret in -8..7:
   - if secret==0 return 0 (point at infinity)
   - if secret>0  return table[j][secret-1]
   - if secret<0  return table[j][-secret-1]

   Note: this is const time, equivalent to the following code:
    if ( secret == 0 ) {
      fd_ed25519_point_set_zero_precomputed( r );
    } else if ( secret > 0 ) {
      fd_ed25519_point_set( r, &fd_ed25519_base_point_const_time_table[j][secret-1] );
    } else {
      fd_ed25519_point_neg( r, &fd_ed25519_base_point_const_time_table[j][-secret-1] );
    }
*/
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_table_select( fd_ed25519_point_t * r,
                         fd_ed25519_point_t * tmp,
                         int j,
                         char secret,
                         uchar * tmp_secret_idx,
                         uchar * tmp_secret_sgn ) {
  // (*tmp_secret_sgn) = secret < 0 ? 1 : 0;
  (*tmp_secret_sgn) = ((uchar)(secret)) >> 7;
  // (*tmp_secret_idx) = (secret < 0) ? (uchar)(-secret-1) : (secret > 0) ? (uchar)secret-1 : 0xff;
  (*tmp_secret_idx) = (uchar)(secret - (2*(*tmp_secret_sgn)*secret) - 1); // e = e - (2*e) = -e = |e| if e<0, e - 2*0 = e = |e| o.w.

  /* select the point from table in const time */
  fd_ed25519_point_set_zero_precomputed( tmp );

  /* for( uchar i=0; i<8; i++ ) unrolled */
  fd_ed25519_point_if( r,   const_time_eq( 0, (*tmp_secret_idx) ), &fd_ed25519_base_point_const_time_table[j][0], tmp );
  fd_ed25519_point_if( tmp, const_time_eq( 1, (*tmp_secret_idx) ), &fd_ed25519_base_point_const_time_table[j][1], r   );
  fd_ed25519_point_if( r,   const_time_eq( 2, (*tmp_secret_idx) ), &fd_ed25519_base_point_const_time_table[j][2], tmp );
  fd_ed25519_point_if( tmp, const_time_eq( 3, (*tmp_secret_idx) ), &fd_ed25519_base_point_const_time_table[j][3], r   );
  fd_ed25519_point_if( r,   const_time_eq( 4, (*tmp_secret_idx) ), &fd_ed25519_base_point_const_time_table[j][4], tmp );
  fd_ed25519_point_if( tmp, const_time_eq( 5, (*tmp_secret_idx) ), &fd_ed25519_base_point_const_time_table[j][5], r   );
  fd_ed25519_point_if( r,   const_time_eq( 6, (*tmp_secret_idx) ), &fd_ed25519_base_point_const_time_table[j][6], tmp );
  fd_ed25519_point_if( tmp, const_time_eq( 7, (*tmp_secret_idx) ), &fd_ed25519_base_point_const_time_table[j][7], r   );

  /* negate point if needed, in const time */
  fd_ed25519_point_neg_if( r, tmp, (*tmp_secret_sgn) );
}

/* fd_ed25519_scalar_mul_base_const_time computes a scalar mul of the base point
   in const time wrt secret_scalar, clearing stack and registers before returning.
   This is the main function used by fd_ed25519_sign.
   All sub-functions called by fd_ed25519_scalar_mul_base_const_time are expected
   to be static inline, have no local variable, and clear their registers. */

fd_ed25519_point_t * FD_FN_SENSITIVE
fd_ed25519_scalar_mul_base_const_time( fd_ed25519_point_t * r,
                                       uchar const          secret_scalar[ 32 ] ) { /* can be a secret */

  //TODO: add input ptr to secure memory from the caller?

  /* memory areas that will contain (partial) secrets and will be cleared at the end */
  char secret_scalar_naf[64 + 2];
  fd_ed25519_point_t secret_tmp_points[5];

  /* human-readable variables */
  char * tmp_secret_carry = &secret_scalar_naf[64];
  uchar * tmp_secret_idx = (uchar *)&secret_scalar_naf[64];
  uchar * tmp_secret_sgn = (uchar *)&secret_scalar_naf[65];
  fd_ed25519_point_t * selected =        &secret_tmp_points[0]; // selected point from precomput table
  fd_ed25519_point_t * r2 =              &secret_tmp_points[1]; // temp result, to 2-unroll loop
  fd_ed25519_point_t * selected2 =       &secret_tmp_points[2]; // temp selectedc point, to 2-unroll loop
  fd_ed25519_point_t * add_secure_tmp0 = &secret_tmp_points[3]; // tmp0 point for fd_ed25519_point_add_secure
  fd_ed25519_point_t * add_secure_tmp1 = &secret_tmp_points[4]; // tmp1 point for fd_ed25519_point_add_secure

  fd_ed25519_scalar_radix16( secret_scalar_naf, secret_scalar, tmp_secret_carry );

  fd_ed25519_point_set_zero( r );
  for( int i=1; i<64; i+=4 ) {
    fd_ed25519_table_select( selected, selected2, i/2, secret_scalar_naf[i], tmp_secret_idx, tmp_secret_sgn );
    fd_ed25519_point_add_secure( r2, r, selected, add_secure_tmp0, add_secure_tmp1 );
    fd_ed25519_table_select( selected2, selected, i/2+1, secret_scalar_naf[i+2], tmp_secret_idx, tmp_secret_sgn );
    fd_ed25519_point_add_secure( r, r2, selected2, add_secure_tmp0, add_secure_tmp1 );
  }

  fd_ed25519_point_dbln_secure( r, r, 4, add_secure_tmp0, add_secure_tmp1 );

  for( int i=0; i<64; i+=4 ) {
    fd_ed25519_table_select( selected, selected2, i/2, secret_scalar_naf[i], tmp_secret_idx, tmp_secret_sgn );
    fd_ed25519_point_add_secure( r2, r, selected, add_secure_tmp0, add_secure_tmp1 );
    fd_ed25519_table_select( selected2, selected, i/2+1, secret_scalar_naf[i+2], tmp_secret_idx, tmp_secret_sgn );
    fd_ed25519_point_add_secure( r, r2, selected2, add_secure_tmp0, add_secure_tmp1 );
  }

  /* Sanitize */

  fd_memset_explicit( secret_scalar_naf, 0, sizeof(secret_scalar_naf) );
  fd_memset_explicit( secret_tmp_points, 0, sizeof(secret_tmp_points) );

  return r;
}
