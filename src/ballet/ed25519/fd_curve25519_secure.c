#include "fd_curve25519.h"

#if FD_HAS_AVX512
#include "avx512/fd_curve25519_secure.c"
#else
#include "ref/fd_curve25519_secure.c"
#endif

/* All the functions in this file are considered "secure", specifically:

   - Constant time in the input, i.e. the input can be a secret
   - Small and auditable code base, incl. simple types
   - Only static allocation
   - Clear local variables before exit
   - TODO: only write in secure memory passed in by the caller
   - TODO: clear the stack
   - C safety
   - Unit tests (including tests for these security properties)
 */

FD_25519_INLINE void
fd_ed25519_scalar_radix16( char        secret_e[ static 64 ],    /* ouput: 64-entry in [-8;8] */
                           uchar const secret_a[ static 32 ] ) { /* input: 32-byte, assumes valid scalar */

  for( int i=0; i<32; i++ ) {
    secret_e[2*i+0] = (char)((secret_a[i]     ) & 0xF);
    secret_e[2*i+1] = (char)((secret_a[i] >> 4) & 0xF);
  }

  /* At this point, e[0:62] are in [0:15], e[63] is in [0:7] */

  char carry = 0;
  for( int i=0; i<63; i++ ) {
    secret_e[i] = (char)(secret_e[i] + carry);
    carry = (char)((secret_e[i] + 8) >> 4);
    secret_e[i] = (char)(secret_e[i] - (carry << 4));
  }
  secret_e[63] = (char)(secret_e[63] + carry);

}

/* const_time_eq returns a==b ? 1 : 0.
   Note: this is const time. */
FD_25519_INLINE uchar const_time_eq( const uchar secret_a, const uchar secret_b ) {
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
FD_25519_INLINE void
fd_ed25519_table_select( fd_ed25519_point_t * r,
                         fd_ed25519_point_t * tmp,
                         int j,
                         char secret ) {
  // uchar secret_sgn = secret < 0 ? 1 : 0;
  uchar secret_sgn = ((uchar)(secret)) >> 7;
  // uchar secret_idx = (secret < 0) ? (uchar)(-secret-1) : (secret > 0) ? (uchar)secret-1 : 0xff;
  uchar secret_idx = (uchar)(secret - (2*secret_sgn*secret) - 1); // e = e - (2*e) = -e = |e| if e<0, e - 2*0 = e = |e| o.w.

  /* select the point from table in const time */
  fd_ed25519_point_set_zero_precomputed( tmp );

  // for( uchar i=0; i<8; i++ ) unrolled
  fd_ed25519_point_if( r,   const_time_eq( 0, secret_idx ), &fd_ed25519_base_point_const_time_table[j][0], tmp );
  fd_ed25519_point_if( tmp, const_time_eq( 1, secret_idx ), &fd_ed25519_base_point_const_time_table[j][1], r   );
  fd_ed25519_point_if( r,   const_time_eq( 2, secret_idx ), &fd_ed25519_base_point_const_time_table[j][2], tmp );
  fd_ed25519_point_if( tmp, const_time_eq( 3, secret_idx ), &fd_ed25519_base_point_const_time_table[j][3], r   );
  fd_ed25519_point_if( r,   const_time_eq( 4, secret_idx ), &fd_ed25519_base_point_const_time_table[j][4], tmp );
  fd_ed25519_point_if( tmp, const_time_eq( 5, secret_idx ), &fd_ed25519_base_point_const_time_table[j][5], r   );
  fd_ed25519_point_if( r,   const_time_eq( 6, secret_idx ), &fd_ed25519_base_point_const_time_table[j][6], tmp );
  fd_ed25519_point_if( tmp, const_time_eq( 7, secret_idx ), &fd_ed25519_base_point_const_time_table[j][7], r   );


  /* negate point if needed, in const time */
  fd_ed25519_point_neg_if( r, tmp, secret_sgn );

  /* Sanitize */

  secret_sgn = 0; //TODO: verify that it works
  secret_idx = 0;
}

fd_ed25519_point_t *
fd_ed25519_scalar_mul_base_const_time( fd_ed25519_point_t * r,
                                       uchar const          n[ static 32 ] ) { /* can be a secret */

  //TODO: add input ptr to secure memory from the caller?
  char e[64];
  fd_ed25519_point_t t[1];
  fd_ed25519_point_t t2[1], r2[1]; // aux var to reduce number of copies in mem

  fd_ed25519_scalar_radix16( e, n );

  fd_ed25519_point_set_zero( r );
  for( int i=1; i<64; i+=4 ) {
    fd_ed25519_table_select( t, t2, i/2, e[i] );
    fd_ed25519_point_add_secure( r2, r, t );
    fd_ed25519_table_select( t2, t, i/2+1, e[i+2] );
    fd_ed25519_point_add_secure( r, r2, t2 );
  }

  fd_ed25519_point_dbln( r, r, 4 );

  for( int i=0; i<64; i+=4 ) {
    fd_ed25519_table_select( t, t2, i/2, e[i] );
    fd_ed25519_point_add_secure( r2, r, t );
    fd_ed25519_table_select( t2, t, i/2+1, e[i+2] );
    fd_ed25519_point_add_secure( r, r2, t2 );
  }

  /* Sanitize */

  //TODO verify that it works
  fd_memset( e, 0, sizeof(e) );
  fd_memset( t, 0, sizeof(fd_ed25519_point_t) );
  fd_memset( t2, 0, sizeof(fd_ed25519_point_t) );
  fd_memset( r2, 0, sizeof(fd_ed25519_point_t) );

  return r;
}
