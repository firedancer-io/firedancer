#include "fd_rsa.h"
#include "../sha256/fd_sha256.h"
#include "../sha512/fd_sha512.h"
#include <string.h>

#ifdef FD_HAS_S2NBIGNUM
#include <stdint.h>
#include "../../third_party/s2n-bignum/include/s2n-bignum.h"
#else
#if !FD_HAS_INT128
#error "fd_rsa requires FD_HAS_INT128"
#endif

/* Portable fallback for the three s2n-bignum routines fd_rsa_public_op
   uses. */

/* Returns -n0^{-1} mod 2^64 (n0 odd) */

static ulong
fd_rsa_ref_n0inv( ulong n0 ) {
  ulong x = n0;  /* correct to 3 bits, Newton doubles per step */
  for( int i=0; i<6; i++ ) x *= 2UL - n0*x;
  return 0UL-x;
}

/* z := x - n if x >= n (both k limbs) */

static void
fd_rsa_ref_reduce( ulong         k,
                   ulong *       x,
                   ulong const * n ) {
  ulong i = k;
  do { i--; } while( i && x[i]==n[i] );
  if( x[i]<n[i] ) return;
  ulong borrow = 0UL;
  for( ulong j=0UL; j<k; j++ ) {
    uint128 d = (uint128)x[j] - n[j] - borrow;
    x[j]   = (ulong)d;
    borrow = (ulong)( d>>64 ) & 1UL;
  }
}

/* z := x*y/2^{64k} mod n (CIOS).  z must not alias x or y. */

static void
bignum_montmul( ulong         k,
                ulong *       z,
                ulong const * x,
                ulong const * y,
                ulong const * n ) {
  ulong n0inv = fd_rsa_ref_n0inv( n[0] );
  ulong t[ FD_RSA_LIMB_CNT_MAX+2UL ];
  memset( t, 0, (k+2UL)*sizeof(ulong) );
  for( ulong i=0UL; i<k; i++ ) {
    uint128 c = 0;
    for( ulong j=0UL; j<k; j++ ) {
      c += (uint128)t[j] + (uint128)x[j]*y[i];
      t[j] = (ulong)c; c >>= 64;
    }
    c += t[k]; t[k] = (ulong)c; t[k+1UL] = (ulong)( c>>64 );

    ulong m = t[0]*n0inv;
    c = (uint128)t[0] + (uint128)m*n[0];
    c >>= 64;
    for( ulong j=1UL; j<k; j++ ) {
      c += (uint128)t[j] + (uint128)m*n[j];
      t[j-1UL] = (ulong)c; c >>= 64;
    }
    c += t[k]; t[k-1UL] = (ulong)c; t[k] = t[k+1UL] + (ulong)( c>>64 );
  }
  /* t < 2n here, and t[k] is 0 or 1 */
  if( t[k] ) {
    ulong borrow = 0UL;
    for( ulong j=0UL; j<k; j++ ) {
      uint128 d = (uint128)t[j] - n[j] - borrow;
      t[j]   = (ulong)d;
      borrow = (ulong)( d>>64 ) & 1UL;
    }
  } else {
    fd_rsa_ref_reduce( k, t, n );
  }
  memcpy( z, t, k*sizeof(ulong) );
}

/* z := x/2^{64k} mod n */

static void
bignum_demont( ulong         k,
               ulong *       z,
               ulong const * x,
               ulong const * n ) {
  ulong one[ FD_RSA_LIMB_CNT_MAX ];
  memset( one, 0, k*sizeof(ulong) );
  one[0] = 1UL;
  bignum_montmul( k, z, x, one, n );
}

/* z := 2^{128k} mod n, by repeated doubling from 2^{b-1} < n where b
   is the bit length of n. */

static void
bignum_montifier( ulong         k,
                  ulong *       z,
                  ulong const * n,
                  ulong *       t ) {
  (void)t;
  ulong bits = 64UL*k;
  while( !( n[ (bits-1UL)>>6 ] >> ( (bits-1UL)&63UL ) & 1UL ) ) bits--;
  memset( z, 0, k*sizeof(ulong) );
  z[ (bits-1UL)>>6 ] = 1UL << ( (bits-1UL)&63UL );
  for( ulong i=bits-1UL; i<128UL*k; i++ ) {
    ulong carry = 0UL;
    for( ulong j=0UL; j<k; j++ ) {
      ulong next = z[j]>>63;
      z[j] = (z[j]<<1) | carry;
      carry = next;
    }
    if( carry ) {
      ulong borrow = 0UL;
      for( ulong j=0UL; j<k; j++ ) {
        uint128 d = (uint128)z[j] - n[j] - borrow;
        z[j]   = (ulong)d;
        borrow = (ulong)( d>>64 ) & 1UL;
      }
    } else {
      fd_rsa_ref_reduce( k, z, n );
    }
  }
}

#endif /* FD_HAS_S2NBIGNUM */

static ulong
fd_rsa_hash_sz( int hash ) {
  switch( hash ) {
  case FD_RSA_HASH_SHA256: return FD_SHA256_HASH_SZ;
  case FD_RSA_HASH_SHA384: return FD_SHA384_HASH_SZ;
  case FD_RSA_HASH_SHA512: return FD_SHA512_HASH_SZ;
  default:                 return 0UL;
  }
}

static void
fd_rsa_hash( int          hash,
             void const * data,
             ulong        sz,
             uchar *      out ) {
  switch( hash ) {
  case FD_RSA_HASH_SHA256: fd_sha256_hash( data, sz, out ); break;
  case FD_RSA_HASH_SHA384: fd_sha384_hash( data, sz, out ); break;
  case FD_RSA_HASH_SHA512: fd_sha512_hash( data, sz, out ); break;
  }
}

/* Big endian bytes <-> little endian 64-bit limbs */

static void
fd_rsa_be_to_limbs( ulong *       limbs,
                    ulong         limb_cnt,
                    uchar const * be,
                    ulong         be_sz ) {
  memset( limbs, 0, limb_cnt*sizeof(ulong) );
  for( ulong i=0UL; i<be_sz; i++ )
    limbs[ i>>3 ] |= (ulong)be[ be_sz-1UL-i ] << ( 8UL*(i&7UL) );
}

FD_FN_UNUSED static void
fd_rsa_limbs_to_be( uchar *       be,
                    ulong         be_sz,
                    ulong const * limbs ) {
  for( ulong i=0UL; i<be_sz; i++ )
    be[ be_sz-1UL-i ] = (uchar)( limbs[ i>>3 ] >> ( 8UL*(i&7UL) ) );
}

fd_rsa_pubkey_t *
fd_rsa_pubkey_init( fd_rsa_pubkey_t * key,
                    uchar const *     n,
                    ulong             n_sz,
                    uchar const *     e,
                    ulong             e_sz ) {
  if( FD_UNLIKELY( !key || !n || !e ) ) return NULL;

  while( n_sz && !n[0] ) { n++; n_sz--; }
  while( e_sz && !e[0] ) { e++; e_sz--; }
  if( FD_UNLIKELY( !n_sz || n_sz>FD_RSA_MOD_SZ_MAX ) ) return NULL;
  if( FD_UNLIKELY( !e_sz || e_sz>sizeof(ulong)   ) ) return NULL;

  ulong mod_bits = 8UL*(n_sz-1UL) + (ulong)fd_uchar_find_msb( n[0] ) + 1UL;
  if( FD_UNLIKELY( mod_bits<FD_RSA_MOD_BITS_MIN || mod_bits>FD_RSA_MOD_BITS_MAX ) ) return NULL;
  if( FD_UNLIKELY( !(n[ n_sz-1UL ] & 1U) ) ) return NULL;

  ulong ev = 0UL;
  for( ulong i=0UL; i<e_sz; i++ ) ev = (ev<<8) | (ulong)e[i];
  if( FD_UNLIKELY( ev<3UL || !(ev & 1UL) ) ) return NULL;

  memset( key, 0, sizeof(fd_rsa_pubkey_t) );
  key->e        = ev;
  key->limb_cnt = (n_sz+7UL)>>3;
  key->n_sz     = n_sz;
  key->mod_bits = mod_bits;
  fd_rsa_be_to_limbs( key->n, key->limb_cnt, n, n_sz );
  return key;
}

/* fd_rsa_public_op computes em = sig^e mod n (RSAVP1, RFC 8017 Section
   5.2.2) and writes it big endian to em[key->n_sz].  Returns 0 if sig
   is not a valid signature representative (wrong length or not below
   the modulus). */

static int
fd_rsa_public_op( fd_rsa_pubkey_t const * key,
                  uchar const *           sig,
                  ulong                   sig_sz,
                  uchar *                 em ) {
  if( FD_UNLIKELY( sig_sz!=key->n_sz ) ) return 0;
  ulong const k = key->limb_cnt;

  ulong s[ FD_RSA_LIMB_CNT_MAX ];
  fd_rsa_be_to_limbs( s, k, sig, sig_sz );

  /* Require s < n */
  ulong i = k;
  do { i--; } while( i && s[i]==key->n[i] );
  if( FD_UNLIKELY( s[i]>=key->n[i] ) ) return 0;

  /* Left-to-right binary exponentiation in the Montgomery domain
     (bignum_montmul does not support aliased operands) */
  ulong r2  [ FD_RSA_LIMB_CNT_MAX ];
  ulong tmp [ FD_RSA_LIMB_CNT_MAX ];
  ulong base[ FD_RSA_LIMB_CNT_MAX ];
  ulong acc0[ FD_RSA_LIMB_CNT_MAX ];
  ulong acc1[ FD_RSA_LIMB_CNT_MAX ];
  bignum_montifier( k, r2, key->n, tmp );
  bignum_montmul( k, base, s, r2, key->n );
  ulong * acc = acc0;
  ulong * nxt = acc1;
  memcpy( acc, base, k*sizeof(ulong) );
  for( int bit=fd_ulong_find_msb( key->e )-1; bit>=0; bit-- ) {
    bignum_montmul( k, nxt, acc, acc, key->n );
    if( (key->e>>bit) & 1UL ) {
      bignum_montmul( k, acc, nxt, base, key->n );
    } else {
      ulong * t = acc; acc = nxt; nxt = t;
    }
  }
  bignum_demont( k, tmp, acc, key->n );
  fd_rsa_limbs_to_be( em, key->n_sz, tmp );
  return 1;
}

/* DER DigestInfo prefixes (RFC 8017 Section 9.2 Note 1) */

static uchar const fd_rsa_digest_info_sha256[ 19 ] = {
  0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20 };
static uchar const fd_rsa_digest_info_sha384[ 19 ] = {
  0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30 };
static uchar const fd_rsa_digest_info_sha512[ 19 ] = {
  0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40 };

int
fd_rsa_verify_pkcs1_v15( fd_rsa_pubkey_t const * key,
                         uchar const *           sig,
                         ulong                   sig_sz,
                         uchar const *           msg,
                         ulong                   msg_sz,
                         int                     hash ) {
  ulong h_sz = fd_rsa_hash_sz( hash );
  if( FD_UNLIKELY( !h_sz ) ) return FD_RSA_FAILURE;
  uchar const * prefix;
  switch( hash ) {
  case FD_RSA_HASH_SHA256: prefix = fd_rsa_digest_info_sha256; break;
  case FD_RSA_HASH_SHA384: prefix = fd_rsa_digest_info_sha384; break;
  default:                 prefix = fd_rsa_digest_info_sha512; break;
  }

  uchar em[ FD_RSA_MOD_SZ_MAX ];
  if( FD_UNLIKELY( !fd_rsa_public_op( key, sig, sig_sz, em ) ) ) return FD_RSA_FAILURE;

  /* Rebuild the one valid encoding for this modulus size and compare
     it whole (RFC 8017 Section 8.2.2 step 4), so no partial parse of
     em can accept an alternative padding. */
  ulong const em_sz = key->n_sz;
  ulong const t_sz  = 19UL + h_sz;
  if( FD_UNLIKELY( em_sz < t_sz+11UL ) ) return FD_RSA_FAILURE;

  uchar expected[ FD_RSA_MOD_SZ_MAX ];
  ulong ps_sz = em_sz - t_sz - 3UL;
  expected[0] = 0x00;
  expected[1] = 0x01;
  memset( expected+2UL, 0xff, ps_sz );
  expected[ 2UL+ps_sz ] = 0x00;
  memcpy( expected+3UL+ps_sz, prefix, 19UL );
  fd_rsa_hash( hash, msg, msg_sz, expected+em_sz-h_sz );

  return fd_memeq( em, expected, em_sz ) ? FD_RSA_SUCCESS : FD_RSA_FAILURE;
}

int
fd_rsa_verify_pss( fd_rsa_pubkey_t const * key,
                   uchar const *           sig,
                   ulong                   sig_sz,
                   uchar const *           msg,
                   ulong                   msg_sz,
                   int                     hash ) {
  ulong h_sz = fd_rsa_hash_sz( hash );
  if( FD_UNLIKELY( !h_sz ) ) return FD_RSA_FAILURE;
  ulong const s_sz = h_sz;

  uchar em_buf[ FD_RSA_MOD_SZ_MAX ];
  if( FD_UNLIKELY( !fd_rsa_public_op( key, sig, sig_sz, em_buf ) ) ) return FD_RSA_FAILURE;

  /* EMSA-PSS-VERIFY (RFC 8017 Section 9.1.2) with emBits = modBits-1.
     When modBits-1 is a multiple of 8, em is one byte shorter than the
     modulus and the public op result must have a zero leading byte. */
  ulong const em_bits = key->mod_bits-1UL;
  ulong const em_sz   = (em_bits+7UL)>>3;
  uchar const * em = em_buf;
  if( em_sz<key->n_sz ) {
    if( FD_UNLIKELY( em_buf[0] ) ) return FD_RSA_FAILURE;
    em++;
  }

  if( FD_UNLIKELY( em_sz < h_sz+s_sz+2UL ) ) return FD_RSA_FAILURE;
  if( FD_UNLIKELY( em[ em_sz-1UL ]!=0xbc ) ) return FD_RSA_FAILURE;

  ulong const   db_sz     = em_sz - h_sz - 1UL;
  uchar const * masked_db = em;
  uchar const * h         = em + db_sz;

  /* The leftmost 8*emLen-emBits bits of maskedDB must be zero */
  ulong const top_bits = 8UL*em_sz - em_bits;
  if( FD_UNLIKELY( masked_db[0] & (uchar)( 0xff00U>>top_bits ) ) ) return FD_RSA_FAILURE;

  /* DB = maskedDB xor MGF1(H, dbLen) */
  uchar db[ FD_RSA_MOD_SZ_MAX ];
  uchar mgf_in[ FD_SHA512_HASH_SZ+4UL ];
  memcpy( mgf_in, h, h_sz );
  for( ulong off=0UL, ctr=0UL; off<db_sz; off+=h_sz, ctr++ ) {
    FD_STORE( uint, mgf_in+h_sz, fd_uint_bswap( (uint)ctr ) );
    uchar mask[ FD_SHA512_HASH_SZ ];
    fd_rsa_hash( hash, mgf_in, h_sz+4UL, mask );
    ulong n = fd_ulong_min( h_sz, db_sz-off );
    for( ulong i=0UL; i<n; i++ ) db[ off+i ] = (uchar)( masked_db[ off+i ] ^ mask[ i ] );
  }
  db[0] = (uchar)( db[0] & (uchar)( 0xffU>>top_bits ) );

  /* DB = PS (zeros) || 0x01 || salt */
  ulong const ps_sz = em_sz - h_sz - s_sz - 2UL;
  uchar acc = 0;
  for( ulong i=0UL; i<ps_sz; i++ ) acc |= db[i];
  if( FD_UNLIKELY( acc || db[ ps_sz ]!=0x01 ) ) return FD_RSA_FAILURE;
  uchar const * salt = db + ps_sz + 1UL;

  /* H' = Hash( 0x00 x8 || mHash || salt ) */
  uchar m_prime[ 8UL + 2UL*FD_SHA512_HASH_SZ ];
  memset( m_prime, 0, 8UL );
  fd_rsa_hash( hash, msg, msg_sz, m_prime+8UL );
  memcpy( m_prime+8UL+h_sz, salt, s_sz );
  uchar h_prime[ FD_SHA512_HASH_SZ ];
  fd_rsa_hash( hash, m_prime, 8UL+h_sz+s_sz, h_prime );

  return fd_memeq( h_prime, h, h_sz ) ? FD_RSA_SUCCESS : FD_RSA_FAILURE;
}
