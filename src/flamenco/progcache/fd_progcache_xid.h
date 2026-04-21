#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h

#include "../../util/bits/fd_bits.h"

#include <immintrin.h>

#define FD_PROGCACHE_TXN_IDX_NULL ((ulong)UINT_MAX)

/* FD_PROGCACHE_REC_KEY_{ALIGN,FOOTPRINT} describe the alignment and
   footprint of a fd_progcache_rec_key_t.  ALIGN is a positive integer power
   of 2.  FOOTPRINT is a multiple of ALIGN.  These are provided to
   facilitate compile time declarations. */

#define FD_PROGCACHE_REC_KEY_ALIGN     (8UL)
#define FD_PROGCACHE_REC_KEY_FOOTPRINT (32UL)

/* A fd_progcache_rec_key_t identifies a progcache record.  Compact binary keys
   are encouraged but a cstr can be used so long as it has
   strlen(cstr)<FD_PROGCACHE_REC_KEY_FOOTPRINT and the characters c[i] for i
   in [strlen(cstr),FD_PROGCACHE_REC_KEY_FOOTPRINT) zero.  (Also, if encoding
   a cstr in a key, recommend using first byte to encode the strlen for
   accelerating cstr operations further but this is up to the user.) */

union __attribute__((aligned(FD_PROGCACHE_REC_KEY_ALIGN))) fd_progcache_rec_key {
  uchar uc[ FD_PROGCACHE_REC_KEY_FOOTPRINT ];
  uint  ui[ 8 ];
  ulong ul[ 4 ];
};

typedef union fd_progcache_rec_key fd_progcache_rec_key_t;

#define FD_PROGCACHE_TXN_XID_ALIGN     (16UL)
#define FD_PROGCACHE_TXN_XID_FOOTPRINT (16UL)

union __attribute__((aligned(FD_PROGCACHE_TXN_XID_ALIGN))) fd_progcache_xid {
  uchar uc[ FD_PROGCACHE_TXN_XID_FOOTPRINT ];
  ulong ul[ FD_PROGCACHE_TXN_XID_FOOTPRINT / sizeof(ulong) ];
#if FD_HAS_INT128
  uint128 uf[1];
#endif
#if FD_HAS_X86
  __m128i xmm[1];
#endif
};

typedef union fd_progcache_xid fd_progcache_xid_t;

/* FD_PROGCACHE_XID_KEY_PAIR_{ALIGN,FOOTPRINT} describe the alignment and
   footprint of a fd_progcache_xid_key_pair_t.  ALIGN is a positive integer
   power of 2.  FOOTPRINT is a multiple of ALIGN.  These are provided to
   facilitate compile time declarations. */

#define FD_PROGCACHE_XID_KEY_PAIR_ALIGN     (16UL)
#define FD_PROGCACHE_XID_KEY_PAIR_FOOTPRINT (48UL)

/* A fd_progcache_xid_key_pair_t identifies a progcache record.  It is just
   xid and key packed into the same structure. */

struct fd_progcache_xid_key_pair {
  fd_progcache_xid_t xid[1];
  fd_progcache_rec_key_t key[1];
};

typedef struct fd_progcache_xid_key_pair fd_progcache_xid_key_pair_t;

/* fd_progcache_rec_key_hash provides a family of hashes that hash the key
   pointed to by k to a uniform quasi-random 64-bit integer.  seed
   selects the particular hash function to use and can be an arbitrary
   64-bit value.  Returns the hash.  The hash functions are high quality
   but not cryptographically secure.  Assumes k is in the caller's
   address space and valid. */

#if FD_HAS_INT128

/* If the target supports uint128, fd_progcache_rec_key_hash is seeded
   xxHash3 with 64-bit output size. (open source BSD licensed) */

static inline ulong
fd_pc_xxh3_mul128_fold64( ulong lhs, ulong rhs ) {
  uint128 product = (uint128)lhs * (uint128)rhs;
  return (ulong)product ^ (ulong)( product>>64 );
}

static inline ulong
fd_pc_xxh3_mix16b( ulong i0, ulong i1,
                ulong s0, ulong s1,
                ulong seed ) {
  return fd_pc_xxh3_mul128_fold64( i0 ^ (s0 + seed), i1 ^ (s1 - seed) );
}

FD_FN_PURE static inline ulong
fd_progcache_rec_key_hash1( uchar const key[ 32 ],
                            ulong       seed ) {
  ulong k0 = FD_LOAD( ulong, key+ 0 );
  ulong k1 = FD_LOAD( ulong, key+ 8 );
  ulong k2 = FD_LOAD( ulong, key+16 );
  ulong k3 = FD_LOAD( ulong, key+24 );
  ulong acc = 32 * 0x9E3779B185EBCA87ULL;
  acc += fd_pc_xxh3_mix16b( k0, k1, 0xbe4ba423396cfeb8UL, 0x1cad21f72c81017cUL, seed );
  acc += fd_pc_xxh3_mix16b( k2, k3, 0xdb979083e96dd4deUL, 0x1f67b3b7a4a44072UL, seed );
  acc = acc ^ (acc >> 37);
  acc *= 0x165667919E3779F9ULL;
  acc = acc ^ (acc >> 32);
  return acc;
}

FD_FN_PURE static inline ulong
fd_progcache_rec_key_hash( fd_progcache_rec_key_t const * k,
                           ulong                          seed ) {
  return fd_progcache_rec_key_hash1( k->uc, seed );
}

#else

/* If the target does not support xxHash3, fallback to the 'old' key
   hash function.

   FIXME This version is vulnerable to HashDoS */

FD_FN_PURE static inline ulong
fd_progcache_rec_key_hash1( uchar const key[ 32 ],
                            ulong       seed ) {
  /* tons of ILP */
  return (fd_ulong_hash( seed ^ (1UL<<0) ^ FD_LOAD( ulong, key+ 0 ) )   ^
          fd_ulong_hash( seed ^ (1UL<<1) ^ FD_LOAD( ulong, key+ 8 ) ) ) ^
         (fd_ulong_hash( seed ^ (1UL<<2) ^ FD_LOAD( ulong, key+16 ) ) ^
          fd_ulong_hash( seed ^ (1UL<<3) ^ FD_LOAD( ulong, key+24 ) ) );
}

FD_FN_PURE static inline ulong
fd_progcache_rec_key_hash( fd_progcache_rec_key_t const * k,
                           ulong                          seed ) {
  return fd_progcache_rec_key_hash1( k->uc, seed );
}

#endif /* FD_HAS_INT128 */

/* fd_progcache_rec_key_copy copies the key pointed to by ks into the key
   pointed to by kd and returns kd.  Assumes kd and ks are in the
   caller's address space and valid. */

static inline fd_progcache_rec_key_t *
fd_progcache_rec_key_copy( fd_progcache_rec_key_t *       kd,
                           fd_progcache_rec_key_t const * ks ) {
  ulong *       d = kd->ul;
  ulong const * s = ks->ul;
  d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = s[3];
  return kd;
}

static inline fd_progcache_xid_t *
fd_progcache_txn_xid_ld_atomic( fd_progcache_xid_t *       xd,
                                fd_progcache_xid_t const * xs ) {
# if FD_HAS_X86
  xd->xmm[0] = FD_VOLATILE_CONST( xs->xmm[0] );
# elif FD_HAS_INT128
  xd->uf[0] = FD_VOLATILE_CONST( xs->uf[0] );
# else
  fd_progcache_txn_xid_copy( xd, xs );
# endif
  return xd;
}

static inline fd_progcache_xid_t *
fd_progcache_txn_xid_st_atomic( fd_progcache_xid_t *       xd,
                                fd_progcache_xid_t const * xs ) {
# if FD_HAS_X86
  FD_VOLATILE( xd->xmm[0] ) = xs->xmm[0];
# elif FD_HAS_INT128
  FD_VOLATILE( xd->uf[0] ) = xs->uf[0];
# else
  fd_progcache_txn_xid_copy( xd, xs );
# endif
  return xd;
}

/* fd_progcache_xid_key_pair_hash produces a 64-bit hash case for a
   xid_key_pair. Assumes p is in the caller's address space and valid. */

FD_FN_PURE static inline ulong
fd_progcache_xid_key_pair_hash( fd_progcache_xid_key_pair_t const * p,
                                ulong                          seed ) {
  /* We ignore the xid part of the key because we need all the instances
     of a given record key to appear in the same hash
     chain. fd_progcache_rec_query_global depends on this. */
  return fd_progcache_rec_key_hash( p->key, seed );
}

/* fd_progcache_txn_xid_hash provides a family of hashes that hash the xid
   pointed to by x to a uniform quasi-random 64-bit integer.  seed
   selects the particular hash function to use and can be an arbitrary
   64-bit value.  Returns the hash.  The hash functions are high quality
   but not cryptographically secure.  Assumes x is in the caller's
   address space and valid. */

FD_FN_UNUSED FD_FN_PURE static ulong /* Work around -Winline */
fd_progcache_txn_xid_hash( fd_progcache_xid_t const * x,
                           ulong                     seed ) {
  return ( fd_ulong_hash( seed ^ (1UL<<0) ^ x->ul[0] ) ^ fd_ulong_hash( seed ^ (1UL<<1) ^ x->ul[1] ) ); /* tons of ILP */
}

/* fd_progcache_txn_xid_eq returns 1 if transaction id pointed to by xa and
   xb are equal and 0 otherwise.  Assumes xa and xb are in the caller's
   address space and valid. */

FD_FN_PURE static inline int
fd_progcache_txn_xid_eq( fd_progcache_xid_t const * xa,
                         fd_progcache_xid_t const * xb ) {
  ulong const * a = xa->ul;
  ulong const * b = xb->ul;
  return !( (a[0]^b[0]) | (a[1]^b[1]) );
}

/* fd_progcache_txn_xid_copy copies the transaction id pointed to by xs into
   the transaction id pointed to by xd and returns xd.  Assumes xd and
   xs are in the caller's address space and valid. */

static inline fd_progcache_xid_t *
fd_progcache_txn_xid_copy( fd_progcache_xid_t *       xd,
                           fd_progcache_xid_t const * xs ) {
  ulong *       d = xd->ul;
  ulong const * s = xs->ul;
  d[0] = s[0]; d[1] = s[1];
  return xd;
}

/* fd_progcache_txn_xid_eq_root returns 1 if transaction id pointed to by x
   is the root transaction.  Assumes x is in the caller's address space
   and valid. */

FD_FN_PURE static inline int
fd_progcache_txn_xid_eq_root( fd_progcache_xid_t const * x ) {
  ulong const * a = x->ul;
  return ((a[0] == ULONG_MAX) & (a[1] == ULONG_MAX));
}

/* fd_progcache_rec_key_eq returns 1 if keys pointed to by ka and kb are
   equal and 0 otherwise.  Assumes ka and kb are in the caller's address
   space and valid. */

FD_FN_UNUSED FD_FN_PURE static int /* Workaround -Winline */
fd_progcache_rec_key_eq( fd_progcache_rec_key_t const * ka,
                         fd_progcache_rec_key_t const * kb ) {
  ulong const * a = ka->ul;
  ulong const * b = kb->ul;
  return !( ((a[0]^b[0]) | (a[1]^b[1])) | ((a[2]^b[2]) | (a[3]^b[3])) ) ;
}

/* fd_progcache_xid_key_pair_eq returns 1 if (xid,key) pair pointed to by pa
   and pb are equal and 0 otherwise.  Assumes pa and pb are in the
   caller's address space and valid. */

FD_FN_UNUSED FD_FN_PURE static int /* Work around -Winline */
fd_progcache_xid_key_pair_eq( fd_progcache_xid_key_pair_t const * pa,
                              fd_progcache_xid_key_pair_t const * pb ) {
  return fd_progcache_txn_xid_eq( pa->xid, pb->xid ) & fd_progcache_rec_key_eq( pa->key, pb->key );
}

/* fd_progcache_txn_xid_set_root sets transaction id pointed to by x to the
   root transaction and returns x.  Assumes x is in the caller's address
   space and valid. */

static inline fd_progcache_xid_t *
fd_progcache_txn_xid_set_root( fd_progcache_xid_t * x ) {
  ulong * a = x->ul;
  a[0] = ULONG_MAX; a[1] = ULONG_MAX;
  return x;
}

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h */
