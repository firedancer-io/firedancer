#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h

#include "../fd_flamenco_base.h"
#include "../../funk/fd_funk_base.h"

#if FD_HAS_X86
#include <immintrin.h>
#endif

#define FD_PROGCACHE_TXN_IDX_NULL ((ulong)UINT_MAX)

union __attribute__((aligned(16))) fd_progcache_xid {
  struct {
    ulong slot;
    ulong bank_seq;
  };
  __extension__ unsigned __int128 uf[1];
#if FD_HAS_X86
  __m128i xmm[1];
#endif
};

typedef union fd_progcache_xid fd_progcache_xid_t;

FD_STATIC_ASSERT( sizeof(fd_progcache_xid_t)==16, layout );

/* A fd_progcache_xid_key_pair_t identifies a progcache record.  It is just
   xid and key packed into the same structure. */

struct fd_progcache_xid_key_pair {
  fd_progcache_xid_t xid[1];
  fd_pubkey_t        key[1];
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
fd_progcache_rec_key_hash( fd_pubkey_t const * k,
                           ulong               seed ) {
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
fd_progcache_rec_key_hash( fd_pubkey_t const * k,
                           ulong               seed ) {
  return fd_progcache_rec_key_hash1( k->uc, seed );
}

#endif /* FD_HAS_INT128 */

#if FD_HAS_THREADS

static inline fd_progcache_xid_t *
fd_progcache_xid_ld_atomic( fd_progcache_xid_t *       xd,
                            fd_progcache_xid_t const * xs ) {
# if FD_HAS_X86
  xd->xmm[0] = FD_VOLATILE_CONST( xs->xmm[0] );
# elif FD_HAS_ARM
  fd_arm_ldp16( &xs->slot, xd->slot, xd->bank_seq );
# elif FD_HAS_ATOMIC
  xd->uf[0] = __atomic_load_n( &xs->uf[0], __ATOMIC_RELAXED );
# else
# error "Unsupported architecture"
# endif
  return xd;
}

static inline fd_progcache_xid_t *
fd_progcache_xid_st_atomic( fd_progcache_xid_t *       xd,
                            fd_progcache_xid_t const * xs ) {
# if FD_HAS_X86
  FD_VOLATILE( xd->xmm[0] ) = xs->xmm[0];
# elif FD_HAS_ARM
  fd_arm_stp16( &xd->slot, xs->slot, xs->bank_seq );
# elif FD_HAS_ATOMIC
  __atomic_store_n( &xd->uf[0], xs->uf[0], __ATOMIC_RELEASE );
# else
# error "Unsupported architecture"
# endif
  return xd;
}

#else

static inline fd_progcache_xid_t *
fd_progcache_xid_ld_atomic( fd_progcache_xid_t *       xd,
                            fd_progcache_xid_t const * xs ) {
  *xd = *xs;
  return xd;
}

static inline fd_progcache_xid_t *
fd_progcache_xid_st_atomic( fd_progcache_xid_t *       xd,
                            fd_progcache_xid_t const * xs ) {
  *xd = *xs;
  return xd;
}

#endif

FD_FN_PURE static inline int
fd_progcache_txn_xid_eq( fd_progcache_xid_t const * xa,
                         fd_progcache_xid_t const * xb ) {
  return (xa->slot == xb->slot) & (xa->bank_seq == xb->bank_seq);
}

/* fd_progcache_xid_key_pair_eq returns 1 if (xid,key) pair pointed to by pa
   and pb are equal and 0 otherwise.  Assumes pa and pb are in the
   caller's address space and valid. */

FD_FN_UNUSED FD_FN_PURE static int /* Work around -Winline */
fd_progcache_xid_key_pair_eq( fd_progcache_xid_key_pair_t const * pa,
                              fd_progcache_xid_key_pair_t const * pb ) {
  return fd_progcache_txn_xid_eq( pa->xid, pb->xid ) & fd_pubkey_eq( pa->key, pb->key );
}

/* fd_progcache_xid_from_funk converts a funk transaction id into a
   progcache transaction id.  fd_progcache_xid_t and fd_funk_txn_xid_t
   are byte-compatible 16-byte identifiers; this helper exists to make
   the type boundary explicit at progcache API call sites. */

FD_FN_PURE static inline fd_progcache_xid_t
fd_progcache_xid_from_funk( fd_funk_txn_xid_t const * src ) {
  fd_progcache_xid_t out;
  out.slot     = src->ul[0];
  out.bank_seq = src->ul[1];
  return out;
}

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h */
