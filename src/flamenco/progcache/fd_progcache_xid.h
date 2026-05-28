#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h

#include "../fd_flamenco_base.h"

#define FD_PROGCACHE_TXN_IDX_NULL ((ulong)UINT_MAX)

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

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_xid_h */
