#ifndef HEADER_fd_src_funk_fd_funk_base_h
#define HEADER_fd_src_funk_fd_funk_base_h

/* Funk terminology / concepts:

   - A funk instance stores records.

   - A record is a key-value pair.

   - keys are a fixed length fd_funk_rec_key_t.

   - values are variable size arbitrary binary data with an upper bound
     to the size.

   - Records are indexed by key.

   - A funk transaction describes changes to the funk records.

   - A transactions has a globally unique identifier and a parent
     transaction.

   - Transactions with children cannot be modified.

   - The chain of transactions through a transaction's ancestors
     (its parent, grandparent, great-grandparent, ...) provides a
     history of the funk all the way back the "root" transaction.

   - A transaction can be either in preparation or published.

   - The ancestors of a published transaction cannot be modified.

   - In preparation transactions can be cancelled.

   - Cancelling a transaction will discard all funk record updates for
     that transaction and any descendant transactions.

   - Published transactions cannot be cancelled.

   - Critically, competing/parallel transaction histories are allowed.

   - A user can update all funk records for the most recently
     published transactions (if it is not frozen) or all transactions
     in preparation (if they are not frozen). */

#include "../util/fd_util.h"
#include "../util/valloc/fd_valloc.h"

/* FD_FUNK_SUCCESS is used by various APIs to indicate the operation
   successfully completed.  This will be 0.  FD_FUNK_ERR_* gives a
   number of error codes used by fd_funk APIs.  These will be negative
   integers. */

#define FD_FUNK_SUCCESS    (0)  /* Success */
#define FD_FUNK_ERR_INVAL  (-1) /* Failed due to obviously invalid inputs */
#define FD_FUNK_ERR_XID    (-2) /* Failed due to transaction id issue (e.g. xid present/absent when it should be absent/present) */
#define FD_FUNK_ERR_KEY    (-3) /* Failed due to record key issue (e.g. key present/absent when it should be absent/present) */
#define FD_FUNK_ERR_FROZEN (-4) /* Failed due to frozen issue (e.g. attempt to change records in a frozen transaction) */
#define FD_FUNK_ERR_TXN    (-5) /* Failed due to transaction map issue (e.g. funk txn_max too small) */
#define FD_FUNK_ERR_REC    (-6) /* Failed due to record map issue (e.g. funk rec_max too small) */
#define FD_FUNK_ERR_MEM    (-7) /* Failed due to wksp issue (e.g. wksp too small) */
#define FD_FUNK_ERR_SYS    (-8) /* Failed system call (e.g. a file write) */
#define FD_FUNK_ERR_PURIFY (-9) /* fd_funk_purify failed. */

/* FD_FUNK_REC_KEY_{ALIGN,FOOTPRINT} describe the alignment and
   footprint of a fd_funk_rec_key_t.  ALIGN is a positive integer power
   of 2.  FOOTPRINT is a multiple of ALIGN.  These are provided to
   facilitate compile time declarations. */

#define FD_FUNK_REC_KEY_ALIGN     (8UL)
#define FD_FUNK_REC_KEY_FOOTPRINT (40UL) /* 32 byte hash + 8 byte meta */

/* A fd_funk_rec_key_t identifies a funk record.  Compact binary keys
   are encouraged but a cstr can be used so long as it has
   strlen(cstr)<FD_FUNK_REC_KEY_FOOTPRINT and the characters c[i] for i
   in [strlen(cstr),FD_FUNK_REC_KEY_FOOTPRINT) zero.  (Also, if encoding
   a cstr in a key, recommend using first byte to encode the strlen for
   accelerating cstr operations further but this is up to the user.) */

union __attribute__((aligned(FD_FUNK_REC_KEY_ALIGN))) fd_funk_rec_key {
  uchar uc[ FD_FUNK_REC_KEY_FOOTPRINT ];
  uint  ui[ 10 ];
  ulong ul[  5 ];
};

typedef union fd_funk_rec_key fd_funk_rec_key_t;

/* FD_FUNK_TXN_XID_{ALIGN,FOOTPRINT} describe the alignment and
   footprint of a fd_funk_txn_xid_t.  ALIGN is a positive integer power
   of 2.  FOOTPRINT is a multiple of ALIGN.  These are provided to
   facilitate compile time declarations. */

#define FD_FUNK_TXN_XID_ALIGN     (8UL)
#define FD_FUNK_TXN_XID_FOOTPRINT (16UL)

/* A fd_funk_txn_xid_t identifies a funk transaction currently in
   preparation.  Compact binary identifiers are encouraged but a cstr
   can be used so long as it has
   strlen(cstr)<FD_FUNK_TXN_XID_FOOTPRINT and characters c[i] for i
   in [strlen(cstr),FD_FUNK_TXN_KEY_FOOTPRINT) zero.  (Also, if
   encoding a cstr in a transaction id, recommend using first byte to
   encode the strlen for accelerating cstr operations even further but
   this is more up to the application.) */

union __attribute__((aligned(FD_FUNK_TXN_XID_ALIGN))) fd_funk_txn_xid {
  uchar uc[ FD_FUNK_TXN_XID_FOOTPRINT ];
  ulong ul[ FD_FUNK_TXN_XID_FOOTPRINT / sizeof(ulong) ];
};

typedef union fd_funk_txn_xid fd_funk_txn_xid_t;

/* FD_FUNK_XID_KEY_PAIR_{ALIGN,FOOTPRINT} describe the alignment and
   footprint of a fd_funk_xid_key_pair_t.  ALIGN is a positive integer
   power of 2.  FOOTPRINT is a multiple of ALIGN.  These are provided to
   facilitate compile time declarations. */

#define FD_FUNK_XID_KEY_PAIR_ALIGN     (8UL)
#define FD_FUNK_XID_KEY_PAIR_FOOTPRINT (56UL)

/* A fd_funk_xid_key_pair_t identifies a funk record.  It is just
   xid and key packed into the same structure. */

struct fd_funk_xid_key_pair {
  fd_funk_txn_xid_t xid[1];
  fd_funk_rec_key_t key[1];
};

typedef struct fd_funk_xid_key_pair fd_funk_xid_key_pair_t;

/* A fd_funk_shmem_t is the top part of a funk object in shared memory. */

struct fd_funk_shmem_private;
typedef struct fd_funk_shmem_private fd_funk_shmem_t;

/* A fd_funk_t * is local join handle to a funk instance */

struct fd_funk_private;
typedef struct fd_funk_private fd_funk_t;

FD_PROTOTYPES_BEGIN

/* fd_funk_rec_key_hash provides a family of hashes that hash the key
   pointed to by k to a uniform quasi-random 64-bit integer.  seed
   selects the particular hash function to use and can be an arbitrary
   64-bit value.  Returns the hash.  The hash functions are high quality
   but not cryptographically secure.  Assumes k is in the caller's
   address space and valid. */

#if FD_HAS_INT128

/* If the target supports uint128, fd_funk_rec_key_hash is seeded
   xxHash3 with 64-bit output size. (open source BSD licensed) */

static inline ulong
fd_xxh3_mul128_fold64( ulong lhs, ulong rhs ) {
  uint128 product = (uint128)lhs * (uint128)rhs;
  return (ulong)product ^ (ulong)( product>>64 );
}

static inline ulong
fd_xxh3_mix16b( ulong i0, ulong i1,
             ulong s0, ulong s1,
             ulong seed ) {
  return fd_xxh3_mul128_fold64( i0 ^ (s0 + seed), i1 ^ (s1 - seed) );
}

FD_FN_PURE static inline ulong
fd_funk_rec_key_hash1( uchar const key[ 32 ],
                       ulong       rec_type,
                       ulong       seed ) {
  seed ^= rec_type;
  ulong k0 = FD_LOAD( ulong, key+ 0 );
  ulong k1 = FD_LOAD( ulong, key+ 8 );
  ulong k2 = FD_LOAD( ulong, key+16 );
  ulong k3 = FD_LOAD( ulong, key+24 );
  ulong acc = 32 * 0x9E3779B185EBCA87ULL;
  acc += fd_xxh3_mix16b( k0, k1, 0xbe4ba423396cfeb8UL, 0x1cad21f72c81017cUL, seed );
  acc += fd_xxh3_mix16b( k2, k3, 0xdb979083e96dd4deUL, 0x1f67b3b7a4a44072UL, seed );
  acc = acc ^ (acc >> 37);
  acc *= 0x165667919E3779F9ULL;
  acc = acc ^ (acc >> 32);
  return acc;
}

FD_FN_PURE static inline ulong
fd_funk_rec_key_hash( fd_funk_rec_key_t const * k,
                      ulong                     seed ) {
  seed ^= k->ul[4];
  /* tons of ILP */
  return (fd_ulong_hash( seed ^ (1UL<<0) ^ k->ul[0] ) ^ fd_ulong_hash( seed ^ (1UL<<1) ^ k->ul[1] ) ) ^
         (fd_ulong_hash( seed ^ (1UL<<2) ^ k->ul[2] ) ^ fd_ulong_hash( seed ^ (1UL<<3) ^ k->ul[3] ) );
}

#else

/* If the target does not support xxHash3, fallback to the 'old' funk
   key hash function.

   FIXME This version is vulnerable to HashDoS */

FD_FN_PURE static inline ulong
fd_funk_rec_key_hash1( uchar const key[ 32 ],
                       ulong       rec_type,
                       ulong       seed ) {
  seed ^= rec_type;
  /* tons of ILP */
  return (fd_ulong_hash( seed ^ (1UL<<0) ^ FD_LOAD( ulong, key+ 0 ) )   ^
          fd_ulong_hash( seed ^ (1UL<<1) ^ FD_LOAD( ulong, key+ 8 ) ) ) ^
         (fd_ulong_hash( seed ^ (1UL<<2) ^ FD_LOAD( ulong, key+16 ) ) ^
          fd_ulong_hash( seed ^ (1UL<<3) ^ FD_LOAD( ulong, key+24 ) ) );
}

FD_FN_PURE static inline ulong
fd_funk_rec_key_hash( fd_funk_rec_key_t const * k,
                      ulong                     seed ) {
  return fd_funk_rec_key_hash1( k->uc, k->ul[4], seed );
}

#endif /* FD_HAS_INT128 */

/* fd_funk_rec_key_eq returns 1 if keys pointed to by ka and kb are
   equal and 0 otherwise.  Assumes ka and kb are in the caller's address
   space and valid. */

FD_FN_UNUSED FD_FN_PURE static int /* Workaround -Winline */
fd_funk_rec_key_eq( fd_funk_rec_key_t const * ka,
                       fd_funk_rec_key_t const * kb ) {
  ulong const * a = ka->ul;
  ulong const * b = kb->ul;
  return !( ((a[0]^b[0]) | (a[1]^b[1])) | ((a[2]^b[2]) | (a[3]^b[3])) | (a[4]^b[4]) ) ;
}

/* fd_funk_rec_key_copy copies the key pointed to by ks into the key
   pointed to by kd and returns kd.  Assumes kd and ks are in the
   caller's address space and valid. */

static inline fd_funk_rec_key_t *
fd_funk_rec_key_copy( fd_funk_rec_key_t *       kd,
                         fd_funk_rec_key_t const * ks ) {
  ulong *       d = kd->ul;
  ulong const * s = ks->ul;
  d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = s[3]; d[4] = s[4];
  return kd;
}

/* fd_funk_txn_xid_hash provides a family of hashes that hash the xid
   pointed to by x to a uniform quasi-random 64-bit integer.  seed
   selects the particular hash function to use and can be an arbitrary
   64-bit value.  Returns the hash.  The hash functions are high quality
   but not cryptographically secure.  Assumes x is in the caller's
   address space and valid. */

FD_FN_UNUSED FD_FN_PURE static ulong /* Work around -Winline */
fd_funk_txn_xid_hash( fd_funk_txn_xid_t const * x,
                         ulong                     seed ) {
  return ( fd_ulong_hash( seed ^ (1UL<<0) ^ x->ul[0] ) ^ fd_ulong_hash( seed ^ (1UL<<1) ^ x->ul[1] ) ); /* tons of ILP */
}

/* fd_funk_txn_xid_eq returns 1 if transaction id pointed to by xa and
   xb are equal and 0 otherwise.  Assumes xa and xb are in the caller's
   address space and valid. */

FD_FN_PURE static inline int
fd_funk_txn_xid_eq( fd_funk_txn_xid_t const * xa,
                       fd_funk_txn_xid_t const * xb ) {
  ulong const * a = xa->ul;
  ulong const * b = xb->ul;
  return !( (a[0]^b[0]) | (a[1]^b[1]) );
}

/* fd_funk_txn_xid_copy copies the transaction id pointed to by xs into
   the transaction id pointed to by xd and returns xd.  Assumes xd and
   xs are in the caller's address space and valid. */

static inline fd_funk_txn_xid_t *
fd_funk_txn_xid_copy( fd_funk_txn_xid_t *       xd,
                         fd_funk_txn_xid_t const * xs ) {
  ulong *       d = xd->ul;
  ulong const * s = xs->ul;
  d[0] = s[0]; d[1] = s[1];
  return xd;
}

/* fd_funk_txn_xid_eq_root returns 1 if transaction id pointed to by x
   is the root transaction.  Assumes x is in the caller's address space
   and valid. */

FD_FN_PURE static inline int
fd_funk_txn_xid_eq_root( fd_funk_txn_xid_t const * x ) {
  ulong const * a = x->ul;
  return !(a[0] | a[1]);
}

/* fd_funk_txn_xid_set_root sets transaction id pointed to by x to the
   root transaction and returns x.  Assumes x is in the caller's address
   space and valid. */

static inline fd_funk_txn_xid_t *
fd_funk_txn_xid_set_root( fd_funk_txn_xid_t * x ) {
  ulong * a = x->ul;
  a[0] = 0UL; a[1] = 0UL;
  return x;
}

/* fd_funk_xid_key_pair_hash produces a 64-bit hash case for a
   xid_key_pair. Assumes p is in the caller's address space and valid. */

FD_FN_PURE static inline ulong
fd_funk_xid_key_pair_hash( fd_funk_xid_key_pair_t const * p,
                              ulong                          seed ) {
  /* We ignore the xid part of the key because we need all the instances
     of a given record key to appear in the same hash
     chain. fd_funk_rec_query_global depends on this. */
  return fd_funk_rec_key_hash( p->key, seed );
}

/* fd_funk_xid_key_pair_eq returns 1 if (xid,key) pair pointed to by pa
   and pb are equal and 0 otherwise.  Assumes pa and pb are in the
   caller's address space and valid. */

FD_FN_UNUSED FD_FN_PURE static int /* Work around -Winline */
fd_funk_xid_key_pair_eq( fd_funk_xid_key_pair_t const * pa,
                            fd_funk_xid_key_pair_t const * pb ) {
  return fd_funk_txn_xid_eq( pa->xid, pb->xid ) & fd_funk_rec_key_eq( pa->key, pb->key );
}

/* fd_funk_xid_key_pair_copy copies the (xid,key) pair pointed to by ps
   into the (xid,key) pair to by pd and returns pd.  Assumes pd and ps
   are in the caller's address space and valid. */

static inline fd_funk_xid_key_pair_t *
fd_funk_xid_key_pair_copy( fd_funk_xid_key_pair_t *       pd,
                              fd_funk_xid_key_pair_t const * ps ) {
  fd_funk_txn_xid_copy( pd->xid, ps->xid );
  fd_funk_rec_key_copy( pd->key, ps->key );
  return pd;
}

/* fd_funk_xid_key_pair_init set the (xid,key) pair p to pair formed
   from the transaction id pointed to by x and the record key pointed to
   by k.  Assumes p, x and k are in the caller's address space and
   valid. */

static inline fd_funk_xid_key_pair_t *
fd_funk_xid_key_pair_init( fd_funk_xid_key_pair_t *  p,
                              fd_funk_txn_xid_t const * x,
                              fd_funk_rec_key_t const * k ) {
  fd_funk_txn_xid_copy( p->xid, x );
  fd_funk_rec_key_copy( p->key, k );
  return p;
}

/* fd_funk_strerror converts an FD_FUNK_SUCCESS / FD_FUNK_ERR_* code
   into a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_funk_strerror( int err );

/* TODO: Consider renaming transaction/txn to update (too much typing)?
   upd (probably too similar to UDP) node? block? blk? state? commit?
   ... to reduce naming collisions with terminology in use elsewhere?

   TODO: Consider fine tuning {REC,TXN}_{ALIGN,FOOTPRINT} to balance
   application use cases with in memory packing with AVX / CPU cache
   friendly accelerability.  Likewise, virtually everything in here can
   be AVX accelerated if desired.  E.g. 8 uint hash in parallel then an
   8 wide xor lane reduction tree in hash?

   TODO: Consider letting the user provide alternatives for record and
   transaction hashes at compile time (e.g. ids in blockchain apps are
   often already crypto secure hashes in which case x->ul[0] ^ seed is
   just as good theoretically and faster practically). */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_base_h */
