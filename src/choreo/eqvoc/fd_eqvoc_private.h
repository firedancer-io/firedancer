#ifndef HEADER_fd_src_choreo_eqvoc_fd_eqvoc_private_h
#define HEADER_fd_src_choreo_eqvoc_fd_eqvoc_private_h

#include "fd_eqvoc.h"

typedef struct {
  ulong key;  /* 32 bits = slot | 32 lsb = fec_set_idx  */
  ulong next; /* reserved for map_chain */
  union {
    fd_shred_t shred;
    uchar      bytes[FD_SHRED_MAX_SZ]; /* entire shred, both header and payload */
  };
} shred_t;

#define POOL_NAME shred_pool
#define POOL_T    shred_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           shred_map
#define MAP_ELE_T                          shred_t
#include "../../util/tmpl/fd_map_chain.c"

#define DEQUE_NAME shred_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

typedef struct {
  ulong      slot;
  ulong      prev;
  ulong      next;
  int        err; /* zero = no proof, positive = proof */
  union {
    fd_shred_t shred;
    uchar      bytes[FD_SHRED_MIN_SZ]; /* entire shred, both header and payload */
  } shred;
} slot_t;

#define POOL_NAME slot_pool
#define POOL_T    slot_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           slot_map
#define MAP_ELE_T                          slot_t
#define MAP_KEY                            slot
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DEQUE_NAME slot_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

typedef struct {
  ulong       slot;
  fd_pubkey_t from;
} xid_t;

/* fd_eqvoc_proof describes an equivocation proof.  Its structure is two
   shreds that demonstrate the leader must have produced two versions of
   a given block, because the shreds conflict in some way.

   Proofs are encoded into Gossip "DuplicateShred" messages, laid out as
   follows:

   ---------
   shred1_sz
   ---------
   shred1
   ---------
   shred2_sz
   ---------
   shred2
   ---------

   Note each shred is prepended with its size in bytes. */

struct fd_eqvoc_proof {
  xid_t key;
  ulong prev; /* reserved for map_chain */
  ulong next; /* reserved for map_chain */
  uchar idxs; /* [0, 7]. bit vec encoding which of the chunk idxs have been received (at most FD_EQVOC_CHUNK_CNT = 3). */
  uchar buf[2 * FD_SHRED_MAX_SZ + 2 * sizeof(ulong)];
  ulong buf_sz;
};
typedef struct fd_eqvoc_proof fd_eqvoc_proof_t;

#define POOL_NAME proof_pool
#define POOL_T    fd_eqvoc_proof_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           proof_map
#define MAP_ELE_T                          fd_eqvoc_proof_t
#define MAP_KEY_T                          xid_t
#define MAP_KEY_EQ(k0,k1)                  ((((k0)->slot)==((k1)->slot)) & !(memcmp(((k0)->from.uc),((k1)->from.uc),sizeof(fd_pubkey_t))))
#define MAP_KEY_HASH(key,seed)             fd_ulong_hash( ((key)->slot) ^ ((key)->from.ul[0]) ^ (seed) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DEQUE_NAME proof_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct from {
  fd_pubkey_t from;
  uint        hash;
  ulong *     proofs; /* deque of proofs, FIFO order. this is the slot number, can lookup proof via proof_map key (slot, from) */
};
typedef struct from from_t;

#define MAP_NAME               from_map
#define MAP_T                  from_t
#define MAP_KEY                from
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           pubkey_null
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_INVAL(k)       MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)   (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key,seed) ((MAP_HASH_T)( (key).ul[1] )) /* FIXME: use seed? */
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_eqvoc {

  /* copy */

  ulong       shred_max;
  ulong       slot_max;
  ulong       from_max;
  ulong       shred_version; /* eqvoc will ignore shreds or chunks with different shred versions */

  /* owned */

  fd_sha512_t *      sha512;
  void *             bmtree_mem;
  shred_t *          shred_pool;
  shred_map_t *      shred_map;
  ulong *            shred_deque;
  slot_t *           slot_pool;
  slot_map_t *       slot_map;
  ulong *            slot_deque;
  fd_eqvoc_proof_t * proof_pool;
  proof_map_t *      proof_map;
  from_t *           from_map;

  /* borrowed */

  fd_epoch_leaders_t const * leaders;
};
typedef struct fd_eqvoc fd_eqvoc_t;

/* The below APIs are exposed for tests. */

void
construct_proof( fd_shred_t const *          shred1,
                 fd_shred_t const *          shred2,
                 fd_gossip_duplicate_shred_t chunks_out[static FD_EQVOC_CHUNK_CNT] );

int
verify_proof( fd_eqvoc_t const * eqvoc,
              fd_shred_t const * shred1,
              fd_shred_t const * shred2 );

#endif /* HEADER_fd_src_choreo_eqvoc_fd_eqvoc_private_h */
