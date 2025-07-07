#ifndef HEADER_fd_src_discof_repair_fd_store_h
#define HEADER_fd_src_discof_repair_fd_store_h

/* fd_store is a high-performance in-memory storage engine for shreds as
   they are received from the network.

   The elements in the store themselves are not shreds, but FEC set
   payloads.  Briefly, FEC sets are groupings of shreds that encode the
   same data but provide redundancy and security.  While Firedancer
   receives individual shreds over Turbine / Repair (the relevant Solana
   protocols), a lot of Firedancer's validation of those shreds can only
   be done at the FEC set boundary.  Also, there are potential future
   protocol changes to encode all shreds in a FEC set so that they can
   only be decoded once the entire FEC set is received ("all-coding").

   Therefore, the FEC set becomes the logical unit for the store vs.
   individual shreds.  Replay will only ever attempt replay of a FEC set
   so there is no need to store at the granularity of individual shreds.
   The store is essentially a mapping of merkle root->FEC set payload,
   in which the merkle root was produced by feeding every shred in a FEC
   set into a merkle tree.  This uniquely identifies a FEC set, because
   if any of the shreds change, the merkle root changes.

   Shreds are coalesced and inserted into the store as bytes.  The max
   bytes per FEC set is currently variable-length but capped at 63985.
   In the future this will be fixed to 31840 bytes, when FEC sets are
   enforced to always be 32 shreds.

   The API is designed to be used inter-process (ie. concurrent joins
   from multiple tiles) and also supports concurrent access, but callers
   must interface with the store through a read-write lock (fd_rwlock).

   EQUIVOCATION

   There is a protocol violation called equivocation (also known as
   "duplicates") that results in two or more blocks for the same slot.
   The actual conflict occurs at the shred level: a leader produces two
   or more shreds for the same slot at the same index, with different
   data payloads.  The result will be two different FEC sets for the
   same "logical" FEC set based on (slot, fec_set_idx).

   Unfortunately a naive keying scheme such as (slot, fec_set_idx) is
   insufficient as a result of equivocation.  As mentioned earlier,
   Store instead uses the merkle root as the key for its FEC set
   elements, at the cost of some keying performance and complexity.

   ARCHITECTURE

   In the Firedancer topology, Shred tile writes to store and Replay
   tile reads from store.  Replay tile only reads from the store after
   Repair tile (which is downstream of Shred) has notified Replay that a
   FEC set is ready.  Shred's writes are append-only and Replay is
   responsible for publishing once it is done consuming (signaled by a
   new Tower root).

   Shred (writes) -> Repair (notif) -> Replay (reads, publishes)

   ORDERING

   In the above architecture, it is guaranteed that Repair will deliver
   FEC sets to Replay in replay order.  That is, the parent FEC set will
   always be delivered before the child (see fd_fec_chainer).  Note
   however concurrent forks are delivered in the order they are received
   from the network ie. arbitrary order.

   CONCURRENCY

   It is possible to design Store access in a way that enables parallel
   writes and minimizes lock contention between readers and writers.  In
   this design, writers (Shred tiles) only hold the read lock during
   their access.  The reader (Replay tile) also holds the read lock
   during its access, but given both Shred and Replay will be taking out
   read locks, they will not contend.  "Write lock" is now a bit of a
   misnomer, because the only operation that will actually need the
   write lock is publish, which will be done by Replay.

   For parallel writes, the Store's hash function should be carefully
   constructed to mirror the Shred tiles' (writers') round-robin hashing
   to ensure the property that any slot collision in the underlying
   fd_map_chain will always occur on the same Shred tile.  So if two
   different hashes point to the same slot, it is guaranteed to be the
   same Shred tile processing both keys (and similarly, a hash collision
   would also be processed by the same tile).  This prevents a data race
   in which multiple Shred tiles attempt to write to the same map slot.

   For reducing lock contention, the Store should 1. only be read by
   Replay after Repair has notified Replay it is time to read, and 2. be
   written to by Shred tile(s) in append-only fashion, so Shred never
   modifies or removes what it has written.  Store is backed by a
   fd_map_chain, which is not thread-safe generally, but in the case of
   a slot collision where Replay tile is reading an element and Shred
   tile writes a new element to the same slot, that new element is
   always appended to the end of the hash chain within that slot (which
   modifies the second-to-last element in the hash chain's `.next` field
   but does not touch application data).  So this can enable lock-free
   concurrent reads and writes.  Note Replay tile (reader) should always
   use fd_store_query_const to ensure the underlying fd_map_chain is not
   modified during querying.

   The exception to the above is publishing.  Publishing requires the
   write lock to ensure the tile doing the publishing (Replay tile) is
   the only thing accessing the store.  Publishing happens at most once
   per slot, so it is a relatively infrequent Store access compared to
   FEC queries and inserts. */

#include "../../flamenco/fd_rwlock.h"
#include "../../flamenco/types/fd_types_custom.h"

/* FD_STORE_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_STORE_USE_HANDHOLDING
#define FD_STORE_USE_HANDHOLDING 1
#endif

/* FD_STORE_ALIGN specifies the alignment needed for store.  ALIGN is
   double x86 cache line to mitigate various kinds of false sharing (eg.
   ACLPF adjacent cache line prefetch). */

#define FD_STORE_ALIGN (128UL)

/* FD_STORE_MAGIC is a magic number for detecting store corruption. */

#define FD_STORE_MAGIC (0xf17eda2ce75702e0UL) /* firedancer store version 0 */

/* FD_STORE_DATA_MAX defines a constant for the maximum size of a FEC
   set payload.  The value is computed from the maximum number
   of shreds in a FEC set * the payload bytes per shred.

   67 shreds per FEC set * 955 payloads per shred = 63985 bytes max. */

#define FD_STORE_DATA_MAX (63985UL) /* FIXME fixed-32 */

/* fd_store_fec describes a store element (FEC set).  The pointer fields
   implement a left-child, right-sibling n-ary tree. */

struct __attribute__((aligned(128UL))) fd_store_fec {

  /* Keys */

  fd_hash_t key; /* map key, merkle root of the FEC set */
  fd_hash_t cmr; /* parent's map key, chained merkle root of the FEC set */

  /* Pointers */

  ulong next;    /* reserved for internal use by fd_pool, fd_map_chain, orphan list */
  ulong parent;  /* pool idx of the parent */
  ulong child;   /* pool idx of the left-child */
  ulong sibling; /* pool idx of the right-sibling */

  /* Data */

  ulong data_sz;                 /* FIXME fixed-32. sz of the FEC set payload, guaranteed < FD_STORE_DATA_MAX */
  uchar data[FD_STORE_DATA_MAX]; /* FEC set payload = coalesced data shreds (byte array) */
};
typedef struct fd_store_fec fd_store_fec_t;

#define POOL_NAME fd_store_pool
#define POOL_T    fd_store_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_store_map
#define MAP_ELE_T              fd_store_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

struct fd_store {
  ulong magic;       /* ==FD_STORE_MAGIC */
  ulong seed;        /* seed for various hashing function used under the hood, arbitrary */
  ulong root;        /* pool idx of the root */
  ulong store_gaddr; /* wksp gaddr of store in the backing wksp, non-zero gaddr */
  ulong pool_gaddr;  /* wksp gaddr of pool of store elements (fd_store_fec) */
  ulong map_gaddr;   /* wksp gaddr of map of fd_store_key->fd_store_fec */

  fd_rwlock_t lock; /* rwlock for concurrent access */
};
typedef struct fd_store fd_store_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_store_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as store with up to
   fec_max elements. */

FD_FN_CONST static inline ulong
fd_store_align( void ) {
  return alignof(fd_store_t);
}

FD_FN_CONST static inline ulong
fd_store_footprint( ulong fec_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_store_t),   sizeof(fd_store_t)                 ),
      fd_store_pool_align(), fd_store_pool_footprint( fec_max ) ),
      fd_store_map_align(),  fd_store_map_footprint( fec_max )  ),
    fd_store_align() );
}

/* fd_store_new formats an unused memory region for use as a store.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_store_new( void * shmem, ulong fec_max, ulong seed );

/* fd_store_join joins the caller to the store.  store points to the
   first byte of the memory region backing the store in the caller's
   address space.

   Returns a pointer in the local address space to store on success. */

fd_store_t *
fd_store_join( void * store );

/* fd_store_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include store is NULL. */

void *
fd_store_leave( fd_store_t const * store );

/* fd_store_delete unformats a memory region used as a store.
   Assumes only the nobody is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. store is obviously not a store ... logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_store_delete( void * store );

/* Accessors */

/* fd_store_wksp returns the local join to the wksp backing the store.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes store is a current local
   join. */

FD_FN_PURE static inline fd_wksp_t *
fd_store_wksp( fd_store_t const * store ) {
  return (fd_wksp_t *)( ( (ulong)store ) - store->store_gaddr );
}

/* fd_store_{pool,map} returns a pointer in the caller's address space
   to the corresponding store field.  const versions for each are also
   provided. */

FD_FN_PURE static inline fd_store_fec_t       * fd_store_pool        ( fd_store_t       * store ) { return fd_wksp_laddr_fast     ( fd_store_wksp      ( store ), store->pool_gaddr ); }
FD_FN_PURE static inline fd_store_fec_t const * fd_store_pool_const  ( fd_store_t const * store ) { return fd_wksp_laddr_fast     ( fd_store_wksp      ( store ), store->pool_gaddr ); }
FD_FN_PURE static inline fd_store_map_t       * fd_store_map         ( fd_store_t       * store ) { return fd_wksp_laddr_fast     ( fd_store_wksp      ( store ), store->map_gaddr  ); }
FD_FN_PURE static inline fd_store_map_t const * fd_store_map_const   ( fd_store_t const * store ) { return fd_wksp_laddr_fast     ( fd_store_wksp      ( store ), store->map_gaddr  ); }
FD_FN_PURE static inline fd_store_fec_t       * fd_store_root        ( fd_store_t       * store ) { return fd_store_pool_ele      ( fd_store_pool      ( store ), store->root       ); }
FD_FN_PURE static inline fd_store_fec_t const * fd_store_root_const  ( fd_store_t const * store ) { return fd_store_pool_ele_const( fd_store_pool_const( store ), store->root       ); }

/* fd_store_{parent,child,sibling} returns a pointer in the caller's
   address space to the corresponding {parent,left-child,right-sibling}
   of fec.  Assumes store is a current local join and fec is a valid
   pointer to a pool element inside store.  const versions for each are
   also provided. */

FD_FN_PURE static inline fd_store_fec_t       * fd_store_parent       ( fd_store_t       * store, fd_store_fec_t const * fec ) { return fd_store_pool_ele      ( fd_store_pool      ( store ), fec->parent  ); }
FD_FN_PURE static inline fd_store_fec_t const * fd_store_parent_const ( fd_store_t const * store, fd_store_fec_t const * fec ) { return fd_store_pool_ele_const( fd_store_pool_const( store ), fec->parent  ); }
FD_FN_PURE static inline fd_store_fec_t       * fd_store_child        ( fd_store_t       * store, fd_store_fec_t const * fec ) { return fd_store_pool_ele      ( fd_store_pool      ( store ), fec->child   ); }
FD_FN_PURE static inline fd_store_fec_t const * fd_store_child_const  ( fd_store_t const * store, fd_store_fec_t const * fec ) { return fd_store_pool_ele_const( fd_store_pool_const( store ), fec->child   ); }
FD_FN_PURE static inline fd_store_fec_t       * fd_store_sibling      ( fd_store_t       * store, fd_store_fec_t const * fec ) { return fd_store_pool_ele      ( fd_store_pool      ( store ), fec->sibling ); }
FD_FN_PURE static inline fd_store_fec_t const * fd_store_sibling_const( fd_store_t const * store, fd_store_fec_t const * fec ) { return fd_store_pool_ele_const( fd_store_pool_const( store ), fec->sibling ); }

/* fd_store_{query,query_const} queries the FEC set keyed by merkle.
   Returns a pointer to the fd_store_fec_t if found, NULL otherwise.

   Assumes caller has already acquired a read lock via fd_rwlock_read.

   IMPORTANT SAFETY TIP!  Caller should only call fd_rwlock_unread when
   they no longer retain interest in the returned pointer. */

FD_FN_PURE static inline fd_store_fec_t *
fd_store_query( fd_store_t * store, fd_hash_t * merkle_root ) {
   return fd_store_map_ele_query( fd_store_map( store ), merkle_root, NULL, fd_store_pool( store ) );
}

FD_FN_PURE static inline fd_store_fec_t const *
fd_store_query_const( fd_store_t const * store, fd_hash_t * merkle_root ) {
   return fd_store_map_ele_query_const( fd_store_map_const( store ), merkle_root, NULL, fd_store_pool_const( store ) );
}

/* Operations */

/* fd_store_insert inserts a new FEC set keyed by merkle.  Returns the
   newly inserted fd_store_fec_t.  Copies data and data_sz into its
   corresponding fields and copies at most FD_STORE_DATA_MAX bytes from
   data (if handholding is enabled, it will abort the caller with a
   descriptive error message if data_sz is too large).

   Assumes store is a current local join and has space for another
   element.  Does additional checks when handholding is enabled and
   fails insertion (returning NULL) if checks fail.  If this is the
   first element being inserted into store, the store root will be set
   to this newly inserted element.

   Assumes caller has already acquired the appropriate lock via
   fd_rwlock_read or fd_rwlock_write.  See top-level documentation for
   why this operation may only require a read lock and not a write.

   IMPORTANT SAFETY TIP!  Caller should only call fd_rwlock_unread when
   they no longer retain interest in the returned pointer. */

fd_store_fec_t *
fd_store_insert( fd_store_t * store,
                 fd_hash_t  * merkle_root,
                 uchar      * data,
                 ulong        data_sz /* FIXME fixed-32 */ );

/* fd_store_link queries for and links the child keyed by merkle_root to
   parent keyed by chained_merkle_root.  Returns a pointer to the child.
   Assumes merkle_root and chained_merkle_root are both non-NULL and key
   elements currently in the store.  Does not require the lock. */

fd_store_fec_t *
fd_store_link( fd_store_t * store,
               fd_hash_t  * merkle_root,
               fd_hash_t  * chained_merkle_root );

/* fd_store_publish publishes merkle_root as the new store root, pruning
   all elements across branches that do not descend from the new root.
   Returns a pointer to the new root.  Assumes merkle_root is in the
   store and connected to the root (if handholding is enabled does
   additional checks and returns NULL on error).  Note pruning can
   result in store elements greater than the new root slot being
   removed.  These are elements that become orphaned as a result of the
   common ancestor with the new root being removed (the entire branch
   ie. fork is pruned).

   For example, in the tree (preorder) [0 1 2 4 3 5 6] publishing 2 will
   result in [0 1] being removed given they are ancestors of 2, and
   removing 1 will leave [3 5 6] orphaned and also removed.

   Assumes caller has already acquired a write lock via fd_rwlock_write.

   IMPORTANT SAFETY TIP!  Caller should only call fd_rwlock_unwrite when
   they no longer retain interest in the returned pointer. */

fd_store_fec_t *
fd_store_publish( fd_store_t * store,
                  fd_hash_t  * merkle_root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_repair_fd_store_h */
