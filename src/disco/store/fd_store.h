#ifndef HEADER_fd_src_disco_store_fd_store_h
#define HEADER_fd_src_disco_store_fd_store_h

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

   The shared memory used by a store instance is within a workspace such
   that it is also persistent and remotely inspectable.  Store is
   designed to be used inter-process (allowing concurrent joins from
   multiple tiles), relocated in memory (via wksp operations), and
   accessed concurrently (managing conflicts with a lock).

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

   In the Firedancer topology, Shred tile inserts to store and Replay
   tile queries from store.  Replay tile only queries from the store
   after Shred tile has notified Replay that a FEC set is ready. Shred's
   inserts are append-only and Replay is responsible for removing once
   it is done consuming (signaled by a new Tower root).

   Shred (inserts) -> Replay (queries, removes)

   ORDERING

   In the above architecture, Shred delivers FEC sets to Replay in
   partial order.  Any given fork will be delivered in-order, but
   concurrent forks can be delivered in arbitrary order.  Another way to
   phrase this is a parent FEC set will always be delivered before the
   child (see fd_reasm).

   CONCURRENCY

   It is possible to design Store access in a way that enables parallel
   inserts and minimizes lock contention between readers and writers.
   Store contains a fd_rwlock (read-write lock), but the name is a bit
   of a misnomer because inserts can actually be concurrent and the only
   operation that will actually need the write lock is remove, which
   will be done by Replay.  It is more appropriate to describe as an
   exclusive-shared access lock.

   In this design, writers (Shred tiles) hold the shared lock during
   their access.  The reader (Replay tile) also holds the shared lock
   during its access, and given both Shred and Replay will be taking out
   shared locks, they will not contend.

   For parallel inserts, the Store's hash function is carefully designed
   to partition the keyspace so that the same Shred tile always inserts
   to the same map slots.  This ensures map collisions always happen on
   the same Shred tile and cannot happen across tiles.  Specifically, if
   two different FEC sets hash to the same slot, it is guaranteed that
   to be the same Shred tile processing both those FEC sets.  This
   prevents a data race in which multiple Shred tiles (each with a
   handle to the shared lock) write to the same map slot.

   The hash function is defined as follows:
   ```
   #define MAP_KEY_HASH(key,seed) ((ulong)key->mr.ul[0]%seed + (key)->part_idx*seed)
   ```
   where `key` is a key type that includes the merkle root (32 bytes)
   and the partition index (8 bytes) that is equivalent to the Shred
   tile index doing the insertion.  seed, on initialization, is the
   number of chains/buckets in the map_chain divided by the number of
   partitions.  In effect, seed is the size of each partition.  For
   example, if the map_chain is sized to 1024, and there are 4 shred
   tiles, then the seed is 1024/4 = 256.  Then the map key hash can
   bound the chain index of each partition as such: shred tile 0 will
   write to chains 0-255, shred tile 1 will write to chains 256-511,
   shred tile 2 will write to chains 512-767, and shred tile 3 will
   write to chains 768-1023, without overlap.  The merkle root is a 32
   byte SHA-256 hash, so we can expect a fairly uniform distribution of
   hash values even after truncating to the first 8 bytes, without
   needing to introduce more randomness.  Thus we can repurpose the
   `seed` argument to be the number of partitions.

   Essentially, this allows for limited single-producer single-consumer
   (SPSC) concurrency, where the producer is a given Shred tile and the
   consumer is Replay tile.  The SPSC concurrency is limited in that the
   Store should 1. only be read by Replay after Shred has notified
   Replay it is time to read (ie. Shred has finished writing), and 2. be
   written to by Shred(s) in append-only fashion, so Shred never
   modifies or removes from the map.  Store is backed by fd_map_chain,
   which is not thread-safe generally, but does support this particular
   SPSC concurrency model in cases where the consumer is guaranteed to
   be lagging the producer.

   Analyzing fd_map_chain in gory detail, in the case of a map collision
   where Replay tile is reading an element and Shred tile inserts a new
   element to the same map slot, that new element is prepended to the
   hash chain within that slot (which modifies what the head of the
   chain points to as well as the now-previous head in the hash chain's
   `.next` field, but does not touch application data).  With fencing
   enabled (MAP_INSERT_FENCE), it is guaranteed the consumer either
   queries the head before or after the update.  If it queries before,
   that is safe, it would just check the key (if no match, iterate down
   the chain etc.)  If it queries after, it is also safe because the new
   element is guaranteed to be before the old element in the chain, so
   it would just do one more iteration.  Note the consumer should always
   use fd_store_query_const to ensure the underlying fd_map_chain is not
   modified during querying.

   The exception to the above is removing.  Removing requires exclusive
   access because it involves removing from fd_map_chain, which is not
   safe for shared access.  So the Replay tile should take out the
   exclusive lock.  Removing happens at most once per slot, so it is a
   relatively infrequent Store access compared to FEC queries and
   inserts (which is good because it is also the most expensive). */

#include "../../flamenco/fd_rwlock.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "../../util/hist/fd_histf.h"

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

#define FD_STORE_DATA_MAX (63985UL) /* TODO fixed-32 */

/* fd_store_fec describes a store element (FEC set).  The pointer fields
   implement a left-child, right-sibling n-ary tree. */

struct __attribute__((packed)) fd_store_key {
   fd_hash_t merkle_root;
   ulong     part_idx; /* partition index of the caller of fd_store_insert */
};
typedef struct fd_store_key fd_store_key_t;

struct __attribute__((aligned(FD_STORE_ALIGN))) fd_store_fec {
  fd_store_key_t key;            /* map key, merkle root of the FEC set + a partition index */
  ulong          next;           /* reserved for internal use by fd_pool, fd_map_chain */
  fd_hash_t      cmr;            /* parent's map key, chained merkle root of the FEC set */
  uint           block_offs[32]; /* TODO fixed-32. block_offs[ i ] is the total size of data shreds [0, i] */
  ulong          data_sz;        /* TODO fixed-32. sz of the FEC set payload, guaranteed < FD_STORE_DATA_MAX */
  uchar          data[FD_STORE_DATA_MAX];
};
typedef struct fd_store_fec fd_store_fec_t;

#define POOL_NAME  fd_store_pool
#define POOL_ELE_T fd_store_fec_t
#include "../../util/tmpl/fd_pool_para.c"

#define MAP_NAME               fd_store_map
#define MAP_ELE_T              fd_store_fec_t
#define MAP_KEY_T              fd_store_key_t
#define MAP_KEY                key
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) ((ulong)key->merkle_root.ul[0]%seed + (key)->part_idx*seed) /* see top-level documentation of hash function */
#define MAP_INSERT_FENCE       1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_store {
  ulong magic;          /* ==FD_STORE_MAGIC */
  ulong fec_max;        /* max number of FEC sets that can be stored */
  ulong part_cnt;       /* number of partitions, also the number of writers */
  ulong store_gaddr;    /* wksp gaddr of store in the backing wksp, non-zero gaddr */
  ulong map_gaddr;      /* wksp gaddr of map of fd_store_key->fd_store_fec */
  ulong pool_mem_gaddr; /* wksp gaddr of shmem_t object in pool_para */
  ulong pool_ele_gaddr; /* wksp gaddr of first ele_t object in pool_para */

  fd_rwlock_t lock; /* shared-exclusive lock */
  struct {
    ulong *      slock_acquire;
    ulong *      slock_release;
    fd_histf_t * slock_wait;
    fd_histf_t * slock_work;

    ulong *      xlock_acquire;
    ulong *      xlock_release;
    fd_histf_t * xlock_wait;
    fd_histf_t * xlock_work;

    ulong * query_cnt;
    ulong * query_missing_cnt;
    ulong * query_mr; /* first 8 bytes of most recently queried merkle root */
    ulong * query_missing_mr; /* first 8 bytes of most recently queried merkle root that was missing */

    ulong * insert_cnt;
    ulong * insert_full_cnt;
    ulong * insert_duplicate_cnt;
    ulong * insert_mr;      /* first 8 bytes of most recently inserted merkle root */
    ulong * insert_full_mr; /* first 8 bytes of most recently attempted insert of a merkle root when store was full */
    ulong * insert_duplicate_mr; /* first 8 bytes of most recently inserted merkle root that was a duplicate */

    ulong * remove_cnt;
    ulong * remove_missing_cnt;
    ulong * remove_mr;         /* first 8 bytes of most recently removed merkle root */
    ulong * remove_missing_mr; /* first 8 bytes of most recently attempted remove of a merkle root that was missing */

    ulong _work; /* private for macro impl */
  } metrics;
};
typedef struct fd_store fd_store_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_store_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as store with up to
   fec_max elements.  fec_max is an integer power-of-two. */

FD_FN_CONST static inline ulong
fd_store_align( void ) {
  return alignof(fd_store_t);
}

FD_FN_CONST static inline ulong
fd_store_footprint( ulong fec_max ) {
  if( FD_UNLIKELY( !fd_ulong_is_pow2( fec_max ) ) ) return 0UL;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_store_t),     sizeof(fd_store_t)                ),
      fd_store_map_align(),    fd_store_map_footprint( fec_max ) ),
      fd_store_pool_align(),   fd_store_pool_footprint()         ),
      alignof(fd_store_fec_t), sizeof(fd_store_fec_t)*fec_max    ),
    fd_store_align() );
}

/* fd_store_new formats an unused memory region for use as a store.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  fec_max is an integer
   power-of-two. */

void *
fd_store_new( void * shmem,
              ulong  fec_max,
              ulong  part_cnt );

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
fd_store_delete( void * shstore );

/* Accessors */

/* fd_store_wksp returns the local join to the wksp backing the store.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes store is a current local
   join. */

FD_FN_PURE static inline fd_wksp_t *
fd_store_wksp( fd_store_t const * store ) {
  return (fd_wksp_t *)( ( (ulong)store ) - store->store_gaddr );
}

/* fd_store_{s}lock_{acquire,release} interface store's shared-exclusive
   lock.  See also FD_STORE_{S,X}LOCK_{BEGIN,END}. */

static inline void fd_store_slock_acquire( fd_store_t * store ) { fd_rwlock_read   ( &store->lock ); }
static inline void fd_store_slock_release( fd_store_t * store ) { fd_rwlock_unread ( &store->lock ); }
static inline void fd_store_xlock_acquire( fd_store_t * store ) { fd_rwlock_write  ( &store->lock ); }
static inline void fd_store_xlock_release( fd_store_t * store ) { fd_rwlock_unwrite( &store->lock ); }

static inline void
fd_store_private_slock_end( fd_store_t ** _store ) {
   fd_store_t * store = *_store;
   fd_store_slock_release( store );
   *store->metrics.slock_release += 1;
   fd_histf_sample( store->metrics.slock_work, (ulong)fd_log_wallclock() - store->metrics._work );
}

#define FD_STORE_SLOCK_BEGIN(store) {                                                 \
  fd_store_t * _store __attribute__((cleanup(fd_store_private_slock_end))) = (store); \
  ulong wait = (ulong)fd_log_wallclock();                                             \
  fd_store_slock_acquire( _store );                                                   \
  *store->metrics.slock_acquire += 1;                                                 \
  fd_histf_sample( store->metrics.slock_wait, (ulong)fd_log_wallclock() - wait );     \
  store->metrics._work = (ulong)fd_log_wallclock();                                   \
  {

#define FD_STORE_SLOCK_END }}

static inline void
fd_store_private_xlock_end( fd_store_t ** _store ) {
   fd_store_t * store = *_store;
   fd_store_xlock_release( store );
   *store->metrics.xlock_release += 1;
   fd_histf_sample( store->metrics.xlock_work, (ulong)fd_log_wallclock() - store->metrics._work );
}

#define FD_STORE_XLOCK_BEGIN(store) {                                                 \
  fd_store_t * _store __attribute__((cleanup(fd_store_private_xlock_end))) = (store); \
  ulong wait = (ulong)fd_log_wallclock();                                             \
  fd_store_xlock_acquire( _store );                                                   \
  *store->metrics.xlock_acquire += 1;                                                 \
  fd_histf_sample( store->metrics.xlock_wait, (ulong)fd_log_wallclock() - wait );     \
  store->metrics._work = (ulong)fd_log_wallclock();                                   \
  {

#define FD_STORE_XLOCK_END }}


/* fd_store_{query,query_const} queries the FEC set keyed by merkle.
   Returns a pointer to the fd_store_fec_t if found, NULL otherwise.

   Both the const and non-const versions are concurrency safe; as in
   they avoid using the non-const map_ele_query that reorders the chain.
   fd_store_query gets around this by calling map idx_query_const, which
   does not reorder the chain, and then indexes directly into the pool
   and returns a non-const pointer to the element of interest.

   Assumes caller has acquired the shared lock via fd_store_shacq.

   IMPORTANT SAFETY TIP!  Caller should only call fd_store_shrel when
   they no longer retain interest in the returned pointer. */

fd_store_fec_t *
fd_store_query( fd_store_t      * store,
                fd_hash_t const * merkle_root );

/* Operations */

/* fd_store_insert inserts a new FEC keyed by merkle_root into the
   store.  Returns a pointer to the inserted pool ele (fd_store_fec_t *)
   on success.  If the merkle root has previously been inserted, returns
   a pointer to the previous element with that key.  Returns NULL if the
   store is full (see fd_store_evict).

   Each fd_store_fec_t can hold at most FD_STORE_DATA_MAX bytes of data,
   and caller is responsible for copying into the region.

   Assumes store is a current local join and caller has acquired either
   the shared or exclusive lock via fd_store_shacq or fd_store_exacq.
   See top-level documentation for how the caller can make it safe to
   store insert with a shared lock using store parts.

   IMPORTANT SAFETY TIP!  Caller must not release the lock while they
   retain interest in the returned pointer. */

fd_store_fec_t *
fd_store_insert( fd_store_t * store,
                 ulong        part_idx,
                 fd_hash_t  * merkle_root );

/* fd_store_remove removes the FEC set keyed by merkle_root.  Returns
   a pointer to the removed pool ele (fd_store_fec_t *) on success.
   Returns NULL if the element is not found in the store.

   This is a blocking operation that acquires an exclusive lock as part
   of its implementation.

   IMPORTANT SAFETY TIP!  Caller should only call fd_store_shrel or
   fd_store_exrel when they no longer retain interest in the returned
   pointer. */

void
fd_store_remove( fd_store_t      * store,
                 fd_hash_t const * merkle_root );

/* fd_store_verify returns 0 if the store is not obviously corrupt or -1
   otherwise (logs details). */

int
fd_store_verify( fd_store_t * store );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_store_fd_store_h */
