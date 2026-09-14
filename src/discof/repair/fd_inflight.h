#ifndef HEADER_fd_src_discof_repair_fd_inflight_h
#define HEADER_fd_src_discof_repair_fd_inflight_h

#include "fd_policy.h"
#include "../../ballet/shred/fd_shred.h"

/* fd_inflight tracks repair requests that are inflight to other
   validators, so that a response can be credited to the request (and
   peer) that solicited it and a request that gets no response can be
   redispatched after a timeout.  Request kinds:

   - Shred requests -- positional FD_REPAIR_KIND_SHRED and Alpenglow
     ShredForBlockId, which are indistinguishable on response -- are
     keyed by (slot, shred_idx, nonce, fec_root).  fec_root is
     all zero for a positional request (i.e., we didnt know the FEC
     root when the request was issued).  For a ShredForBlockId request,
     it is the 20-byte prefix of the known FEC root.

   - Metadata requests -- getParentAndFecSetCount and getFecSetRoot --
     are matched by nonce alone.  Their kind, slot and FEC set index
     ride in the key for redispatch (and so the caller can reject a
     response of the wrong kind) but do not participate in matching.

   Exact updates of shred requests are critical: the repair policy does
   not request any shred twice, so re-requests come only from this
   table.  Whether a shred belongs to a version is decided structurally
   by the chainer, which keys FECs by root; this table is request
   accounting only.

   Each record is FREE, OUTSTANDING, or POPPED:

            insert                  pop
     FREE  --------> OUTSTANDING -----------> POPPED
      ^                  |                      |
      |     match        |  match, or evicted   |
      -------------------------------------------

   OUTSTANDING records are in map and outstanding_dl (insertion order,
   oldest at head).  A record that ages past FD_REQLIM_DEDUP_TIMEOUT is
   popped: the caller redispatches it under a fresh nonce and the record
   moves to popped_map / popped_dl rather than being released, so a late
   response to the old nonce still matches.  When the pool is exhausted
   the oldest POPPED record is evicted first. */

/* Max number of pending requests */
#define FD_INFLIGHT_REQ_MAX (1<<20)

struct fd_inflight_key {
  ulong slot;
  uint  idx;        /* shred idx (shred kinds) or fec_set_idx (AG_REPAIR_KIND_FEC_ROOT) */
  uint  nonce;      /* rnonce or counter nonce (metadata) */
  uint  kind;       /* FD_REPAIR_KIND_SHRED for every shred request, else AG_REPAIR_KIND_{PARENT_FEC_COUNT,FEC_ROOT} */
  /* shred kinds: first FD_SHRED_MERKLE_NODE_SZ bytes of the FEC root a
     ShredForBlockId request was issued against, all-zero for a
     positional request.  All-zero for metadata kinds. */
  uchar fec_root[ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_inflight_key fd_inflight_key_t;
FD_STATIC_ASSERT( sizeof(fd_inflight_key_t)==40UL, fd_inflight_key_sz );

/* fd_inflight_key_init fills key.  For shred requests fec_root is the
   (full or 20-byte-padded) FEC root the request targets, or NULL for a
   positional request; only the first FD_SHRED_MERKLE_NODE_SZ bytes are
   kept.  For metadata kinds pass NULL. */
static inline void
fd_inflight_key_init( fd_inflight_key_t * key,
                      uint                kind,
                      ulong               slot,
                      ulong               idx,
                      ulong               nonce,
                      fd_hash_t const *   fec_root ) {
  key->slot  = slot;
  key->idx   = (uint)idx;
  key->nonce = (uint)nonce;
  key->kind  = kind;
  if( FD_LIKELY( fec_root ) ) memcpy( key->fec_root, fec_root->uc, FD_SHRED_MERKLE_NODE_SZ );
  else                        memset( key->fec_root, 0,            FD_SHRED_MERKLE_NODE_SZ );
}

/* Key equality and hashing.  A shred request is identified by the whole
   key.  A metadata request is identified by its nonce alone -- the
   counter nonce is unique -- so its kind, slot and idx are not
   considered when matching. */

static inline int
fd_inflight_key_is_shred( fd_inflight_key_t const * k ) { return k->kind==FD_REPAIR_KIND_SHRED; }

static inline int
fd_inflight_key_eq( fd_inflight_key_t const * k0,
                    fd_inflight_key_t const * k1 ) {
  if( FD_UNLIKELY( k0->nonce!=k1->nonce ) )                                           return 0;
  if( FD_UNLIKELY( fd_inflight_key_is_shred( k0 )!=fd_inflight_key_is_shred( k1 ) ) ) return 0;
  if( FD_UNLIKELY( !fd_inflight_key_is_shred( k0 ) ) )                                return 1;
  return ( k0->slot==k1->slot ) & ( k0->idx==k1->idx ) & !memcmp( k0->fec_root, k1->fec_root, FD_SHRED_MERKLE_NODE_SZ );
}

static inline ulong
fd_inflight_key_hash( fd_inflight_key_t const * k,
                      ulong                     seed ) {
  if( FD_UNLIKELY( !fd_inflight_key_is_shred( k ) ) ) return fd_hash( seed, &k->nonce, sizeof(uint) );
  return fd_hash( seed, k, sizeof(fd_inflight_key_t) );
}

struct __attribute__((aligned(128UL))) fd_inflight {
  fd_inflight_key_t key;
  uint              next;          /* reserved for internal use by fd_pool and fd_map_chain */
  uint              prev;          /* for fd_map_chain */
  uint              prevll;        /* for fd_inflight_dlist */
  uint              nextll;
  long              timestamp_ns;  /* when the request was created (caller's clock, nanoseconds) */

  fd_pubkey_t       pubkey;        /* peer the request went to (all-zero if parked unsent) */

  /* Version being repaired: the block_id of a ShredForBlockId or
     metadata request, all-zero for a positional shred request. */
  fd_hash_t         block_id;
};
typedef struct fd_inflight fd_inflight_t;
FD_STATIC_ASSERT( sizeof(fd_inflight_t)==128UL, fd_inflight_sz );

#define POOL_NAME   fd_inflight_pool
#define POOL_T      fd_inflight_t
#define POOL_IDX_T  uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME            fd_inflight_map
#define MAP_KEY             key
#define MAP_ELE_T           fd_inflight_t
#define MAP_KEY_T           fd_inflight_key_t
#define MAP_IDX_T           uint
#define MAP_KEY_EQ(k0, k1)  fd_inflight_key_eq( (k0), (k1) )
#define MAP_KEY_HASH(k,s)   fd_inflight_key_hash( (k), (s) )
#define MAP_MULTI           1 /* the same shred request within one rnonce time bucket */
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME      fd_inflight_dlist
#define DLIST_ELE_T     fd_inflight_t
#define DLIST_IDX_T     uint
#define DLIST_PREV      prevll
#define DLIST_NEXT      nextll
#include "../../util/tmpl/fd_dlist.c"

struct fd_inflights {
  fd_inflight_t       * pool;
  fd_inflight_map_t   * map;             /* OUTSTANDING */
  fd_inflight_map_t   * popped_map;      /* POPPED */
  fd_inflight_dlist_t   outstanding_dl[1];
  fd_inflight_dlist_t   popped_dl[1];
  ulong                 popped_cnt;
};
typedef struct fd_inflights fd_inflights_t;

FD_FN_CONST static inline ulong
fd_inflights_align( void ) { return 128UL; }

FD_FN_CONST static inline ulong
fd_inflights_footprint( void ) {
  ulong chain_cnt = fd_inflight_map_chain_cnt_est( FD_INFLIGHT_REQ_MAX );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_inflights_t),  sizeof(fd_inflights_t)                            ),
      fd_inflight_pool_align(), fd_inflight_pool_footprint( FD_INFLIGHT_REQ_MAX ) ),
      fd_inflight_map_align(),  fd_inflight_map_footprint ( chain_cnt           ) ),
      fd_inflight_map_align(),  fd_inflight_map_footprint ( chain_cnt           ) ),
    fd_inflights_align() );
}

void *
fd_inflights_new( void * shmem,
                  ulong  seed );

fd_inflights_t *
fd_inflights_join( void * shmem );

/* Timestamps.  Every insert and match takes now, the caller's current
   time in nanoseconds, rather than reading a clock itself: records are
   stamped with it on insert, fd_inflights_shred_match reports RTT
   against it, and fd_inflights_should_drain compares against it.  All
   calls on a table must use the same clock (the tile clock,
   fd_clock_tile_now) so age and RTT are consistent. */

/* fd_inflights_shred_insert records a shred request to pubkey.
   block_id is the ShredForBlockId version being repaired and fec_root
   the root the chainer holds for that version at the requested FEC set
   (the key a response is matched by); both NULL (or all-zero) for a
   positional request. */

void
fd_inflights_shred_insert( fd_inflights_t *    table,
                           ulong               nonce,
                           fd_pubkey_t const * pubkey,
                           ulong               slot,
                           ulong               shred_idx,
                           fd_hash_t const *   block_id,
                           fd_hash_t const *   fec_root,
                           long                now );

/* fd_inflights_shred_match matches a shred response.  fec_root is the
   response shred's merkle root (only the first FD_SHRED_MERKLE_NODE_SZ
   bytes are keyed on), or NULL to match a positional request.  Removes
   every record with that key from both the outstanding and popped sets
   and credits the response to the oldest: returns its RTT in
   nanoseconds relative to now (>0), or 0 if nothing matched.  On a
   match *peer_out is set, and *block_id_out (if non-NULL) to the
   matched request's block_id. */

long
fd_inflights_shred_match( fd_inflights_t *  table,
                          ulong             nonce,
                          ulong             slot,
                          ulong             shred_idx,
                          fd_hash_t const * fec_root,
                          fd_pubkey_t *     peer_out,
                          fd_hash_t *       block_id_out,
                          long              now );

/* fd_inflights_meta_insert records a metadata request to pubkey.  kind
   is AG_REPAIR_KIND_PARENT_FEC_COUNT or AG_REPAIR_KIND_FEC_ROOT;
   fec_set_idx is meaningful for the latter only. */

void
fd_inflights_meta_insert( fd_inflights_t *    table,
                          ulong               nonce,
                          uint                kind,
                          fd_pubkey_t const * pubkey,
                          ulong               slot,
                          fd_hash_t const *   block_id,
                          uint                fec_set_idx,
                          long                now );

/* fd_inflights_meta_match matches a metadata response by nonce in the
   outstanding then the popped set.  On a match the record is copied to
   *out (out->key.kind is the kind that was requested), removed, and 1
   is returned; 0 otherwise. */

int
fd_inflights_meta_match( fd_inflights_t * table,
                         ulong            nonce,
                         fd_inflight_t *  out );

/* fd_inflights_should_drain returns 1 if the oldest outstanding request
   has aged past FD_REQLIM_DEDUP_TIMEOUT and should be redispatched. */

static inline int
fd_inflights_should_drain( fd_inflights_t * table, long now ) {
  if( FD_UNLIKELY( fd_inflight_dlist_is_empty( table->outstanding_dl, table->pool ) ) ) return 0;
  fd_inflight_t * head = fd_inflight_dlist_ele_peek_head( table->outstanding_dl, table->pool );
  return head->timestamp_ns + FD_REQLIM_DEDUP_TIMEOUT < now;
}

/* fd_inflights_pop copies the oldest outstanding request to *out and
   moves it to the popped set, so a late response to its nonce still
   matches.  A record with nonce 0 (parked by the caller, never sent) is
   released instead, since nothing can match it.  The outstanding set
   must be non-empty: only call this after fd_inflights_should_drain
   returns 1. */

void
fd_inflights_pop( fd_inflights_t * table,
                  fd_inflight_t *  out );

/* fd_inflights_outstanding_free returns how many new requests can be
   inserted before an insert would have to evict an OUTSTANDING record
   (FREE records plus evictable POPPED ones). */

static inline ulong
fd_inflights_outstanding_free( fd_inflights_t * table ) {
  return fd_inflight_pool_free( table->pool ) + table->popped_cnt;
}

/* fd_inflights_outstanding_cnt returns the number of OUTSTANDING
   records. */

static inline ulong
fd_inflights_outstanding_cnt( fd_inflights_t * table ) {
  return fd_inflight_pool_used( table->pool ) - table->popped_cnt;
}

void
fd_inflights_print( fd_inflight_dlist_t * dlist, fd_inflight_t * pool );

#endif /* HEADER_fd_src_discof_repair_fd_inflight_h */
