#ifndef HEADER_fd_src_discof_rotor_fd_rotor_h
#define HEADER_fd_src_discof_rotor_fd_rotor_h

/* Fec rotor is an API for reassembling shreds and FECs into slots.
   It maintains 2 levels of granularity:

   FECs, and blocks (versions of a slot).  Blocks are keyed by
   slot in a MAP_MULTI: the several versions of a slot chain off the
   same slot key and are distinguished by their block_id.  FECs are
   keyed by their unique merkle root, and can be shared by multiple
   blocks.

   The block_id for the turbine version is all-zero until finalization,
   after which point it will be impossible to distinguish from other
   versions. Thus, it is marked with a `turbine` flag (prevents extra
   trailing turbine shreds from creating unbounded block contexts).
   notar-fallback / SafeToNotar versions carry a real block_id from
   their cert.

   Under alpenglow, we can simplify equivocation handling. As turbine
   shreds arrive, each (slot, fec_set_idx) only accepts shreds of the
   first-seen root. Any shred with a different root is dropped.

   When a notar-fallback cert or a SafeToNotar is received for a
   block_id of a slot we don't have yet, we can add additional versions.
   No correct node ever stores more than 7 distinct blocks per slot
   (Corollary 50).

   A cert or SafeToNotar should trigger getParentandFecCount requests.
   The response should trigger getSliceHash (2.8, Definition 19)
   requests. Extra versions of a FEC set only exists once a getFecRoot
   response creates the sentinel with that root. Equivocating FEC shreds
   are accepted iff the sentinel already exists.  If the sentinel does
   not exist, the FEC shreds are dropped. This way -- turbine shreds are
   accepted without concern for whether the FEC sets belong to the "same
   slot", but votor-driven events guarantee repair of shreds that
   verifiably belong to the same slot.

   Note that in the uncommon but not impossible case where we may be
   taking a long to complete a block, we may receive a votor event for
   an honest slot that we are still in the process of receiving from
   turbine.  Since we can't compute the block_id for a slot still
   incomplete from turbine, we would create a redundant block entry for,
   logically, the same slot.  In effect, this would generate an extra
   getParentAndFecCount request and getFecRoot requests, but since we
   already have most of the data for the slot, we can avoid
   re-requesting the shreds.  This case should be rare enough that the
   redundancy is worth the simplicity.

   When that happens the turbine version is ABANDONED: arriving shreds
   are still accepted and fill the FECs, but it never delivers to
   replay, never finalizes a block_id, and is dropped from the repair
   worklists.  Were it to keep delivering, and its block_id to finalize
   to the same block a votor version is repairing, replay would
   materialize two banks for the same {slot, block_id} (see
   fd_rotor_tile.h).  An abandoned block is pruned with its slot at
   publish.  Note that replay can handle two fully-delivered slots, so
   whether we should maintain this abandon state is debatable.  But
   logically we want to only deliver verified blocks to replay if
   we have something verifiable available.

   *Parent Discovery*

   The trickiness with chaining is that there's 3 different sources of
   parent information. Shreds contain parent_off field, which may or may
   not be removed in the future. The block header contains the initial
   replay parent_slot, and there can be an updateParent marker anywhere
   in the middle of the block.

   In the case where we are disconnected momentarily, or we are catching
   up, we won't ever receive shreds for the original parent slot, only
   for the updated parent slot. We currently assume parent_off will
   update with the parentUpdate marker.
*/

#include <math.h>

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../disco/store/fd_store.h"

#define FD_ROTOR_MAGIC (0xf17eda2ce7c4a112UL) /* firedancer rotor v1 */

#define FD_ROTOR_SLOT_VER_MAX      7 /* see Corollary 50 */
#define FD_ROTOR_EXPECTED_SLOT_CNT (2.2) /* =(0.8*1 + 0.2*7). 80% of nodes expected to produce 1 version, 20% expected to produce up to 7. */

#define FD_ROTOR_SRC_TURBINE   (0)
#define FD_ROTOR_SRC_REPAIR    (1)
#define FD_ROTOR_SRC_RECOVERED (2)
#define FD_ROTOR_SRC_LEADER    (3)

#define ABANDON_REASON_NOT_CANCELLED         (1) /* Not cancelled. */
#define ABANDON_REASON_MERKLE_ROOT_MISMATCH  (2)
#define ABANDON_REASON_VOTOR_BLOCK_ID_EVENT  (3)
#define ABANDON_REASON_VOTOR_BLOCK_ID_PARENT (4)

FD_STATIC_ASSERT( FD_FEC_SHRED_CNT==32UL, fd_rotor_fec_bitmap );

struct fd_rotor_fec {
  fd_hash_t merkle_root; /* key: first FD_SHRED_MERKLE_NODE_SZ bytes */
  uint      slot;        /* slot this FEC belongs to */
  uint      data_idxs;   /* available data shreds, including recovered shreds */
  uint      next;        /* reserved by pool and map_chain */
  uint      prev;        /* reserved by map_chain (doubly-linked chains) */
  uint      fec_set_idx  : 28; /* position within the slot (multiple of FD_FEC_SHRED_CNT) */
  uint      complete     : 1;  /* set is reconstructable and may be delivered */
  uint      slot_complete: 1;
  uint      data_complete: 1;
  uint      is_leader    : 1;

  /* Reception for the current resolver attempt.  Shared by all versions
     owning this root; cleared on eviction.  Reconstructed/leader shreds
     do not set received bits.  Completed sets retain their snapshot. */
  struct {
    uint data_received;
    uint parity_received;
    uint repair_received; /* subset of data_received */
    int  last_shred_src;  /* FD_ROTOR_SRC_*, excluding RECOVERED */
    long first_shred_ts;  /* wallclock ns from the incoming fragment's tsorig */
    long completed_ts;    /* tsorig of the shred that completed the FEC */
  } metrics;
};
typedef struct fd_rotor_fec fd_rotor_fec_t;
FD_STATIC_ASSERT( sizeof(fd_rotor_fec_t)==88UL, fd_rotor_fec );

#define POOL_NAME  fd_fec_pool
#define POOL_T     fd_rotor_fec_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_map
#define MAP_ELE_T fd_rotor_fec_t
#define MAP_IDX_T uint
#define MAP_KEY   merkle_root
#define MAP_KEY_T fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0)->uc, (k1)->uc, FD_SHRED_MERKLE_NODE_SZ )) /* 20-byte root prefix */
#define MAP_KEY_HASH(key,seed) ( (seed) ^ fd_ulong_load_8( (key)->uc ) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define AG_UNKNOWN_SLOT ULONG_MAX
struct fd_rotor_blk {
  ulong           slot; /* MAP_MULTI key */
  ulong           next; /* reserved by pool and map_chain */
  ulong           prev; /* reserved by map_chain */

  uchar           turbine;   /* 1 for the block created through turbine */
  uchar           is_leader; /* 1 once a FEC set we produced as leader completed under this (turbine) version */
  uchar           abandoned; /* 1 once a votor-driven version of the slot was
                                created while this (turbine) version's block_id
                                was still unknown: keeps accepting shred/FEC
                                bookkeeping but never delivers, never finalizes
                                a block_id, and stays off the repair worklists.
                                See the header comment above. */
  fd_hash_t       block_id;
  uint            complete_idx;
  uint            buffered_idx;     /* idx of highest buffered shred */
  uint            buffered_fec_idx; /* last shred idx of highest buffered FEC set we have received completion for */

  ulong           parent_slot;       /* AG_UNKNOWN_SLOT if unknown */
  fd_hash_t       parent_block_id;   /* block_id of the parent slot */
  uint            parent_slot_batch; /* fec_idx of the last known parent_slot information.
                                        before FLH is activated, can only be 0 or UINT_MAX. After FLH
                                        is activated, can be 0 or UINT_MAX or a multiple of FD_FEC_SHRED_CNT,
                                        and can only update to a non-zero fec_idx value once.  */

  /* delivery to replay */
  uchar           connected;         /* ancestor chain reaches the root */
  uint            delivered_idx;     /* last shred idx of highest fec_set_idx contiguously delivered to replay, UINT_MAX = none */

  /* Reception statistics. */
  struct {
    int  abandoned_reason; /* ABANDON_REASON_* */

    uint turbine_cnt;   /* data shreds received via turbine, plus every coding shred */
    uint repair_cnt;    /* data shreds received via repair */
    uint recovered_cnt; /* data shreds reconstructed via reed-solomon */
    uint parity_cnt;    /* coding shreds received */

    uint last_completed_fec_idx; /* fec_set_idx of the FEC set that most recently completed for this version */

    long first_meta_ts;  /* the version's first verified getParentAndFecCount or FecRoot response arrived, wallclock ns, 0 if none */
    long abandoned_ts;   /* the version was abandoned, wallclock ns, 0 if not abandoned */
    long first_shred_ts; /* the version's first shred arrived, wallclock ns */
    long last_shred_ts;  /* the version became fully buffered (buffered_idx==complete_idx), wallclock ns */

    uint req_window_cnt;     /* positional specific-shred requests sent (Shred) */
    uint req_highest_cnt;    /* highest-shred requests sent (HighestShred) */
    uint req_orphan_cnt;     /* ancestry requests sent (Orphan) */
    uint req_shred_bid_cnt;  /* alpenglow specific-shred requests sent (ShredForBlockId) */
    uint req_parent_cnt;     /* alpenglow ancestry requests sent (ParentAndFecCount) */
    uint req_fec_root_cnt;   /* alpenglow FEC-set-root requests sent (FecRoot) */
    uint req_retransmit_cnt; /* requests re-issued after a timeout or a bad response, shred or metadata */
    uint shred_repair_responses;     /* shred repair responses matched to an outstanding request */
    uint parent_fec_count_responses; /* verified ParentAndFecCount responses matched to an outstanding request */
    uint fec_root_responses;         /* verified FecRoot responses matched to an outstanding request */

    long first_req_ts;        /* wallclock ns of the first specific-shred request sent, 0 if none */
    long last_repair_resp_ts; /* wallclock ns of the most recent matched repair response, 0 if none */
  } metrics;
};
typedef struct fd_rotor_blk fd_rotor_blk_t;

#define POOL_NAME fd_block_pool
#define POOL_T    fd_rotor_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_block_map
#define MAP_ELE_T fd_rotor_blk_t
#define MAP_KEY   slot
#define MAP_MULTI 1 /* several versions of a slot share the slot key */
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1 /* remove a specific version, not an arbitrary slot match */
#include "../../util/tmpl/fd_map_chain.c"

#define DEQUE_NAME bfs
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct out_ele {
  uint block_idx;  /* block pool idx */
  uint fec_idx;    /* fd_fec_pool idx */
};
typedef struct out_ele out_ele_t;

/* out_queue holds pool indices of FECs that have been delivered
   (contiguous from root and connected) and are awaiting publish to
   replay by the repair tile.  Sized to the max number of FECs.  Since
   out_ele maintains pool indices, the out_queue must be drained between
   any rotor call that can modify the pool. */

#define DEQUE_NAME out_queue
#define DEQUE_T    out_ele_t
#include "../../util/tmpl/fd_deque_dynamic.c"

/* Optional block reporting callback.  Called when an incomplete block
   is pruned, or a block is completed.  NULL disables reporting. */
typedef void (*fd_rotor_block_event_fn)( void *                 ctx,
                                       fd_rotor_blk_t const * block );

struct fd_rotor {
  ulong root;             /* root slot, ULONG_MAX if unset */
  ulong highest_repaired; /* max slot ever marked fully_delivered (contiguous-from-root repaired tip) */
  ulong wksp_gaddr;       /* wksp gaddr of fd_rotor in the backing wksp, non-zero gaddr */

  fd_rotor_fec_t * fec_pool;
  fd_fec_map_t   * fec_map;

  fd_rotor_blk_t * block_pool;
  fd_block_map_t * block_map;
  uint          * fec_tbl;     /* fec_tbl[ block_idx*fec_blk_max + k ] = fd_fec_pool idx of the FEC
                                  that block owns at FEC set k, UINT_MAX if none */
  ulong           fec_blk_max; /* max FEC sets per block (max_shreds_per_block/FD_FEC_SHRED_CNT) */

  ulong     * bfs;       /* bfs queue */
  out_ele_t * out_queue; /* delivered FEC pool idxs awaiting publish to replay */

  ulong magic; /* ==FD_ROTOR_MAGIC */

  fd_rotor_block_event_fn block_event_fn;
  void                  * block_event_ctx;
};
typedef struct fd_rotor fd_rotor_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_rotor_align( void ) {
  return fd_ulong_max( alignof(fd_rotor_t), 128UL );
}

/* fd_rotor_blk_max returns the max number of block versions the
   rotor tracks across ele_max slots, ie. ele_max *
   FD_ROTOR_EXPECTED_SLOT_CNT rounded up.  This is the expected, not
   the worst case: a slot may have up to FD_ROTOR_SLOT_VER_MAX
   versions, but only a minority of leaders are expected to equivocate. */

FD_FN_CONST static inline ulong
fd_rotor_blk_max( ulong ele_max ) {
  return (ulong)ceil( (double)ele_max * FD_ROTOR_EXPECTED_SLOT_CNT );
}

FD_FN_CONST static inline ulong
fd_rotor_footprint( ulong ele_max,
                    ulong max_shreds_per_block ) {
  if( FD_UNLIKELY( !max_shreds_per_block || max_shreds_per_block%FD_FEC_SHRED_CNT || max_shreds_per_block>FD_SHRED_BLK_MAX_RAISED ) ) return 0UL;
  ulong blk_max       = fd_rotor_blk_max( ele_max );
  ulong fec_blk_max   = max_shreds_per_block / FD_FEC_SHRED_CNT;
  ulong fec_max       = blk_max * fec_blk_max;
  if( FD_UNLIKELY( !fd_fec_pool_footprint( fec_max ) ) ) return 0UL;
  ulong fec_chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  ulong blk_chain_cnt = fd_block_map_chain_cnt_est( blk_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_rotor_t),    sizeof(fd_rotor_t)                       ),
      fd_fec_pool_align(),    fd_fec_pool_footprint  ( fec_max       ) ),
      fd_fec_map_align(),     fd_fec_map_footprint   ( fec_chain_cnt ) ),
      fd_block_pool_align(),  fd_block_pool_footprint( blk_max       ) ),
      alignof(uint),          fec_max*sizeof(uint)                     ), /* fec_tbl */
      fd_block_map_align(),   fd_block_map_footprint ( blk_chain_cnt ) ),
      bfs_align(),            bfs_footprint          ( blk_max       ) ),
      out_queue_align(),      out_queue_footprint    ( fec_max       ) ),
    fd_rotor_align() );
}

void *
fd_rotor_new( void * shmem,
              ulong  ele_max,
              ulong  max_shreds_per_block,
              ulong  seed );

fd_rotor_t *
fd_rotor_join( void * rotor );

FD_FN_PURE static inline fd_wksp_t *
fd_rotor_wksp( fd_rotor_t * rotor ) {
  return (fd_wksp_t *)( ( (ulong)rotor ) - rotor->wksp_gaddr );
}

/* fd_rotor_highest_repaired_slot returns the highest slot on the
   contiguously-repaired chain from root (the analog of
   fd_forest_highest_repaired_slot) */

FD_FN_PURE static inline ulong
fd_rotor_highest_repaired_slot( fd_rotor_t const * rotor ) {
  return rotor->highest_repaired;
}

int
fd_rotor_verify( fd_rotor_t const * rotor );

void
fd_rotor_init( fd_rotor_t *            rotor,
               ulong                   slot,
               fd_hash_t const *       block_id,
               fd_rotor_block_event_fn block_event_fn,
               void *                  block_event_ctx );

/* Mutators that can create a block return it, or NULL if everything
   they touched already existed; no call creates more than one.
   shred_insert, fec_complete and verified_hash_insert can create the
   slot's turbine version, verified_block_insert the version named.
   (verified_parent_fec_count keeps its own contract, below.)  Pointers
   stay valid until the next fd_rotor_publish. */

/* fd_rotor_shred_insert inserts a data shred into the rotor.  If
   the parent_slot is provided, parent_block_id must also be provided.
   Otherwise caller should pass AG_UNKNOWN_SLOT for parent_slot.  src is
   one of FD_ROTOR_SRC_*.

   The shred may be rejected (unauthorized equivocation); the caller
   does not need to know.  Returns the turbine version if this call
   created it, else NULL.

   Caller must supply the full 32-byte merkle-root, not the 20-byte
   prefix. */

fd_rotor_blk_t *
fd_rotor_shred_insert( fd_rotor_t *      rotor,
                       ulong             slot,
                       uint              shred_idx,
                       int               slot_complete,
                       int               src,
                       long              rx_ts,
                       fd_hash_t const * mr,
                       ulong             parent_slot,
                       fd_hash_t const * parent_block_id );

/* Best-effort tracking for an existing FEC; does not create FEC entries.
   code_idx is the relative coding index (0..31).
   Coding shreds, including nonconformant repair responses, count as
   turbine. */

void
fd_rotor_code_shred_insert( fd_rotor_t *      rotor,
                            ulong             slot,
                            uint              fec_set_idx,
                            uint              code_idx,
                            long              rx_ts,
                            fd_hash_t const * mr );

/* fd_rotor_fec_complete returns the turbine version if this call
   created it, else NULL.  If opt_rejected is non-NULL it is set to 1
   when the set was rejected (unauthorized equivocating root: dropped,
   nothing completed) and 0 otherwise.

   If opt_turbine_finalized is non-NULL, it is set to the turbine
   version whose block_id changed from zero to its final value during
   this call, or NULL if none did.  Callers tracking versions by
   {slot, block_id} can use this to replace the old zero-ID key.

   Caller must supply the full 32-byte merkle-root, not the 20-byte
   prefix. */

fd_rotor_blk_t *
fd_rotor_fec_complete( fd_rotor_t *      rotor,
                       ulong             slot,
                       uint              fec_set_idx,
                       int               slot_complete,
                       int               data_complete,
                       int               is_leader,
                       long              rx_ts,
                       fd_hash_t *       mr,
                       int *             opt_rejected,
                       fd_rotor_blk_t ** opt_turbine_finalized );

/* fd_rotor_fec_evicted clears out the received shreds for a given
   FEC set, and also updates shred tracking for slots that have this FEC
   root. */

void
fd_rotor_fec_evicted( fd_rotor_t * rotor,
                      ulong        slot,
                      uint         fec_set_idx,
                      fd_hash_t *  merkle_root );

/* fd_rotor_verified_block_insert records {slot, block_id} as a
   verified version, abandoning the slot's turbine version if its
   block_id is still unknown.  Returns the new version, or NULL if it
   already existed.  now is the wallclock ns the block id became known
   and stamps an abandoned turbine version's abandoned_ts. */

fd_rotor_blk_t *
fd_rotor_verified_block_insert( fd_rotor_t * rotor,
                                ulong        slot,
                                fd_hash_t    block_id,
                                long         now );

/* fd_rotor_verified_parent_fec_count is rotor's entrypoint for
   updating information on what a slots fec set count, parent slot, and
   parent block id are.  This mirrors the Alpenglow repair type
   getParentAndFecSetCount.  The information should be verified before
   calling this function; rotor does no verification.  Will CRIT if
   {slot, block_id} does not exist in the rotor yet, otherwise creates
   {parent, p_bid} block if it doesn't exist yet, and returns parent
   block.  May return NULL if the parent block is on a dead fork.
   rx_ts is the wallclock ns the response arrived and stamps the
   block's first_meta_ts. */

fd_rotor_blk_t *
fd_rotor_verified_parent_fec_count( fd_rotor_t * rotor,
                                    ulong        slot,
                                    fd_hash_t *  block_id,
                                    uint         fec_set_cnt,
                                    ulong        parent_slot,
                                    fd_hash_t *  parent_block_id,
                                    long         rx_ts );

/* fd_rotor_verified_hash_insert is rotor's entrypoint for updating
   information on what a block's FEC root is.  This mirrors the Alpenglow
   repair type getFecSetRoot.  The information should be verified before
   calling this function; rotor does no verification.  Will CRIT if
   {slot, block_id} does not exist in the rotor yet, otherwise creates
   the FEC entry if it doesn't exist yet and updates bookkeeping.  If
   the root was already complete under another version the completion
   is replayed, which can create the slot's turbine version (returned);
   otherwise returns NULL.  mr_prefix is the 20-byte root prefix the
   getFecSetRoot response carries.  rx_ts is as in
   fd_rotor_verified_parent_fec_count. */

fd_rotor_blk_t *
fd_rotor_verified_hash_insert( fd_rotor_t * rotor,
                               ulong        slot,
                               fd_hash_t *  block_id,
                               uint         fec_set_idx,
                               uchar const  mr_prefix[ static FD_SHRED_MERKLE_NODE_SZ ],
                               long         rx_ts );

/* fd_rotor_fec_query returns the FEC that the version of slot
   identified by block_id owns at fec_set_idx, or NULL. */

fd_rotor_fec_t *
fd_rotor_fec_query( fd_rotor_t *      rotor,
                    ulong             slot,
                    uint              fec_set_idx,
                    fd_hash_t const * block_id );

/* fd_rotor_shred_test returns 1 if block has data shred shred_idx --
   i.e. it owns the FEC at shred_idx's position and that FEC's presence
   bitmap has the shred.  The per-shred bitmap lives on the (shared) FEC,
   so this indexes block's fec_tbl row then tests fd_rotor_fec.data_idxs.
   Returns 0 for shred_idx at or beyond max_shreds_per_block. */

int
fd_rotor_shred_test( fd_rotor_t *           rotor,
                     fd_rotor_blk_t const * block,
                     uint                   shred_idx );

/* fd_rotor_publish advances the root to slot.  block_id identifies
   which version of slot is being rooted; every other version of it is
   pruned along with the slots below.  Pass NULL (or a block_id no
   version matches) to keep all versions of slot.  If store is non-NULL,
   each pruned FEC set is removed from it (rotor is the store
   publisher).

   IMPORTANT! The out_queue must be drained before calling this
   function, else there could be stale references to pruned blocks. */

void
fd_rotor_publish( fd_rotor_t *      rotor,
                  ulong             slot,
                  fd_hash_t const * block_id,
                  fd_store_t *      store );

/* fd_rotor_repair_tally records one repair request or response
   against a block version.  A re-issued request counts only
   as a retransmit, not additionally as a request of its original kind. */

#define FD_ROTOR_REQ_WINDOW     (0)
#define FD_ROTOR_REQ_HIGHEST    (1)
#define FD_ROTOR_REQ_ORPHAN     (2)
#define FD_ROTOR_REQ_SHRED_BID  (3)
#define FD_ROTOR_REQ_PARENT     (4)
#define FD_ROTOR_REQ_FEC_ROOT   (5)
#define FD_ROTOR_REQ_RETRANSMIT (6)
#define FD_ROTOR_RESP_SHRED     (7)
#define FD_ROTOR_RESP_PARENT    (8)
#define FD_ROTOR_RESP_FEC_ROOT  (9)

static inline void
fd_rotor_repair_tally( fd_rotor_blk_t * block, int kind, long now ) {
  if( FD_UNLIKELY( !block ) ) return;

  if( FD_LIKELY( now ) ) {
    if( kind==FD_ROTOR_REQ_WINDOW || kind==FD_ROTOR_REQ_SHRED_BID ) {
      if( FD_UNLIKELY( !block->metrics.first_req_ts ) ) block->metrics.first_req_ts = now;
    } else if( kind==FD_ROTOR_RESP_SHRED ) {
      block->metrics.last_repair_resp_ts = now;
    }
  }

  switch( kind ) {
    case FD_ROTOR_REQ_WINDOW:     block->metrics.req_window_cnt++;     break;
    case FD_ROTOR_REQ_HIGHEST:    block->metrics.req_highest_cnt++;    break;
    case FD_ROTOR_REQ_ORPHAN:     block->metrics.req_orphan_cnt++;     break;
    case FD_ROTOR_REQ_SHRED_BID:  block->metrics.req_shred_bid_cnt++;  break;
    case FD_ROTOR_REQ_PARENT:     block->metrics.req_parent_cnt++;     break;
    case FD_ROTOR_REQ_FEC_ROOT:   block->metrics.req_fec_root_cnt++;   break;
    case FD_ROTOR_REQ_RETRANSMIT: block->metrics.req_retransmit_cnt++; break;
    case FD_ROTOR_RESP_SHRED:     block->metrics.shred_repair_responses++;     break;
    case FD_ROTOR_RESP_PARENT:    block->metrics.parent_fec_count_responses++; break;
    case FD_ROTOR_RESP_FEC_ROOT:  block->metrics.fec_root_responses++;         break;
    default: FD_LOG_CRIT(( "bad rotor repair tally kind %d", kind ));
  }
}

static inline fd_rotor_blk_t *
fd_rotor_slot_version_query( fd_rotor_t *      rotor,
                             ulong             slot,
                             fd_hash_t const * block_id ) {
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_block_map_t * block_map  = rotor->block_map;
  for( ulong idx = fd_block_map_idx_query_const( block_map, &slot, ULONG_MAX, block_pool );
             idx != ULONG_MAX;
             idx = fd_block_map_idx_next_const( idx, ULONG_MAX, block_pool ) ) {
    fd_rotor_blk_t * block = fd_block_pool_ele( block_pool, idx );
    if( FD_UNLIKELY( fd_hash_eq( &block->block_id, block_id ) ) ) return block;
  }
  return NULL;
}

/* fd_rotor_block_fecs returns block's row of rotor->fec_tbl:
   fecs[ k ] is the fd_fec_pool idx of the FEC block owns at FEC set k
   (shred position k*FD_FEC_SHRED_CNT), UINT_MAX if none, for k in
   [0,rotor->fec_blk_max). */

FD_FN_PURE static inline uint *
fd_rotor_block_fecs( fd_rotor_t const *     rotor,
                     fd_rotor_blk_t const * block ) {
  return rotor->fec_tbl + fd_block_pool_idx( rotor->block_pool, block )*rotor->fec_blk_max;
}

/* fd_rotor_turbine_block_query returns slot's turbine version, or
   NULL if none exists.  Its block_id is all-zero until the block is
   whole and finalized; after that it is the only way to find the
   version the turbine stream built, since its key has changed. */

fd_rotor_blk_t *
fd_rotor_turbine_block_query( fd_rotor_t const * rotor,
                              ulong              slot );

/* fd_rotor_slot_query returns any version of slot, or NULL if the slot
   has no versions in the rotor. */

static inline fd_rotor_blk_t *
fd_rotor_slot_query( fd_rotor_t * rotor, ulong slot ) {
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_block_map_t * block_map  = rotor->block_map;
  ulong            idx        = fd_block_map_idx_query_const( block_map, &slot, ULONG_MAX, block_pool );
  return idx==ULONG_MAX ? NULL : fd_block_pool_ele( block_pool, idx );
}

void
fd_rotor_print( fd_rotor_t * rotor );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rotor_fd_rotor_h */
