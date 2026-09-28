#ifndef HEADER_fd_src_discof_chainer_fd_chainer_h
#define HEADER_fd_src_discof_chainer_fd_chainer_h

/* Fec chainer is an API for reassembling shreds and FECs into slots.
   It maintains 2 levels of granularity:

   FECs, and SLOTVs (short for "slot versions").  SLOTVs are keyed by
   slot in a MAP_MULTI: the several versions of a slot chain off the
   same slot key and are distinguished by their block_id.  FECs are
   keyed by their unique merkle root, and can be shared by multiple
   slotvs.

   The block_id for the turbine version is all-zero until finalization,
   after which point it will be impossible to distinguish from other
   versions. Thus, it is marked with a `turbine` flag (prevents extra
   trailing turbine shreds from creating unbounded slotv contexts).
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
   incomplete from turbine, we would create a redundant SLOTV entry for,
   logically, the same slot.  In effect, this would generate an extra
   getParentAndFecCount request and getFecRoot requests, but since we
   already have most of the data for the slot, we can avoid
   re-requesting the shreds.  This case should be rare enough that the
   redundancy is worth the simplicity.

   Turbine state is created only for a slot with no versions.  A slot
   with only named versions accepts shreds after a verified root has
   been inserted.  Known roots update existing matching entries without
   creating or backfilling turbine state.

   When an incomplete turbine version is superseded it is ABANDONED:
   arriving shreds still fill its existing FECs with known roots, but
   cannot add new roots.  It never delivers to replay, never finalizes
   a block_id, and is dropped from the repair
   worklists.  Were it to keep delivering, and its block_id to finalize
   to the same block a votor version is repairing, replay would
   materialize two banks for the same {slot, block_id} (see
   fd_rotor_tile.h).  An abandoned slotv is pruned with its slot at
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

#define FD_CHAINER_MAGIC (0xf17eda2ce7c4a112UL) /* firedancer chainer v1 */

#define FD_CHAINER_SLOT_VER_MAX      7 /* see Corollary 50 */
#define FD_CHAINER_EXPECTED_SLOT_CNT (2.2) /* =(0.8*1 + 0.2*7). 80% of nodes expected to produce 1 version, 20% expected to produce up to 7. */

#define FD_CHAINER_SRC_TURBINE   (0)
#define FD_CHAINER_SRC_REPAIR    (1)
#define FD_CHAINER_SRC_RECOVERED (2)
#define FD_CHAINER_SRC_LEADER    (3)

FD_STATIC_ASSERT( FD_FEC_SHRED_CNT==32UL, fd_chainer_fec_bitmap );

struct fd_chainer_fec {
  fd_hash_t merkle_root; /* key: first FD_SHRED_MERKLE_NODE_SZ bytes */
  uint      slot;        /* slot this FEC belongs to */
  uint      data_idxs;   /* received data shreds; authoritative only when root is set, otherwise zero */
  uint      next;        /* reserved by pool and map_chain */
  uint      prev;        /* reserved by map_chain (doubly-linked chains) */
  uint      fec_set_idx  : 26; /* position within the slot (multiple of FD_FEC_SHRED_CNT) */
  uint      root         : 1;  /* 1 if this entry is the one keyed in fd_fec_map under merkle_root */
  uint      treap        : 1;  /* 1 while on its version's worklist; set 0 stays until the slot is delivered */
  uint      complete     : 1;  /* set is reconstructable and may be delivered */
  uint      slot_complete: 1;
  uint      data_complete: 1;
  uint      is_leader    : 1;

  /* treap fields */
  uint      parent;      /* reserved by fd_rotor_treap */
  uint      left;        /* reserved by fd_rotor_treap */
  uint      right;       /* reserved by fd_rotor_treap */
  uint      prio;        /* reserved by fd_rotor_treap */

  long      next_req_ts; /* wallclock ns before which this set should not be asked for again.
                            Not part of the worklist key: it filters, it does not order. */
};
typedef struct fd_chainer_fec fd_chainer_fec_t;
FD_STATIC_ASSERT( sizeof(fd_chainer_fec_t)==80, fd_chainer_fec );

#define POOL_NAME  fd_fec_pool
#define POOL_T     fd_chainer_fec_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_map
#define MAP_ELE_T fd_chainer_fec_t
#define MAP_IDX_T uint
#define MAP_KEY   merkle_root
#define MAP_KEY_T fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0)->uc, (k1)->uc, FD_SHRED_MERKLE_NODE_SZ )) /* 20-byte root prefix */
#define MAP_KEY_HASH(key,seed) ( (seed) ^ fd_ulong_load_8( (key)->uc ) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define AG_UNKNOWN_SLOT ULONG_MAX
struct fd_chainer_slotv {
  ulong           slot; /* MAP_MULTI key */
  ulong           next; /* reserved by pool and map_chain */
  ulong           prev; /* reserved by map_chain */

  uchar           turbine;   /* 1 for the slotv created through turbine --
                                we need to track this for various reasons to be documented */
  uchar           final : 1; /* this is the final version of the slot */
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
    uint turbine_cnt;   /* data shreds received via turbine, plus every coding shred */
    uint repair_cnt;    /* data shreds received via repair */
    uint recovered_cnt; /* data shreds reconstructed via reed-solomon */
    uint parity_cnt;    /* coding shreds received */

    uint last_completed_fec_idx; /* fec_set_idx of the FEC set that most recently completed for this version */

    long first_shred_ts; /* the version's first shred arrived, wallclock ns */
    long last_shred_ts;  /* the version became fully buffered (buffered_idx==complete_idx), wallclock ns */

    uint req_window_cnt;     /* positional specific-shred requests sent (Shred) */
    uint req_highest_cnt;    /* highest-shred requests sent (HighestShred) */
    uint req_orphan_cnt;     /* ancestry requests sent (Orphan) */
    uint req_shred_bid_cnt;  /* alpenglow specific-shred requests sent (ShredForBlockId) */
    uint req_parent_cnt;     /* alpenglow ancestry requests sent (ParentAndFecCount) */
    uint req_fec_root_cnt;   /* alpenglow FEC-set-root requests sent (FecRoot) */
    uint req_retransmit_cnt; /* requests re-issued after a timeout or a bad response, shred or metadata */
    uint repair_responses;   /* repair responses matched to an outstanding request */

    long first_req_ts;        /* wallclock ns of the first specific-shred request sent, 0 if none */
    long last_repair_resp_ts; /* wallclock ns of the most recent matched repair response, 0 if none */
  } metrics;
};
typedef struct fd_chainer_slotv fd_chainer_slotv_t;

#define POOL_NAME fd_slotv_pool
#define POOL_T    fd_chainer_slotv_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_slotv_map
#define MAP_ELE_T fd_chainer_slotv_t
#define MAP_KEY   slot
#define MAP_MULTI 1 /* several versions of a slot share the slot key */
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1 /* remove a specific version, not an arbitrary slot match */
#include "../../util/tmpl/fd_map_chain.c"

/* Every version owns its FEC entries privately: one fd_fec_pool
   element per (version, FEC set), reachable as chainer->fec_tbl[ slotv,
   k ].  Private entries are what let each version carry its own
   worklist node and be torn down without asking whether a sibling
   still needs the set.

   Versions of an equivocating slot that genuinely share a set hold two
   entries carrying the same merkle root, but fd_fec_map keys uniquely:
   exactly one of them is keyed, and it is the one with root==1.  The
   others are shadows -- they know their root but are not findable by
   it, and are reached by walking the slot's versions.  Releasing the
   keyed entry promotes a surviving shadow in its place, so a root
   stays findable while any version still holds it.

   chainer->eager_treap and chainer->notar_treap hold the incomplete
   sets of, respectively, the turbine version and the cert-named
   versions, ordered by (slot, fec_set_idx).  That is the repair
   worklist, and it is ordered by nothing but position: the minimum is
   always the lowest set of the lowest slot still missing something,
   which is the one the delivery frontier is waiting on.

   Time is deliberately not in the key.  A set carries next_req_ts, a
   plain field saying when it may next be asked for; it filters a
   candidate, it does not order one.  Keeping the key immutable while
   the set is enrolled means a request is a field write rather than a
   remove-and-reinsert, and it means the seven paths that retire work
   -- completion, eviction, abandonment, publish, and the version
   teardowns -- never have to reason about a key that moved underneath
   them.

   Callers walk the worklist with fd_rotor_treap_idx_ge( treap, cursor,
   fec_pool ), an O(log n) seek to the first enrolled set at or after a
   (slot, fec_set_idx).  A drain is a sweep: seek, service the set the
   seek landed on, advance the cursor strictly past it, repeat until
   the budget runs out; resume from the cursor next time and wrap when
   the seek runs off the end.  Do not scan from the head for each
   request -- that is O(n) a request.

   The cursor is the full key, not just the slot, so a sweep can resume
   inside a slot.  Note that fd_rotor_treap_cursor.fec_set_idx is a
   shred index -- a multiple of FD_FEC_SHRED_CNT, matching
   fd_chainer_fec_t -- not a set ordinal, so stepping past a set is
   += FD_FEC_SHRED_CNT.

   Nothing on the set records which of its shreds have been asked for:
   that is the sweep cursor's shred_idx, and a lap of the cursor is one
   round of requests.

   A set is enrolled the moment it is known to exist and leaves when it
   completes.  fd_chainer_fec_rearm sets next_req_ts after a request;
   a turbine placeholder starts with a grace period, since turbine is
   probably still streaming it, while a cert-named one is due at once.

   Set 0 is special: it stays enrolled until the slot's final FEC is
   queued for delivery, including while the tip is unknown, later sets
   are missing, or delivery is waiting on a parent.  Abandonment and
   pruning also remove it along with the version's other work.

   Both treaps are backed by chainer->fec_pool, so an element is valid
   only until the next fd_chainer_* call. */

/* fd_rotor_treap_cursor_t is the worklist key as a value, so a seek can
   land inside a slot rather than only at its first set.  It mirrors
   TREAP_LT below; the element tie-break on pointer has no query
   equivalent, which only means idx_ge may land on any of several
   entries sharing a key -- they are all equally due. */

struct fd_rotor_treap_cursor {
  ulong slot;
  uint  fec_set_idx; /* shred index, a multiple of FD_FEC_SHRED_CNT */
};
typedef struct fd_rotor_treap_cursor fd_rotor_treap_cursor_t;

#define TREAP_NAME      fd_rotor_treap
#define TREAP_T         fd_chainer_fec_t
#define TREAP_QUERY_T   fd_rotor_treap_cursor_t /* idx_ge( treap, cursor ) seeks the sweep cursor */
#define TREAP_IDX_T     uint  /* parent/left/right/prio on fd_chainer_fec_t are uint */
#define TREAP_CMP(q,e)  ( (q).slot!=(ulong)(e)->slot                                                        \
                          ? ( ((q).slot>(ulong)(e)->slot) - ((q).slot<(ulong)(e)->slot) )                   \
                          : ( ((q).fec_set_idx>(e)->fec_set_idx) - ((q).fec_set_idx<(e)->fec_set_idx) ) )
#define TREAP_LT(e0,e1) ( (e0)->slot<(e1)->slot || ( (e0)->slot==(e1)->slot && ( (e0)->fec_set_idx<(e1)->fec_set_idx || ( (e0)->fec_set_idx==(e1)->fec_set_idx && (e0)<(e1) ) ) ) )
#include "../../util/tmpl/fd_treap.c"


#define DEQUE_NAME bfs
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct out_ele {
  uint slotv_idx;  /* slotv pool idx */
  uint fec_idx;    /* fd_fec_pool idx */
};
typedef struct out_ele out_ele_t;

/* out_queue holds pool indices of FECs that have been delivered
   (contiguous from root and connected) and are awaiting publish to
   replay by the repair tile.  Sized to the max number of FECs.  Since
   out_ele maintains pool indices, the out_queue must be drained between
   any chainer call that can modify the pool. */

#define DEQUE_NAME out_queue
#define DEQUE_T    out_ele_t
#include "../../util/tmpl/fd_deque_dynamic.c"

struct fd_chainer {
  ulong root;             /* root slot, ULONG_MAX if unset */
  ulong highest_repaired; /* max slot ever marked fully_delivered (contiguous-from-root repaired tip) */
  ulong wksp_gaddr;       /* wksp gaddr of fd_chainer in the backing wksp, non-zero gaddr */

  fd_chainer_fec_t * fec_pool;
  fd_fec_map_t     * fec_map;

  fd_chainer_slotv_t * slotv_pool;
  fd_slotv_map_t     * slotv_map;
  uint               * fec_tbl;     /* fec_tbl[ slotv_idx*fec_blk_max + k ] = fd_fec_pool idx of the FEC
                                       that slotv owns at FEC set k, UINT_MAX if none */
  ulong                fec_blk_max; /* max FEC sets per block (max_shreds_per_block/FD_FEC_SHRED_CNT) */

  fd_rotor_treap_t * eager_treap;
  fd_rotor_treap_t * notar_treap;

  ulong     * bfs;       /* bfs queue */
  out_ele_t * out_queue; /* delivered FEC pool idxs awaiting publish to replay */

  ulong magic; /* ==FD_CHAINER_MAGIC */
};
typedef struct fd_chainer fd_chainer_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_chainer_align( void ) {
  return fd_ulong_max( alignof(fd_chainer_t), 128UL );
}

/* fd_chainer_blk_max returns the max number of block versions the
   chainer tracks across ele_max slots, ie. ele_max *
   FD_CHAINER_EXPECTED_SLOT_CNT rounded up.  This is the expected, not
   the worst case: a slot may have up to FD_CHAINER_SLOT_VER_MAX
   versions, but only a minority of leaders are expected to equivocate. */

FD_FN_CONST static inline ulong
fd_chainer_blk_max( ulong ele_max ) {
  return (ulong)ceil( (double)ele_max * FD_CHAINER_EXPECTED_SLOT_CNT );
}

FD_FN_CONST static inline ulong
fd_chainer_footprint( ulong ele_max,
                      ulong max_shreds_per_block ) {
  if( FD_UNLIKELY( !max_shreds_per_block || max_shreds_per_block%FD_FEC_SHRED_CNT || max_shreds_per_block>FD_SHRED_BLK_MAX_RAISED ) ) return 0UL;
  ulong blk_max       = fd_chainer_blk_max( ele_max );
  ulong fec_blk_max   = max_shreds_per_block / FD_FEC_SHRED_CNT;
  ulong fec_max       = blk_max * fec_blk_max;
  if( FD_UNLIKELY( !fd_fec_pool_footprint( fec_max ) ) ) return 0UL;
  ulong fec_chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  ulong blk_chain_cnt = fd_slotv_map_chain_cnt_est( blk_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_chainer_t),   sizeof(fd_chainer_t)                       ),
      fd_fec_pool_align(),     fd_fec_pool_footprint    ( fec_max       ) ),
      fd_fec_map_align(),      fd_fec_map_footprint     ( fec_chain_cnt ) ),
      fd_slotv_pool_align(),   fd_slotv_pool_footprint  ( blk_max       ) ),
      alignof(uint),           fec_max*sizeof(uint)                       ), /* fec_tbl */
      fd_slotv_map_align(),    fd_slotv_map_footprint   ( blk_chain_cnt ) ),
      fd_rotor_treap_align(),  fd_rotor_treap_footprint ( fec_max       ) ),
      fd_rotor_treap_align(),  fd_rotor_treap_footprint ( fec_max       ) ),
      bfs_align(),             bfs_footprint            ( blk_max       ) ),
      out_queue_align(),       out_queue_footprint      ( fec_max       ) ),
    fd_chainer_align() );
}

void *
fd_chainer_new( void * shmem,
                ulong  ele_max,
                ulong  max_shreds_per_block,
                ulong  seed );

fd_chainer_t *
fd_chainer_join( void * chainer );

FD_FN_PURE static inline fd_wksp_t *
fd_chainer_wksp( fd_chainer_t * chainer ) {
  return (fd_wksp_t *)( ( (ulong)chainer ) - chainer->wksp_gaddr );
}

/* fd_chainer_highest_repaired_slot returns the highest slot on the
   contiguously-repaired chain from root (the analog of
   fd_forest_highest_repaired_slot) */

FD_FN_PURE static inline ulong
fd_chainer_highest_repaired_slot( fd_chainer_t const * chainer ) {
  return chainer->highest_repaired;
}

int
fd_chainer_verify( fd_chainer_t const * chainer );

void
fd_chainer_init( fd_chainer_t *    chainer,
                 ulong             slot,
                 fd_hash_t const * block_id );

/* Slotv pointers stay valid until the next fd_chainer_publish. */

/* fd_chainer_shred_insert inserts a data shred into the chainer.  If
   the parent_slot is provided, parent_block_id must also be provided.
   Otherwise caller should pass AG_UNKNOWN_SLOT for parent_slot.  src is
   one of FD_CHAINER_SRC_*.

   Known roots update their mapped FEC and bookkeeping for each version
   already holding that root at this position.  Unknown roots require an
   active turbine version with an unknown block_id; a turbine version
   is created only if the slot has no versions.  Conflicting roots,
   roots mapped to a different position, and unknown roots without an
   active turbine version are dropped.

   Caller must supply the full 32-byte merkle-root, not the 20-byte
   prefix. */

void
fd_chainer_shred_insert( fd_chainer_t *    chainer,
                         ulong             slot,
                         uint              shred_idx,
                         int               slot_complete,
                         int               src,
                         long              rx_ts,
                         fd_hash_t const * mr,
                         ulong             parent_slot,
                         fd_hash_t const * parent_block_id );

void
fd_chainer_code_shred_insert( fd_chainer_t *    chainer,
                              ulong             slot,
                              uint              fec_set_idx,
                              long              rx_ts,
                              fd_hash_t const * mr );

/* fd_chainer_fec_complete returns 1 when the set was rejected (no
   version of the slot holds the root: an unauthorized equivocation,
   dropped, nothing completed) and 0 otherwise.

   Caller must supply the full 32-byte merkle-root, not the 20-byte
   prefix. */

int
fd_chainer_fec_complete( fd_chainer_t *        chainer,
                         ulong                 slot,
                         uint                  fec_set_idx,
                         int                   slot_complete,
                         int                   data_complete,
                         int                   is_leader,
                         long                  rx_ts,
                         fd_hash_t *           mr );

/* fd_chainer_fec_evicted clears out the received shreds for a given
   FEC set, and also updates shred tracking for slots that have this FEC
   root. */

void
fd_chainer_fec_evicted( fd_chainer_t * chainer,
                        ulong          slot,
                        uint           fec_set_idx,
                        fd_hash_t    * merkle_root );

/* fd_chainer_verified_block_insert records {slot, block_id} as a
   verified version, abandoning the slot's turbine version if its
   block_id is still unknown.  Returns the new version, or NULL if it
   already existed or a different version is final. */

fd_chainer_slotv_t *
fd_chainer_verified_block_insert( fd_chainer_t * chainer,
                                  ulong          slot,
                                  fd_hash_t      block_id );

/* fd_chainer_slot_inval removes an unfinished turbine version's current
   repair work from the eager treap, retaining the version and its FECs.
   Repeated calls are harmless.  Subsequent admission and delivery use
   the usual rules.  Named versions and turbine versions with a derived
   block_id are unaffected. */

void
fd_chainer_slot_inval( fd_chainer_t * chainer,
                       ulong          slot );

/* fd_chainer_blk_final marks {slot, block_id} final, creating it if
   necessary, and deletes the slot's other versions.  Subsequent calls
   naming a different version are ignored.  Shared root-map entries and
   received bitmaps transfer to the surviving version.  If store is
   non-NULL, completed FECs with no surviving owner are removed from it.

   Pending out_queue entries for deleted versions are discarded.  The
   caller must drain any external queues holding chainer pool indices
   before calling.  Finality here applies to this slot only. */

void
fd_chainer_blk_final( fd_chainer_t *    chainer,
                      ulong             slot,
                      fd_hash_t const * block_id,
                      fd_store_t *      store );

/* fd_chainer_verified_parent_fec_count is chainer's entrypoint for
   updating information on what a slots fec set count, parent slot, and
   parent block id are.  This mirrors the Alpenglow repair type
   getParentAndFecSetCount.  The information should be verified before
   calling this function; chainer does no verification.  A response for
   a removed version is ignored.  Creates {parent, p_bid} if necessary
   unless another parent version is already final. */

void
fd_chainer_verified_parent_fec_count( fd_chainer_t * chainer,
                                      ulong          slot,
                                      fd_hash_t    * block_id,
                                      uint           fec_set_cnt,
                                      ulong          parent_slot,
                                      fd_hash_t    * parent_block_id );

/* fd_chainer_verified_hash_insert is chainer's entrypoint for updating
   information on what a slotv's FEC root is.  This mirrors the Alpenglow
   repair type getFecSetRoot.  The information should be verified before
   calling this function; chainer does no verification.  A response for
   a removed version is ignored.  Otherwise creates the FEC entry if it
   doesn't exist yet and updates bookkeeping.  If the root was already
   complete under another version the completion is replayed for the
   matching versions.  mr_prefix is the 20-byte root prefix the
   getFecSetRoot response carries. */

void
fd_chainer_verified_hash_insert( fd_chainer_t * chainer,
                                 ulong          slot,
                                 fd_hash_t *    block_id,
                                 uint           fec_set_idx,
                                 uchar const    mr_prefix[ static FD_SHRED_MERKLE_NODE_SZ ] );

/* fd_chainer_fec_owner returns the version that owns fec, or NULL if
   none does.  Entries are private per version, so this is well
   defined; it is how a worklist pop recovers the block it belongs to. */

fd_chainer_slotv_t *
fd_chainer_fec_owner( fd_chainer_t *           chainer,
                      fd_chainer_fec_t const * fec );

/* fd_chainer_fec_rearm records that a set was just asked for: it may
   not be asked again before `next_req_ts`.  The set keeps its place in
   the worklist -- the key does not move -- so this is a field write,
   not a re-insert.  A set that already completed has left the worklist
   and is not re-enrolled.

   Passing 0 means "still due, I am mid-fill". */

void
fd_chainer_fec_rearm( fd_chainer_fec_t * fec,
                      long               next_req_ts );

/* fd_chainer_fec_query returns the FEC that the version of slot
   identified by block_id owns at fec_set_idx, or NULL. */

fd_chainer_fec_t *
fd_chainer_fec_query( fd_chainer_t *    chainer,
                      ulong             slot,
                      uint              fec_set_idx,
                      fd_hash_t const * block_id );

/* fd_chainer_fec_data_idxs returns the received data shred bitmap for
   fec's Merkle root.  Only the entry with root set stores these bits;
   other versions resolve that entry through fd_fec_map.  Returns 0 if
   fec's root is unknown. */

uint
fd_chainer_fec_data_idxs( fd_chainer_t *           chainer,
                          fd_chainer_fec_t const * fec );

/* fd_chainer_shred_test returns 1 if slotv has data shred shred_idx.
   It looks up slotv's private FEC entry, then tests the shared bitmap
   returned by fd_chainer_fec_data_idxs.
   Returns 0 for shred_idx at or beyond max_shreds_per_block. */

int
fd_chainer_shred_test( fd_chainer_t *             chainer,
                       fd_chainer_slotv_t const * slotv,
                       uint                       shred_idx );

/* fd_chainer_publish advances the root to slot.  block_id identifies
   which version of slot is being rooted; every other version of it is
   pruned along with the slots below.  Pass NULL (or a block_id no
   version matches) to keep all versions of slot.  If store is non-NULL,
   each pruned FEC set is removed from it (rotor is the store
   publisher).

   IMPORTANT! The out_queue must be drained before calling this
   function, else there could be stale references to pruned slotvs. */

void
fd_chainer_publish( fd_chainer_t *    chainer,
                    ulong             slot,
                    fd_hash_t const * block_id,
                    fd_store_t *      store );

/* fd_chainer_repair_tally records one repair request or response
   against a block version.  A re-issued request counts only
   as a retransmit, not additionally as a request of its original kind. */

#define FD_CHAINER_REQ_WINDOW     (0)
#define FD_CHAINER_REQ_HIGHEST    (1)
#define FD_CHAINER_REQ_ORPHAN     (2)
#define FD_CHAINER_REQ_SHRED_BID  (3)
#define FD_CHAINER_REQ_PARENT     (4)
#define FD_CHAINER_REQ_FEC_ROOT   (5)
#define FD_CHAINER_REQ_RETRANSMIT (6)
#define FD_CHAINER_REQ_RESPONSE   (7)

static inline void
fd_chainer_repair_tally( fd_chainer_slotv_t * slotv, int kind, long now ) {
  if( FD_UNLIKELY( !slotv ) ) return;

  if( FD_LIKELY( now ) ) {
    if( kind==FD_CHAINER_REQ_WINDOW || kind==FD_CHAINER_REQ_SHRED_BID ) {
      if( FD_UNLIKELY( !slotv->metrics.first_req_ts ) ) slotv->metrics.first_req_ts = now;
    } else if( kind==FD_CHAINER_REQ_RESPONSE ) {
      slotv->metrics.last_repair_resp_ts = now;
    }
  }

  switch( kind ) {
    case FD_CHAINER_REQ_WINDOW:     slotv->metrics.req_window_cnt++;     break;
    case FD_CHAINER_REQ_HIGHEST:    slotv->metrics.req_highest_cnt++;    break;
    case FD_CHAINER_REQ_ORPHAN:     slotv->metrics.req_orphan_cnt++;     break;
    case FD_CHAINER_REQ_SHRED_BID:  slotv->metrics.req_shred_bid_cnt++;  break;
    case FD_CHAINER_REQ_PARENT:     slotv->metrics.req_parent_cnt++;     break;
    case FD_CHAINER_REQ_FEC_ROOT:   slotv->metrics.req_fec_root_cnt++;   break;
    case FD_CHAINER_REQ_RETRANSMIT: slotv->metrics.req_retransmit_cnt++; break;
    case FD_CHAINER_REQ_RESPONSE:   slotv->metrics.repair_responses++;   break;
    default: FD_LOG_CRIT(( "bad chainer repair tally kind %d", kind ));
  }
}

/* fd_chainer_slotv_iter_* walks the versions of a slot, of which there
   are at most FD_CHAINER_SLOT_VER_MAX:

     for( ulong i=fd_chainer_slotv_iter_init( chainer, slot ); i!=ULONG_MAX;
               i=fd_chainer_slotv_iter_next( chainer, i ) ) {
       fd_chainer_slotv_t * slotv = fd_chainer_slotv_iter_ele( chainer, i );
       ...
     }

   Indices are only valid until the next fd_chainer_* call. */

FD_FN_PURE static inline ulong
fd_chainer_slotv_iter_init( fd_chainer_t const * chainer, ulong slot ) {
  return fd_slotv_map_idx_query_const( chainer->slotv_map, &slot, ULONG_MAX, chainer->slotv_pool );
}

FD_FN_PURE static inline ulong
fd_chainer_slotv_iter_next( fd_chainer_t const * chainer, ulong idx ) {
  return fd_slotv_map_idx_next_const( idx, ULONG_MAX, chainer->slotv_pool );
}

FD_FN_PURE static inline fd_chainer_slotv_t *
fd_chainer_slotv_iter_ele( fd_chainer_t const * chainer, ulong idx ) {
  return fd_slotv_pool_ele( chainer->slotv_pool, idx );
}

static inline fd_chainer_slotv_t *
fd_chainer_slot_version_query( fd_chainer_t *    chainer,
                               ulong             slot,
                               fd_hash_t const * block_id ) {
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;
  for( ulong idx = fd_slotv_map_idx_query_const( slotv_map, &slot, ULONG_MAX, slotv_pool );
             idx != ULONG_MAX;
             idx = fd_slotv_map_idx_next_const( idx, ULONG_MAX, slotv_pool ) ) {
    fd_chainer_slotv_t * slotv = fd_slotv_pool_ele( slotv_pool, idx );
    if( FD_UNLIKELY( fd_hash_eq( &slotv->block_id, block_id ) ) ) return slotv;
  }
  return NULL;
}

/* fd_chainer_slotv_fecs returns slotv's row of chainer->fec_tbl:
   fecs[ k ] is the fd_fec_pool idx of the FEC slotv owns at FEC set k
   (shred position k*FD_FEC_SHRED_CNT), UINT_MAX if none, for k in
   [0,chainer->fec_blk_max). */

FD_FN_PURE static inline uint *
fd_chainer_slotv_fecs( fd_chainer_t const *       chainer,
                       fd_chainer_slotv_t const * slotv ) {
  return chainer->fec_tbl + fd_slotv_pool_idx( chainer->slotv_pool, slotv )*chainer->fec_blk_max;
}

/* fd_chainer_turbine_slotv_query returns slot's turbine version, or
   NULL if none exists.  Its block_id is all-zero until the block is
   whole and finalized; after that it is the only way to find the
   version the turbine stream built, since its key has changed. */

FD_FN_PURE static inline fd_chainer_slotv_t *
fd_chainer_turbine_slotv_query( fd_chainer_t const * chainer,
                                ulong                slot ) {
  fd_chainer_slotv_t * slotv_pool = (fd_chainer_slotv_t *)chainer->slotv_pool;
  fd_slotv_map_t     * slotv_map  = (fd_slotv_map_t     *)chainer->slotv_map;
  for( ulong idx = fd_slotv_map_idx_query_const( slotv_map, &slot, ULONG_MAX, slotv_pool );
             idx != ULONG_MAX;
             idx = fd_slotv_map_idx_next_const( idx, ULONG_MAX, slotv_pool ) ) {
    fd_chainer_slotv_t * slotv = fd_slotv_pool_ele( slotv_pool, idx );
    if( FD_LIKELY( slotv->turbine ) ) return slotv;
  }
  return NULL;
}

/* fd_chainer_slotv_complete returns 1 if every FEC set of the version
   is reconstructable: its tip is known and the complete sets buffered
   contiguously from 0 reach it. */

FD_FN_PURE static inline int
fd_chainer_slotv_complete( fd_chainer_slotv_t const * slotv ) {
  return slotv->complete_idx!=UINT_MAX && slotv->buffered_fec_idx==slotv->complete_idx;
}

/* fd_chainer_slot_query returns any version of slot, or NULL if the slot
   has no versions in the chainer. */

static inline fd_chainer_slotv_t *
fd_chainer_slot_query( fd_chainer_t * chainer, ulong slot ) {
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;
  ulong idx = fd_slotv_map_idx_query_const( slotv_map, &slot, ULONG_MAX, slotv_pool );
  return idx==ULONG_MAX ? NULL : fd_slotv_pool_ele( slotv_pool, idx );
}

void
fd_chainer_print( fd_chainer_t * chainer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_chainer_fd_chainer_h */
