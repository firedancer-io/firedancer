#ifndef HEADER_fd_src_choreo_rotor_fd_rotor_h
#define HEADER_fd_src_choreo_rotor_fd_rotor_h

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../votor/ag_votor_base.h"

/* fd_rotor reassembles FEC sets into their order in the block as they
   are received over the network via Turbine and Repair.  Every FEC set
   is guaranteed to be eventually delivered by rotor to the caller after
   it has been "chained" to its parent (defined below).

   Every FEC set has a parent (the immediately preceding FEC set in the
   slot or parent slot) and children (immediately succeeding FEC set(s)
   for the same slot or child slots).  Rotor always delivers a parent
   before its child.  This guarantees that every fork will be delivered
   in-order  Forks are treated as concurrent, and thus Rotor only
   provides a partial ordering such that Rotor makes no guarantees about
   the delivery order of FEC sets across forks, but in general this will
   be the order in which Rotor is able to chain them to their connected
   parents.

   Blocks are ordered collections of FEC sets.  Rotor maintains an array
   of FEC sets per block  Blocks are keyed by their slot in a MAP_MULTI:
   as a result, in case of equivocation by a bad leader, all the blocks
   will bucket into the same map chain.  The same FEC set can be part of
   multiple blocks.

   When Rotor detects either a complete block is received over turbine
   (every FEC set) or the block is bad (equivocating, merkle roots don't
   verify, etc.) Rotor will stop processing Turbine shreds or FEC sets
   and go into "repair-only".  At this point, new blocks can be added to
   Rotor only if they are attached to a NotarFallback (or stronger) cert
   or marked SafeToNotar by the Votor tile.  By limiting equivocation to
   only blocks marked NotarFallback or SafeToNotar, we ensure that we
   never store more than 7 distinct blocks per slot (Corollary 50).

   On receipt of a NotarFallback (or stronger) cert or SafeToNotar,
   Rotor will make a "getParentAndFecCount" Alpenglow-specific repair
   requests.  The response should trigger getSliceHash (2.8, Definition
   19) requests. Extra versions of a FEC set only exists once a
       getFecRoot response creates the sentinel with that root.
       Equivocating FEC shreds are accepted iff the sentinel already
       exists.  If the sentinel does not exist, the FEC shreds are
       dropped. This way -- turbine shreds are accepted without concern
       for whether the FEC sets belong to the "same slot", but
       votor-driven events guarantee repair of shreds that verifiably
       belong to the same slot.

   Note that in the uncommon but not impossible case where we may be
   taking a long to complete a block, we may receive a votor event for
   an honest slot that we are still in the process of receiving from
   turbine.  Since we can't compute the block_id for a slot still
   incomplete from turbine, we would create a redundant BLOCK entry for,
   logically, the same slot.  In effect, this would generate an extra
   getParentAndFecCount request and getFecRoot requests, but since we
   already have most of the data for the slot, we can avoid
   re-requesting the shreds.  This case should be rare enough that the
   redundancy is worth the simplicity.

   Note much of the complexity in chainer surrounds the fact that
   different versions of the block can share FEC sets.  It would be
   simpler to just repair the FEC sets independently per block, but
   fec_resolver de-duplicates FEC sets for as long as it lives in the
   resolver, which means it is currently not feasible to receive
   multiple FEC_COMPLETE messages for the same FEC set.  Thus once a
   shred is received for a FEC set, we have to update tracking for all
   versions of a block that share that FEC set.

   *Parent Discovery*

   The trickiness with chaining is that there's 3 different sources of
   parent information. Shreds contain parent_off field, which may or may
   not be removed in the future. The block header contains the initial
   replay parent_slot, and there can be an updateParent marker anywhere
   in the middle of the block.

   In the case where we are disconnected momentarily, or we are catching
   up, we won't ever receive shreds for the original parent slot, only
   for the updated parent slot. */

/* API

   fd_rotor_blk_final     => (direct or implicit) cancel all eager / notar,
                             except final block_id
   fd_rotor_blk_notar     => cancel all eager
   fd_rotor_blk_parent    => check for connected
   fd_rotor_fec_complete  => cancel fec, check for connected
   fd_rotor_shred_insert  => only check for connected in fec_complete
   fd_rotor_slot_eqvoc    => equivocation seen by the shred tile or any
                             other source: free the slot's eager block
   fd_rotor_slot_inval    => bad header (does not parse, or its parent
                             disagrees with parent_off): free the slot's
                             eager block
   fd_rotor_slot_skip     => (implicitly skipped via final) cancel all for
                             slot

   fec_idx is a FEC set's index within its block, shred_idx /
   FD_FEC_SHRED_CNT.  complete_fec_idx is the last set's, UINT_MAX until
   known.  A set is connected once complete and chained: set 0 to the
   last set of the parent version, set k to set k-1.  Connected sets are
   pushed onto rotor->reasm_queue as {blk_idx, fec_idx} in delivery
   order.

   FEC entries live in rotor->fec_pool, keyed in rotor->fec_map by
   merkle root once it is known; a version's sets are rotor->fec_pool
   indices in blk->fecs and fd_rotor_fec_query reads one.
   rotor->eager_treap and rotor->notar_treap are fd_rotor_treap_t of the
   incomplete sets of eager / notar versions, ordered by (slot, fec_idx),
   backed by rotor->fec_pool.  A treap element is valid only until the
   next fd_rotor_* call.

   The eager block is the version with the all-zero block id, at most
   one per slot.  It is created by the first shred or completion for a
   slot that has no version yet, latches the first root seen at each
   set, and is freed outright on a conflicting root, data past the tip,
   an invalid header, or a notar signal.  Once whole and chained it
   derives its block id and is an ordinary version from then on.
   Cancelling a version frees it and its sets.

   fd_rotor_blk_parent with a NULL block_id is the eager block's header:
   the caller passes shred 0's parent_slot and parent_block_id.  With a
   block_id it is the verified ParentAndFecCount response. */

FD_STATIC_ASSERT( FD_FEC_SHRED_CNT==32UL, fd_rotor_fec_bitmap );

struct fd_rotor_dmr {
  uchar uc[ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_rotor_dmr fd_rotor_dmr_t;
FD_STATIC_ASSERT( sizeof(fd_rotor_dmr_t)==20UL, fd_rotor_dmr );

struct fd_rotor_fec {
  fd_rotor_dmr_t merkle_root;
  uint           fec_idx;
  ulong          slot;
  uint           rcvd;
  uchar          root          : 1;
  uchar          complete      : 1;
  uchar          connected     : 1;
  uchar          data_complete : 1;
  uchar          is_leader     : 1;
  uchar          treap         : 1;
  ulong          next;
  ulong          prev;
  ulong          parent;
  ulong          left;
  ulong          right;
  ulong          prio;
};
typedef struct fd_rotor_fec fd_rotor_fec_t;
FD_STATIC_ASSERT( sizeof(fd_rotor_fec_t)==88UL, fd_rotor_fec );

#define POOL_NAME fec_pool
#define POOL_T    fd_rotor_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fec_map
#define MAP_ELE_T              fd_rotor_fec_t
#define MAP_KEY_T              fd_rotor_dmr_t
#define MAP_KEY                merkle_root
#define MAP_KEY_EQ(k0,k1)      ( !memcmp( (k0), (k1), sizeof(fd_rotor_dmr_t) ) )
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( (seed) ^ FD_LOAD( ulong, (key)->uc ) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME      fd_rotor_treap
#define TREAP_T         fd_rotor_fec_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ( ((q)>(e)->slot) - ((q)<(e)->slot) )
#define TREAP_LT(e0,e1) ( (e0)->slot<(e1)->slot || ( (e0)->slot==(e1)->slot && ( (e0)->fec_idx<(e1)->fec_idx || ( (e0)->fec_idx==(e1)->fec_idx && (e0)<(e1) ) ) ) )
#include "../../util/tmpl/fd_treap.c"

struct fd_rotor_blk {
  ulong     slot;
  ulong     prev;
  ulong     next;

  uchar     final;
  fd_hash_t block_id;
  uint      complete_fec_idx;

  ulong     parent_slot;
  fd_hash_t parent_block_id;

  uint      fecs[ FD_FEC_BLK_MAX ];
};
typedef struct fd_rotor_blk fd_rotor_blk_t;

#define POOL_NAME blk_pool
#define POOL_T    fd_rotor_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  blk_map
#define MAP_ELE_T fd_rotor_blk_t
#define MAP_KEY   slot
#define MAP_MULTI 1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct reasm {
  uint blk_idx;
  uint fec_idx;
};
typedef struct reasm reasm_t;

#define QUEUE_NAME reasm_queue
#define QUEUE_T    reasm_t
#include "../../util/tmpl/fd_queue_dynamic.c"

struct fd_rotor {
  ulong              root;
  ulong              slot_max;

  fd_rotor_blk_t   * blk_pool;
  blk_map_t        * blk_map;
  fd_rotor_fec_t   * fec_pool;
  fec_map_t        * fec_map;
  fd_rotor_treap_t * eager_treap;
  fd_rotor_treap_t * notar_treap;
  reasm_t          * reasm_queue;
};
typedef struct fd_rotor fd_rotor_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_rotor_align( void );

FD_FN_CONST ulong
fd_rotor_footprint( ulong slot_max );

void *
fd_rotor_new( void * shmem,
              ulong  slot_max,
              ulong  seed );

fd_rotor_t *
fd_rotor_join( void * shrotor );

void *
fd_rotor_leave( fd_rotor_t const * rotor );

void *
fd_rotor_delete( void * shrotor );

void
fd_rotor_init( fd_rotor_t *      rotor,
               ulong             root,
               fd_hash_t const * root_block_id );

void
fd_rotor_fini( fd_rotor_t * rotor );

void
fd_rotor_blk_final( fd_rotor_t *      rotor,
                    ulong             slot,
                    fd_hash_t const * block_id );

void
fd_rotor_blk_notar( fd_rotor_t *      rotor,
                    ulong             slot,
                    fd_hash_t const * block_id );

void
fd_rotor_blk_parent( fd_rotor_t *      rotor,
                     ulong             slot,
                     fd_hash_t const * block_id,
                     ulong             parent_slot,
                     fd_hash_t const * parent_block_id,
                     uint              complete_fec_idx );

int
fd_rotor_fec_complete( fd_rotor_t *           rotor,
                       ulong                  slot,
                       uint                   fec_idx,
                       fd_rotor_dmr_t const * merkle_root,
                       int                    slot_complete,
                       int                    data_complete,
                       int                    is_leader );

fd_rotor_fec_t *
fd_rotor_fec_query( fd_rotor_t const *     rotor,
                    fd_rotor_blk_t const * blk,
                    uint                   fec_idx );

void
fd_rotor_shred_insert( fd_rotor_t *           rotor,
                       ulong                  slot,
                       uint                   shred_idx,
                       fd_rotor_dmr_t const * merkle_root );

void
fd_rotor_slot_eqvoc( fd_rotor_t * rotor,
                     ulong        slot );

void
fd_rotor_slot_inval( fd_rotor_t * rotor,
                     ulong        slot );

void
fd_rotor_slot_skip( fd_rotor_t * rotor,
                    ulong        slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_rotor_fd_rotor_h */
