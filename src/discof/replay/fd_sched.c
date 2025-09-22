#include "fd_sched.h"
#include "../../flamenco/runtime/fd_runtime.h" /* for fd_runtime_load_txn_address_lookup_tables */

#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_hashes.h" /* for ALUTs */


// TODO can the bounds be tighter?
#define FD_SCHED_MAX_TXN_PER_BLOCK         (FD_TXN_MAX_PER_SLOT)
#define FD_SCHED_MAX_BLOCK_DEPTH           (1024UL)
#define FD_SCHED_MAX_NON_EMPTY_BLOCK_DEPTH (32UL)
#define FD_SCHED_MAX_DEPTH                 (FD_RDISP_MAX_DEPTH>>2)
#define FD_SCHED_MAX_STAGING_LANES_LOG     (2)
#define FD_SCHED_MAX_STAGING_LANES         (1UL<<FD_SCHED_MAX_STAGING_LANES_LOG)

/* We size the buffer to be able to hold residual data from the previous
   FEC set that only becomes parseable after the next FEC set is
   ingested, as well as the incoming FEC set.  The largest minimally
   parseable unit of data is a transaction.  So that much data may
   straddle FEC set boundaries.  Other minimally parseable units of data
   include the microblock header and the microblock count within a
   batch. */
#define FD_SCHED_MAX_PAYLOAD_PER_FEC       (FD_STORE_DATA_MAX)
#define FD_SCHED_MAX_FEC_BUF_SZ            (FD_SCHED_MAX_PAYLOAD_PER_FEC+FD_TXN_MTU)
FD_STATIC_ASSERT( FD_TXN_MTU>=sizeof(fd_microblock_hdr_t), resize buffer for residual data );
FD_STATIC_ASSERT( FD_TXN_MTU>=sizeof(ulong),               resize buffer for residual data );

#define FD_SCHED_MAGIC (0xace8a79c181f89b6UL) /* echo -n "fd_sched_v0" | sha512sum | head -c 16 */


/* Structs. */

struct fd_sched_block {
  fd_sched_block_id_t block_id;
  ulong               next;        /* reserved for internal use by fd_pool, fd_map_chain */
  ulong               parent_idx;  /* index of the parent in the pool */
  ulong               child_idx;   /* index of the left-child in the pool */
  ulong               sibling_idx; /* index of the right-sibling in the pool */

  /* Counters. */
  uint                txn_parsed_cnt;
  /*                  txn_queued_cnt = txn_parsed_cnt-txn_in_flight_cnt-txn_done_cnt */
  uint                txn_in_flight_cnt;
  uint                txn_done_cnt;
  uint                shred_cnt;

  /* Parser state. */
  uchar               txn[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_hash_t           poh;          /* latest PoH hash we've seen from the ingested FEC sets */
  ulong               mblks_rem;    /* number of microblocks remaining in the current batch */
  ulong               txns_rem;     /* number of transactions remaining in the current microblock */
  fd_acct_addr_t      aluts[ 256 ]; /* resolve ALUT accounts into this buffer for more parallelism */
  uint                fec_buf_sz;   /* size of the fec_buf in bytes */
  uint                fec_buf_soff; /* starting offset into fec_buf for unparsed transactions */
  uint                fec_eob:1;    /* FEC end-of-batch: set if the last FEC set in the batch is being
                                       ingested */
  uint                fec_sob:1;    /* FEC start-of-batch: set if the parser expects to be receiving a new
                                       batch */

  /* Block state. */
  uint                fec_eos:1;                          /* FEC end-of-stream: set if the last FEC set in the block has been
                                                             ingested */
  uint                rooted:1;                           /* set if the block is rooted */
  uint                dying:1;                            /* set if the block has been abandoned and no transactions should be
                                                             scheduled from it */
  uint                in_rdisp:1;                         /* set if the block is being tracked by the dispatcher, either as staged
                                                             or unstaged */
  uint                block_start_signaled:1;             /* set if the start-of-block sentinel has been dispatched */
  uint                block_end_signaled:1;               /* set if the end-of-block sentinel has been dispatched */
  uint                staged:1;                           /* set if the block is in a dispatcher staging lane; a staged block is
                                                             tracked by the dispatcher */
  ulong               staging_lane;                       /* ignored if staged==0 */
  ulong               luf_depth;                          /* depth of longest unstaged fork starting from this node; only
                                                             stageable unstaged descendants are counted */
  uchar               fec_buf[ FD_SCHED_MAX_FEC_BUF_SZ ]; /* the previous FEC set could have some residual data that only becomes
                                                             parseable after the next FEC set is ingested */
};
typedef struct fd_sched_block fd_sched_block_t;

FD_STATIC_ASSERT( sizeof(fd_hash_t)==sizeof(((fd_microblock_hdr_t *)0)->hash), unexpected poh hash size );

#define POOL_NAME  block_pool
#define POOL_T     fd_sched_block_t
#define POOL_NEXT  next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               block_map
#define MAP_ELE_T              fd_sched_block_t
#define MAP_KEY_T              fd_sched_block_id_t
#define MAP_KEY                block_id
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_sched_block_id_t)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash((key)->id^seed))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct fd_sched_metrics {
  uint  block_added_cnt;
  uint  block_added_staged_cnt;
  uint  block_added_unstaged_cnt;
  uint  block_added_dead_ood_cnt;
  uint  block_removed_cnt;
  uint  block_abandoned_cnt;
  uint  block_promoted_cnt;
  uint  block_demoted_cnt;
  uint  deactivate_no_child_cnt;
  uint  deactivate_no_txn_cnt;
  uint  deactivate_pruned_cnt;
  uint  deactivate_abandoned_cnt;
  uint  lane_switch_cnt;
  uint  lane_promoted_cnt;
  uint  lane_demoted_cnt;
  uint  alut_success_cnt;
  uint  alut_serializing_cnt;
  uint  txn_abandoned_parsed_cnt;
  uint  txn_abandoned_done_cnt;
  uint  txn_max_in_flight_cnt;
  ulong txn_weighted_in_flight_cnt;
  ulong txn_weighted_in_flight_tickcount;
  ulong txn_none_in_flight_tickcount;
  ulong txn_parsed_cnt;
  ulong txn_done_cnt;
  ulong bytes_ingested_cnt;
  ulong bytes_ingested_unparsed_cnt;
  ulong bytes_dropped_cnt;
  ulong fec_cnt;
};
typedef struct fd_sched_metrics fd_sched_metrics_t;

struct fd_sched {
  fd_sched_metrics_t  metrics[ 1 ];
  long                txn_in_flight_last_tick;
  ulong               root_idx;
  fd_rdisp_t *        rdisp;
  ulong               active_block_idx; /* index of the actively replayed block, or null_idx if no block is
                                           actively replayed; has to have a transaction to dispatch; staged
                                           blocks that have no transactions to dispatch are not eligible for
                                           being active. */
  ulong               staged_bitset;    /* bit i set if staging lane i is occupied */
  ulong               staged_head_block_idx[ FD_SCHED_MAX_STAGING_LANES ]; /* head of the linear chain in each staging lane, ignored if bit i is
                                                                              not set in the bitset */
  ulong               txn_pool_free_cnt;
  fd_txn_p_t          txn_pool[ FD_SCHED_MAX_DEPTH ];
  ulong               txn_to_block_idx[ FD_SCHED_MAX_DEPTH ]; /* index of the block that the txn belongs to */
  fd_sched_block_t *  block_pool; /* fd_pool of max_block_depth elements */
  block_map_t *       block_map;  /* map_chain */
};
typedef struct fd_sched fd_sched_t;


/* Internal helpers. */

static void
add_block( fd_sched_t *          sched,
           fd_sched_block_id_t * block_id,
           fd_sched_block_id_t * parent_block_id,
           fd_sched_block_t * *  out_block,
           fd_sched_block_t * *  out_parent_block );

static void
fd_sched_parse( fd_sched_t * sched, fd_sched_block_t * block, fd_sched_alut_ctx_t * alut_ctx );

static int
fd_sched_parse_txn( fd_sched_t * sched, fd_sched_block_t * block, fd_sched_alut_ctx_t * alut_ctx );

static void
try_activate_block( fd_sched_t * sched );

static void
subtree_abandon( fd_sched_t * sched, fd_sched_block_t * block );

FD_FN_UNUSED static ulong
find_and_stage_longest_unstaged_fork( fd_sched_t * sched, int lane_idx );

static ulong
compute_longest_unstaged_fork( fd_sched_t * sched, ulong block_idx );

static ulong
stage_longest_unstaged_fork( fd_sched_t * sched, ulong block_idx, int lane_idx );

FD_FN_UNUSED static inline int
block_is_void( fd_sched_block_t * block ) {
  /* We've seen everything in the block and no transaction got parsed
     out. */
  return block->fec_eos && block->txn_parsed_cnt==0;
}

static inline int
block_should_signal_end( fd_sched_block_t * block ) {
  ulong txn_queued_cnt = block->txn_parsed_cnt-block->txn_in_flight_cnt-block->txn_done_cnt;
  return block->fec_eos && txn_queued_cnt==0UL && !block->block_end_signaled;
}

static inline int
block_is_dispatchable( fd_sched_block_t * block ) {
  return block->txn_parsed_cnt>block->txn_done_cnt ||
         !block->block_start_signaled ||
         block_should_signal_end( block );
}

static inline int
block_is_done( fd_sched_block_t * block ) {
  return block->fec_eos && !block_is_dispatchable( block );
}

static inline int
block_is_stageable( fd_sched_block_t * block ) {
  int rv = !block_is_done( block ) && !block->dying;
  if( FD_UNLIKELY( rv && !block->in_rdisp ) ) {
    /* Invariant: stageable blocks may be currently staged or unstaged,
       but must be in the dispatcher either way.  When a block
       transitions to DONE, it will be immediately removed from the
       dispatcher.  When a block transitions to DYING, it will be
       eventually abandoned from the dispatcher. */
    FD_LOG_CRIT(( "invariant violation: stageable block->in_rdisp==0, slot %lu, prime %lu",
                  (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }
  return rv;
}

static inline int
block_is_promotable( fd_sched_block_t * block ) {
  return block_is_stageable( block ) && !block->staged;
}

static inline int
block_is_activatable( fd_sched_block_t * block ) {
  return block_is_stageable( block ) && block_is_dispatchable( block ) && block->staged;
}

FD_FN_UNUSED static void
debug_print_block( fd_sched_block_t * block ) {
  FD_LOG_INFO(( "block slot %lu, prime %lu, staged %d (lane %lu), dying %d, in_rdisp %d, fec_eos %d, rooted %d, block_start_signaled %d, block_end_signaled %d, txn_parsed_cnt %u, txn_in_flight_cnt %u, txn_done_cnt %u, shred_cnt %u",
                (ulong)block->block_id.slot, (ulong)block->block_id.prime, block->staged, block->staging_lane, block->dying, block->in_rdisp, block->fec_eos, block->rooted, block->block_start_signaled, block->block_end_signaled, block->txn_parsed_cnt, block->txn_in_flight_cnt, block->txn_done_cnt, block->shred_cnt ));
}

FD_FN_UNUSED static void
debug_print_metrics( fd_sched_t * sched ) {
  FD_LOG_INFO(( "metrics: block_added_cnt %u, block_added_staged_cnt %u, block_added_unstaged_cnt %u, block_added_dead_ood_cnt %u, block_removed_cnt %u, block_abandoned_cnt %u, block_promoted_cnt %u, block_demoted_cnt %u, deactivate_no_child_cnt %u, deactivate_no_txn_cnt %u, deactivate_pruned_cnt %u, deactivate_abandoned_cnt %u, lane_switch_cnt %u, lane_promoted_cnt %u, lane_demoted_cnt %u, alut_success_cnt %u, alut_serializing_cnt %u, txn_abandoned_parsed_cnt %u, txn_abandoned_done_cnt %u, txn_max_in_flight_cnt %u, txn_weighted_in_flight_cnt %lu, txn_weighted_in_flight_tickcount %lu, txn_none_in_flight_tickcount %lu, txn_parsed_cnt %lu, txn_done_cnt %lu, bytes_ingested_cnt %lu, bytes_ingested_unparsed_cnt %lu, bytes_dropped_cnt %lu, fec_cnt %lu",
                sched->metrics->block_added_cnt, sched->metrics->block_added_staged_cnt, sched->metrics->block_added_unstaged_cnt, sched->metrics->block_added_dead_ood_cnt, sched->metrics->block_removed_cnt, sched->metrics->block_abandoned_cnt, sched->metrics->block_promoted_cnt, sched->metrics->block_demoted_cnt, sched->metrics->deactivate_no_child_cnt, sched->metrics->deactivate_no_txn_cnt, sched->metrics->deactivate_pruned_cnt, sched->metrics->deactivate_abandoned_cnt, sched->metrics->lane_switch_cnt, sched->metrics->lane_promoted_cnt, sched->metrics->lane_demoted_cnt, sched->metrics->alut_success_cnt, sched->metrics->alut_serializing_cnt, sched->metrics->txn_abandoned_parsed_cnt, sched->metrics->txn_abandoned_done_cnt, sched->metrics->txn_max_in_flight_cnt, sched->metrics->txn_weighted_in_flight_cnt, sched->metrics->txn_weighted_in_flight_tickcount, sched->metrics->txn_none_in_flight_tickcount, sched->metrics->txn_parsed_cnt, sched->metrics->txn_done_cnt, sched->metrics->bytes_ingested_cnt, sched->metrics->bytes_ingested_unparsed_cnt, sched->metrics->bytes_dropped_cnt, sched->metrics->fec_cnt ));
}

/* Public functions. */

ulong fd_sched_align( void ) {
  return fd_ulong_max( alignof(fd_sched_t),
         fd_ulong_max( fd_rdisp_align(),
         fd_ulong_max( block_map_align(),
         fd_ulong_max( block_pool_align(), 64UL )))); /* Minimally cache line aligned. */
}

ulong
fd_sched_footprint( void ) {
  ulong chain_cnt = block_map_chain_cnt_est( FD_SCHED_MAX_BLOCK_DEPTH );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_sched_align(),   sizeof(fd_sched_t)                                                   );
  l = FD_LAYOUT_APPEND( l, fd_rdisp_align(),   fd_rdisp_footprint  ( FD_SCHED_MAX_DEPTH, FD_SCHED_MAX_BLOCK_DEPTH ) ); /* dispatcher */
  l = FD_LAYOUT_APPEND( l, block_map_align(),  block_map_footprint ( chain_cnt                                    ) ); /* block map  */
  l = FD_LAYOUT_APPEND( l, block_pool_align(), block_pool_footprint( FD_SCHED_MAX_BLOCK_DEPTH                     ) ); /* block pool */
  return FD_LAYOUT_FINI( l, fd_sched_align() );
}

void *
fd_sched_new( void * mem ) {
  ulong chain_cnt = block_map_chain_cnt_est( FD_SCHED_MAX_BLOCK_DEPTH );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_sched_t * sched = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_align(),   sizeof(fd_sched_t)                                                   );
  void * _rdisp      = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),   fd_rdisp_footprint  ( FD_SCHED_MAX_DEPTH, FD_SCHED_MAX_BLOCK_DEPTH ) );
  void * _bmap       = FD_SCRATCH_ALLOC_APPEND( l, block_map_align(),  block_map_footprint ( chain_cnt                                    ) );
  void * _bpool      = FD_SCRATCH_ALLOC_APPEND( l, block_pool_align(), block_pool_footprint( FD_SCHED_MAX_BLOCK_DEPTH                     ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_sched_align() );

  ulong seed = ((ulong)fd_tickcount()) ^ FD_SCHED_MAGIC;
  fd_rdisp_new  ( _rdisp, FD_SCHED_MAX_DEPTH, FD_SCHED_MAX_BLOCK_DEPTH, seed );
  block_map_new ( _bmap, chain_cnt, seed+1UL                                 );
  block_pool_new( _bpool, FD_SCHED_MAX_BLOCK_DEPTH                           );

  fd_sched_block_t * _bpool_join = block_pool_join( _bpool );
  ulong null_idx = block_pool_idx_null( _bpool_join );
  block_pool_leave( _bpool_join );

  fd_memset( sched->metrics, 0, sizeof(fd_sched_metrics_t) );
  sched->txn_in_flight_last_tick = LONG_MAX;

  sched->root_idx         = null_idx;
  sched->active_block_idx = null_idx;
  sched->staged_bitset    = 0UL;

  sched->txn_pool_free_cnt = FD_SCHED_MAX_DEPTH-1UL; /* -1 because index 0 is unusable as a sentinel reserved by the dispatcher */

  return sched;
}

fd_sched_t *
fd_sched_join( void * mem ) {
  fd_sched_t * sched = (fd_sched_t *)mem;

  ulong chain_cnt = block_map_chain_cnt_est( FD_SCHED_MAX_BLOCK_DEPTH );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  /*                */ FD_SCRATCH_ALLOC_APPEND( l, fd_sched_align(),   sizeof(fd_sched_t)                                                   );
  void  * _rdisp     = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),   fd_rdisp_footprint  ( FD_SCHED_MAX_DEPTH, FD_SCHED_MAX_BLOCK_DEPTH ) );
  void  * _bmap      = FD_SCRATCH_ALLOC_APPEND( l, block_map_align(),  block_map_footprint ( chain_cnt                                    ) );
  void  * _bpool     = FD_SCRATCH_ALLOC_APPEND( l, block_pool_align(), block_pool_footprint( FD_SCHED_MAX_BLOCK_DEPTH                     ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_sched_align() );

  sched->rdisp      = fd_rdisp_join( _rdisp );
  sched->block_map  = block_map_join( _bmap );
  sched->block_pool = block_pool_join( _bpool );

  return sched;
}

int
fd_sched_fec_can_ingest( fd_sched_t * sched, fd_sched_fec_t * fec ) {
  if( FD_UNLIKELY( fec->fec->data_sz>FD_SCHED_MAX_PAYLOAD_PER_FEC ) ) {
    FD_LOG_CRIT(( "invalid FEC set: fec->data_sz %lu, fec->mr %s, slot %lu, prime %lu, parent slot %lu, parent prime %lu",
                  fec->fec->data_sz, FD_BASE58_ENC_32_ALLOCA( fec->fec->key.mr.hash ), (ulong)fec->block_id.slot, (ulong)fec->block_id.prime, (ulong)fec->parent_block_id.slot, (ulong)fec->parent_block_id.prime ));
  }

  ulong fec_buf_sz = 0UL;
  fd_sched_block_t * block = block_map_ele_query( sched->block_map, &fec->block_id, NULL, sched->block_pool );
  if( FD_LIKELY( block ) ) {
    fec_buf_sz += block->fec_buf_sz-block->fec_buf_soff;
  } else {
    /* This FEC set will need to allocate a new block from the pool. */
    if( FD_UNLIKELY( !block_pool_free( sched->block_pool ) ) ) {
      return 0;
    }
  }
  /* Addition is safe and won't overflow because we checked the FEC set
     size above. */
  fec_buf_sz += fec->fec->data_sz;
  /* Assuming every transaction is min size, do we have enough free
     entries in the txn pool?  For a more precise txn count, we would
     have to do some parsing. */
  return sched->txn_pool_free_cnt>=fec_buf_sz/FD_TXN_MIN_SERIALIZED_SZ;
}

int
fd_sched_can_ingest( fd_sched_t * sched ) {
  /* Assume worst case we will need to allocate a new block from the
     pool. */
  if( FD_UNLIKELY( !block_pool_free( sched->block_pool ) ) ) {
    return 0;
  }

  /* Worst case, we need one byte from the incoming data to extract a
     transaction out of the residual data, and the rest of the incoming
     data contributes toward min sized transactions. */
  ulong txn_cnt = (FD_SCHED_MAX_PAYLOAD_PER_FEC-1UL)/FD_TXN_MIN_SERIALIZED_SZ+1UL; /* 478 */
  return sched->txn_pool_free_cnt>=txn_cnt;
}

void
fd_sched_fec_ingest( fd_sched_t * sched, fd_sched_fec_t * fec ) {
  if( FD_UNLIKELY( fec->fec->data_sz>FD_SCHED_MAX_PAYLOAD_PER_FEC ) ) {
    FD_LOG_CRIT(( "invalid FEC set: fec->data_sz %lu, fec->mr %s, slot %lu, prime %lu, parent slot %lu, parent prime %lu",
                  fec->fec->data_sz, FD_BASE58_ENC_32_ALLOCA( fec->fec->key.mr.hash ), (ulong)fec->block_id.slot, (ulong)fec->block_id.prime, (ulong)fec->parent_block_id.slot, (ulong)fec->parent_block_id.prime ));
  }

  ulong null_idx = block_pool_idx_null( sched->block_pool );

  fd_sched_block_t * block = block_map_ele_query( sched->block_map, &fec->block_id, NULL, sched->block_pool );
  if( FD_UNLIKELY( !block ) ) {
    /* This is a new block. */
    fd_sched_block_t * parent_block = NULL;
    add_block( sched, &fec->block_id, &fec->parent_block_id, &block, &parent_block );

    if( FD_UNLIKELY( block->dying ) ) {
      /* The child of a dead block is also dead.  We added it to our
         fork tree just so we could track an entire lineage of dead
         children and propagate the dead property to the entire lineage,
         in case there were frags for more than one dead children
         in-flight at the time the parent was abandoned.  That being
         said, we shouldn't need to add the dead child to the
         dispatcher. */
      sched->metrics->block_added_dead_ood_cnt++;

      /* Ignore the FEC set for a dead block. */
      sched->metrics->bytes_dropped_cnt += fec->fec->data_sz;
      return;
    }

    /* Try to find a staging lane for this block. */
    int alloc_lane = 0;
    if( FD_LIKELY( parent_block->staged ) ) {
      /* Parent is staged.  So see if we can continue down the same
         staging lane. */
      ulong staging_lane = parent_block->staging_lane;
      ulong child_idx    = parent_block->child_idx;
      while( child_idx != null_idx ) {
        fd_sched_block_t * child = block_pool_ele( sched->block_pool, child_idx );
        if( child->staged && child->staging_lane==staging_lane ) {
          /* Found a child on the same lane.  So we're done. */
          staging_lane = FD_RDISP_UNSTAGED;
          break;
        }
        child_idx = child->sibling_idx;
      }
      /* No child is staged on the same lane as the parent.  So stage
         this block.  This is the common case. */
      if( FD_LIKELY( staging_lane!=FD_RDISP_UNSTAGED ) ) {
        block->in_rdisp     = 1;
        block->staged       = 1;
        block->staging_lane = staging_lane;
        fd_rdisp_add_block( sched->rdisp, block->block_id.id, staging_lane );
        sched->metrics->block_added_cnt++;
        sched->metrics->block_added_staged_cnt++;
      } else {
        alloc_lane = 1;
      }
    } else {
      if( block_is_stageable( parent_block ) ) {
        /* Parent is unstaged but stageable.  So let's be unstaged too.
           This is a policy decision to be lazy and not promote parent
           at the moment. */
        block->in_rdisp = 1;
        block->staged   = 0;
        fd_rdisp_add_block( sched->rdisp, block->block_id.id, FD_RDISP_UNSTAGED );
        sched->metrics->block_added_cnt++;
        sched->metrics->block_added_unstaged_cnt++;
      } else {
        alloc_lane = 1;
      }
    }
    if( FD_UNLIKELY( alloc_lane ) ) {
      /* We weren't able to inherit the parent's staging lane.  So try
         to find a new staging lane. */
      if( FD_LIKELY( sched->staged_bitset!=fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES ) ) ) { /* Optimize for lane available. */
        int lane_idx = fd_ulong_find_lsb( ~sched->staged_bitset );
        if( FD_UNLIKELY( lane_idx>=(int)FD_SCHED_MAX_STAGING_LANES ) ) {
          FD_LOG_CRIT(( "invariant violation: lane_idx %d, sched->staged_bitset %lx",
                        lane_idx, sched->staged_bitset ));
        }
        sched->staged_bitset = fd_ulong_set_bit( sched->staged_bitset, lane_idx );
        sched->staged_head_block_idx[ lane_idx ] = block_pool_idx( sched->block_pool, block );
        block->in_rdisp     = 1;
        block->staged       = 1;
        block->staging_lane = (ulong)lane_idx;
        fd_rdisp_add_block( sched->rdisp, block->block_id.id, block->staging_lane );
        sched->metrics->block_added_cnt++;
        sched->metrics->block_added_staged_cnt++;
      } else {
        /* No lanes available. */
        block->in_rdisp = 1;
        block->staged   = 0;
        fd_rdisp_add_block( sched->rdisp, block->block_id.id, FD_RDISP_UNSTAGED );
        sched->metrics->block_added_cnt++;
        sched->metrics->block_added_unstaged_cnt++;
      }
    }
  }

  if( FD_UNLIKELY( block->dying ) ) {
    /* Ignore the FEC set for a dead block. */
    sched->metrics->bytes_dropped_cnt += fec->fec->data_sz;
    return;
  }

  if( FD_UNLIKELY( !block->in_rdisp ) ) {
    /* Invariant: block must be in the dispatcher at this point. */
    FD_LOG_CRIT(( "invariant violation: block->in_rdisp==0, slot %lu, prime %lu",
                  (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }

  if( FD_UNLIKELY( block->fec_eos ) ) {
    /* This means something is wrong upstream. */
    FD_LOG_CRIT(( "invariant violation: block->fec_eos set but getting more FEC sets fec->mr %s, slot %lu, prime %lu, parent slot %lu, parent prime %lu",
                  FD_BASE58_ENC_32_ALLOCA( fec->fec->key.mr.hash ), (ulong)fec->block_id.slot, (ulong)fec->block_id.prime, (ulong)fec->parent_block_id.slot, (ulong)fec->parent_block_id.prime ));
  }
  if( FD_UNLIKELY( block->fec_eob && fec->is_last_in_batch ) ) {
    /* This means the previous batch didn't parse properly.  So this is
       a bad block.  We should refuse to replay down the fork. */
    FD_LOG_WARNING(( "invariant violation: block->fec_eob set but getting another FEC set that is last in batch fec->mr %s, slot %lu, prime %lu, parent slot %lu, parent prime %lu",
                     FD_BASE58_ENC_32_ALLOCA( fec->fec->key.mr.hash ), (ulong)fec->block_id.slot, (ulong)fec->block_id.prime, (ulong)fec->parent_block_id.slot, (ulong)fec->parent_block_id.prime ));
    block->dying = 1;//FIXME inform replay/banks that it's dead?
    sched->metrics->bytes_dropped_cnt += fec->fec->data_sz;
    return;
  }
  if( FD_UNLIKELY( block->child_idx!=null_idx ) ) {
    /* This means something is wrong upstream.  FEC sets are not being
       delivered in replay order. */
    FD_LOG_CRIT(( "invariant violation: block->child_idx %lu, fec->mr %s, slot %lu, prime %lu, parent slot %lu, parent prime %lu",
                  block->child_idx, FD_BASE58_ENC_32_ALLOCA( fec->fec->key.mr.hash ), (ulong)fec->block_id.slot, (ulong)fec->block_id.prime, (ulong)fec->parent_block_id.slot, (ulong)fec->parent_block_id.prime ));
  }

  FD_TEST( block->fec_buf_sz>=block->fec_buf_soff );
  if( FD_LIKELY( block->fec_buf_sz>block->fec_buf_soff ) ) {
    /* If there is residual data from the previous FEC set within the
       same batch, we move it to the beginning of the buffer and append
       the new FEC set. */
    memmove( block->fec_buf, block->fec_buf+block->fec_buf_soff, block->fec_buf_sz-block->fec_buf_soff );
  }
  block->fec_buf_sz  -= block->fec_buf_soff;
  block->fec_buf_soff = 0;
  /* Addition is safe and won't overflow because we checked the FEC
     set size above. */
  if( FD_UNLIKELY( block->fec_buf_sz-block->fec_buf_soff+fec->fec->data_sz>FD_SCHED_MAX_FEC_BUF_SZ ) ) {
    /* In a conformant block, there shouldn't be more than a
       transaction's worth of residual data left over from the previous
       FEC set within the same batch.  So if this condition doesn't
       hold, it's a bad block.  Instead of crashing, we should refuse to
       replay down the fork. */
    FD_LOG_WARNING(( "bad block: fec_buf_sz %u, fec_buf_soff %u, fec->data_sz %lu, fec->mr %s, slot %lu, prime %lu, parent slot %lu, parent prime %lu",
                     block->fec_buf_sz, block->fec_buf_soff, fec->fec->data_sz, FD_BASE58_ENC_32_ALLOCA( fec->fec->key.mr.hash ), (ulong)fec->block_id.slot, (ulong)fec->block_id.prime, (ulong)fec->parent_block_id.slot, (ulong)fec->parent_block_id.prime ));
    block->dying = 1;//FIXME inform replay/banks that it's dead?
    sched->metrics->bytes_dropped_cnt += fec->fec->data_sz;
    return;
  }

  block->shred_cnt += fec->shred_cnt;
  sched->metrics->fec_cnt++;

  /* Append the new FEC set to the end of the buffer. */
  fd_memcpy( block->fec_buf+block->fec_buf_sz, fec->fec->data, fec->fec->data_sz );
  block->fec_buf_sz += (uint)fec->fec->data_sz;
  sched->metrics->bytes_ingested_cnt += fec->fec->data_sz;

  block->fec_eob = fec->is_last_in_batch;
  block->fec_eos = fec->is_last_in_block;

  fd_sched_parse( sched, block, fec->alut_ctx );

  /* Check if we need to set the active block. */
  if( FD_UNLIKELY( sched->active_block_idx==null_idx ) ) {
    try_activate_block( sched );
  } else {
    fd_sched_block_t * active_block = block_pool_ele( sched->block_pool, sched->active_block_idx );
    if( FD_UNLIKELY( !block_is_activatable( active_block ) ) ) {
      FD_LOG_CRIT(( "invariant violation: active_block_idx %lu is not activatable, txn_parsed_cnt %u, txn_done_cnt %u, fec_eos %u, dying %u, slot %lu, prime %lu",
                    sched->active_block_idx, active_block->txn_parsed_cnt, active_block->txn_done_cnt, (uint)active_block->fec_eos, (uint)active_block->dying, (ulong)active_block->block_id.slot, (ulong)active_block->block_id.prime ));
    }
  }

  return;
}

ulong
fd_sched_txn_next_ready( fd_sched_t * sched, fd_sched_txn_ready_t * out_txn ) {
  ulong null_idx = block_pool_idx_null( sched->block_pool );
  if( FD_UNLIKELY( sched->active_block_idx==null_idx ) ) {
    /* No need to try activating a block.  If we're in this state,
       there's truly nothing to execute.  We will activate something
       when we ingest a FEC set with transactions. */
    return 0UL;
  }

  out_txn->txn_id      = FD_SCHED_TXN_ID_NULL;
  out_txn->block_start = 0;
  out_txn->block_end   = 0;

  /* We could in theory reevaluate staging lane allocation here and do
     promotion/demotion as needed.  It's a policy decision to minimize
     fork churn for now and just execute down the same active fork. */

  fd_sched_block_t * block = block_pool_ele( sched->block_pool, sched->active_block_idx );
  if( FD_UNLIKELY( !block_is_activatable( block ) ) ) {
    FD_LOG_CRIT(( "invariant violation: active_block_idx %lu is not activatable, txn_parsed_cnt %u, txn_done_cnt %u, fec_eos %u, dying %u, slot %lu, prime %lu",
                  sched->active_block_idx, block->txn_parsed_cnt, block->txn_done_cnt, (uint)block->fec_eos, (uint)block->dying, (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }

  if( FD_UNLIKELY( !block->block_start_signaled ) ) {
    out_txn->txn_id           = FD_SCHED_TXN_ID_BLOCK_START;
    out_txn->block_id         = block->block_id;
    out_txn->parent_block_id  = block_pool_ele( sched->block_pool, block->parent_idx )->block_id;
    out_txn->block_start      = 1;

    block->block_start_signaled = 1;
    return 1UL;
  }

  ulong txn_queued_cnt = block->txn_parsed_cnt-block->txn_in_flight_cnt-block->txn_done_cnt;
  if( FD_LIKELY( txn_queued_cnt>0 ) ) { /* Optimize for no fork switching. */
    out_txn->txn_id          = fd_rdisp_get_next_ready( sched->rdisp, block->block_id.id );
    if( FD_UNLIKELY( out_txn->txn_id==0UL ) ) {
      /* There are transactions queued but none ready for execution.
         This implies that there must be in-flight transactions on whose
         completion the queued transactions depend. So we return and
         wait for those in-flight transactions to retire.  This is a
         policy decision to execute as much as we can down the current
         fork. */
      if( FD_UNLIKELY( !block->txn_in_flight_cnt ) ) {
        FD_LOG_CRIT(( "invariant violation: no ready transaction found but block->txn_in_flight_cnt==0, txn_parsed_cnt %u, txn_queued_cnt %lu, fec_eos %u, slot %lu, prime %lu",
                      block->txn_parsed_cnt, txn_queued_cnt, (uint)block->fec_eos, (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
      }
      return 0UL;
    }
    out_txn->block_id         = block->block_id;
    out_txn->parent_block_id  = block_pool_ele( sched->block_pool, block->parent_idx )->block_id;

    long now = fd_tickcount();
    ulong delta = (ulong)(now-sched->txn_in_flight_last_tick);
    sched->metrics->txn_none_in_flight_tickcount     += fd_ulong_if( block->txn_in_flight_cnt==0U && sched->txn_in_flight_last_tick!=LONG_MAX, delta, 0UL );
    sched->metrics->txn_weighted_in_flight_tickcount += fd_ulong_if( block->txn_in_flight_cnt!=0U, delta, 0UL );
    sched->metrics->txn_weighted_in_flight_cnt       += delta*block->txn_in_flight_cnt;
    sched->txn_in_flight_last_tick = now;

    block->txn_in_flight_cnt++;
    txn_queued_cnt--;
    sched->metrics->txn_max_in_flight_cnt = fd_uint_max( sched->metrics->txn_max_in_flight_cnt, block->txn_in_flight_cnt );
    return 1UL;
  }

  if( FD_UNLIKELY( block_should_signal_end( block ) ) ) {
    FD_TEST( block->block_start_signaled );
    out_txn->txn_id           = FD_SCHED_TXN_ID_BLOCK_END;
    out_txn->block_id         = block->block_id;
    out_txn->parent_block_id  = block_pool_ele( sched->block_pool, block->parent_idx )->block_id;
    out_txn->block_end        = 1;

    block->block_end_signaled = 1;
    return 1UL;
  }

  /* Nothing queued for the active block.  If we haven't received all
     the FEC sets for it, then return and wait for more FEC sets, while
     there are in-flight transactions.  This is a policy decision to
     minimize fork churn and allow for executing down the current fork
     as much as we can.  If we have received all the FEC sets for it,
     then we'd still like to return and wait for the in-flight
     transactions to retire, before switching to a different block.

     Either way, there should be in-flight transactions.  We deactivate
     the active block the moment we exhausted transactions from it. */
  if( FD_UNLIKELY( !block->txn_in_flight_cnt ) ) {
    FD_LOG_CRIT(( "invariant violation: expected in-flight transactions but none, txn_parsed_cnt %u, txn_done_cnt %u, fec_eos %u, slot %lu, prime %lu",
                  block->txn_parsed_cnt, block->txn_done_cnt, (uint)block->fec_eos, (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }

  return 0UL;
}

void
fd_sched_txn_done( fd_sched_t * sched, ulong txn_id ) {
  FD_TEST( txn_id!=FD_SCHED_TXN_ID_NULL );

  ulong              null_idx  = block_pool_idx_null( sched->block_pool );
  ulong              block_idx = fd_ulong_if( txn_id==FD_SCHED_TXN_ID_BLOCK_START||txn_id==FD_SCHED_TXN_ID_BLOCK_END, sched->active_block_idx, sched->txn_to_block_idx[ txn_id ] );
  fd_sched_block_t * block     = block_pool_ele( sched->block_pool, block_idx );

  if( FD_UNLIKELY( !block->staged ) ) {
    /* Invariant: only staged blocks can have in-flight transactions. */
    FD_LOG_CRIT(( "invariant violation: block->staged==0, slot %lu, prime %lu",
                  (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }
  if( FD_UNLIKELY( !block->in_rdisp ) ) {
    /* Invariant: staged blocks must be in the dispatcher. */
    FD_LOG_CRIT(( "invariant violation: block->in_rdisp==0, slot %lu, prime %lu",
                  (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }

  if( FD_LIKELY( txn_id!=FD_SCHED_TXN_ID_BLOCK_START && txn_id!=FD_SCHED_TXN_ID_BLOCK_END ) ) {
    FD_TEST( txn_id<FD_SCHED_MAX_DEPTH );
    long now = fd_tickcount();
    ulong delta = (ulong)(now-sched->txn_in_flight_last_tick);
    sched->metrics->txn_weighted_in_flight_tickcount += delta;
    sched->metrics->txn_weighted_in_flight_cnt       += delta*block->txn_in_flight_cnt;
    sched->txn_in_flight_last_tick = now;

    block->txn_done_cnt++;
    block->txn_in_flight_cnt--;
    fd_rdisp_complete_txn( sched->rdisp, txn_id );
    sched->txn_pool_free_cnt++;
    sched->metrics->txn_done_cnt++;
  }

  if( FD_UNLIKELY( block->dying && block->txn_in_flight_cnt==0U ) ) {
    if( FD_UNLIKELY( sched->active_block_idx==block_idx ) ) {
      FD_LOG_CRIT(( "invariant violation: active block shouldn't be dying, block_idx %lu, slot %lu, prime %lu",
                    block_idx, (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
    }
    subtree_abandon( sched, block );
    return;
  }

  if( FD_UNLIKELY( !block->dying && sched->active_block_idx!=block_idx ) ) {
    /* Block is not dead.  So we should be actively replaying it. */
    fd_sched_block_t * active_block = block_pool_ele( sched->block_pool, sched->active_block_idx );
    FD_LOG_CRIT(( "invariant violation: sched->active_block_idx %lu, slot %lu, prime %lu, block_idx %lu, slot %lu, prime %lu",
                  sched->active_block_idx, (ulong)active_block->block_id.slot, (ulong)active_block->block_id.prime,
                  block_idx, (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }

  if( FD_UNLIKELY( block_is_done( block ) ) ) {
    block->in_rdisp = 0;
    block->staged   = 0;
    fd_rdisp_remove_block( sched->rdisp, block->block_id.id );
    sched->metrics->block_removed_cnt++;

    /* See if there is a child block down the same staging lane.  This
       is a policy decision to minimize fork churn.  We could in theory
       reevaluate staging lane allocation here and do promotion/demotion
       as needed. */
    ulong child_idx = block->child_idx;
    while( child_idx != null_idx ) {
      fd_sched_block_t * child = block_pool_ele( sched->block_pool, child_idx );
      if( FD_LIKELY( child->staged && child->staging_lane==block->staging_lane ) ) {
        /* There is a child block down the same staging lane.  So switch
           the active block to it, and have the child inherit the head
           status of the lane.  This is the common case. */
        sched->active_block_idx = child_idx;
        sched->staged_head_block_idx[ block->staging_lane ] = child_idx;
        if( FD_UNLIKELY( !fd_ulong_extract_bit( sched->staged_bitset, (int)block->staging_lane ) ) ) {
          FD_LOG_CRIT(( "invariant violation: staged_bitset 0x%lx bit %lu is not set, slot %lu, prime %lu, child slot %lu, prime %lu",
                        sched->staged_bitset, block->staging_lane, (ulong)block->block_id.slot, (ulong)block->block_id.prime, (ulong)child->block_id.slot, (ulong)child->block_id.prime ));
        }
        return;
      }
      child_idx = child->sibling_idx;
    }
    /* There isn't a child block down the same staging lane.  This is
       the last block in the staging lane.  Release the staging lane. */
    sched->staged_bitset = fd_ulong_clear_bit( sched->staged_bitset, (int)block->staging_lane );
    sched->staged_head_block_idx[ block->staging_lane ] = null_idx;

    /* Reset the active block. */
    sched->active_block_idx = null_idx;
    sched->metrics->deactivate_no_child_cnt++;
    try_activate_block( sched );
  } else if( !block_is_activatable( block ) ) {
    /* We exhaused the active block, but it's not fully done yet.  We
       are just not getting FEC sets for it fast enough.  This could
       happen when the network path is congested, or when the leader
       simply went down.  Reset the active block. */
    sched->active_block_idx = null_idx;
    sched->metrics->deactivate_no_txn_cnt++;
    try_activate_block( sched );
  }
}

void
fd_sched_block_abandon( fd_sched_t * sched, fd_sched_block_id_t * block_id ) {
  fd_sched_block_t * block = block_map_ele_query( sched->block_map, block_id, NULL, sched->block_pool );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_CRIT(( "invariant violation: block not found slot %lu, prime %lu",
                  (ulong)block_id->slot, (ulong)block_id->prime ));
  }
  ulong block_idx = block_pool_idx( sched->block_pool, block );
  if( FD_UNLIKELY( block_idx!=sched->active_block_idx ) ) {
    /* Invariant: abandoning should only be performed on actively
       replayed blocks.  We impose this requirement on the caller
       because the dispatcher expects blocks to be abandoned in the same
       order that they were added, and having this requirement makes it
       easier to please the dispatcher. */
    FD_LOG_CRIT(( "invariant violation: active_block_idx %lu, block_idx %lu, slot %lu, prime %lu",
                  sched->active_block_idx, block_idx, (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }

  subtree_abandon( sched, block );

  /* Reset the active block. */
  ulong null_idx = block_pool_idx_null( sched->block_pool );
  sched->active_block_idx = null_idx;
  sched->metrics->deactivate_abandoned_cnt++;
  try_activate_block( sched );
}

int
fd_sched_block_is_done( fd_sched_t * sched, fd_sched_block_id_t * block_id ) {
  fd_sched_block_t * block = block_map_ele_query( sched->block_map, block_id, NULL, sched->block_pool );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_CRIT(( "invariant violation: block not found slot %lu, prime %lu",
                  (ulong)block_id->slot, (ulong)block_id->prime ));
  }
  return block_is_done( block );
}

void
fd_sched_block_add_done( fd_sched_t * sched, fd_sched_block_id_t * block_id, fd_sched_block_id_t * parent_block_id ) {
  fd_sched_block_t * block        = NULL;
  fd_sched_block_t * parent_block = NULL;
  add_block( sched, block_id, parent_block_id, &block, &parent_block );
  block->txn_done_cnt = block->txn_parsed_cnt = UINT_MAX;
  block->fec_eos = 1;
  block->block_start_signaled = 1;
  block->block_end_signaled   = 1;
  if( FD_UNLIKELY( !parent_block_id ) ) {
    /* Assumes that a NULL parent implies the snapshot slot. */
    sched->root_idx = block_pool_idx( sched->block_pool, block );
    block->rooted = 1;
  }
}

void
fd_sched_root_publish( fd_sched_t * sched, fd_sched_block_id_t * root ) {
  ulong null_idx = block_pool_idx_null( sched->block_pool );

  fd_sched_block_t * new_root = block_map_ele_query( sched->block_map, root, NULL, sched->block_pool );
  if( FD_UNLIKELY( !new_root ) ) {
    FD_LOG_CRIT(( "invariant violation: new_root not found slot %lu, prime %lu",
                  (ulong)root->slot, (ulong)root->prime ));
  }

  fd_sched_block_t * old_root = block_pool_ele( sched->block_pool, sched->root_idx );
  if( FD_UNLIKELY( !old_root ) ) {
    FD_LOG_CRIT(( "invariant violation: old_root not found" ));
  }
  if( FD_UNLIKELY( !old_root->rooted ) ) {
    FD_LOG_CRIT(( "invariant violation: old_root is not rooted, slot %lu, prime %lu",
                  (ulong)old_root->block_id.slot, (ulong)old_root->block_id.prime ));
  }

  /* Early exit if the new root is the same as the old root. */
  if( FD_UNLIKELY( old_root->block_id.id==new_root->block_id.id ) ) {
    FD_LOG_WARNING(( "new root is the same as the old root, slot %lu, prime %lu",
                     (ulong)new_root->block_id.slot, (ulong)new_root->block_id.prime ));
    return;
  }

  fd_sched_block_t * head = block_map_ele_remove( sched->block_map, &old_root->block_id, NULL, sched->block_pool );
  head->next              = null_idx;
  fd_sched_block_t * tail = head;

  while( head ) {
    fd_sched_block_t * child = block_pool_ele( sched->block_pool, head->child_idx );
    while( child ) {
      /* Add children to be pruned. */
      if( child!=new_root ) {
        tail->next = block_map_idx_remove( sched->block_map, &child->block_id, null_idx, sched->block_pool );
        tail       = block_pool_ele( sched->block_pool, tail->next );
        tail->next = null_idx;
      }
      child = block_pool_ele( sched->block_pool, child->sibling_idx );
    }

    /* Prune the current block.  We will never publish halfway into a
       staging lane, because anything on the rooted fork should have
       finished replaying gracefully and be out of the dispatcher.  In
       fact, anything that we are publishing away should be out of the
       dispatcher at this point.  And there should be no more in-flight
       transactions. */
    if( FD_UNLIKELY( head->txn_in_flight_cnt ) ) {
      FD_LOG_CRIT(( "invariant violation: block has transactions in flight, slot %lu, prime %lu",
                    (ulong)head->block_id.slot, (ulong)head->block_id.prime ));
    }
    if( FD_UNLIKELY( head->in_rdisp ) ) {
      /* We should have removed it from the dispatcher when we were
         notified of the new root, or when in-flight transactions were
         drained. */
      FD_LOG_CRIT(( "invariant violation: block is in the dispatcher, slot %lu, prime %lu",
                    (ulong)head->block_id.slot, (ulong)head->block_id.prime ));
    }
    fd_sched_block_t * next = block_pool_ele( sched->block_pool, head->next );
    block_pool_ele_release( sched->block_pool, head );
    head = next;
  }

  new_root->parent_idx = null_idx;
  sched->root_idx = block_pool_idx( sched->block_pool, new_root );
}

void
fd_sched_root_notify( fd_sched_t * sched, fd_sched_block_id_t * root ) {
  ulong null_idx = block_pool_idx_null( sched->block_pool );

  fd_sched_block_t * block = block_map_ele_query( sched->block_map, root, NULL, sched->block_pool );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_CRIT(( "invariant violation: block not found slot %lu, prime %lu",
                  (ulong)root->slot, (ulong)root->prime ));
  }

  fd_sched_block_t * old_root = block_pool_ele( sched->block_pool, sched->root_idx );
  if( FD_UNLIKELY( !old_root ) ) {
    FD_LOG_CRIT(( "invariant violation: old_root not found" ));
  }
  if( FD_UNLIKELY( !old_root->rooted ) ) {
    FD_LOG_CRIT(( "invariant violation: old_root is not rooted, slot %lu, prime %lu",
                  (ulong)old_root->block_id.slot, (ulong)old_root->block_id.prime ));
  }

  /* Early exit if the new root is the same as the old root. */
  if( FD_UNLIKELY( old_root->block_id.id==block->block_id.id ) ) {
    FD_LOG_WARNING(( "new root is the same as the old root, slot %lu, prime %lu",
                     (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
    return;
  }

  /* Mark every node from the new root up through its parents to the
     old root as being rooted. */
  fd_sched_block_t * curr = block;
  fd_sched_block_t * prev = NULL;
  while( curr ) {
    if( FD_UNLIKELY( !block_is_done( curr ) ) ) {
      FD_LOG_CRIT(( "invariant violation: rooting a block that is not done, slot %lu, prime %lu",
                    (ulong)curr->block_id.slot, (ulong)curr->block_id.prime ));
    }
    if( FD_UNLIKELY( curr->dying ) ) {
      FD_LOG_CRIT(( "invariant violation: rooting a block that is dying, slot %lu, prime %lu",
                    (ulong)curr->block_id.slot, (ulong)curr->block_id.prime ));
    }
    if( FD_UNLIKELY( curr->staged ) ) {
      FD_LOG_CRIT(( "invariant violation: rooting a block that is staged, slot %lu, prime %lu",
                    (ulong)curr->block_id.slot, (ulong)curr->block_id.prime ));
    }
    if( FD_UNLIKELY( curr->in_rdisp ) ) {
      FD_LOG_CRIT(( "invariant violation: rooting a block that is in the dispatcher, slot %lu, prime %lu",
                    (ulong)curr->block_id.slot, (ulong)curr->block_id.prime ));
    }
    curr->rooted = 1;
    prev = curr;
    curr = block_pool_ele( sched->block_pool, curr->parent_idx );
  }

  /* If we didn't reach the old root, the new root is not a descendant. */
  if( FD_UNLIKELY( prev!=old_root ) ) {
    FD_LOG_CRIT(( "invariant violation: new root is not a descendant of old root, new root slot %lu, prime %lu, old root slot %lu, prime %lu",
                  (ulong)block->block_id.slot, (ulong)block->block_id.prime, (ulong)old_root->block_id.slot, (ulong)old_root->block_id.prime ));
  }

  ulong old_active_block_idx = sched->active_block_idx;

  /* Now traverse from old root towards new root, and abandon all
     minority forks. */
  curr = old_root;
  while( curr && curr->rooted && curr!=block ) { /* curr!=block to avoid abandoning good forks. */
    fd_sched_block_t * rooted_child_block = NULL;
    ulong              child_idx          = curr->child_idx;
    while( child_idx!=null_idx ) {
      fd_sched_block_t * child = block_pool_ele( sched->block_pool, child_idx );
      if( child->rooted ) {
        rooted_child_block = child;
      } else {
        /* This is a minority fork. */
        subtree_abandon( sched, child );
      }
      child_idx = child->sibling_idx;
    }
    curr = rooted_child_block;
  }

  /* If the active block got abandoned, we need to reset it. */
  if( sched->active_block_idx==null_idx ) {
    sched->metrics->deactivate_pruned_cnt += fd_uint_if( old_active_block_idx!=null_idx, 1U, 0U );
    try_activate_block( sched );
  }
}

fd_txn_p_t *
fd_sched_get_txn( fd_sched_t * sched, ulong txn_id ) {
  if( FD_UNLIKELY( txn_id>=FD_SCHED_MAX_DEPTH ) ) {
    return NULL;
  }
  return sched->txn_pool + txn_id;
}

fd_hash_t *
fd_sched_get_poh( fd_sched_t * sched, fd_sched_block_id_t * block_id ) {
  fd_sched_block_t * block = block_map_ele_query( sched->block_map, block_id, NULL, sched->block_pool );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_CRIT(( "invariant violation: block not found slot %lu, prime %lu",
                  (ulong)block_id->slot, (ulong)block_id->prime ));
  }
  return &block->poh;
}

uint
fd_sched_get_shred_cnt( fd_sched_t * sched, fd_sched_block_id_t * block_id ) {
  fd_sched_block_t * block = block_map_ele_query( sched->block_map, block_id, NULL, sched->block_pool );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_CRIT(( "invariant violation: block not found slot %lu, prime %lu",
                  (ulong)block_id->slot, (ulong)block_id->prime ));
  }
  return block->shred_cnt;
}

void * fd_sched_leave ( fd_sched_t * sched ) { return sched; }
void * fd_sched_delete( void * mem         ) { return   mem; }


/* Internal helpers. */

static void
add_block( fd_sched_t *          sched,
           fd_sched_block_id_t * block_id,
           fd_sched_block_id_t * parent_block_id,
           fd_sched_block_t * *  out_block,
           fd_sched_block_t * *  out_parent_block ) {
  if( FD_UNLIKELY( !block_pool_free( sched->block_pool ) ) ) {
    FD_LOG_CRIT(( "block_pool is full" ));
  }
  fd_sched_block_t * block = block_pool_ele_acquire( sched->block_pool );
  block->block_id = *block_id;
  block_map_ele_insert( sched->block_map, block, sched->block_pool );
  *out_block = block;

  block->txn_parsed_cnt    = 0U;
  block->txn_in_flight_cnt = 0U;
  block->txn_done_cnt      = 0U;
  block->shred_cnt         = 0U;

  block->mblks_rem    = 0UL;
  block->txns_rem     = 0UL;
  block->fec_buf_sz   = 0U;
  block->fec_buf_soff = 0U;
  block->fec_eob      = 0;
  block->fec_sob      = 1;

  block->fec_eos              = 0;
  block->rooted               = 0;
  block->dying                = 0;
  block->in_rdisp             = 0;
  block->block_start_signaled = 0;
  block->block_end_signaled   = 0;
  block->staged               = 0;

  block->luf_depth = 0UL;

  /* New leaf node, no child, no sibling. */
  ulong null_idx     = block_pool_idx_null( sched->block_pool );
  block->child_idx   = null_idx;
  block->sibling_idx = null_idx;
  block->parent_idx  = null_idx;

  /* node->parent link */
  if( FD_LIKELY( parent_block_id ) ) {
    fd_sched_block_t * parent_block = block_map_ele_query( sched->block_map, parent_block_id, NULL, sched->block_pool );
    if( FD_UNLIKELY( !parent_block ) ) {
      FD_LOG_CRIT(( "invariant violation: parent block not found slot %lu, prime %lu",
                    (ulong)parent_block_id->slot, (ulong)parent_block_id->prime ));
    }
    block->parent_idx = block_pool_idx( sched->block_pool, parent_block );
    *out_parent_block = parent_block;

    /* parent->node and sibling->node links */
    ulong child_idx = block_pool_idx( sched->block_pool, block );
    if( FD_LIKELY( parent_block->child_idx == null_idx ) ) { /* Optimize for no forking. */
      parent_block->child_idx = child_idx;
    } else {
      fd_sched_block_t * curr_block = block_pool_ele( sched->block_pool, parent_block->child_idx );
      while( curr_block->sibling_idx != null_idx ) {
        curr_block = block_pool_ele( sched->block_pool, curr_block->sibling_idx );
      }
      curr_block->sibling_idx = child_idx;
    }

    if( FD_UNLIKELY( parent_block->dying ) ) {
      block->dying = 1;
    }
  }
}

#define CHECK( cond )  do {      \
  if( FD_UNLIKELY( !(cond) ) ) { \
    return;                      \
  }                              \
} while( 0 )

/* CHECK that it is safe to read at least n more bytes. */
#define CHECK_LEFT( n ) CHECK( (n)<=(block->fec_buf_sz-block->fec_buf_soff) )

/* Consume as much as possible from the buffer.  By the end of this
   function, we will either have residual data that is unparseable only
   because it is a batch that straddles FEC set boundaries, or we will
   have reached the end of a batch.  In the former case, any remaining
   bytes should be concatenated with the next FEC set for further
   parsing.  In the latter case, any remaining bytes should be thrown
   away. */
static void
fd_sched_parse( fd_sched_t * sched, fd_sched_block_t * block, fd_sched_alut_ctx_t * alut_ctx ) {
  while( 1 ) {
    while( block->txns_rem>0UL ) {
      if( FD_UNLIKELY( !fd_sched_parse_txn( sched, block, alut_ctx ) ) ) {
        return;
      }
    }
    if( block->txns_rem==0UL && block->mblks_rem>0UL ) {
      CHECK_LEFT( sizeof(fd_microblock_hdr_t) );
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)fd_type_pun( block->fec_buf+block->fec_buf_soff );
      block->fec_buf_soff      += (uint)sizeof(fd_microblock_hdr_t);

      memcpy( block->poh.hash, hdr->hash, sizeof(block->poh.hash) );
      block->txns_rem = hdr->txn_cnt;
      block->mblks_rem--;
      continue;
    }
    if( block->txns_rem==0UL && block->mblks_rem==0UL && block->fec_sob ) {
      CHECK_LEFT( sizeof(ulong) );
      FD_TEST( block->fec_buf_soff==0U );
      block->mblks_rem     = FD_LOAD( ulong, block->fec_buf );
      block->fec_buf_soff += (uint)sizeof(ulong);
      /* FIXME what happens if someone sends us mblks_rem==0UL here? */

      block->fec_sob = 0;
      continue;
    }
    if( block->txns_rem==0UL && block->mblks_rem==0UL ) {
      break;
    }
  }
  if( block->fec_eob ) {
    /* Ignore trailing bytes at the end of a batch. */
    sched->metrics->bytes_ingested_unparsed_cnt += block->fec_buf_sz-block->fec_buf_soff;
    block->fec_buf_soff = 0U;
    block->fec_buf_sz   = 0U;
    block->fec_sob      = 1;
    block->fec_eob      = 0;
  }
}

static int
fd_sched_parse_txn( fd_sched_t * sched, fd_sched_block_t * block, fd_sched_alut_ctx_t * alut_ctx ) {
  fd_txn_t * txn = fd_type_pun( block->txn );

  ulong pay_sz = 0UL;
  ulong txn_sz = fd_txn_parse_core( block->fec_buf+block->fec_buf_soff,
                                    fd_ulong_min( FD_TXN_MTU, block->fec_buf_sz-block->fec_buf_soff ),
                                    txn,
                                    NULL,
                                    &pay_sz );

  if( FD_UNLIKELY( !pay_sz || !txn_sz ) ) {
    /* Can't parse out a full transaction. */
    return 0;
  }

  /* Try to expand ALUTs. */
  int has_aluts   = txn->transaction_version==FD_TXN_V0 && txn->addr_table_adtl_cnt>0;
  int serializing = 0;
  if( has_aluts ) {
    /* FIXME: statically size out slot hashes decode footprint. */
    FD_SPAD_FRAME_BEGIN( alut_ctx->runtime_spad ) {
    fd_slot_hashes_global_t const * slot_hashes_global = fd_sysvar_slot_hashes_read( alut_ctx->accdb, &alut_ctx->funk_txn_xid, alut_ctx->runtime_spad );
    if( FD_LIKELY( slot_hashes_global ) ) {
      fd_slot_hash_t * slot_hash = deq_fd_slot_hash_t_join( (uchar *)slot_hashes_global + slot_hashes_global->hashes_offset );
      serializing = !!fd_runtime_load_txn_address_lookup_tables( txn, block->fec_buf+block->fec_buf_soff, alut_ctx->accdb, &alut_ctx->funk_txn_xid, alut_ctx->els, slot_hash, block->aluts );
      sched->metrics->alut_success_cnt += (uint)!serializing;
    } else {
      serializing = 1;
    }
    } FD_SPAD_FRAME_END;
  }

  ulong txn_idx = fd_rdisp_add_txn( sched->rdisp, block->block_id.id, txn, block->fec_buf+block->fec_buf_soff, serializing ? NULL : block->aluts, serializing );
  FD_TEST( txn_idx!=0UL );
  sched->metrics->txn_parsed_cnt++;
  sched->metrics->alut_serializing_cnt += (uint)serializing;
  sched->txn_pool_free_cnt--;
  fd_txn_p_t * txn_p = sched->txn_pool + txn_idx;
  txn_p->payload_sz  = pay_sz;
  fd_memcpy( txn_p->payload, block->fec_buf+block->fec_buf_soff, pay_sz );
  fd_memcpy( TXN(txn_p),     txn,                                txn_sz );
  sched->txn_to_block_idx[ txn_idx ] = block_pool_idx( sched->block_pool, block );

  block->fec_buf_soff += (uint)pay_sz;
  block->txn_parsed_cnt++;
  block->txns_rem--;
  return 1;
}

#undef CHECK
#undef CHECK_LEFT

static void
try_activate_block( fd_sched_t * sched ) {
  ulong null_idx = block_pool_idx_null( sched->block_pool );

  /* See if there are any allocated staging lanes that we can activate
     for scheduling ... */
  ulong staged_bitset = sched->staged_bitset;
  while( staged_bitset ) {
    int lane_idx  = fd_ulong_find_lsb( staged_bitset );
    staged_bitset = fd_ulong_pop_lsb( staged_bitset );

    ulong              head_idx     = sched->staged_head_block_idx[ lane_idx ];
    fd_sched_block_t * head_block   = block_pool_ele( sched->block_pool, head_idx );
    fd_sched_block_t * parent_block = block_pool_ele( sched->block_pool, head_block->parent_idx );
    if( FD_UNLIKELY( parent_block->dying ) ) {
      /* Invariant: no child of a dying block should be staged. */
      FD_LOG_CRIT(( "invariant violation: staged_head_block_idx %lu, slot %lu, prime %lu on lane %d has parent_block->dying set, slot %lu, prime %lu",
                    head_idx, (ulong)head_block->block_id.slot, (ulong)head_block->block_id.prime, lane_idx, (ulong)parent_block->block_id.slot, (ulong)parent_block->block_id.prime ));
    }
    //FIXME: restore this invariant check when we have immediate demotion of dying blocks
    // if( FD_UNLIKELY( head_block->dying ) ) {
    //   /* Invariant: no dying block should be staged. */
    //   FD_LOG_CRIT(( "invariant violation: staged_head_block_idx %lu, slot %lu, prime %lu on lane %u has head_block->dying set",
    //                 head_idx, (ulong)head_block->block_id.slot, (ulong)head_block->block_id.prime, lane_idx ));
    // }
    if( block_is_done( parent_block ) && block_is_activatable( head_block ) ) {
      /* ... Yes, on this staging lane the parent block is done.  So we
         can switch to the staged child. */
      sched->active_block_idx = head_idx;
      sched->metrics->lane_switch_cnt++;
      return;
    }
  }

  /* ... No, promote unstaged blocks. */
  ulong root_idx = sched->root_idx;
  if( FD_UNLIKELY( root_idx==null_idx ) ) {
    FD_LOG_CRIT(( "invariant violation: root_idx==null_idx indicating fd_sched is unintialized" ));
  }
  /* Find and stage the longest stageable unstaged fork.  This is a
     policy decision. */
  ulong depth = compute_longest_unstaged_fork( sched, root_idx );
  if( FD_LIKELY( depth>0UL ) ) {
    if( FD_UNLIKELY( sched->staged_bitset==fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES ) ) ) {
      /* No more staging lanes available.  All of them are occupied by
         slow squatters.  Demote one of them. */
      //FIXME implement this
      FD_LOG_CRIT(( "unimplemented" ));
      sched->metrics->lane_demoted_cnt++;
      // sched->metrics->block_demoted_cnt++; for every demoted block
    }
    FD_TEST( sched->staged_bitset!=fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES ) );
    int lane_idx = fd_ulong_find_lsb( ~sched->staged_bitset );
    if( FD_UNLIKELY( lane_idx>=(int)FD_SCHED_MAX_STAGING_LANES ) ) {
      FD_LOG_CRIT(( "invariant violation: lane_idx %d, sched->staged_bitset %lx",
                    lane_idx, sched->staged_bitset ));
    }
    ulong head_block_idx = stage_longest_unstaged_fork( sched, root_idx, lane_idx );
    if( FD_UNLIKELY( head_block_idx==null_idx ) ) {
      /* We found a promotable fork depth>0.  This should not happen. */
      FD_LOG_CRIT(( "invariant violation: head_block_idx==null_idx" ));
    }
    sched->active_block_idx = head_block_idx;
    return;
  }
  /* No unstaged blocks to promote.  So we're done.  Yay. */
}

/* It's safe to call this function more than once on the same block. */
static void
subtree_abandon( fd_sched_t * sched, fd_sched_block_t * block ) {
  if( FD_UNLIKELY( block->rooted ) ) {
    FD_LOG_CRIT(( "invariant violation: rooted block should not be abandoned, slot %lu, prime %lu",
                  (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }
  /* All minority fork nodes pass through this function eventually.  So
     this is a good point to check per-node invariants for minority
     forks. */
  if( FD_UNLIKELY( block->staged && !block->in_rdisp ) ) {
    FD_LOG_CRIT(( "invariant violation: staged block is not in the dispatcher, slot %lu, prime %lu",
                  (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
  }

  ulong null_idx  = block_pool_idx_null( sched->block_pool );

  /* Setting the flag is non-optional and can happen more than once. */
  block->dying = 1;

  /* Removal from dispatcher should only happen once. */
  if( block->in_rdisp ) {
    fd_sched_block_t * parent = block_pool_ele( sched->block_pool, block->parent_idx );
    if( FD_UNLIKELY( !parent ) ) {
      /* Only the root has no parent.  Abandon should never be called on
         the root.  So any block we are trying to abandon should have a
         parent. */
      FD_LOG_CRIT(( "invariant violation: parent not found slot %lu, prime %lu",
                    (ulong)block->block_id.slot, (ulong)block->block_id.prime ));
    }

    /* The dispatcher expects blocks to be abandoned in the same order
       that they were added on each lane.  There are no requirements on
       the order of abandoning if two blocks are not on the same lane,
       or if a block is unstaged.  This means that in general we
       shouldn't abandon a child block if the parent hasn't been
       abandoned yet, if and only if they are on the same lane.  So wait
       until we can abandon the parent, and then descend down the fork
       tree to ensure orderly abandoning. */
    int abandon = !parent->in_rdisp || /* parent is not in the dispatcher */
                  !parent->staged   || /* parent is in the dispatcher but not staged */
                  !block->staged    || /* parent is in the dispatcher and staged but this block is unstaged */
                  block->staging_lane!=parent->staging_lane; /* this block is on a different staging lane than its parent */

    /* We inform the dispatcher of an abandon only when there are no
       more in-flight transactions.  Otherwise, if the dispatcher
       recycles the same txn_id that was just abandoned, and we receive
       completion of an in-flight transaction whose txn_id was just
       recycled, we would basically be aliasing the same txn_id and end
       up indexing into txn_to_block_idx[] that is already overwritten
       with new blocks. */
    abandon = abandon && block->txn_in_flight_cnt==0;

    if( abandon ) {
      block->in_rdisp = 0;
      fd_rdisp_abandon_block( sched->rdisp, block->block_id.id );
      sched->txn_pool_free_cnt += block->txn_parsed_cnt-block->txn_done_cnt; /* in_flight_cnt==0 */
      sched->metrics->block_abandoned_cnt++;
      sched->metrics->txn_abandoned_parsed_cnt += block->txn_parsed_cnt;
      sched->metrics->txn_abandoned_done_cnt   += block->txn_done_cnt;

      /* Now release the staging lane. */
      //FIXME when demote supports non-empty blocks, we should demote
      //the block from the lane unconditionally and immediately,
      //regardles of whether it's safe to abandon or not.  So a block
      //would go immediately from staged to unstaged and eventually to
      //abandoned.
      if( FD_LIKELY( block->staged ) ) {
        block->staged = 0;
        sched->staged_bitset = fd_ulong_clear_bit( sched->staged_bitset, (int)block->staging_lane );
        sched->staged_head_block_idx[ block->staging_lane ] = null_idx;
      }
    }

    if( FD_UNLIKELY( block->staged && sched->active_block_idx==sched->staged_head_block_idx[ block->staging_lane ] ) ) {
      /* Dying blocks should not be active. */
      sched->active_block_idx = null_idx;
    }
  }

  /* Abandon the entire fork chaining off of this block. */
  ulong child_idx = block->child_idx;
  while( child_idx != null_idx ) {
    fd_sched_block_t * child = block_pool_ele( sched->block_pool, child_idx );
    subtree_abandon( sched, child );
    child_idx = child->sibling_idx;
  }
}

FD_FN_UNUSED static ulong
find_and_stage_longest_unstaged_fork( fd_sched_t * sched, int lane_idx ) {
  ulong null_idx = block_pool_idx_null( sched->block_pool );
  ulong root_idx = sched->root_idx;

  if( FD_UNLIKELY( root_idx==null_idx ) ) {
    FD_LOG_CRIT(( "invariant violation: root_idx==null_idx indicating fd_sched is unintialized" ));
  }

  /* First pass: compute the longest unstaged fork depth for each node
     in the fork tree. */
  ulong depth = compute_longest_unstaged_fork( sched, root_idx );

  /* Second pass: stage blocks on the longest unstaged fork. */
  ulong head_block_idx = stage_longest_unstaged_fork( sched, root_idx, lane_idx );

  if( FD_UNLIKELY( (depth>0UL && head_block_idx==null_idx) || (depth==0UL && head_block_idx!=null_idx) ) ) {
    FD_LOG_CRIT(( "invariant violation: depth %lu, head_block_idx %lu",
                  depth, head_block_idx ));
  }

  return head_block_idx;
}

/* Returns length of the longest stageable unstaged fork, if there is
   one, and 0 otherwise. */
static ulong
compute_longest_unstaged_fork( fd_sched_t * sched, ulong block_idx ) {
  ulong null_idx = block_pool_idx_null( sched->block_pool );
  if( FD_UNLIKELY( block_idx==null_idx ) ) {
    FD_LOG_CRIT(( "invariant violation: block_idx==null_idx" ));
  }

  fd_sched_block_t * block = block_pool_ele( sched->block_pool, block_idx );

  ulong max_child_depth = 0UL;
  ulong child_idx       = block->child_idx;
  while( child_idx!=null_idx ) {
    ulong child_depth = compute_longest_unstaged_fork( sched, child_idx );
    if( child_depth > max_child_depth ) {
      max_child_depth = child_depth;
    }
    fd_sched_block_t * child = block_pool_ele( sched->block_pool, child_idx );
    child_idx = child->sibling_idx;
  }

  block->luf_depth = max_child_depth + fd_ulong_if( block_is_promotable( block ), 1UL, 0UL );
  return block->luf_depth;
}

static ulong
stage_longest_unstaged_fork_helper( fd_sched_t * sched, ulong block_idx, int lane_idx ) {
  ulong null_idx = block_pool_idx_null( sched->block_pool );
  if( FD_UNLIKELY( block_idx==null_idx ) ) {
    FD_LOG_CRIT(( "invariant violation: block_idx==null_idx" ));
  }

  fd_sched_block_t * block = block_pool_ele( sched->block_pool, block_idx );

  int   stage_it = fd_int_if( block_is_promotable( block ), 1, 0 );
  ulong rv       = fd_ulong_if( stage_it, block_idx, null_idx );
  if( FD_LIKELY( stage_it ) ) {
    block->staged = 1;
    block->staging_lane = (ulong)lane_idx;
    fd_rdisp_promote_block( sched->rdisp, block->block_id.id, block->staging_lane );
    sched->metrics->block_promoted_cnt++;
  }

  /* Base case: leaf node. */
  if( block->child_idx==null_idx ) return rv;

  ulong max_depth      = 0UL;
  ulong best_child_idx = null_idx;
  ulong child_idx      = block->child_idx;
  while( child_idx!=null_idx ) {
    fd_sched_block_t * child = block_pool_ele( sched->block_pool, child_idx );
    if( child->luf_depth>max_depth ) {
      max_depth      = child->luf_depth;
      best_child_idx = child_idx;
    }
    child_idx = child->sibling_idx;
  }

  /* Recursively stage descendants. */
  if( best_child_idx!=null_idx ) {
    ulong head_block_idx = stage_longest_unstaged_fork_helper( sched, best_child_idx, lane_idx );
    rv = fd_ulong_if( rv!=null_idx, rv, head_block_idx );
  }

  return rv;
}

/* Returns idx of head block of staged lane on success, idx_null
   otherwise. */
static ulong
stage_longest_unstaged_fork( fd_sched_t * sched, ulong block_idx, int lane_idx ) {
  ulong head_block_idx = stage_longest_unstaged_fork_helper( sched, block_idx, lane_idx );
  if( FD_LIKELY( head_block_idx!=block_pool_idx_null( sched->block_pool ) ) ) {
    sched->metrics->lane_promoted_cnt++;
    sched->staged_bitset = fd_ulong_set_bit( sched->staged_bitset, lane_idx );
    sched->staged_head_block_idx[ lane_idx ] = head_block_idx;
  }
  return head_block_idx;
}
