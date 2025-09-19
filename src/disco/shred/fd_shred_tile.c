#include "../tiles.h"

#include "generated/fd_shred_tile_seccomp.h"
#include "../../util/pod/fd_pod_format.h"
#include "../shred/fd_shredder.h"
#include "../shred/fd_shred_batch.h"
#include "../shred/fd_shred_dest.h"
#include "../shred/fd_fec_resolver.h"
#include "../shred/fd_stake_ci.h"
#include "../store/fd_store.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyguard.h"
#include "../keyguard/fd_keyswitch.h"
#include "../fd_disco.h"
#include "../net/fd_net_tile.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../util/net/fd_net_headers.h"
#include "../../flamenco/gossip/fd_gossip_types.h"

#include <linux/unistd.h>

/* The shred tile handles shreds from two data sources: shreds generated
   from microblocks from the banking tile, and shreds retransmitted from
   the network.

   They have rather different semantics, but at the end of the day, they
   both result in a bunch of shreds and FEC sets that need to be sent to
   the blockstore and on the network, which is why one tile handles
   both.

   We segment the memory for the two types of shreds into two halves of
   a dcache because they follow somewhat different flow control
   patterns. For flow control, the normal guarantee we want to provide
   is that the dcache entry is not overwritten unless the mcache entry
   has also been overwritten.  The normal way to do this when using both
   cyclically and with a 1-to-1 mapping is to make the dcache at least
   `burst` entries bigger than the mcache.

   In this tile, we use one output mcache with one output dcache (which
   is logically partitioned into two) for the two sources of data.  The
   worst case for flow control is when we're only sending with one of
   the dcache partitions at a time though, so we can consider them
   separately.

   From bank: Every FEC set triggers at least two mcache entries (one
   for parity and one for data), so at most, we have ceil(mcache
   depth/2) FEC sets exposed.  This means we need to decompose dcache
   into at least ceil(mcache depth/2)+1 FEC sets.

   From the network: The FEC resolver doesn't use a cyclic order, but it
   does promise that once it returns an FEC set, it will return at least
   complete_depth FEC sets before returning it again.  This means we
   want at most complete_depth-1 FEC sets exposed, so
   complete_depth=ceil(mcache depth/2)+1 FEC sets as above.  The FEC
   resolver has the ability to keep individual shreds for partial_depth
   calls, but because in this version of the shred tile, we send each
   shred to all its destinations as soon as we get it, we don't need
   that functionality, so we set partial_depth=1.

   Adding these up, we get 2*ceil(mcache_depth/2)+3+fec_resolver_depth
   FEC sets, which is no more than mcache_depth+4+fec_resolver_depth.
   Each FEC is paired with 4 fd_shred34_t structs, so that means we need
   to decompose the dcache into 4*mcache_depth + 4*fec_resolver_depth +
   16 fd_shred34_t structs.

   A note on parallelization.  From the network, shreds are distributed
   to tiles by their signature, so all the shreds for a given FEC set
   are processed by the same tile.  From bank, the original
   implementation used to parallelize by batch of microblocks (so within
   a block, batches were distributed to different tiles).  To support
   chained merkle shreds, the current implementation processes all the
   batches on tile 0 -- this should be a temporary state while Solana
   moves to a newer shred format that support better parallelization. */

/* The memory this tile uses is a bit complicated and has some logical
   aliasing to facilitate zero-copy use.  We have a dcache containing
   fd_shred34_t objects, which are basically 34 fd_shred_t objects
   padded to their max size, where 34 is set so that the size of the
   fd_shred34_t object (including some metadata) is less than
   USHORT_MAX, which facilitates sending it using Tango.  Then, for each
   set of 4 consecutive fd_shred34_t objects, we have an fd_fec_set_t.
   The first 34 data shreds point to the payload section of the payload
   section of each of the packets in the first fd_shred34_t.  The other
   33 data shreds point into the second fd_shred34_t.  Similar for the
   parity shreds pointing into the third and fourth fd_shred34_t. */

#define FD_SHRED_TILE_SCRATCH_ALIGN 128UL

#define IN_KIND_CONTACT (0UL)
#define IN_KIND_STAKE   (1UL)
#define IN_KIND_POH     (2UL)
#define IN_KIND_NET     (3UL)
#define IN_KIND_SIGN    (4UL)
#define IN_KIND_REPAIR  (5UL)
#define IN_KIND_IPECHO  (6UL)
#define IN_KIND_GOSSIP  (7UL)

#define NET_OUT_IDX     1
#define SIGN_OUT_IDX    2

#define DCACHE_ENTRIES_PER_FEC_SET (4UL)
FD_STATIC_ASSERT( sizeof(fd_shred34_t) < USHORT_MAX, shred_34 );
FD_STATIC_ASSERT( 34*DCACHE_ENTRIES_PER_FEC_SET >= FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX, shred_34 );
FD_STATIC_ASSERT( sizeof(fd_shred34_t) == FD_SHRED_STORE_MTU, shred_34 );

FD_STATIC_ASSERT( sizeof(fd_entry_batch_meta_t)==56UL, poh_shred_mtu );

#define FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT 2

/* Number of entries in the block_ids table. Each entry is 32 byte.
   This table is used to keep track of block ids that we create
   when we're leader, so that we can access them whenever we need
   a *parent* block id for a new block. Larger table allows to
   retrieve older parent block ids. Currently it's set for worst
   case parent offset of USHORT_MAX (max allowed in a shred),
   making the total table 2MiB.
   See also comment on chained_merkle_root. */
#define BLOCK_IDS_TABLE_CNT USHORT_MAX

/* See note on parallelization above. Currently we process all batches in tile 0. */
#if 1
#define SHOULD_PROCESS_THESE_SHREDS ( ctx->round_robin_id==0 )
#else
#define SHOULD_PROCESS_THESE_SHREDS ( ctx->batch_cnt%ctx->round_robin_cnt==ctx->round_robin_id )
#endif

/* The behavior of the shred tile is slightly different for
   Frankendancer vs Firedancer.  For example, Frankendancer produces
   chained merkle shreds, while Firedancer doesn't yet.  We can check
   at runtime the difference by inspecting the topology. The simplest
   way is to test if ctx->store is initialized.

   FIXME don't assume only frank vs. fire */
#define IS_FIREDANCER ( ctx->store!=NULL )

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  };
  fd_net_rx_bounds_t net_rx;
} fd_shred_in_ctx_t;

typedef struct {
  fd_shredder_t      * shredder;
  fd_fec_resolver_t  * resolver;
  fd_pubkey_t          identity_key[1]; /* Just the public key */

  ulong                round_robin_id;
  ulong                round_robin_cnt;
  /* Number of batches shredded from PoH during the current slot.
     This should be the same for all the shred tiles. */
  ulong                batch_cnt;
  /* Slot of the most recent microblock we've seen from PoH,
     or 0 if we haven't seen one yet */
  ulong                slot;

  fd_keyswitch_t *     keyswitch;
  fd_keyguard_client_t keyguard_client[1];

  /* shred34 and fec_sets are very related: fec_sets[i] has pointers
     to the shreds in shred34[4*i + k] for k=0,1,2,3. */
  fd_shred34_t       * shred34;
  fd_fec_set_t       * fec_sets;

  fd_stake_ci_t      * stake_ci;
  /* These are used in between during_frag and after_frag */
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;
  ulong                      shredded_txn_cnt;

  ulong poh_in_expect_seq;

  ushort net_id;

  int skip_frag;

  ulong                    adtl_dests_leader_cnt;
  fd_shred_dest_weighted_t adtl_dests_leader    [ FD_TOPO_ADTL_DESTS_MAX ];
  ulong                    adtl_dests_retransmit_cnt;
  fd_shred_dest_weighted_t adtl_dests_retransmit[ FD_TOPO_ADTL_DESTS_MAX ];

  fd_ip4_udp_hdrs_t data_shred_net_hdr  [1];
  fd_ip4_udp_hdrs_t parity_shred_net_hdr[1];

  ulong shredder_fec_set_idx;     /* In [0, shredder_max_fec_set_idx) */
  ulong shredder_max_fec_set_idx; /* exclusive */

  uchar shredder_merkle_root[32];

  ulong send_fec_set_idx[ FD_SHRED_BATCH_FEC_SETS_MAX ];
  ulong send_fec_set_cnt;
  ulong tsorig;  /* timestamp of the last packet in compressed form */

  /* Includes Ethernet, IP, UDP headers */
  ulong shred_buffer_sz;
  uchar shred_buffer[ FD_NET_MTU ];

  fd_shred_in_ctx_t in[ 32 ];
  int               in_kind[ 32 ];

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  ulong       store_out_idx;
  fd_wksp_t * store_out_mem;
  ulong       store_out_chunk0;
  ulong       store_out_wmark;
  ulong       store_out_chunk;

  ulong       repair_out_idx;
  fd_wksp_t * repair_out_mem;
  ulong       repair_out_chunk0;
  ulong       repair_out_wmark;
  ulong       repair_out_chunk;

  fd_store_t * store;

  fd_gossip_update_message_t gossip_upd_buf[1];

  struct {
    fd_histf_t contact_info_cnt[ 1 ];
    fd_histf_t batch_sz[ 1 ];
    fd_histf_t batch_microblock_cnt[ 1 ];
    fd_histf_t shredding_timing[ 1 ];
    fd_histf_t add_shred_timing[ 1 ];
    ulong shred_processing_result[ FD_FEC_RESOLVER_ADD_SHRED_RETVAL_CNT+FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT ];
    ulong invalid_block_id_cnt;
    ulong shred_rejected_unchained_cnt;
    ulong repair_rcv_cnt;
    ulong turbine_rcv_cnt;
    fd_histf_t store_insert_wait[ 1 ];
    fd_histf_t store_insert_work[ 1 ];
  } metrics[ 1 ];

  struct {
    ulong txn_cnt;
    ulong pos; /* in payload, range [0, FD_SHRED_BATCH_RAW_BUF_SZ-8UL) */
    ulong slot; /* set to 0 when pos==0 */
    union {
      struct {
        ulong microblock_cnt;
        uchar payload[ FD_SHRED_BATCH_RAW_BUF_SZ - 8UL ];
      };
      uchar raw[ FD_SHRED_BATCH_RAW_BUF_SZ ];
    };
  } pending_batch;

  fd_shred_features_activation_t features_activation[1];
  /* too large to be left in the stack */
  fd_shred_dest_idx_t scratchpad_dests[ FD_SHRED_DEST_MAX_FANOUT*(FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX) ];

  uchar * chained_merkle_root;
  fd_bmtree_node_t out_merkle_roots[ FD_SHRED_BATCH_FEC_SETS_MAX ];
  uchar block_ids[ BLOCK_IDS_TABLE_CNT ][ FD_SHRED_MERKLE_ROOT_SZ ];
} fd_shred_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {

  ulong fec_resolver_footprint = fd_fec_resolver_footprint( tile->shred.fec_resolver_depth, 1UL, tile->shred.depth,
                                                            128UL * tile->shred.fec_resolver_depth );
  ulong fec_set_cnt = tile->shred.depth + tile->shred.fec_resolver_depth + 4UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_shred_ctx_t),          sizeof(fd_shred_ctx_t)                  );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()                 );
  l = FD_LAYOUT_APPEND( l, fd_fec_resolver_align(),          fec_resolver_footprint                  );
  l = FD_LAYOUT_APPEND( l, fd_shredder_align(),              fd_shredder_footprint()                 );
  l = FD_LAYOUT_APPEND( l, alignof(fd_fec_set_t),            sizeof(fd_fec_set_t)*fec_set_cnt        );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_shred_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ulong seq_must_complete = ctx->keyswitch->param;

    if( FD_UNLIKELY( fd_seq_lt( ctx->poh_in_expect_seq, seq_must_complete ) ) ) {
      /* See fd_keyswitch.h, we need to flush any in-flight shreds from
         the leader pipeline before switching key. */
      FD_LOG_WARNING(( "Flushing in-flight unpublished shreds, must reach seq %lu, currently at %lu ...", seq_must_complete, ctx->poh_in_expect_seq ));
      return;
    }

    memcpy( ctx->identity_key->uc, ctx->keyswitch->bytes, 32UL );
    fd_stake_ci_set_identity( ctx->stake_ci, ctx->identity_key );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_shred_ctx_t * ctx ) {
  FD_MHIST_COPY( SHRED, CLUSTER_CONTACT_INFO_CNT,   ctx->metrics->contact_info_cnt             );
  FD_MHIST_COPY( SHRED, BATCH_SZ,                   ctx->metrics->batch_sz                     );
  FD_MHIST_COPY( SHRED, BATCH_MICROBLOCK_CNT,       ctx->metrics->batch_microblock_cnt         );
  FD_MHIST_COPY( SHRED, SHREDDING_DURATION_SECONDS, ctx->metrics->shredding_timing             );
  FD_MHIST_COPY( SHRED, ADD_SHRED_DURATION_SECONDS, ctx->metrics->add_shred_timing             );
  FD_MCNT_SET  ( SHRED, SHRED_REPAIR_RCV,           ctx->metrics->repair_rcv_cnt               );
  FD_MCNT_SET  ( SHRED, SHRED_TURBINE_RCV,          ctx->metrics->turbine_rcv_cnt              );

  FD_MCNT_SET  ( SHRED, INVALID_BLOCK_ID,           ctx->metrics->invalid_block_id_cnt         );
  FD_MCNT_SET  ( SHRED, SHRED_REJECTED_UNCHAINED,   ctx->metrics->shred_rejected_unchained_cnt );
  FD_MHIST_COPY( SHRED, STORE_INSERT_WAIT,          ctx->metrics->store_insert_wait            );
  FD_MHIST_COPY( SHRED, STORE_INSERT_WORK,          ctx->metrics->store_insert_work            );

  FD_MCNT_ENUM_COPY( SHRED, SHRED_PROCESSED, ctx->metrics->shred_processing_result             );
}

static inline void
handle_new_cluster_contact_info( fd_shred_ctx_t * ctx,
                                 uchar const    * buf ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = header[ 0 ];
  fd_histf_sample( ctx->metrics->contact_info_cnt, dest_cnt );

  if( dest_cnt >= MAX_SHRED_DESTS )
    FD_LOG_ERR(( "Cluster nodes had %lu destinations, which was more than the max of %lu", dest_cnt, MAX_SHRED_DESTS ));

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header+1UL );
  fd_shred_dest_weighted_t * dests = fd_stake_ci_dest_add_init( ctx->stake_ci );

  ctx->new_dest_ptr = dests;
  ctx->new_dest_cnt = dest_cnt;

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    memcpy( dests[i].pubkey.uc, in_dests[i].pubkey, 32UL );
    dests[i].ip4  = in_dests[i].ip4_addr;
    dests[i].port = in_dests[i].udp_port;
  }
}

static inline void
finalize_new_cluster_contact_info( fd_shred_ctx_t * ctx ) {
  fd_stake_ci_dest_add_fini( ctx->stake_ci, ctx->new_dest_cnt );
}

static inline int
before_frag( fd_shred_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig ) {
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPECHO ) ) {
    FD_TEST( sig!=0UL && sig<=USHORT_MAX );
    fd_shredder_set_shred_version    ( ctx->shredder, (ushort)sig );
    fd_fec_resolver_set_shred_version( ctx->resolver, (ushort)sig );
    return 1;
  }

  if( FD_UNLIKELY( !ctx->shredder->shred_version ) ) return -1;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_POH ) ) {
    ctx->poh_in_expect_seq = seq+1UL;
    return (int)(fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_MICROBLOCK) & (int)(fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_FEAT_ACT_SLOT);
  }
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    return (int)(fd_disco_netmux_sig_proto( sig )!=DST_PROTO_SHRED) & (int)(fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR);
  }
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ){
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
           sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  return 0;
}

static void
during_frag( fd_shred_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig,
             ulong            chunk,
             ulong            sz,
             ulong            ctl ) {

  ctx->skip_frag = 0;

  ctx->tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPAIR ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_memcpy( ctx->shred_buffer, dcache_entry, sz );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_CONTACT ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    uchar const * gossip_upd_msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_memcpy( ctx->gossip_upd_buf, gossip_upd_msg, sz );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, fd_type_pun_const( dcache_entry ) );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_POH ) ) {
    ctx->send_fec_set_cnt = 0UL;

    if( FD_UNLIKELY( (fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_FEAT_ACT_SLOT) ) ) {
      /* There is a subset of FD_SHRED_FEATURES_ACTIVATION_... slots that
          the shred tile needs to be aware of.  Since this requires the
          bank, we are forced (so far) to receive them from the poh tile
          (as a POH_PKT_TYPE_FEAT_ACT_SLOT).  This is not elegant, and it
          should be revised in the future (TODO), but it provides a
          "temporary" working solution to handle features activation. */
      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=(sizeof(fd_shred_features_activation_t)) ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
              ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_shred_features_activation_t const * act_data = (fd_shred_features_activation_t const *)dcache_entry;
      memcpy( ctx->features_activation, act_data, sizeof(fd_shred_features_activation_t) );
    }
    else { /* (fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK) */
      /* This is a frag from the PoH tile.  We'll copy it to our pending
        microblock batch and shred it if necessary (last in block or
        above watermark).  We just go ahead and shred it here, even
        though we may get overrun.  If we do end up getting overrun, we
        just won't send these shreds out and we'll reuse the FEC set for
        the next one.  From a higher level though, if we do get overrun,
        a bunch of shreds will never be transmitted, and we'll end up
        producing a block that never lands on chain. */

      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_POH_SHRED_MTU ||
          sz<(sizeof(fd_entry_batch_meta_t)+sizeof(fd_entry_batch_header_t)) ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
              ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_entry_batch_meta_t const * entry_meta = (fd_entry_batch_meta_t const *)dcache_entry;
      uchar const *                 entry      = dcache_entry + sizeof(fd_entry_batch_meta_t);
      ulong                         entry_sz   = sz           - sizeof(fd_entry_batch_meta_t);

      fd_entry_batch_header_t const * microblock = (fd_entry_batch_header_t const *)entry;

      /* It should never be possible for this to fail, but we check it
        anyway. */
      FD_TEST( entry_sz + ctx->pending_batch.pos <= sizeof(ctx->pending_batch.payload) );

      ulong target_slot = fd_disco_poh_sig_slot( sig );
      if( FD_UNLIKELY( (ctx->pending_batch.microblock_cnt>0) & (ctx->pending_batch.slot!=target_slot) ) ) {
        /* TODO: The Agave client sends a dummy entry batch with only 1
          byte and the block-complete bit set.  This helps other
          validators know that the block is dead and they should not try
          to continue building a fork on it.  We probably want a similar
          approach eventually. */
        FD_LOG_WARNING(( "Abandoning %lu microblocks for slot %lu and switching to slot %lu",
              ctx->pending_batch.microblock_cnt, ctx->pending_batch.slot, target_slot ));
        ctx->pending_batch.slot           = 0UL;
        ctx->pending_batch.pos            = 0UL;
        ctx->pending_batch.microblock_cnt = 0UL;
        ctx->pending_batch.txn_cnt        = 0UL;
        ctx->batch_cnt                    = 0UL;

        FD_MCNT_INC( SHRED, MICROBLOCKS_ABANDONED, 1UL );
      }

      ctx->pending_batch.slot = target_slot;
      if( FD_UNLIKELY( target_slot!=ctx->slot )) {
        /* Reset batch count if we are in a new slot */
        ctx->batch_cnt = 0UL;
        ctx->slot      = target_slot;

        /* At the beginning of a new slot, prepare chained_merkle_root.
           chained_merkle_root is initialized at the block_id of the parent
           block, there's two cases:

           1. block_id is passed in by the poh tile:
              - it's always passed when parent block had a different leader
              - it may be passed when we were leader for parent block (there
                are race conditions when it's not passed)

           2. block_id is taken from block_ids table if we were the leader
              for the parent block (when we were NOT the leader, because of
              equivocation, we can't store block_id in the table)

           chained_merkle_root is stored in block_ids table at target_slot
           and it's progressively updated as more microblocks are received.
           As a result, when we move to a new slot, the block_ids table at
           the old slot will contain the block_id.

           The block_ids table is designed to protect against the race condition
           case in 1., therefore the table may not be set in some cases, e.g. if
           a validator (re)starts, but in those cases we don't expect the race
           condition to apply. */
        ctx->chained_merkle_root = ctx->block_ids[ target_slot % BLOCK_IDS_TABLE_CNT ];
        if( FD_UNLIKELY( SHOULD_PROCESS_THESE_SHREDS ) ) {
          if( FD_LIKELY( entry_meta->parent_block_id_valid ) ) {
            /* 1. Initialize chained_merkle_root sent from poh tile */
            memcpy( ctx->chained_merkle_root, entry_meta->parent_block_id, FD_SHRED_MERKLE_ROOT_SZ );
          } else {
            ulong parent_slot = target_slot - entry_meta->parent_offset;
            fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, parent_slot );
            fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, parent_slot );

            if( lsched && slot_leader && fd_memeq( slot_leader, ctx->identity_key, sizeof(fd_pubkey_t) ) ) {
              /* 2. Initialize chained_merkle_root from block_ids table, if we were the leader */
              memcpy( ctx->chained_merkle_root, ctx->block_ids[ parent_slot % BLOCK_IDS_TABLE_CNT ], FD_SHRED_MERKLE_ROOT_SZ );
            } else {
              /* This should never happen, log a metric and set chained_merkle_root to 0 */
              ctx->metrics->invalid_block_id_cnt++;
              memset( ctx->chained_merkle_root, 0, FD_SHRED_MERKLE_ROOT_SZ );
            }
          }
        }
      }

      if( FD_LIKELY( !SHOULD_PROCESS_THESE_SHREDS ) ) {
        /* If we are not processing this batch, filter in after_frag. */
        ctx->skip_frag = 1;
      }

      ulong   pending_batch_wmark = FD_SHRED_BATCH_WMARK_CHAINED;
      uchar * chained_merkle_root = ctx->chained_merkle_root;
      ulong   load_for_32_shreds  = FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ;
      /* All fec sets in the last batch of a block need to be resigned.
         This needs to match Agave's behavior - as a reference, see:
         https://github.com/anza-xyz/agave/blob/v2.3/ledger/src/shred/merkle.rs#L1040 */
      if( FD_UNLIKELY( entry_meta->block_complete ) ) {
        pending_batch_wmark = FD_SHRED_BATCH_WMARK_RESIGNED;
        /* chained_merkle_root also applies to resigned FEC sets. */
        load_for_32_shreds = FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ;
      }
      if( FD_LIKELY( IS_FIREDANCER ) ) {
        pending_batch_wmark = FD_SHRED_BATCH_WMARK_NORMAL;
        load_for_32_shreds  = FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ;
      }

      /* If this microblock completes the block, the batch is then
         finalized here.  Otherwise, we check whether the new entry
         would exceed the pending_batch_wmark.  If true, then the
         batch is closed now, shredded, and a new batch is started
         with the incoming microblock.  If false, no shredding takes
         place, and the microblock is added to the current batch. */
      int batch_would_exceed_wmark = ( ctx->pending_batch.pos + entry_sz ) > pending_batch_wmark;
      int include_in_current_batch = entry_meta->block_complete | ( !batch_would_exceed_wmark );
      int process_current_batch    = entry_meta->block_complete | batch_would_exceed_wmark;
      int init_new_batch           = !include_in_current_batch;

      if( FD_LIKELY( include_in_current_batch ) ) {
        if( FD_UNLIKELY( SHOULD_PROCESS_THESE_SHREDS ) ) {
          /* Ugh, yet another memcpy */
          fd_memcpy( ctx->pending_batch.payload + ctx->pending_batch.pos, entry, entry_sz );
        }
        ctx->pending_batch.pos            += entry_sz;
        ctx->pending_batch.microblock_cnt += 1UL;
        ctx->pending_batch.txn_cnt        += microblock->txn_cnt;
      }

      if( FD_LIKELY( process_current_batch )) {
        /* Batch and padding size calculation. */
        ulong batch_sz        = sizeof(ulong) + ctx->pending_batch.pos; /* without padding */
        ulong batch_sz_padded = load_for_32_shreds * ( ( batch_sz + load_for_32_shreds - 1UL ) / load_for_32_shreds );
        ulong padding_sz      = batch_sz_padded - batch_sz;

        if( FD_UNLIKELY( SHOULD_PROCESS_THESE_SHREDS ) ) {
          /* If it's our turn, shred this batch. FD_UNLIKELY because shred
             tile cnt generally >= 2 */

          long shredding_timing = -fd_tickcount();

          fd_memset( ctx->pending_batch.payload + ctx->pending_batch.pos, 0, padding_sz );

          ctx->send_fec_set_cnt = 0UL; /* verbose */
          ctx->shredded_txn_cnt = ctx->pending_batch.txn_cnt;

          fd_shredder_init_batch( ctx->shredder, ctx->pending_batch.raw, batch_sz_padded, target_slot, entry_meta );

          ulong pend_sz  = batch_sz_padded;
          ulong pend_idx = 0;
          while( pend_sz > 0UL ) {

            fd_fec_set_t * out = ctx->fec_sets + ctx->shredder_fec_set_idx;

            FD_TEST( fd_shredder_next_fec_set( ctx->shredder, out, chained_merkle_root, ctx->out_merkle_roots[pend_idx].hash ) );

            d_rcvd_join( d_rcvd_new( d_rcvd_delete( d_rcvd_leave( out->data_shred_rcvd   ) ) ) );
            p_rcvd_join( p_rcvd_new( p_rcvd_delete( p_rcvd_leave( out->parity_shred_rcvd ) ) ) );

            ctx->send_fec_set_idx[ ctx->send_fec_set_cnt ] = ctx->shredder_fec_set_idx;
            ctx->send_fec_set_cnt += 1UL;
            ctx->shredder_fec_set_idx = (ctx->shredder_fec_set_idx+1UL)%ctx->shredder_max_fec_set_idx;

            pend_sz -= load_for_32_shreds;
            pend_idx++;
          }

          fd_shredder_fini_batch( ctx->shredder );
          shredding_timing += fd_tickcount();

          /* Update metrics */
          fd_histf_sample( ctx->metrics->batch_sz,             batch_sz /* without padding */    );
          fd_histf_sample( ctx->metrics->batch_microblock_cnt, ctx->pending_batch.microblock_cnt );
          fd_histf_sample( ctx->metrics->shredding_timing,     (ulong)shredding_timing           );
        } else {
          ctx->send_fec_set_cnt = 0UL; /* verbose */

          ulong shred_type = FD_SHRED_TYPE_MERKLE_DATA_CHAINED;
          if( FD_UNLIKELY( entry_meta->block_complete ) ) {
            shred_type = FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED;
          }
          if( FD_LIKELY( IS_FIREDANCER ) ) {
            shred_type = FD_SHRED_TYPE_MERKLE_DATA;
          }
          fd_shredder_skip_batch( ctx->shredder, batch_sz_padded, target_slot, shred_type );
        }

        ctx->pending_batch.slot           = 0UL;
        ctx->pending_batch.pos            = 0UL;
        ctx->pending_batch.microblock_cnt = 0UL;
        ctx->pending_batch.txn_cnt        = 0UL;
        ctx->batch_cnt++;
      }

      if( FD_UNLIKELY( init_new_batch ) ) {
        /* TODO: this assumes that SHOULD_PROCESS_THESE_SHREDS is
           constant across batches.  Otherwise, the condition may
           need to be removed (or adjusted). */
        if( FD_UNLIKELY( SHOULD_PROCESS_THESE_SHREDS ) ) {
          /* Ugh, yet another memcpy */
          fd_memcpy( ctx->pending_batch.payload + 0UL /* verbose */, entry, entry_sz );
        }
        ctx->pending_batch.slot           = target_slot;
        ctx->pending_batch.pos            = entry_sz;
        ctx->pending_batch.microblock_cnt = 1UL;
        ctx->pending_batch.txn_cnt        = microblock->txn_cnt;
      }
    }
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    /* The common case, from the net tile.  The FEC resolver API does
       not present a prepare/commit model. If we get overrun between
       when the FEC resolver verifies the signature and when it stores
       the local copy, we could end up storing and retransmitting
       garbage.  Instead we copy it locally, sadly, and only give it to
       the FEC resolver when we know it won't be overrun anymore. */
    uchar const * dcache_entry = fd_net_rx_translate_frag( &ctx->in[ in_idx ].net_rx, chunk, ctl, sz );
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */
    fd_shred_t const * shred = fd_shred_parse( dcache_entry+hdr_sz, sz-hdr_sz );
    if( FD_UNLIKELY( !shred ) ) {
      ctx->skip_frag = 1;
      return;
    };

    if( FD_UNLIKELY( fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR ) ) ctx->metrics->repair_rcv_cnt++;
    else                                                                    ctx->metrics->turbine_rcv_cnt++;

    /* Drop unchained merkle shreds (if feature is active) */
    int is_unchained = !fd_shred_is_chained( fd_shred_type( shred->variant ) );
    if( FD_UNLIKELY( is_unchained && shred->slot >= ctx->features_activation->drop_unchained_merkle_shreds ) ) {
      ctx->metrics->shred_rejected_unchained_cnt++;
      ctx->skip_frag = 1;
      return;
    };

    /* all shreds in the same FEC set will have the same signature
       so we can round-robin shreds between the shred tiles based on
       just the signature without splitting individual FEC sets. */
    ulong sig = fd_ulong_load_8( shred->signature );
    if( FD_LIKELY( sig%ctx->round_robin_cnt!=ctx->round_robin_id ) ) {
      ctx->skip_frag = 1;
      return;
    }
    fd_memcpy( ctx->shred_buffer, dcache_entry+hdr_sz, sz-hdr_sz );
    ctx->shred_buffer_sz = sz-hdr_sz;
  }
}

static inline void
send_shred( fd_shred_ctx_t                 * ctx,
            fd_stem_context_t              * stem,
            fd_shred_t const               * shred,
            fd_shred_dest_weighted_t const * dest,
            ulong                            tsorig ) {

  if( FD_UNLIKELY( !dest->ip4 ) ) return;

  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  int is_data = fd_shred_is_data( fd_shred_type( shred->variant ) );
  fd_ip4_udp_hdrs_t * hdr  = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *( is_data ? ctx->data_shred_net_hdr : ctx->parity_shred_net_hdr );

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->daddr  = dest->ip4;
  ip4->net_id = fd_ushort_bswap( ctx->net_id++ );
  ip4->check  = 0U;
  ip4->check  = fd_ip4_hdr_check_fast( ip4 );

  hdr->udp->net_dport = fd_ushort_bswap( dest->port );

  ulong shred_sz = fd_ulong_if( is_data, FD_SHRED_MIN_SZ, FD_SHRED_MAX_SZ );
#if FD_HAS_AVX
  /* We're going to copy this shred potentially a bunch of times without
     reading it again, and we'd rather not thrash our cache, so we want
     to use non-temporal writes here.  We need to make sure we don't
     touch the cache line containing the network headers that we just
     wrote to though.  We know the destination is 64 byte aligned.  */
  FD_STATIC_ASSERT( sizeof(*hdr)<64UL, non_temporal );
  /* src[0:sizeof(hdrs)] is invalid, but now we want to copy
     dest[i]=src[i] for i>=sizeof(hdrs), so it simplifies the code. */
  uchar const * src = (uchar const *)((ulong)shred - sizeof(fd_ip4_udp_hdrs_t));
  memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), src+sizeof(fd_ip4_udp_hdrs_t), 64UL-sizeof(fd_ip4_udp_hdrs_t) );

  ulong end_offset = shred_sz + sizeof(fd_ip4_udp_hdrs_t);
  ulong i;
  for( i=64UL; end_offset-i<64UL; i+=64UL ) {
#  if FD_HAS_AVX512
    _mm512_stream_si512( (void *)(packet+i     ), _mm512_loadu_si512( (void const *)(src+i     ) ) );
#  else
    _mm256_stream_si256( (void *)(packet+i     ), _mm256_loadu_si256( (void const *)(src+i     ) ) );
    _mm256_stream_si256( (void *)(packet+i+32UL), _mm256_loadu_si256( (void const *)(src+i+32UL) ) );
#  endif
  }
  _mm_sfence();
  fd_memcpy( packet+i, src+i, end_offset-i ); /* Copy the last partial cache line */

#else
  fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), shred, shred_sz );
#endif

  ulong pkt_sz = shred_sz + sizeof(fd_ip4_udp_hdrs_t);
  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig    = fd_disco_netmux_sig( dest->ip4, dest->port, dest->ip4, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  ulong const chunk = ctx->net_out_chunk;
  fd_stem_publish( stem, NET_OUT_IDX, sig, chunk, pkt_sz, 0UL, tsorig, tspub );
  ctx->net_out_chunk = fd_dcache_compact_next( chunk, pkt_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static void
after_frag( fd_shred_ctx_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               _tspub,
            fd_stem_context_t * stem ) {
  (void)seq;
  (void)sz;
  (void)tsorig;
  (void)_tspub;

  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_CONTACT ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    if( ctx->gossip_upd_buf->tag==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) {
      fd_contact_info_t const * ci = ctx->gossip_upd_buf->contact_info.contact_info;
      fd_ip4_port_t tvu_addr = ci->sockets[ FD_CONTACT_INFO_SOCKET_TVU ];
      if( !tvu_addr.l ){
        fd_stake_ci_dest_remove( ctx->stake_ci, &ci->pubkey );
      } else {
        fd_stake_ci_dest_update( ctx->stake_ci, &ci->pubkey, tvu_addr.addr, fd_ushort_bswap( tvu_addr.port ) );
      }
    } else if( ctx->gossip_upd_buf->tag==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) {
      if( FD_UNLIKELY( !memcmp( ctx->identity_key->uc, ctx->gossip_upd_buf->origin_pubkey, 32UL ) ) ) {
        /* If our own contact info was dropped, we update with dummy IP
           instead of removing since stake_ci expects our contact info
           in the sdests table all the time. fd_stake_ci_new initializes
           both ei->sdests with our contact info so this should always
           update (and not append). */
        fd_stake_ci_dest_update( ctx->stake_ci, (fd_pubkey_t *)ctx->gossip_upd_buf->origin_pubkey, 1U, 0U );
      } else {
        fd_stake_ci_dest_remove( ctx->stake_ci, (fd_pubkey_t *)ctx->gossip_upd_buf->origin_pubkey );
      }
    }
    return;
  }

  if( FD_UNLIKELY( (ctx->in_kind[ in_idx ]==IN_KIND_POH) & (ctx->send_fec_set_cnt==0UL) ) ) {
    /* Entry from PoH that didn't trigger a new FEC set to be made */
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPAIR ) ) {
    FD_MCNT_INC( SHRED, FORCE_COMPLETE_REQUEST, 1UL );
    fd_ed25519_sig_t const * shred_sig = (fd_ed25519_sig_t const *)fd_type_pun( ctx->shred_buffer );
    if( FD_UNLIKELY( fd_fec_resolver_done_contains( ctx->resolver, shred_sig ) ) ) {
      /* This is a FEC completion message from the repair tile.  We need
         to make sure that we don't force complete something that's just
         been completed. */
      FD_MCNT_INC( SHRED, FORCE_COMPLETE_FAILURE, 1UL );
      return;
    }

    uint last_idx = fd_disco_repair_shred_sig_last_shred_idx( sig );
    uchar buf_last_shred[FD_SHRED_MIN_SZ];
    int rv = fd_fec_resolver_shred_query( ctx->resolver, shred_sig, last_idx, buf_last_shred );
    if( FD_UNLIKELY( rv != FD_FEC_RESOLVER_SHRED_OKAY ) ) {

      /* We will hit this case if FEC is no longer in curr_map, or if
         the shred signature is invalid, which is okay.

         There's something of a race condition here.  It's possible (but
         very unlikely) that between when the repair tile observed the
         FEC set needed to be force completed and now, the FEC set was
         completed, and then so many additional FEC sets were completed
         that it fell off the end of the done list.  In that case
         fd_fec_resolver_done_contains would have returned false, but
         fd_fec_resolver_shred_query will not return OKAY, which means
         we'll end up in this block of code.  If the FEC set was
         completed, then there's nothing we need to do.  If it was
         spilled, then we'll need to re-repair all the shreds in the FEC
         set, but it's not fatal. */

      FD_MCNT_INC( SHRED, FORCE_COMPLETE_FAILURE, 1UL );
      return;
    }
    fd_shred_t * out_last_shred = (fd_shred_t *)fd_type_pun( buf_last_shred );

    fd_fec_set_t const * out_fec_set[1];
    rv = fd_fec_resolver_force_complete( ctx->resolver, out_last_shred, out_fec_set, &ctx->out_merkle_roots[0] );
    if( FD_UNLIKELY( rv != FD_FEC_RESOLVER_SHRED_COMPLETES ) ) {
      FD_LOG_WARNING(( "Shred tile %lu cannot force complete the slot %lu fec_set_idx %u %s", ctx->round_robin_id, out_last_shred->slot, out_last_shred->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( shred_sig ) ));
      FD_MCNT_INC( SHRED, FORCE_COMPLETE_FAILURE, 1UL );
      return;
    }
    FD_MCNT_INC( SHRED, FORCE_COMPLETE_SUCCESS, 1UL );
    FD_TEST( ctx->fec_sets <= *out_fec_set );
    ctx->send_fec_set_idx[ 0UL ] = (ulong)(*out_fec_set - ctx->fec_sets);
    ctx->send_fec_set_cnt = 1UL;
    ctx->shredded_txn_cnt = 0UL;
  }

  ulong fanout = 200UL; /* Default Agave's DATA_PLANE_FANOUT = 200UL */

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    uchar * shred_buffer    = ctx->shred_buffer;
    ulong   shred_buffer_sz = ctx->shred_buffer_sz;

    fd_shred_t const * shred = fd_shred_parse( shred_buffer, shred_buffer_sz );

    if( FD_UNLIKELY( !shred       ) ) { ctx->metrics->shred_processing_result[ 1 ]++; return; }

    fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, shred->slot );
    if( FD_UNLIKELY( !lsched      ) ) { ctx->metrics->shred_processing_result[ 0 ]++; return; }

    fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, shred->slot );
    if( FD_UNLIKELY( !slot_leader ) ) { ctx->metrics->shred_processing_result[ 0 ]++; return; } /* Count this as bad slot too */

    uint nonce = fd_disco_netmux_sig_proto( sig ) == DST_PROTO_SHRED ? UINT_MAX : FD_LOAD(uint, shred_buffer + fd_shred_sz( shred ) );

    fd_fec_set_t const * out_fec_set[1];
    fd_shred_t const   * out_shred[1];
    fd_fec_resolver_spilled_t spilled_fec = { 0 };

    long add_shred_timing  = -fd_tickcount();
    int rv = fd_fec_resolver_add_shred( ctx->resolver, shred, shred_buffer_sz, slot_leader->uc, out_fec_set, out_shred, &ctx->out_merkle_roots[0], &spilled_fec );
    add_shred_timing      +=  fd_tickcount();

    fd_histf_sample( ctx->metrics->add_shred_timing, (ulong)add_shred_timing );
    ctx->metrics->shred_processing_result[ rv + FD_FEC_RESOLVER_ADD_SHRED_RETVAL_OFF+FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT ]++;

    /* Fanout is subject to feature activation. The code below replicates
        Agave's get_data_plane_fanout() in turbine/src/cluster_nodes.rs
        on 2025-03-25. Default Agave's DATA_PLANE_FANOUT = 200UL.
        TODO once the experiments are disabled, consider removing these
        fanout variations from the code. */
    if( FD_LIKELY( shred->slot >= ctx->features_activation->disable_turbine_fanout_experiments ) ) {
      fanout = 200UL;
    } else {
      if( FD_LIKELY( shred->slot >= ctx->features_activation->enable_turbine_extended_fanout_experiments ) ) {
        switch( shred->slot % 359 ) {
          case  11UL: fanout = 1152UL;  break;
          case  61UL: fanout = 1280UL;  break;
          case 111UL: fanout = 1024UL;  break;
          case 161UL: fanout = 1408UL;  break;
          case 211UL: fanout =  896UL;  break;
          case 261UL: fanout = 1536UL;  break;
          case 311UL: fanout =  768UL;  break;
          default   : fanout =  200UL;
        }
      } else {
        switch( shred->slot % 359 ) {
          case  11UL: fanout =   64UL;  break;
          case  61UL: fanout =  768UL;  break;
          case 111UL: fanout =  128UL;  break;
          case 161UL: fanout =  640UL;  break;
          case 211UL: fanout =  256UL;  break;
          case 261UL: fanout =  512UL;  break;
          case 311UL: fanout =  384UL;  break;
          default   : fanout =  200UL;
        }
      }
    }

    if( FD_UNLIKELY( ctx->repair_out_idx!=ULONG_MAX &&  /* Only send to repair in full Firedancer */
                     spilled_fec.slot!=0 && spilled_fec.max_dshred_idx!=FD_SHRED_BLK_MAX ) ) {
      /* We've spilled an in-progress FEC set in the fec_resolver. We
         need to let repair know to clear out it's cached info for that
         fec set and re-repair those shreds. */
      ulong sig_ = fd_disco_shred_repair_shred_sig( 0, spilled_fec.slot, spilled_fec.fec_set_idx, 0, spilled_fec.max_dshred_idx );
      fd_stem_publish( stem, ctx->repair_out_idx, sig_, ctx->repair_out_chunk, 0, 0, ctx->tsorig, ctx->tsorig );
    }

    if( (rv==FD_FEC_RESOLVER_SHRED_OKAY) | (rv==FD_FEC_RESOLVER_SHRED_COMPLETES) ) {
      if( FD_LIKELY( fd_disco_netmux_sig_proto( sig ) != DST_PROTO_REPAIR ) ) {
        /* Relay this shred */
        ulong max_dest_cnt[1];
        do {
          /* If we've validated the shred and it COMPLETES but we can't
            compute the destination for whatever reason, don't forward
            the shred, but still send it to the blockstore. */
          fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, shred->slot );
          if( FD_UNLIKELY( !sdest ) ) break;
          fd_shred_dest_idx_t * dests = fd_shred_dest_compute_children( sdest, &shred, 1UL, ctx->scratchpad_dests, 1UL, fanout, fanout, max_dest_cnt );
          if( FD_UNLIKELY( !dests ) ) break;

          for( ulong i=0UL; i<ctx->adtl_dests_retransmit_cnt; i++ ) send_shred( ctx, stem, *out_shred, ctx->adtl_dests_retransmit+i, ctx->tsorig );
          for( ulong j=0UL; j<*max_dest_cnt; j++ ) send_shred( ctx, stem, *out_shred, fd_shred_dest_idx_to_dest( sdest, dests[ j ] ), ctx->tsorig );
        } while( 0 );
      }

      if( FD_LIKELY( ctx->repair_out_idx!=ULONG_MAX ) ) { /* Only send to repair in full Firedancer */

        /* Construct the sig from the shred. */

        int  is_code               = fd_shred_is_code( fd_shred_type( shred->variant ) );
        uint shred_idx_or_data_cnt = shred->idx;
        if( FD_LIKELY( is_code ) ) shred_idx_or_data_cnt = shred->code.data_cnt;  /* optimize for code_cnt >= data_cnt */
        ulong _sig = fd_disco_shred_repair_shred_sig( fd_disco_netmux_sig_proto(sig)==DST_PROTO_SHRED, shred->slot, shred->fec_set_idx, is_code, shred_idx_or_data_cnt );

        /* Copy the shred header into the frag and publish. */

        ulong sz = fd_shred_header_sz( shred->variant );
        fd_memcpy( fd_chunk_to_laddr( ctx->repair_out_mem, ctx->repair_out_chunk ), shred, sz );
        FD_STORE(uint, fd_chunk_to_laddr( ctx->repair_out_mem, ctx->repair_out_chunk ) + sz, nonce );
        sz += 4UL;

        ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
        fd_stem_publish( stem, ctx->repair_out_idx, _sig, ctx->repair_out_chunk, sz, 0UL, ctx->tsorig, tspub );
        ctx->repair_out_chunk = fd_dcache_compact_next( ctx->repair_out_chunk, sz, ctx->repair_out_chunk0, ctx->repair_out_wmark );
      }
    }
    if( FD_LIKELY( rv!=FD_FEC_RESOLVER_SHRED_COMPLETES ) ) return;

    FD_TEST( ctx->fec_sets <= *out_fec_set );
    ctx->send_fec_set_idx[ 0UL ] = (ulong)(*out_fec_set - ctx->fec_sets);
    ctx->send_fec_set_cnt = 1UL;
    ctx->shredded_txn_cnt = 0UL;
  }

  if( FD_UNLIKELY( ctx->send_fec_set_cnt==0UL ) ) return;

  /* Try to distribute shredded txn count across the fec sets.
     This is an approximation, but it is acceptable. */
  ulong shredded_txn_cnt_per_fec_set  = ctx->shredded_txn_cnt / ctx->send_fec_set_cnt;
  ulong shredded_txn_cnt_remain       = ctx->shredded_txn_cnt - shredded_txn_cnt_per_fec_set * ctx->send_fec_set_cnt;
  ulong shredded_txn_cnt_last_fec_set = shredded_txn_cnt_per_fec_set + shredded_txn_cnt_remain;

  /* If this shred completes a FEC set or is part of a microblock from
    pack (ie. we're leader), we now have a full FEC set: so we notify
    repair and insert into the blockstore, as well as retransmit. */

  for( ulong fset_k=0; fset_k<ctx->send_fec_set_cnt; fset_k++ ) {

    fd_fec_set_t * set = ctx->fec_sets + ctx->send_fec_set_idx[ fset_k ];
    fd_shred34_t * s34 = ctx->shred34 + 4UL*ctx->send_fec_set_idx[ fset_k ];

    s34[ 0 ].shred_cnt =                         fd_ulong_min( set->data_shred_cnt,   34UL );
    s34[ 1 ].shred_cnt = set->data_shred_cnt   - fd_ulong_min( set->data_shred_cnt,   34UL );
    s34[ 2 ].shred_cnt =                         fd_ulong_min( set->parity_shred_cnt, 34UL );
    s34[ 3 ].shred_cnt = set->parity_shred_cnt - fd_ulong_min( set->parity_shred_cnt, 34UL );

    ulong s34_cnt     = 2UL + !!(s34[ 1 ].shred_cnt) + !!(s34[ 3 ].shred_cnt);
    ulong txn_per_s34 = fd_ulong_if( fset_k<( ctx->send_fec_set_cnt - 1UL ), shredded_txn_cnt_per_fec_set, shredded_txn_cnt_last_fec_set ) / s34_cnt;

    /* Attribute the transactions evenly to the non-empty shred34s */
    for( ulong j=0UL; j<4UL; j++ ) s34[ j ].est_txn_cnt = fd_ulong_if( s34[ j ].shred_cnt>0UL, txn_per_s34, 0UL );

    /* Add whatever is left to the last shred34 */
    s34[ fd_ulong_if( s34[ 3 ].shred_cnt>0UL, 3, 2 ) ].est_txn_cnt += ctx->shredded_txn_cnt - txn_per_s34*s34_cnt;

    /* Set the sz field so that metrics are more accurate. */
    ulong sz0 = sizeof(fd_shred34_t) - (34UL - s34[ 0 ].shred_cnt)*FD_SHRED_MAX_SZ;
    ulong sz1 = sizeof(fd_shred34_t) - (34UL - s34[ 1 ].shred_cnt)*FD_SHRED_MAX_SZ;
    ulong sz2 = sizeof(fd_shred34_t) - (34UL - s34[ 2 ].shred_cnt)*FD_SHRED_MAX_SZ;
    ulong sz3 = sizeof(fd_shred34_t) - (34UL - s34[ 3 ].shred_cnt)*FD_SHRED_MAX_SZ;

    fd_shred_t const * last = (fd_shred_t const *)fd_type_pun_const( set->data_shreds[ set->data_shred_cnt - 1 ] );

    /* Compute merkle root and chained merkle root. */

    if( FD_LIKELY( ctx->store ) ) { /* firedancer-only */

      /* Insert shreds into the store. We do this regardless of whether
         we are leader. */

      /* See top-level documentation in fd_store.h under CONCURRENCY to
         understand why it is safe to use a Store read vs. write lock in
         Shred tile. */

      long shacq_start, shacq_end, shrel_end;
      fd_store_fec_t * fec = NULL;
      FD_STORE_SHARED_LOCK( ctx->store, shacq_start, shacq_end, shrel_end ) {
        fec = fd_store_insert( ctx->store, ctx->round_robin_id, (fd_hash_t *)fd_type_pun( &ctx->out_merkle_roots[fset_k] ) );
      } FD_STORE_SHARED_LOCK_END;

      for( ulong i=0UL; i<set->data_shred_cnt; i++ ) {
        fd_shred_t * data_shred = (fd_shred_t *)fd_type_pun( set->data_shreds[i] );
        ulong        payload_sz = fd_shred_payload_sz( data_shred );
        if( FD_UNLIKELY( fec->data_sz + payload_sz > FD_STORE_DATA_MAX ) ) {

          /* This code is only reachable if shred tile has completed the
             FEC set, which implies it was able to validate it, yet
             somehow the total payload sz of this FEC set exceeds the
             maximum payload sz. This indicates either a serious bug or
             shred tile is compromised so log_crit. */

          FD_LOG_CRIT(( "Shred tile %lu: completed FEC set %lu %u data_sz: %lu exceeds FD_STORE_DATA_MAX: %lu. Ignoring FEC set.", ctx->round_robin_id, data_shred->slot, data_shred->fec_set_idx, fec->data_sz + payload_sz, FD_STORE_DATA_MAX ));
        }
        fd_memcpy( fec->data + fec->data_sz, fd_shred_data_payload( data_shred ), payload_sz );
        fec->data_sz += payload_sz;
      }

      /* It's safe to memcpy the FEC payload outside of the shared-lock,
         because the fec object ptr is guaranteed to be valid.  It is
         not possible for a store_publish to free/invalidate the fec
         object during the data memcpy, because the free can only happen
         after the fec is linked to its parent, which happens in the
         repair tile, and crucially, only after we call stem publish in
         this tile.  Copying outside the shared lock scope also means
         that we can lower the duration for which the shared lock is
         held, and enables replay to acquire the exclusive lock and
         avoid getting starved. */

      fd_histf_sample( ctx->metrics->store_insert_wait, (ulong)fd_long_max(shacq_end - shacq_start, 0) );
      fd_histf_sample( ctx->metrics->store_insert_work, (ulong)fd_long_max(shrel_end - shacq_end,   0) );
    }

    if( FD_LIKELY( ctx->repair_out_idx!=ULONG_MAX ) ) { /* firedancer-only */

      /* Additionally, publish a frag to notify repair that the FEC set
         is complete. Note the ordering wrt store shred insertion above
         is intentional: shreds are inserted into the store before
         notifying repair. This is because the replay tile is downstream
         of repair, and replay assumes the shreds are already in the
         store when repair notifies it that the FEC set is complete, and
         we don't know whether shred will finish inserting into store
         first or repair will finish validating the FEC set first. The
         header and merkle root of the last shred in the FEC set are
         sent as part of this frag.

         This message, the shred msg, and the FEC evict msg constitute
         the max 3 possible messages to repair per after_frag.  In
         reality, it is only possible to publish all 3 in the case where
         we receive a coding shred first for a FEC set where (N=1,K=18),
         which allows for the FEC set to be instantly completed by the
         singular coding shred, and that also happens to evict a FEC set
         from the curr_map. When fix-32 arrives, the link burst value
         can be lowered to 2. */

      ulong   sig   = fd_disco_shred_repair_fec_sig( last->slot, last->fec_set_idx, (uint)set->data_shred_cnt, last->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE, last->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE );
      uchar * chunk = fd_chunk_to_laddr( ctx->repair_out_mem, ctx->repair_out_chunk );
      memcpy( chunk,                                                   last,                                                FD_SHRED_DATA_HEADER_SZ );
      memcpy( chunk+FD_SHRED_DATA_HEADER_SZ,                           ctx->out_merkle_roots[fset_k].hash,                  FD_SHRED_MERKLE_ROOT_SZ );
      memcpy( chunk+FD_SHRED_DATA_HEADER_SZ + FD_SHRED_MERKLE_ROOT_SZ, (uchar *)last + fd_shred_chain_off( last->variant ), FD_SHRED_MERKLE_ROOT_SZ );
      ulong sz    = FD_SHRED_DATA_HEADER_SZ + FD_SHRED_MERKLE_ROOT_SZ * 2;
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      fd_stem_publish( stem, ctx->repair_out_idx, sig, ctx->repair_out_chunk, sz, 0UL, ctx->tsorig, tspub );
      ctx->repair_out_chunk = fd_dcache_compact_next( ctx->repair_out_chunk, sz, ctx->repair_out_chunk0, ctx->repair_out_wmark );

    } else if( FD_UNLIKELY( ctx->store_out_idx != ULONG_MAX ) ) { /* frankendancer-only */

      /* Send to the blockstore, skipping any empty shred34_t s. */

      ulong new_sig = ctx->in_kind[ in_idx ]!=IN_KIND_NET; /* sig==0 means the store tile will do extra checks */
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      fd_stem_publish( stem, 0UL, new_sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+0UL ), sz0, 0UL, ctx->tsorig, tspub );
      if( FD_UNLIKELY( s34[ 1 ].shred_cnt ) )
        fd_stem_publish( stem, 0UL, new_sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+1UL ), sz1, 0UL, ctx->tsorig, tspub );
      if( FD_UNLIKELY( s34[ 2 ].shred_cnt ) )
        fd_stem_publish( stem, 0UL, new_sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+2UL), sz2, 0UL, ctx->tsorig, tspub );
      if( FD_UNLIKELY( s34[ 3 ].shred_cnt ) )
        fd_stem_publish( stem, 0UL, new_sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+3UL ), sz3, 0UL, ctx->tsorig, tspub );
    }

    /* Compute all the destinations for all the new shreds */

    fd_shred_t const * new_shreds[ FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX ];
    ulong k=0UL;
    for( ulong i=0UL; i<set->data_shred_cnt; i++ )
      if( !d_rcvd_test( set->data_shred_rcvd,   i ) )  new_shreds[ k++ ] = (fd_shred_t const *)set->data_shreds  [ i ];
    for( ulong i=0UL; i<set->parity_shred_cnt; i++ )
      if( !p_rcvd_test( set->parity_shred_rcvd, i ) )  new_shreds[ k++ ] = (fd_shred_t const *)set->parity_shreds[ i ];

    if( FD_UNLIKELY( !k ) ) return;
    fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, new_shreds[ 0 ]->slot );
    if( FD_UNLIKELY( !sdest ) ) return;

    ulong out_stride;
    ulong max_dest_cnt[1];
    fd_shred_dest_idx_t * dests;
    if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
      for( ulong i=0UL; i<k; i++ ) {
        for( ulong j=0UL; j<ctx->adtl_dests_retransmit_cnt; j++ ) send_shred( ctx, stem, new_shreds[ i ], ctx->adtl_dests_retransmit+j, ctx->tsorig );
      }
      out_stride = k;
      /* In the case of feature activation, the fanout used below is
          the same as the one calculated/modified previously at the
          beginning of after_frag() for IN_KIND_NET in this slot. */
      dests = fd_shred_dest_compute_children( sdest, new_shreds, k, ctx->scratchpad_dests, k, fanout, fanout, max_dest_cnt );
    } else {
      for( ulong i=0UL; i<k; i++ ) {
        for( ulong j=0UL; j<ctx->adtl_dests_leader_cnt; j++ ) send_shred( ctx, stem, new_shreds[ i ], ctx->adtl_dests_leader+j, ctx->tsorig );
      }
      out_stride = 1UL;
      *max_dest_cnt = 1UL;
      dests = fd_shred_dest_compute_first   ( sdest, new_shreds, k, ctx->scratchpad_dests );
    }
    if( FD_UNLIKELY( !dests ) ) return;

    /* Send only the ones we didn't receive. */
    for( ulong i=0UL; i<k; i++ ) {
      for( ulong j=0UL; j<*max_dest_cnt; j++ ) send_shred( ctx, stem, new_shreds[ i ], fd_shred_dest_idx_to_dest( sdest, dests[ j*out_stride+i ]), ctx->tsorig );
    }
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( scratch!=NULL );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->shred.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->shred.identity_key_path, /* pubkey only: */ 1 ) );
}

static void
fd_shred_signer( void *        signer_ctx,
                 uchar         signature[ static 64 ],
                 uchar const   merkle_root[ static 32 ] ) {
  fd_keyguard_client_sign( signer_ctx, signature, merkle_root, 32UL, FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  FD_TEST( 0==strcmp( topo->links[tile->out_link_id[ NET_OUT_IDX   ]].name, "shred_net"   ) );
  FD_TEST( 0==strcmp( topo->links[tile->out_link_id[ SIGN_OUT_IDX  ]].name, "shred_sign"  ) );

  if( FD_UNLIKELY( !tile->out_cnt ) )
    FD_LOG_ERR(( "shred tile has no primary output link" ));

  ulong shred_store_mcache_depth = tile->shred.depth;
  if( topo->links[ tile->out_link_id[ 0 ] ].depth != shred_store_mcache_depth )
    FD_LOG_ERR(( "shred tile out depths are not equal %lu %lu",
                 topo->links[ tile->out_link_id[ 0 ] ].depth, shred_store_mcache_depth ));

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( scratch!=NULL );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_id  = tile->kind_id;
  ctx->batch_cnt       = 0UL;
  ctx->slot            = ULONG_MAX;

  /* If the default partial_depth is ever changed, correspondingly
     change the size of the fd_fec_intra_pool in fd_fec_repair. */
  ulong fec_resolver_footprint = fd_fec_resolver_footprint( tile->shred.fec_resolver_depth, 1UL, shred_store_mcache_depth,
                                                            128UL * tile->shred.fec_resolver_depth );
  ulong fec_set_cnt            = shred_store_mcache_depth + tile->shred.fec_resolver_depth + 4UL;
  ulong fec_sets_required_sz   = fec_set_cnt*DCACHE_ENTRIES_PER_FEC_SET*sizeof(fd_shred34_t);

  void * fec_sets_shmem = NULL;
  ctx->repair_out_idx = fd_topo_find_tile_out_link( topo, tile, "shred_repair", ctx->round_robin_id );
  ctx->store_out_idx  = fd_topo_find_tile_out_link( topo, tile, "shred_store",  ctx->round_robin_id );
  if( FD_LIKELY( ctx->repair_out_idx!=ULONG_MAX ) ) { /* firedancer-only */
    fd_topo_link_t * repair_out = &topo->links[ tile->out_link_id[ ctx->repair_out_idx ] ];
    ctx->repair_out_mem    = topo->workspaces[ topo->objs[ repair_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->repair_out_chunk0 = fd_dcache_compact_chunk0( ctx->repair_out_mem, repair_out->dcache );
    ctx->repair_out_wmark  = fd_dcache_compact_wmark ( ctx->repair_out_mem, repair_out->dcache, repair_out->mtu );
    ctx->repair_out_chunk  = ctx->repair_out_chunk0;
    FD_TEST( fd_dcache_compact_is_safe( ctx->repair_out_mem, repair_out->dcache, repair_out->mtu, repair_out->depth ) );
    ulong fec_sets_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "fec_sets" );
    if( FD_UNLIKELY( fec_sets_obj_id == ULONG_MAX ) ) FD_LOG_ERR(( "invalid firedancer topo" ));
    fd_topo_obj_t const * obj = &topo->objs[ fec_sets_obj_id ];
    if( FD_UNLIKELY( obj->footprint<(fec_sets_required_sz*ctx->round_robin_cnt) ) ) {
      FD_LOG_ERR(( "fec_sets wksp obj too small. It is %lu bytes but must be at least %lu bytes. ",
                   obj->footprint,
                   fec_sets_required_sz ));
    }
    fec_sets_shmem = (uchar *)fd_topo_obj_laddr( topo, fec_sets_obj_id ) + (ctx->round_robin_id * fec_sets_required_sz);
  } else if ( FD_LIKELY( ctx->store_out_idx!=ULONG_MAX ) ) { /* frankendancer-only */
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[ ctx->store_out_idx ]].name, "shred_store" ) );
    fec_sets_shmem = topo->links[ tile->out_link_id[ ctx->store_out_idx ] ].dcache;
    if( FD_UNLIKELY( fd_dcache_data_sz( fec_sets_shmem )<fec_sets_required_sz ) ) {
      FD_LOG_ERR(( "shred_store dcache too small. It is %lu bytes but must be at least %lu bytes. ",
                  fd_dcache_data_sz( fec_sets_shmem ),
                  fec_sets_required_sz ));
    }
  }

  if( FD_UNLIKELY( !tile->shred.fec_resolver_depth ) ) FD_LOG_ERR(( "fec_resolver_depth not set" ));
  if( FD_UNLIKELY( !tile->shred.shred_listen_port  ) ) FD_LOG_ERR(( "shred_listen_port not set" ));

  void * _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()            );
  void * _resolver = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_resolver_align(),          fec_resolver_footprint             );
  void * _shredder = FD_SCRATCH_ALLOC_APPEND( l, fd_shredder_align(),              fd_shredder_footprint()            );
  void * _fec_sets = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fec_set_t),            sizeof(fd_fec_set_t)*fec_set_cnt   );

  fd_fec_set_t * fec_sets = (fd_fec_set_t *)_fec_sets;
  fd_shred34_t * shred34  = (fd_shred34_t *)fec_sets_shmem;

  for( ulong i=0UL; i<fec_set_cnt; i++ ) {
    fd_shred34_t * p34_base = shred34 + i*DCACHE_ENTRIES_PER_FEC_SET;
    for( ulong k=0UL; k<DCACHE_ENTRIES_PER_FEC_SET; k++ ) {
      fd_shred34_t * p34 = p34_base + k;

      p34->stride   = (ulong)p34->pkts[1].buffer - (ulong)p34->pkts[0].buffer;
      p34->offset   = (ulong)p34->pkts[0].buffer - (ulong)p34;
      p34->shred_sz = fd_ulong_if( k<2UL, 1203UL, 1228UL );
    }

    uchar ** data_shred   = fec_sets[ i ].data_shreds;
    uchar ** parity_shred = fec_sets[ i ].parity_shreds;
    for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) data_shred  [ j ] = p34_base[       j/34UL ].pkts[ j%34UL ].buffer;
    for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) parity_shred[ j ] = p34_base[ 2UL + j/34UL ].pkts[ j%34UL ].buffer;
  }

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  int has_ipecho_in = fd_topo_find_tile_in_link( topo, tile, "ipecho_out", 0UL )!=ULONG_MAX;
  ushort expected_shred_version = tile->shred.expected_shred_version;
  if( FD_UNLIKELY( !has_ipecho_in && !expected_shred_version ) ) {
    ulong busy_obj_id = fd_pod_query_ulong( topo->props, "poh_shred", ULONG_MAX );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ulong * gossip_shred_version = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    FD_LOG_INFO(( "Waiting for shred version to be determined via gossip." ));
    ulong _expected_shred_version = ULONG_MAX;
    do {
      _expected_shred_version = FD_VOLATILE_CONST( *gossip_shred_version );
    } while( _expected_shred_version==ULONG_MAX );

    if( FD_UNLIKELY( _expected_shred_version>USHORT_MAX ) ) FD_LOG_ERR(( "invalid shred version %lu", _expected_shred_version ));
    FD_LOG_INFO(( "Using shred version %hu", (ushort)_expected_shred_version ));
    expected_shred_version = (ushort)_expected_shred_version;
  }

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  /* populate ctx */
  ulong sign_in_idx = fd_topo_find_tile_in_link( topo, tile, "sign_shred", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];
  NONNULL( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache,
                                                            sign_out->mtu ) ) );

  ulong shred_limit = fd_ulong_if( tile->shred.larger_shred_limits_per_block, 32UL*32UL*1024UL, 32UL*1024UL );
  fd_fec_set_t * resolver_sets = fec_sets + (shred_store_mcache_depth+1UL)/2UL + 1UL;
  ctx->shredder = NONNULL( fd_shredder_join     ( fd_shredder_new     ( _shredder, fd_shred_signer, ctx->keyguard_client ) ) );
  ctx->resolver = NONNULL( fd_fec_resolver_join ( fd_fec_resolver_new ( _resolver,
                                                                        fd_shred_signer, ctx->keyguard_client,
                                                                        tile->shred.fec_resolver_depth, 1UL,
                                                                        (shred_store_mcache_depth+3UL)/2UL,
                                                                        128UL * tile->shred.fec_resolver_depth, resolver_sets,
                                                                        shred_limit ) ) );

  if( FD_LIKELY( !!expected_shred_version ) ) {
    fd_shredder_set_shred_version    ( ctx->shredder, expected_shred_version );
    fd_fec_resolver_set_shred_version( ctx->resolver, expected_shred_version );
  }

  ctx->shred34  = shred34;
  ctx->fec_sets = fec_sets;

  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci, ctx->identity_key ) );

  ctx->net_id   = (ushort)0;

  fd_ip4_udp_hdr_init( ctx->data_shred_net_hdr,   FD_SHRED_MIN_SZ, 0, tile->shred.shred_listen_port );
  fd_ip4_udp_hdr_init( ctx->parity_shred_net_hdr, FD_SHRED_MAX_SZ, 0, tile->shred.shred_listen_port );

  ctx->adtl_dests_retransmit_cnt = tile->shred.adtl_dests_retransmit_cnt;
  for( ulong i=0UL; i<ctx->adtl_dests_retransmit_cnt; i++) {
    ctx->adtl_dests_retransmit[ i ].ip4 = tile->shred.adtl_dests_retransmit[ i ].ip;
    ctx->adtl_dests_retransmit[ i ].port = tile->shred.adtl_dests_retransmit[ i ].port;
  }
  ctx->adtl_dests_leader_cnt = tile->shred.adtl_dests_leader_cnt;
  for( ulong i=0UL; i<ctx->adtl_dests_leader_cnt; i++) {
    ctx->adtl_dests_leader[i].ip4  = tile->shred.adtl_dests_leader[i].ip;
    ctx->adtl_dests_leader[i].port = tile->shred.adtl_dests_leader[i].port;
  }

  uchar has_contact_info_in = 0;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY(      !strcmp( link->name, "net_shred"    ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in[ i ].net_rx, link->dcache );
      continue; /* only net_rx needs to be set in this case. */
    }
    else if( FD_LIKELY( !strcmp( link->name, "poh_shred"    ) ) )   ctx->in_kind[ i ] = IN_KIND_POH;
    else if( FD_LIKELY( !strcmp( link->name, "stake_out"    ) ) )   ctx->in_kind[ i ] = IN_KIND_STAKE;
    else if( FD_LIKELY( !strcmp( link->name, "replay_stake" ) ) )   ctx->in_kind[ i ] = IN_KIND_STAKE;
    else if( FD_LIKELY( !strcmp( link->name, "sign_shred"   ) ) )   ctx->in_kind[ i ] = IN_KIND_SIGN;
    else if( FD_LIKELY( !strcmp( link->name, "repair_shred" ) ) )   ctx->in_kind[ i ] = IN_KIND_REPAIR;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"   ) ) )   ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "crds_shred"   ) ) ) { ctx->in_kind[ i ] = IN_KIND_CONTACT;
      if( FD_UNLIKELY( has_contact_info_in ) ) FD_LOG_ERR(( "shred tile has multiple contact info in link types, can only be either gossip_out or crds_shred" ));
      has_contact_info_in = 1;
    }
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out"   ) ) ) { ctx->in_kind[ i ] = IN_KIND_GOSSIP;
      if( FD_UNLIKELY( has_contact_info_in ) ) FD_LOG_ERR(( "shred tile has multiple contact info in link types, can only be either gossip_out or crds_shred" ));
      has_contact_info_in = 1;
    }

    else FD_LOG_ERR(( "shred tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( !!link->mtu ) ) {
      ctx->in[ i ].mem    = link_wksp->wksp;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    }
  }

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ NET_OUT_IDX ] ];

  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  ctx->store = NULL;
  ulong store_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "store" );
  if( FD_LIKELY( store_obj_id!=ULONG_MAX ) ) { /* firedancer-only */
    ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
    FD_TEST( ctx->store->magic == FD_STORE_MAGIC );
  }

  if( FD_LIKELY( ctx->repair_out_idx!=ULONG_MAX ) ) { /* firedancer-only */
    fd_topo_link_t * repair_out = &topo->links[ tile->out_link_id[ ctx->repair_out_idx ] ];
    ctx->repair_out_mem         = topo->workspaces[ topo->objs[ repair_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->repair_out_chunk0      = fd_dcache_compact_chunk0( ctx->repair_out_mem, repair_out->dcache );
    ctx->repair_out_wmark       = fd_dcache_compact_wmark ( ctx->repair_out_mem, repair_out->dcache, repair_out->mtu );
    ctx->repair_out_chunk       = ctx->repair_out_chunk0;
    FD_TEST( fd_dcache_compact_is_safe( ctx->repair_out_mem, repair_out->dcache, repair_out->mtu, repair_out->depth ) );
  }

  if( FD_LIKELY( ctx->store_out_idx!=ULONG_MAX ) ) { /* frankendancer-only */
    fd_topo_link_t * store_out = &topo->links[ tile->out_link_id[ ctx->store_out_idx ] ];
    ctx->store_out_mem         = topo->workspaces[ topo->objs[ store_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->store_out_chunk0      = fd_dcache_compact_chunk0( ctx->store_out_mem, store_out->dcache );
    ctx->store_out_wmark       = fd_dcache_compact_wmark ( ctx->store_out_mem, store_out->dcache, store_out->mtu );
    ctx->store_out_chunk       = ctx->store_out_chunk0;
    FD_TEST( fd_dcache_compact_is_safe( ctx->store_out_mem, store_out->dcache, store_out->mtu, store_out->depth ) );
  }

  ctx->poh_in_expect_seq = 0UL;

  ctx->shredder_fec_set_idx = 0UL;
  ctx->shredder_max_fec_set_idx = (shred_store_mcache_depth+1UL)/2UL + 1UL;

  ctx->chained_merkle_root = NULL;
  memset( ctx->out_merkle_roots, 0, sizeof(ctx->out_merkle_roots) );

  for( ulong i=0UL; i<FD_SHRED_BATCH_FEC_SETS_MAX; i++ ) { ctx->send_fec_set_idx[ i ] = ULONG_MAX; }
  ctx->send_fec_set_cnt = 0UL;

  ctx->shred_buffer_sz  = 0UL;
  memset( ctx->shred_buffer, 0xFF, FD_NET_MTU );

  fd_histf_join( fd_histf_new( ctx->metrics->contact_info_cnt,     FD_MHIST_MIN(         SHRED, CLUSTER_CONTACT_INFO_CNT   ),
                                                                   FD_MHIST_MAX(         SHRED, CLUSTER_CONTACT_INFO_CNT   ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->batch_sz,             FD_MHIST_MIN(         SHRED, BATCH_SZ                   ),
                                                                   FD_MHIST_MAX(         SHRED, BATCH_SZ                   ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->batch_microblock_cnt, FD_MHIST_MIN(         SHRED, BATCH_MICROBLOCK_CNT       ),
                                                                   FD_MHIST_MAX(         SHRED, BATCH_MICROBLOCK_CNT       ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->shredding_timing,     FD_MHIST_SECONDS_MIN( SHRED, SHREDDING_DURATION_SECONDS ),
                                                                   FD_MHIST_SECONDS_MAX( SHRED, SHREDDING_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->add_shred_timing,     FD_MHIST_SECONDS_MIN( SHRED, ADD_SHRED_DURATION_SECONDS ),
                                                                   FD_MHIST_SECONDS_MAX( SHRED, ADD_SHRED_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->store_insert_wait,    FD_MHIST_SECONDS_MIN( SHRED, STORE_INSERT_WAIT ),
                                                                   FD_MHIST_SECONDS_MAX( SHRED, STORE_INSERT_WAIT ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->store_insert_work,    FD_MHIST_SECONDS_MIN( SHRED, STORE_INSERT_WORK ),
                                                                   FD_MHIST_SECONDS_MAX( SHRED, STORE_INSERT_WORK ) ) );
  memset( ctx->metrics->shred_processing_result, '\0', sizeof(ctx->metrics->shred_processing_result) );
  ctx->metrics->invalid_block_id_cnt         = 0UL;
  ctx->metrics->shred_rejected_unchained_cnt = 0UL;
  ctx->metrics->repair_rcv_cnt               = 0UL;
  ctx->metrics->turbine_rcv_cnt              = 0UL;

  ctx->pending_batch.microblock_cnt = 0UL;
  ctx->pending_batch.txn_cnt        = 0UL;
  ctx->pending_batch.pos            = 0UL;
  ctx->pending_batch.slot           = 0UL;
  memset( ctx->pending_batch.payload, 0, sizeof(ctx->pending_batch.payload) );

  for( ulong i=0UL; i<FD_SHRED_FEATURES_ACTIVATION_SLOT_CNT; i++ )
    ctx->features_activation->slots[i] = FD_SHRED_FEATURES_ACTIVATION_SLOT_DISABLED;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  memset( ctx->block_ids, 0, sizeof(ctx->block_ids) );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_shred_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_shred_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

/* Excluding net_out (where the link is unreliable), STEM_BURST needs
   to guarantee enough credits for the worst case. There are 4 cases
   to consider: (IN_KIND_NET/IN_KIND_POH) x (Frankendancer/Firedancer)
   In the IN_KIND_NET case:  (Frankendancer) that can be 4 frags to
   store;  (Firedancer) that is one frag for the shred to repair, and
   then another frag to repair for the FEC set.
   In the IN_KIND_POH case:  (Frankendancer) there might be
   FD_SHRED_BATCH_FEC_SETS_MAX FEC sets, but we know they are 32:32,
   which means only two shred34s per FEC set;  (Firedancer) that is
   FD_SHRED_BATCH_FEC_SETS_MAX frags to repair (one per FEC set).
   Therefore, the worst case is IN_KIND_POH for Frankendancer. */
#define STEM_BURST (FD_SHRED_BATCH_FEC_SETS_MAX*2UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_shred_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_shred_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_shred = {
  .name                     = "shred",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
