#define _GNU_SOURCE
#include "../tiles.h"

#if FD_HAS_X86
#include <x86intrin.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/futex.h>
#include "generated/fd_shred_tile_seccomp.h"
#include "../../util/pod/fd_pod_format.h"
#include "fd_shredder.h"
#include "fd_shred_batch.h"
#include "fd_shred_dest.h"
#include "fd_fec_resolver.h"
#include "fd_stake_ci.h"
#include "fd_rnonce_ss.h"
#include "fd_shred_tile.h"
#include "../store/fd_store.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyguard.h"
#include "../keyguard/fd_keyswitch.h"
#include "../fd_disco.h"
#include "../net/fd_net_tile.h"
#include "fd_shred_dest_resolver.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../util/net/fd_net_headers.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/runtime/fd_slot_params.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../repair/fd_repair_serde.h"
#if FD_HAS_AVX
#include "../../util/simd/fd_nt_memcpy.h"
#else
#define fd_memcpy_tn         fd_memcpy
#define fd_memcpy_nt_nofence fd_memcpy
#define _mm_sfence()         do {} while( 0 )
#endif

/* The shred tile handles shreds from two data sources: shreds generated
   from microblocks from the leader pipeline, and shreds retransmitted
   from the network.

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

   The FEC arena uses an exposure window e.  Data is copied out before
   after_frag returns, so e is a small bound.

   Leader pipeline: Every entry creates up to FD_SHRED_BATCH_FEC_SETS_MAX
   FEC sets, and a set stays in the ring from its creation until the
   sign tile's response completes it, so up to FD_SHRED_SIGN_PEND_MAX
   are created but not yet exposed.  The leader section therefore needs
   e+FD_SHRED_SIGN_PEND_MAX entries.

   From the network: The FEC resolver doesn't use a cyclic order, but it
   does promise that once it returns an FEC set, it will return at least
   complete_depth FEC sets before returning it again.  This means we
   want at most complete_depth-1 FEC sets exposed, so
   complete_depth=e+1 FEC sets.  The FEC resolver has the
   ability to keep individual shreds for partial_depth calls, but
   because in this version of the shred tile, we send each shred to all
   its destinations as soon as we get it, we don't need that
   functionality, so we set partial_depth=1.

   Adding these up and plugging in the current value of
   SIGN_PEND_MAX, we get 2*e+10+fec_resolver_depth FEC sets.

   A note on parallelization.  From the network, shreds are distributed
   to tiles based on a validator-specific seeded hash of (slot, FEC set
   index) so all the shreds for a given FEC set (and any equivocating
   FEC set) are processed by the same tile.  From the leader pipeline,
   the original implementation used to parallelize by batch of
   microblocks (so within a block, batches were distributed to different
   tiles).  To support chained merkle shreds, the current implementation
   processes all the batches on tile 0 -- this should be a temporary
   state while Solana moves to a newer shred format that support better
   parallelization. */

#define IN_KIND_EPOCH   ( 1UL)
#define IN_KIND_POH     ( 3UL)
#define IN_KIND_NET     ( 4UL)
#define IN_KIND_SIGN    ( 5UL)
#define IN_KIND_REPAIR  ( 6UL)
#define IN_KIND_IPECHO  ( 7UL)
#define IN_KIND_GOSSIP  ( 8UL)
#define IN_KIND_ROOTEDR (11UL) /* Alpenglow */

#define NET_OUT_IDX     1
#define SIGN_OUT_IDX    2
#define IN_LINK_MAX     32UL

FD_STATIC_ASSERT( sizeof(fd_entry_batch_meta_t)==56UL, poh_shred_mtu );

#define FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT 3
FD_STATIC_ASSERT( FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT+FD_FEC_RESOLVER_ADD_SHRED_RETVAL_CNT==FD_METRICS_ENUM_SHRED_PROCESS_RESULT_CNT, metrics );
FD_STATIC_ASSERT( FD_FEC_RESOLVER_SHRED_OKAY+FD_FEC_RESOLVER_ADD_SHRED_RETVAL_OFF+FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT==FD_METRICS_ENUM_SHRED_PROCESS_RESULT_V_ACCEPTED_IDX, metrics );

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

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  };
  fd_net_rx_bounds_t net_rx;
} fd_shred_in_ctx_t;

/* A leader FEC set whose sign request went out on shred_sign and has
   not been answered. */

typedef struct {
  ulong            fec_set_idx;
  ulong            tsorig;
  fd_bmtree_node_t merkle_root;
} fd_shred_sign_pend_t;

typedef struct {
  fd_shredder_t      * shredder;
  fd_fec_resolver_t  * resolver;
  ulong                shred_limit;
  fd_pubkey_t          identity_key[1]; /* Just the public key */

  ulong                round_robin_id;
  ulong                round_robin_cnt;
  /* Number of batches shredded from PoH during the current slot.
     This should be the same for all the shred tiles. */
  ulong                batch_cnt;
  /* Slot of the most recent microblock we've seen from PoH,
     or 0 if we haven't seen one yet */
  ulong                slot;

  fd_rnonce_ss_t       repair_nonce_ss[1];

  fd_keyswitch_t *     keyswitch;

  fd_fec_set_t       * fec_sets;

  fd_stake_ci_t      * stake_ci;
  /* These are used in between during_frag and after_frag */
  ulong                      new_root;
  ulong                      slot_max;
  ulong                      future_slot;

  ulong poh_in_expect_seq;

  ushort net_id;

  int skip_frag;
  int parse_failed; /* during_frag's parse failed and this tile owns the frag, counted in after_frag once not overrun */
  int fwd_meta;     /* during_frag copied a repair ping or metadata response this tile owns, forwarded in after_frag */

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

  /* Leader FEC sets awaiting their signature, oldest first.  The sign
     tile answers in order on sign_shred, so each response frag belongs
     to the head, which it finishes. */
  fd_shred_sign_pend_t sign_pend[ FD_SHRED_SIGN_PEND_MAX ];

  ulong sign_pend_head;
  ulong sign_pend_cnt;
  ulong sign_seq;
  uchar signature[ 64 ] __attribute__((aligned(32UL)));

  fd_wksp_t * sign_out_mem;
  ulong       sign_out_chunk0;
  ulong       sign_out_wmark;
  ulong       sign_out_chunk;

  /* Includes Ethernet, IP, UDP headers */
  ulong shred_buffer_sz;
  uchar shred_buffer[ FD_NET_MTU ];

  /* These seeds get generated in privileged_init but used in
     unprivileged_init, so we store them here in between. */
  ulong resolver_seed;
  ulong shred_dest_seed;

  fd_shred_in_ctx_t in[ IN_LINK_MAX ];
  int               in_kind[ IN_LINK_MAX ];

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  /* This is the output link for shreds that is currently consumed by
     the repair and replay tile. */
  ulong       shred_out_idx;
  fd_wksp_t * shred_out_mem;
  ulong       shred_out_chunk0;
  ulong       shred_out_wmark;
  ulong       shred_out_chunk;

  /* Repair pings and metadata responses arrive on the repair client
     port with repair shreds, and are forwarded to the repair tile. */
  ulong       repair_out_idx;
  fd_wksp_t * repair_out_mem;
  ulong       repair_out_chunk0;
  ulong       repair_out_wmark;
  ulong       repair_out_chunk;

  /* Highest slot relayed on turbine, published for rpc
     (getMaxRetransmitSlot).  NULL if rpc is disabled. */
  ulong *     rtx_fseq;
  ulong       rtx_slot;

  fd_store_t    * store;
  int             disk_fd;

  fd_gossip_update_message_t gossip_upd_buf[1];

  struct {
    fd_histf_t batch_sz[ 1 ];
    fd_histf_t batch_microblock_cnt[ 1 ];
    fd_histf_t shredding_timing[ 1 ];
    fd_histf_t add_shred_timing[ 1 ];
    fd_histf_t fec_fallback_write_timing[ 1 ];
    fd_histf_t store_insert_park_timing[ 1 ];
    ulong shred_processing_result[ FD_FEC_RESOLVER_ADD_SHRED_RETVAL_CNT+FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT ];
    ulong invalid_block_id_cnt;
    ulong shred_rejected_unchained_cnt;
    ulong repair_rcv_cnt;
    ulong repair_rcv_bytes;
    ulong turbine_rcv_cnt;
    ulong turbine_rcv_bytes;
    ulong bad_nonce;
    ulong fec_fallback_write_cnt;
    ulong fec_fallback_write_bytes;
    ulong store_insert_park_cnt;
  } metrics[ 1 ];

  struct {
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

  fd_epoch_schedule_t            epoch_schedule[1];
  fd_shred_features_activation_t features_activation[1];

  /* max_shred_idx is the exclusive upper bound for shred
     indices. We need to reject any shred with an
     index >= current_max_shred_idx, but we also want to reject anything
     that is part of an FEC set whose highest shred index would reach
     the bound.

     Because this bound can change with feature gates, for example the
     reduce_slot_time feature gates, we store the bound for the
     previous, current, and next regimes, along with the slots at which
     the current and next bounds take effect. This lets us apply, to
     each shred, the limit effective at that shreds slot.

     For a given shred slot, the max_shred_idx for that shred is:
      next_max_shred_idx_start_slot    <= slot                                    -> next_max_shred_idx
      current_max_shred_idx_start_slot <= slot < next_max_shred_idx_start_slot    -> current_max_shred_idx
                                          slot < current_max_shred_idx_start_slot -> prev_max_shred_idx
  */
  ulong                          prev_max_shred_idx;
  ulong                          current_max_shred_idx;
  ulong                          next_max_shred_idx;
  ulong                          current_max_shred_idx_start_slot;
  ulong                          next_max_shred_idx_start_slot;
  ulong                          bench_max_shred_idx; /* [development.bench.max_shreds_per_block], floors the chain's limits */
  /* too large to be left in the stack */
  fd_shred_dest_idx_t scratchpad_dests[ FD_SHRED_DEST_MAX_FANOUT*(FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX) ];

  uchar * chained_merkle_root;
  fd_bmtree_node_t out_merkle_roots[ FD_SHRED_BATCH_FEC_SETS_MAX ];
  uchar block_ids[ BLOCK_IDS_TABLE_CNT ][ FD_SHRED_MERKLE_ROOT_SZ ];

  fd_sha512_t sha512[1];
  uchar       bmtree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( FD_SHRED_MERKLE_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
} fd_shred_ctx_t;

/* shred features are generally considered active at the epoch *following*
   the epoch in which the feature gate is activated.

   As an optimization, when the activation slot is received, it is converted
   into the first slot of the subsequent epoch.  This allows for a more
   efficient check (shred_slot >= feature_slot) and avoids the overhead of
   repeatedly converting slots into epochs for comparison.

   In Agave, this is done with check_feature_activation():
   https://github.com/anza-xyz/agave/blob/v3.1.4/turbine/src/cluster_nodes.rs#L771
   https://github.com/anza-xyz/agave/blob/v3.1.4/core/src/shred_fetch_stage.rs#L456 */
static inline ulong
fd_shred_get_feature_activation_slot0( ulong feature_slot, fd_shred_ctx_t * ctx ) {
  /* if the feature does not have an activation slot yet, return ULONG_MAX */
  if( FD_UNLIKELY( feature_slot==ULONG_MAX ) ) {
    return ULONG_MAX;
  }
  /* if we don't have an epoch schedule yet, return ULONG_MAX */
  if( FD_UNLIKELY( ctx->epoch_schedule->slots_per_epoch==0 ) ) {
    return ULONG_MAX;
  }
  /* compute the activation epoch, add one, return the first slot. */
  ulong feature_epoch = 1 + fd_slot_to_epoch( ctx->epoch_schedule, feature_slot, NULL );
  return fd_epoch_slot0( ctx->epoch_schedule, feature_epoch );
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {

  ulong fec_resolver_footprint = fd_fec_resolver_footprint( tile->shred.fec_resolver_depth, 1UL, tile->shred.fec_exposure+1UL,
                                                            128UL * tile->shred.fec_resolver_depth );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_shred_ctx_t),          sizeof(fd_shred_ctx_t)                  );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()                 );
  l = FD_LAYOUT_APPEND( l, fd_fec_resolver_align(),          fec_resolver_footprint                  );
  l = FD_LAYOUT_APPEND( l, fd_shredder_align(),              fd_shredder_footprint()                 );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_shred_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ulong seq_must_complete = ctx->keyswitch->param;

    if( FD_UNLIKELY( fd_seq_lt( ctx->poh_in_expect_seq, seq_must_complete ) || ctx->sign_pend_cnt ) ) {
      /* See fd_keyswitch.h, we need to flush any in-flight shreds from
         the leader pipeline before switching key.  Sets still awaiting
         their signature were requested under the old key. */
      FD_LOG_WARNING(( "Flushing in-flight unpublished shreds, must reach seq %lu, currently at %lu with %lu awaiting signature ...", seq_must_complete, ctx->poh_in_expect_seq, ctx->sign_pend_cnt ));
      return;
    }

    memcpy( ctx->identity_key->uc, ctx->keyswitch->bytes, 32UL );
    fd_stake_ci_set_identity( ctx->stake_ci, ctx->identity_key );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_shred_ctx_t * ctx ) {
  FD_MHIST_COPY( SHRED, REPAIR_LEAD_DELAY_NANOS,             fd_fec_resolver_completion_lag_hist( ctx->resolver ) );
  FD_MHIST_COPY( SHRED, BATCH_SIZE_BYTES,                    ctx->metrics->batch_sz                               );
  FD_MHIST_COPY( SHRED, MICROBLOCK_PER_BATCH,                ctx->metrics->batch_microblock_cnt                   );
  FD_MHIST_COPY( SHRED, BATCH_SHRED_DURATION_NANOS,          ctx->metrics->shredding_timing                       );
  FD_MHIST_COPY( SHRED, ADD_SHRED_DURATION_NANOS,            ctx->metrics->add_shred_timing                       );
  FD_MHIST_COPY( SHRED, STORE_FEC_SYNC_SPILL_DURATION_NANOS, ctx->metrics->fec_fallback_write_timing              );
  FD_MHIST_COPY( SHRED, STORE_FEC_INSERT_PARK_DURATION_NANOS, ctx->metrics->store_insert_park_timing              );
  FD_MCNT_SET  ( SHRED, REPAIR_RX,                           ctx->metrics->repair_rcv_cnt                         );
  FD_MCNT_SET  ( SHRED, REPAIR_RX_BYTES,                     ctx->metrics->repair_rcv_bytes                       );
  FD_MCNT_SET  ( SHRED, TURBINE_RX,                          ctx->metrics->turbine_rcv_cnt                        );
  FD_MCNT_SET  ( SHRED, TURBINE_RX_BYTES,                    ctx->metrics->turbine_rcv_bytes                      );
  FD_MCNT_SET  ( SHRED, REPAIR_NONCE_FAILED,                 ctx->metrics->bad_nonce                              );
  FD_MCNT_SET  ( SHRED, STORE_FEC_SYNC_SPILLED,              ctx->metrics->fec_fallback_write_cnt                 );
  FD_MCNT_SET  ( SHRED, STORE_FEC_SYNC_SPILLED_BYTES,        ctx->metrics->fec_fallback_write_bytes               );
  FD_MCNT_SET  ( SHRED, STORE_FEC_INSERT_PARKED,             ctx->metrics->store_insert_park_cnt                  );

  FD_MCNT_SET  ( SHRED, PARENT_BLOCK_ID_ZEROED, ctx->metrics->invalid_block_id_cnt         );
  FD_MCNT_SET  ( SHRED, UNCHAINED_REJECTED,     ctx->metrics->shred_rejected_unchained_cnt );

  FD_MCNT_ENUM_COPY( SHRED, PROCESSED,      ctx->metrics->shred_processing_result      );
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
    if( FD_UNLIKELY( (fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK) &
                     (ctx->sign_pend_cnt+FD_SHRED_BATCH_FEC_SETS_MAX>FD_SHRED_SIGN_PEND_MAX) ) ) return -1;
    ctx->poh_in_expect_seq = seq+1UL;
    return fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_MICROBLOCK;
  }
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    return (int)(fd_disco_netmux_sig_proto( sig )!=DST_PROTO_SHRED) & (int)(fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR);
  }
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ){
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
           sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_ROOTEDR ) ) {
    return sig!=REPLAY_SIG_ROOT_ADVANCED; /* only care about root_advanced messages */
  }
  return 0;
}

static void
during_frag( fd_shred_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig,
             ulong            chunk,
             ulong            sz,
             ulong            ctl ) {

  ctx->skip_frag    = 0;
  ctx->parse_failed = 0;
  ctx->fwd_meta     = 0;

  ctx->tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPAIR ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_memcpy( ctx->shred_buffer, dcache_entry, sz );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>sizeof(fd_gossip_update_message_t) ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    uchar const * gossip_upd_msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_memcpy( ctx->gossip_upd_buf, gossip_upd_msg, sz );
    return;
  }

  /* Alpenglow */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_ROOTEDR ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz<sizeof(fd_replay_root_advanced_t) ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    fd_replay_root_advanced_t const * rooted_msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    ctx->new_root = rooted_msg->slot;
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EPOCH ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar const *               dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_epoch_info_msg_t const * epoch_msg    = fd_type_pun_const( dcache_entry );

    FD_TEST( epoch_msg->staked_vote_cnt<=MAX_STAKE_WEIGHTS );
    FD_TEST( epoch_msg->staked_id_cnt<=MAX_STAKE_WEIGHTS );

    fd_stake_ci_epoch_msg_init( ctx->stake_ci, epoch_msg );

    *ctx->epoch_schedule = epoch_msg->epoch_schedule;

    fd_slot_params_t slot_params = fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS,
                                                          &epoch_msg->features,
                                                          &epoch_msg->epoch_schedule,
                                                          epoch_msg->start_slot );

    ctx->current_max_shred_idx            = fd_ulong_max( slot_params.max_shred_idx, ctx->bench_max_shred_idx );
    ctx->current_max_shred_idx_start_slot = fd_slot_params_effective_slot( &slot_params,
                                                                           &epoch_msg->features,
                                                                           &epoch_msg->epoch_schedule );
    ctx->next_max_shred_idx_start_slot    = fd_slot_params_next_effective_slot( &slot_params,
                                                                                &epoch_msg->features,
                                                                                &epoch_msg->epoch_schedule );
    ctx->prev_max_shred_idx               = fd_ulong_max( fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS,
                                                                                 &epoch_msg->features,
                                                                                 &epoch_msg->epoch_schedule,
                                                                                 fd_ulong_sat_sub( ctx->current_max_shred_idx_start_slot, 1UL ) ).max_shred_idx, ctx->bench_max_shred_idx );
    ctx->next_max_shred_idx               = fd_ulong_max( fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS,
                                                                                 &epoch_msg->features,
                                                                                 &epoch_msg->epoch_schedule,
                                                                                 ctx->next_max_shred_idx_start_slot ).max_shred_idx, ctx->bench_max_shred_idx );
    ctx->features_activation->enforce_fixed_fec_set = fd_shred_get_feature_activation_slot0(
      epoch_msg->features.enforce_fixed_fec_set, ctx );

    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SIGN ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=64UL ) ) FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    if( FD_UNLIKELY( seq!=ctx->sign_seq ) ) FD_LOG_CRIT(( "sign response seq %lu, expected %lu", seq, ctx->sign_seq ));
    fd_memcpy( ctx->signature, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), 64UL );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_POH ) ) {
    ctx->send_fec_set_cnt = 0UL;

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
      ctx->batch_cnt                    = 0UL;

      FD_MCNT_INC( SHRED, BATCH_ABANDONED, 1UL );
    }

    ctx->pending_batch.slot = target_slot;
    /* We want to send out some shreds immediately when we start a new
       slot to help with leader targeting. */
    int new_slot = 0;
    if( FD_UNLIKELY( target_slot!=ctx->slot )) {
      /* Reset batch count if we are in a new slot */
      ctx->batch_cnt = 0UL;
      ctx->slot      = target_slot;
      new_slot       = 1;

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
    /* All fec sets in the last batch of a block need to be resigned.
       This needs to match Agave's behavior - as a reference, see:
       https://github.com/anza-xyz/agave/blob/v2.3/ledger/src/shred/merkle.rs#L1040 */
    if( FD_UNLIKELY( entry_meta->block_complete==1 ) ) {
      pending_batch_wmark = FD_SHRED_BATCH_WMARK_RESIGNED;
    }

    /* If this microblock completes the block, the batch is then
       finalized here.  Otherwise, we check whether the new entry
       would exceed the pending_batch_wmark.  If true, then the
       batch is closed now, shredded, and a new batch is started
       with the incoming microblock.  If false, no shredding takes
       place, and the microblock is added to the current batch.
       Pack limits entry bytes so this batching cannot exceed
       max_shred_idx. */
    int is_marker                = entry_meta->block_complete==-1;
    int writing_marker           = 0;
    int forced_end_batch         = entry_meta->block_complete | new_slot;
    int batch_would_exceed_wmark = ( ctx->pending_batch.pos + entry_sz ) > pending_batch_wmark;
    int include_in_current_batch = !is_marker && ( forced_end_batch | ( !batch_would_exceed_wmark ) );
    int process_current_batch    = is_marker ? !!ctx->pending_batch.pos : ( forced_end_batch | batch_would_exceed_wmark );
    int init_new_batch           = !include_in_current_batch;

    if( FD_LIKELY( include_in_current_batch ) ) {
      if( FD_UNLIKELY( SHOULD_PROCESS_THESE_SHREDS ) ) {
        /* Ugh, yet another memcpy */
        fd_memcpy_tn( ctx->pending_batch.payload + ctx->pending_batch.pos, entry, entry_sz );
      }
      ctx->pending_batch.pos            += entry_sz;
      ctx->pending_batch.microblock_cnt += 1UL;
    }

alpenglow_marker:
    if( FD_LIKELY( process_current_batch )) {
      ulong batch_sz = sizeof(ulong) + ctx->pending_batch.pos;

      if( FD_UNLIKELY( SHOULD_PROCESS_THESE_SHREDS ) ) {
        /* If it's our turn, shred this batch. FD_UNLIKELY because shred
           tile cnt generally >= 2 */

        long shredding_timing = -fd_tickcount();

        if( FD_UNLIKELY( !writing_marker ) ) ctx->send_fec_set_cnt = 0UL; /* verbose */

        fd_shredder_init_batch( ctx->shredder, ctx->pending_batch.raw, batch_sz, target_slot, entry_meta );

        ulong fec_set_cnt = fd_shredder_count_fec_sets( batch_sz, entry_meta->block_complete==1 );
        ulong pend_idx    = ctx->send_fec_set_cnt;
        for( ulong j=0UL; j<fec_set_cnt; j++ ) {

          fd_fec_set_t * out = ctx->fec_sets + ctx->shredder_fec_set_idx;

          FD_TEST( fd_shredder_next_fec_set( ctx->shredder, out, chained_merkle_root ) );
          FD_TEST( pend_idx<FD_SHRED_BATCH_FEC_SETS_MAX );
          memcpy( ctx->out_merkle_roots[pend_idx].hash, chained_merkle_root, 32UL );

          out->data_shred_rcvd     = 0U;
          out->parity_shred_rcvd   = 0U;
          out->turbine_shred_rcvd  = 0UL;
          out->repair_shred_rcvd   = 0UL;

          FD_TEST( ctx->send_fec_set_cnt<FD_SHRED_BATCH_FEC_SETS_MAX );
          ctx->send_fec_set_idx[ ctx->send_fec_set_cnt ] = ctx->shredder_fec_set_idx;
          ctx->send_fec_set_cnt += 1UL;
          ctx->shredder_fec_set_idx = (ctx->shredder_fec_set_idx+1UL)%ctx->shredder_max_fec_set_idx;

          pend_idx++;
        }

        fd_shredder_fini_batch( ctx->shredder );
        shredding_timing += fd_tickcount();

        /* Update metrics */
        fd_histf_sample( ctx->metrics->batch_sz,             batch_sz                          );
        fd_histf_sample( ctx->metrics->batch_microblock_cnt, ctx->pending_batch.microblock_cnt );
        fd_histf_sample( ctx->metrics->shredding_timing,     (ulong)shredding_timing           );
      } else {
        if( FD_UNLIKELY( !writing_marker ) ) ctx->send_fec_set_cnt = 0UL; /* verbose */

        fd_shredder_skip_batch( ctx->shredder, batch_sz, target_slot, entry_meta->block_complete==1 );
      }

      ctx->pending_batch.slot           = 0UL;
      ctx->pending_batch.pos            = 0UL;
      ctx->pending_batch.microblock_cnt = 0UL;
      ctx->batch_cnt++;
    }

    if( FD_UNLIKELY( init_new_batch && !writing_marker ) ) {
      /* TODO: this assumes that SHOULD_PROCESS_THESE_SHREDS is
         constant across batches.  Otherwise, the condition may
         need to be removed (or adjusted). */
      if( FD_UNLIKELY( SHOULD_PROCESS_THESE_SHREDS ) ) {
        /* Ugh, yet another memcpy */
        fd_memcpy_tn( is_marker ? ctx->pending_batch.raw : ctx->pending_batch.payload + 0UL /* verbose */, entry, entry_sz );
      }
      ctx->pending_batch.slot           = target_slot;
      ctx->pending_batch.pos            = fd_ulong_if( is_marker, entry_sz-sizeof(ulong), entry_sz );
      ctx->pending_batch.microblock_cnt = fd_ulong_if( is_marker, 0UL, 1UL                 );
    }

    /* The entry opened a batch of its own, so close it now. */
    if( FD_UNLIKELY( is_marker && !writing_marker ) ) {
      process_current_batch = 1;
      writing_marker        = 1;
      goto alpenglow_marker;
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
    fd_udp_hdr_t const * udp_hdr = (fd_udp_hdr_t const *)( dcache_entry + hdr_sz - sizeof(fd_udp_hdr_t) );
    ulong dgram_sz = fd_ulong_min( fd_ulong_sat_sub( fd_ushort_bswap( udp_hdr->net_len ), sizeof(fd_udp_hdr_t) ), sz-hdr_sz );
    if( FD_UNLIKELY( fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR && dgram_sz<=FD_REPAIR_RES_DE_MAX ) ) {
      ctx->skip_frag = 1;
      ctx->fwd_meta  = ctx->repair_out_idx!=ULONG_MAX &&
                       fd_disco_netmux_sig_hash( sig )%ctx->round_robin_cnt==ctx->round_robin_id;
      if( ctx->fwd_meta ) { /* trim trailing bytes outside the datagram */
        fd_memcpy( ctx->shred_buffer, dcache_entry, hdr_sz+dgram_sz );
        ctx->shred_buffer_sz = hdr_sz+dgram_sz;
      }
      return;
    }
    /* ctx->shred_limit is the smallest per-slot max_shred_idx, so no
       later parse is stricter.  The result may be garbage if the frag
       is overrun meanwhile, which the stem detects before after_frag. */
    fd_shred_t const * shred = fd_shred_parse( dcache_entry+hdr_sz, sz-hdr_sz, ctx->shred_limit );
    if( FD_UNLIKELY( !shred ) ) {
      ulong owner = sz-hdr_sz>=sizeof(ulong) ? fd_ulong_load_8( dcache_entry+hdr_sz )%ctx->round_robin_cnt : 0UL; /* round-robin key, the signature */
      ctx->parse_failed = owner==ctx->round_robin_id;
      ctx->skip_frag    = 1;
      return;
    };

    /* all shreds in the same FEC set will have the same signature
       so we can round-robin shreds between the shred tiles based on
       just the signature without splitting individual FEC sets. */
    if( FD_LIKELY( fd_ulong_load_8( shred->signature )%ctx->round_robin_cnt!=ctx->round_robin_id ) ) {
      ctx->skip_frag = 1;
      return;
    }

    if( FD_UNLIKELY( fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR ) ) {
      ctx->metrics->repair_rcv_cnt++;
      ctx->metrics->repair_rcv_bytes += sz;
    } else {
      ctx->metrics->turbine_rcv_cnt++;
      ctx->metrics->turbine_rcv_bytes += sz;
    }

    /* Drop unchained merkle shreds */
    int is_unchained = !fd_shred_is_chained( fd_shred_type( shred->variant ) );
    if( FD_UNLIKELY( is_unchained ) ) {
      ctx->metrics->shred_rejected_unchained_cnt++;
      ctx->skip_frag = 1;
      return;
    };

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
  fd_memcpy_nt( packet+sizeof(fd_ip4_udp_hdrs_t), shred, shred_sz );
#else
  fd_memcpy   ( packet+sizeof(fd_ip4_udp_hdrs_t), shred, shred_sz );
#endif

  ulong pkt_sz = shred_sz + sizeof(fd_ip4_udp_hdrs_t);
  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig    = fd_disco_netmux_sig( dest->ip4, dest->port, dest->ip4, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  ulong const chunk = ctx->net_out_chunk;
  fd_stem_publish( stem, NET_OUT_IDX, sig, chunk, pkt_sz, 0UL, tsorig, tspub );
  ctx->net_out_chunk = fd_dcache_compact_next( chunk, pkt_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

/* Send the set's received (or, if received is 0, its produced and
   recovered) shreds to their turbine destinations: the leader's first
   hop, or our children. */

static void
fan_out( fd_shred_ctx_t *     ctx,
         fd_stem_context_t *  stem,
         fd_fec_set_t const * set,
         int                  is_leader,
         int                  received,
         ulong                tsorig ) {
  ulong fanout = 200UL; /* Default Agave's DATA_PLANE_FANOUT = 200UL */
  fd_shred_t const * shreds[ FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX ];
  ulong k=0UL;
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ )
    if( !!(set->data_shred_rcvd   & (1U<<i))==!!received ) shreds[ k++ ] = set->data_shreds  [ i ].s;
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ )
    if( !!(set->parity_shred_rcvd & (1U<<i))==!!received ) shreds[ k++ ] = set->parity_shreds[ i ].s;

  if( FD_UNLIKELY( !k ) ) return;
  fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, shreds[ 0 ]->slot );
  if( FD_UNLIKELY( !sdest ) ) return;

  fd_shred_dest_idx_t * _dests = ctx->scratchpad_dests;

  ulong out_stride;
  ulong max_dest_cnt[1];
  fd_shred_dest_idx_t * dests;
  if( FD_LIKELY( !is_leader ) ) {
    out_stride = k;
    dests = fd_shred_dest_compute_children( sdest, shreds, k, _dests, k, fanout, fanout, max_dest_cnt );
    if( FD_UNLIKELY( !dests ) ) return; /* our own slot, or unknown leader: nothing to retransmit */

    for( ulong i=0UL; i<k; i++ ) {
      for( ulong j=0UL; j<ctx->adtl_dests_retransmit_cnt; j++ ) send_shred( ctx, stem, shreds[ i ], ctx->adtl_dests_retransmit+j, tsorig );
    }
  } else {
    for( ulong i=0UL; i<k; i++ ) {
      for( ulong j=0UL; j<ctx->adtl_dests_leader_cnt; j++ ) send_shred( ctx, stem, shreds[ i ], ctx->adtl_dests_leader+j, tsorig );
    }
    out_stride = k;
    *max_dest_cnt = 2UL; /* Root of turbine tree and next leader */
    dests = fd_shred_dest_compute_first( sdest, shreds, k, _dests );

    /* Send leader shreds to the next leader.  At the epoch boundary,
       this will be a no-op so we don't need to get the other sdest. */
    fd_shred_dest_idx_t next_leader = fd_shred_dest_leader_for_slot( sdest, shreds[ 0 ]->slot + 4UL );
    for( ulong i=0UL; i<k; i++ ) _dests[ k+i ] = fd_uint_if( next_leader==_dests[ i ], FD_SHRED_DEST_NO_DEST, next_leader );
  }
  if( FD_UNLIKELY( !dests ) ) return;

  for( ulong i=0UL; i<k; i++ ) {
    for( ulong j=0UL; j<*max_dest_cnt; j++ ) send_shred( ctx, stem, shreds[ i ], fd_shred_dest_idx_to_dest( sdest, dests[ j*out_stride+i ]), tsorig );
  }
}

/* Finish a complete FEC set: copy it into the store, tell repair and
   replay, and fan it out to the network. */

static void
complete_fec_set( fd_shred_ctx_t *         ctx,
                  fd_stem_context_t *      stem,
                  ulong                    fec_set_idx,
                  fd_bmtree_node_t const * merkle_root,
                  int                      is_leader,
                  ulong                    tsorig ) {
  fd_fec_set_t * set = ctx->fec_sets + fec_set_idx;

  fd_shred_t const * last = set->data_shreds[ FD_FEC_SHRED_CNT - 1 ].s;

  /* Broadcast locally produced shreds before any disk work. */
  if( FD_UNLIKELY( is_leader ) ) fan_out( ctx, stem, set, is_leader, 0, tsorig );

  /* Compute merkle root and chained merkle root. */

  int replay_fwd = 1;
  int again      = 0;
  if( FD_LIKELY( ctx->store ) ) {
    fd_hash_t const * mr = fd_type_pun_const( merkle_root );

    /* The payload is filled before the FEC is linked.  All shreds of a
       FEC share the signature over its merkle root, so only this tile
       ever inserts it: a duplicate is a committed FEC, or one being torn
       down below the root. */

    fd_store_insert_stats_t stats[1];
    fd_store_insert_t       ins;
    int err = fd_store_insert_begin( ctx->store, ctx->disk_fd, mr, last->slot, ctx->round_robin_id, stats, &ins );
    if( FD_UNLIKELY( stats->spill.write_cnt ) ) {
      fd_histf_sample( ctx->metrics->fec_fallback_write_timing, stats->spill.write_ticks );
      ctx->metrics->fec_fallback_write_cnt   += stats->spill.write_cnt;
      ctx->metrics->fec_fallback_write_bytes += stats->spill.write_bytes;
    }
    if( FD_UNLIKELY( stats->park_cnt ) ) {
      fd_histf_sample( ctx->metrics->store_insert_park_timing, stats->park_ticks );
      ctx->metrics->store_insert_park_cnt += stats->park_cnt;
    }
    if( FD_LIKELY( err==FD_STORE_SUCCESS ) ) {
      fd_store_fec_t * rec     = fd_store_insert_data( ctx->store, ins );
      uint             data_sz = 0U;
      for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) {
        fd_shred_t * data_shred = set->data_shreds[i].s;
        ulong        payload_sz = fd_shred_payload_sz( data_shred );
        if( FD_UNLIKELY( data_sz + payload_sz > ctx->store->fec_data_max ) ) {
          FD_LOG_CRIT(( "Shred tile %lu: completed FEC set %lu %u data_sz: %lu exceeds data_max: %lu", ctx->round_robin_id, data_shred->slot, data_shred->fec_set_idx, data_sz + payload_sz, ctx->store->fec_data_max ));
        }
        fd_memcpy_nt_nofence( rec->payload + data_sz, fd_shred_data_payload( data_shred ), payload_sz );
        data_sz += (uint)payload_sz;
        FD_TEST( payload_sz<=USHORT_MAX );
        rec->shred_sz[ i ] = (ushort)payload_sz;
      }
      _mm_sfence();
      err = fd_store_insert_commit( ctx->store, ins, data_sz );
    }
    switch( err ) {
    case FD_STORE_SUCCESS:
      break;
    case FD_STORE_ERR_DUPLICATE:
    case FD_STORE_ERR_EXPIRED: /* below the root: rotor drops it anyway */
      again = 1;
      break;
    default:
      /* The FEC can't be dropped and retried: the resolver ignores every
         later shred of a completed set. */
      FD_LOG_CRIT(( "Shred tile %lu: store could not insert FEC set (slot %lu, err %d)", ctx->round_robin_id, last->slot, err ));
    }
    replay_fwd = 1;
  }

  if( FD_LIKELY( ctx->shred_out_idx!=ULONG_MAX && replay_fwd ) ) {

    /* Send all of the data shreds we recovered (weren't received), or
       all of them when we are the leader.  The chunks are all written
       before any is published, so the link burst must cover them or a
       chunk could be reused while an unreliable consumer still sees
       its old seq. */
    FD_STATIC_ASSERT( FD_SHRED_STEM_BURST>=32UL, shred_out_burst );
    ulong missing_chunk[ 32 ];
    ulong missing_cnt = 0UL;
    for( int i=0; !again && i<32; i++ ) {
      if( fd_uint_extract_bit( set->data_shred_rcvd, i )==0 ) {
        fd_shred_t * const missing = &set->data_shreds[ i ].s[0];

        fd_shred_base_t * shred_msg = (fd_shred_base_t *)fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk );
        fd_memcpy_nt_nofence( shred_msg->shred_, missing, fd_shred_sz( missing ) );
        memcpy( &shred_msg->merkle_root, merkle_root->hash, sizeof(fd_hash_t) );

        missing_chunk[ missing_cnt++ ] = ctx->shred_out_chunk;
        ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, sizeof(fd_shred_base_t), ctx->shred_out_chunk0, ctx->shred_out_wmark );
      }
    }

    if( FD_LIKELY( missing_cnt ) ) {
      _mm_sfence();
      ulong sig   = ((ulong)FD_FEC_RESOLVER_SHRED_COMPLETES << 32UL) | ( is_leader ? SHRED_SIG_SRC_LEADER : SHRED_SIG_SRC_RECONSTRUCTED );
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      for( ulong i=0UL; i<missing_cnt; i++ ) fd_stem_publish( stem, ctx->shred_out_idx, sig, missing_chunk[ i ], sizeof(fd_shred_base_t), 0UL, tsorig, tspub );
    }

    /* Replay requires the FEC payload before this notification.
       Wire-shred persistence on rserve is asynchronous.

       This message, the shred msg, and the FEC evict msg constitute
       the max 3 possible messages to repair/replay per after_frag.
       In reality, it is only possible to publish all 3 in the case
       where we receive a coding shred first for a FEC set where
       (N=1,K=18), which allows for the FEC set to be instantly
       completed by the singular coding shred, and that also happens
       to evict a FEC set from the curr_map.  When fix-32 arrives, the
       link burst value can be lowered to 2. */
    ulong sig = again ? SHRED_SIG_FEC_COMPLETE_AGAIN : ( is_leader ? SHRED_SIG_FEC_COMPLETE_LEADER : SHRED_SIG_FEC_COMPLETE );

    fd_fec_complete_t * complete_msg = fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk );
    complete_msg->last_shred_hdr = *last;
    memcpy( &complete_msg->merkle_root, merkle_root->hash, sizeof(fd_hash_t) );
    complete_msg->chained_merkle_root = *(fd_hash_t *)fd_type_pun((uchar *)last + fd_shred_chain_off( last->variant ));
    if( FD_LIKELY( sig==SHRED_SIG_FEC_COMPLETE ) ) {
      complete_msg->turbine_shred_cnt       = (ulong)fd_ulong_popcnt( set->turbine_shred_rcvd );
      complete_msg->repair_shred_cnt        = (ulong)fd_ulong_popcnt( set->repair_shred_rcvd );
      complete_msg->reconstructed_shred_cnt = 2U*(uint)FD_FEC_SHRED_CNT-(uint)(fd_uint_popcnt( set->data_shred_rcvd ) + fd_uint_popcnt( set->parity_shred_rcvd ));
      complete_msg->data_shred_rcvd         = set->data_shred_rcvd;
      complete_msg->parity_shred_rcvd       = set->parity_shred_rcvd;
      complete_msg->repair_data_rcvd        = (uint)set->repair_shred_rcvd; /* data shreds are the low FD_FEC_SHRED_CNT bits */
    } else {
      complete_msg->turbine_shred_cnt       = 0U;
      complete_msg->repair_shred_cnt        = 0U;
      complete_msg->reconstructed_shred_cnt = 0U;
      complete_msg->data_shred_rcvd         = 0U;
      complete_msg->parity_shred_rcvd       = 0U;
      complete_msg->repair_data_rcvd        = 0U;
    }

    fd_stem_publish( stem, ctx->shred_out_idx, sig, ctx->shred_out_chunk, sizeof(fd_fec_complete_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, sizeof(fd_fec_complete_t), ctx->shred_out_chunk0, ctx->shred_out_wmark );

  }

  /* Relay recovered shreds only after replay is told, computing their
     turbine children is costly on staked nodes.  A set rebuilt purely
     from repair is not on the live turbine path (catch-up), so its
     recovered shreds are not relayed. */
  if( FD_LIKELY( !is_leader && set->turbine_shred_rcvd ) ) fan_out( ctx, stem, set, is_leader, 0, tsorig );
}

static void
after_frag( fd_shred_ctx_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq;
  (void)sz;
  (void)tsorig;

  if( FD_UNLIKELY( ctx->skip_frag ) ) {
    ctx->metrics->shred_processing_result[ FD_METRICS_ENUM_SHRED_PROCESS_RESULT_V_PARSE_FAILED_IDX ] += (ulong)ctx->parse_failed;
    if( FD_UNLIKELY( ctx->fwd_meta ) ) {
      fd_memcpy( fd_chunk_to_laddr( ctx->repair_out_mem, ctx->repair_out_chunk ), ctx->shred_buffer, ctx->shred_buffer_sz );
      fd_stem_publish( stem, ctx->repair_out_idx, sig, ctx->repair_out_chunk, ctx->shred_buffer_sz, 0UL, 0UL, tspub );
      ctx->repair_out_chunk = fd_dcache_compact_next( ctx->repair_out_chunk, ctx->shred_buffer_sz, ctx->repair_out_chunk0, ctx->repair_out_wmark );
    }
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EPOCH ) ) {
    fd_stake_ci_epoch_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_ROOTEDR ) ) {
    if( FD_LIKELY( (ctx->new_root > 0UL) & (ctx->new_root<ULONG_MAX) ) ) fd_fec_resolver_advance_slot_old( ctx->resolver, ctx->new_root );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    if( ctx->gossip_upd_buf->tag==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) {
      fd_gossip_contact_info_t const * ci = ctx->gossip_upd_buf->contact_info->value;
      fd_ip4_port_t tvu_addr;
      tvu_addr.addr = ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ].is_ipv6 ? 0U : ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ].ip4;
      tvu_addr.port = ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ].port;
      if( !tvu_addr.addr || !tvu_addr.port ) {
        fd_stake_ci_dest_remove( ctx->stake_ci, fd_type_pun_const( ctx->gossip_upd_buf->origin ) );
      } else {
        fd_stake_ci_dest_update( ctx->stake_ci, fd_type_pun_const( ctx->gossip_upd_buf->origin ), tvu_addr.addr, fd_ushort_bswap( tvu_addr.port ) );
      }
    } else if( ctx->gossip_upd_buf->tag==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) {
      if( FD_UNLIKELY( !memcmp( ctx->identity_key->uc, ctx->gossip_upd_buf->origin, 32UL ) ) ) {
        /* If our own contact info was dropped, we update with dummy IP
           instead of removing since stake_ci expects our contact info
           in the sdests table all the time. fd_stake_ci_new initializes
           both ei->sdests with our contact info so this should always
           update (and not append). */
        fd_stake_ci_dest_update( ctx->stake_ci, fd_type_pun_const( ctx->gossip_upd_buf->origin ), 1U, 0U );
      } else {
        fd_stake_ci_dest_remove( ctx->stake_ci, fd_type_pun_const( ctx->gossip_upd_buf->origin ) );
      }
    }
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SIGN ) ) {
    FD_TEST( ctx->sign_pend_cnt );

    ctx->sign_seq++;
    fd_shred_sign_pend_t * pend = ctx->sign_pend + ctx->sign_pend_head;
    ctx->sign_pend_head = (ctx->sign_pend_head+1UL)%FD_SHRED_SIGN_PEND_MAX;
    ctx->sign_pend_cnt--;

    fd_fec_set_t * set = ctx->fec_sets + pend->fec_set_idx;
    for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) fd_memcpy( set->data_shreds  [ i ].s->signature, ctx->signature, FD_ED25519_SIG_SZ );
    for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) fd_memcpy( set->parity_shreds[ i ].s->signature, ctx->signature, FD_ED25519_SIG_SZ );
    complete_fec_set( ctx, stem, pend->fec_set_idx, &pend->merkle_root, 1, pend->tsorig );
    return;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_POH ) ) {
    FD_TEST( ctx->sign_pend_cnt+ctx->send_fec_set_cnt<=FD_SHRED_SIGN_PEND_MAX );
    for( ulong k=0UL; k<ctx->send_fec_set_cnt; k++ ) {
      fd_shred_sign_pend_t * pend = ctx->sign_pend + (ctx->sign_pend_head+ctx->sign_pend_cnt++)%FD_SHRED_SIGN_PEND_MAX;
      pend->fec_set_idx = ctx->send_fec_set_idx[ k ];
      pend->tsorig      = ctx->tsorig;
      pend->merkle_root = ctx->out_merkle_roots[ k ];

      memcpy( fd_chunk_to_laddr( ctx->sign_out_mem, ctx->sign_out_chunk ), ctx->out_merkle_roots[ k ].hash, 32UL );
      fd_stem_publish( stem, SIGN_OUT_IDX, FD_KEYGUARD_SIGN_TYPE_ED25519, ctx->sign_out_chunk, 32UL, 0UL, ctx->tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
      ctx->sign_out_chunk = fd_dcache_compact_next( ctx->sign_out_chunk, 32UL, ctx->sign_out_chunk0, ctx->sign_out_wmark );
    }
    return;
  }
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPAIR ) ) {
    return;
  }

  ulong fanout = 200UL; /* Default Agave's DATA_PLANE_FANOUT = 200UL */

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    uchar * shred_buffer    = ctx->shred_buffer;
    ulong   shred_buffer_sz = ctx->shred_buffer_sz;

    /* Parsed in during_frag */
    fd_shred_t const * shred = (fd_shred_t const *)shred_buffer;
    ulong max_shred_idx = ctx->current_max_shred_idx;
    if( FD_UNLIKELY( shred->slot< ctx->current_max_shred_idx_start_slot ) ) max_shred_idx = ctx->prev_max_shred_idx;
    if( FD_UNLIKELY( shred->slot>=ctx->next_max_shred_idx_start_slot    ) ) max_shred_idx = ctx->next_max_shred_idx;

    fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, shred->slot );
    if( FD_UNLIKELY( !lsched      ) ) { ctx->metrics->shred_processing_result[ FD_METRICS_ENUM_SHRED_PROCESS_RESULT_V_LEADER_UNKNOWN_IDX ]++; return; }

    fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, shred->slot );
    if( FD_UNLIKELY( !slot_leader ) ) { ctx->metrics->shred_processing_result[ FD_METRICS_ENUM_SHRED_PROCESS_RESULT_V_LEADER_UNKNOWN_IDX ]++; return; } /* Count this as bad slot too */

    /* Our own block echoed back by a relay: we already have it, so skip
       the verify and recovery.  Repair responses for our own slots are
       kept, so a restarted leader can repair its block. */
    if( FD_UNLIKELY( fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR && fd_memeq( slot_leader, ctx->identity_key, sizeof(fd_pubkey_t) ) ) ) {
      ctx->metrics->shred_processing_result[ FD_METRICS_ENUM_SHRED_PROCESS_RESULT_V_OWN_LEADER_ECHOED_IDX ]++;
      return;
    }

    fd_fec_set_t const * out_fec_set[1];
    fd_shred_t const   * out_shred[1];
    fd_fec_resolver_spilled_t spilled_fec = { 0 };
    int from_repair = 0;

    uint nonce = UINT_MAX;
    ulong shred_sz = fd_shred_sz( shred );
    if( FD_UNLIKELY( (fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR) & (shred_buffer_sz>=shred_sz+sizeof(uint)) ) ) {
      nonce = FD_LOAD(uint, shred_buffer + shred_sz );
      long est_now_ns = fd_log_wallclock(); /* TODO: switch to fd_clock for performance */
      int  slot_complete = fd_shred_is_data( fd_shred_type( shred->variant ) ) && (shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
      int  nonce_okay = fd_rnonce_ss_verify( ctx->repair_nonce_ss, nonce, shred->slot, shred->idx, slot_complete, est_now_ns );
      ctx->metrics->bad_nonce += (ulong)(!nonce_okay);
      from_repair = nonce_okay;
    }

    uint shred_source = fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR
                      ? fd_uint_if( from_repair, FD_FEC_RESOLVER_SHRED_SRC_REPAIR, FD_FEC_RESOLVER_SHRED_SRC_BAD_REPAIR )
                      : FD_FEC_RESOLVER_SHRED_SRC_TURBINE;

    long add_shred_timing  = -fd_tickcount();
    int rv = fd_fec_resolver_add_shred( ctx->resolver, shred, shred_buffer_sz, max_shred_idx, shred_source, slot_leader->uc, out_fec_set, out_shred, &ctx->out_merkle_roots[0], &spilled_fec );
    add_shred_timing      +=  fd_tickcount();

    fd_histf_sample( ctx->metrics->add_shred_timing, (ulong)add_shred_timing );
    ctx->metrics->shred_processing_result[ rv + FD_FEC_RESOLVER_ADD_SHRED_RETVAL_OFF+FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT ]++;

    if( FD_UNLIKELY( ctx->shred_out_idx!=ULONG_MAX &&
                     spilled_fec.slot!=0 ) ) {
      /* We've spilled an in-progress FEC set in the fec_resolver. We
         need to let repair know to clear out it's cached info for that
         fec set and re-repair those shreds. */
      fd_fec_evicted_t * evicted_msg = (fd_fec_evicted_t *)fd_type_pun( fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk ) );
      evicted_msg->slot        = spilled_fec.slot;
      evicted_msg->fec_set_idx = spilled_fec.fec_set_idx;
      fd_memcpy( evicted_msg->merkle_root.uc, spilled_fec.merkle_root->hash, sizeof(fd_hash_t) );

      fd_stem_publish( stem, ctx->shred_out_idx, SHRED_SIG_FEC_EVICTED, ctx->shred_out_chunk, sizeof(fd_fec_evicted_t), 0, ctx->tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
      ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, sizeof(fd_fec_evicted_t), ctx->shred_out_chunk0, ctx->shred_out_wmark );
    }

    /* Send rotor future slots past max_live_slots so that unstaked
       nodes can catch up. */

    if( FD_UNLIKELY( rv==FD_FEC_RESOLVER_SHRED_IGNORED &&
                     shred_source==FD_FEC_RESOLVER_SHRED_SRC_TURBINE &&
                     shred->version==ctx->shredder->shred_version &&
                     shred->slot>ctx->future_slot &&
                     ctx->new_root<ULONG_MAX &&
                     shred->slot>=ctx->new_root+ctx->slot_max &&
                     fd_shred_type( shred->variant )!=FD_SHRED_TYPE_LEGACY_DATA &&
                     fd_shred_type( shred->variant )!=FD_SHRED_TYPE_LEGACY_CODE ) ) {
      fd_bmtree_node_t root[1];
      int signed_ = fd_shred_merkle_root( shred, ctx->bmtree_mem, root ) &&
                    FD_ED25519_SUCCESS==fd_ed25519_verify( root->hash, FD_SHRED_MERKLE_ROOT_SZ, shred->signature, slot_leader->uc, ctx->sha512 );
      if( FD_LIKELY( signed_ ) ) {
        ctx->future_slot = shred->slot;
        fd_stem_publish( stem, ctx->shred_out_idx, fd_shred_sig_future( shred->slot ), 0UL, 0UL, 0UL, ctx->tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
      }
    }

    if( FD_LIKELY( ctx->shred_out_idx!=ULONG_MAX
                   && ( ( rv==FD_FEC_RESOLVER_SHRED_OKAY )
                      | ( rv==FD_FEC_RESOLVER_SHRED_COMPLETES )
                      | ( rv==FD_FEC_RESOLVER_SHRED_DUPLICATE )
                      | ( rv==FD_FEC_RESOLVER_SHRED_EQUIVOC   ) ) ) ) {

      /* Construct the sig from fec_resolver result and shred source. */

      ulong _sig = fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR
                     ? ( from_repair /*nonce_okay*/ ? SHRED_SIG_SRC_REPAIR : SHRED_SIG_SRC_BAD_REPAIR )
                     : ( SHRED_SIG_SRC_TURBINE );
      _sig = ((ulong)rv << 32UL) | _sig;

      /* Copy the full shred into the frag and publish. */

      fd_shred_base_t * shred_msg = (fd_shred_base_t *)fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk );
      memcpy(  shred_msg->shred_, shred, fd_shred_sz( shred ) );
      memcpy( &shred_msg->merkle_root, ctx->out_merkle_roots[0].hash, sizeof(fd_hash_t) );
      if( FD_UNLIKELY( fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR ) ) { shred_msg->rnonce = nonce; }

      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      fd_stem_publish( stem, ctx->shred_out_idx, _sig, ctx->shred_out_chunk, sizeof(fd_shred_base_t), 0UL, ctx->tsorig, tspub );
      ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, sizeof(fd_shred_base_t), ctx->shred_out_chunk0, ctx->shred_out_wmark );
    }

    if( FD_LIKELY( fd_disco_netmux_sig_proto( sig ) != DST_PROTO_REPAIR &&
                 ( (rv==FD_FEC_RESOLVER_SHRED_OKAY) | (rv==FD_FEC_RESOLVER_SHRED_COMPLETES) ) ) ) {
      /* Relay this shred */
      if( FD_UNLIKELY( ctx->rtx_fseq && shred->slot>ctx->rtx_slot ) ) {
        ctx->rtx_slot = shred->slot;
        fd_fseq_update( ctx->rtx_fseq, shred->slot );
      }
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

    if( FD_LIKELY( rv!=FD_FEC_RESOLVER_SHRED_COMPLETES ) ) return;

    FD_TEST( ctx->fec_sets <= *out_fec_set );
    complete_fec_set( ctx, stem, (ulong)(*out_fec_set - ctx->fec_sets), &ctx->out_merkle_roots[0], 0, ctx->tsorig );
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( scratch!=NULL );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->shred.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->shred.identity_key_path, /* pubkey only: */ 1 ) );

  ctx->adtl_dests_retransmit_cnt = tile->shred.adtl_dests_retransmit_cnt;
  fd_shred_resolve_additional_destinations( tile->shred.adtl_dests_retransmit,
                                            tile->shred.adtl_dests_retransmit_cnt,
                                            "tiles.shred.additional_shred_destinations_retransmit",
                                            ctx->adtl_dests_retransmit );
  ctx->adtl_dests_leader_cnt = tile->shred.adtl_dests_leader_cnt;
  fd_shred_resolve_additional_destinations( tile->shred.adtl_dests_leader,
                                            tile->shred.adtl_dests_leader_cnt,
                                            "tiles.shred.additional_shred_destinations_leader",
                                            ctx->adtl_dests_leader );

  if( FD_UNLIKELY( !fd_rng_secure( &(ctx->resolver_seed), sizeof(ulong) ) ) ) {
    FD_LOG_CRIT(( "fd_rng_secure failed" ));
  }
  if( FD_UNLIKELY( !fd_rng_secure( &(ctx->shred_dest_seed), sizeof(ulong) ) ) ) {
    FD_LOG_CRIT(( "fd_rng_secure failed" ));
  }

  ctx->disk_fd = -1;
  ulong store_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "store" );
  if( FD_LIKELY( store_obj_id!=ULONG_MAX ) ) {
    fd_store_t * store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
    FD_TEST( store );
    ctx->disk_fd = FD_STORE_FD_RW;
    if( FD_UNLIKELY( fcntl( ctx->disk_fd, F_GETFD )<0 ) )
      FD_LOG_ERR(( "store file descriptor was not inherited (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {

  FD_TEST( 0==strcmp( topo->links[tile->out_link_id[ NET_OUT_IDX   ]].name, "shred_net"   ) );
  FD_TEST( 0==strcmp( topo->links[tile->out_link_id[ SIGN_OUT_IDX  ]].name, "shred_sign"  ) );

  if( FD_UNLIKELY( !tile->out_cnt ) )
    FD_LOG_ERR(( "shred tile has no primary output link" ));

  ulong fec_exposure = tile->shred.fec_exposure;
  if( FD_UNLIKELY( !fec_exposure ) ) FD_LOG_ERR(( "fec_exposure not set" ));

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( scratch!=NULL );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  FD_CHECK_ERR( tile->in_cnt<=IN_LINK_MAX, "too many input links" );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_id  = tile->kind_id;
  ctx->batch_cnt       = 0UL;
  ctx->slot            = ULONG_MAX;
  ctx->store           = NULL;

  ulong store_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "store" );
  if( FD_LIKELY( store_obj_id!=ULONG_MAX ) ) {
    ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
    FD_TEST( ctx->store->magic==FD_STORE_MAGIC );
  }

  /* If the default partial_depth is ever changed, correspondingly
     change the size of the fd_fec_intra_pool in fd_fec_repair. */
  ulong fec_resolver_footprint = fd_fec_resolver_footprint( tile->shred.fec_resolver_depth, 1UL, fec_exposure+1UL,
                                                            128UL * tile->shred.fec_resolver_depth );
  ulong fec_set_cnt            = fd_shred_tile_fec_set_cnt( fec_exposure, tile->shred.fec_resolver_depth );

  void * fec_sets_shmem = NULL;

  ctx->rtx_fseq = NULL;
  ctx->rtx_slot = 0UL;
  ulong rtx_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "shred_rtx.%lu", tile->kind_id );
  if( FD_UNLIKELY( rtx_obj_id!=ULONG_MAX ) ) {
    ctx->rtx_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, rtx_obj_id ) );
    FD_TEST( ctx->rtx_fseq );
  }

  ctx->repair_out_idx = fd_topo_find_tile_out_link( topo, tile, "shred_rotor", ctx->round_robin_id );
  if( FD_LIKELY( ctx->repair_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * repair_out = &topo->links[ tile->out_link_id[ ctx->repair_out_idx ] ];
    FD_TEST( repair_out->mtu>=FD_REPAIR_NET_FRAME_MAX );
    ctx->repair_out_mem    = topo->workspaces[ topo->objs[ repair_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->repair_out_chunk0 = fd_dcache_compact_chunk0( ctx->repair_out_mem, repair_out->dcache );
    ctx->repair_out_wmark  = fd_dcache_compact_wmark ( ctx->repair_out_mem, repair_out->dcache, repair_out->mtu );
    ctx->repair_out_chunk  = ctx->repair_out_chunk0;
  }

  ctx->shred_out_idx = fd_topo_find_tile_out_link( topo, tile, "shred_out", ctx->round_robin_id );
  if( FD_LIKELY( ctx->shred_out_idx!=ULONG_MAX ) ) {
    FD_TEST( fec_exposure==FD_SHRED_FIREDANCER_FEC_EXPOSURE );
    fd_topo_link_t const * shred_out = &topo->links[ tile->out_link_id[ ctx->shred_out_idx ] ];
    ctx->shred_out_mem    = topo->workspaces[ topo->objs[ shred_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->shred_out_chunk0 = fd_dcache_compact_chunk0( ctx->shred_out_mem, shred_out->dcache );
    ctx->shred_out_wmark  = fd_dcache_compact_wmark ( ctx->shred_out_mem, shred_out->dcache, shred_out->mtu );
    ctx->shred_out_chunk  = ctx->shred_out_chunk0;
    FD_TEST( fd_dcache_compact_is_safe( ctx->shred_out_mem, shred_out->dcache, shred_out->mtu, shred_out->depth ) );
    ulong fec_sets_required_cnt = fec_set_cnt*ctx->round_robin_cnt;
    if( FD_LIKELY( ctx->store ) ) {
      FD_TEST( ctx->store->fec_set_cnt>=fec_sets_required_cnt );
      fd_fec_set_t * store_fec_sets = fd_store_fec_sets( ctx->store );
      FD_TEST( store_fec_sets );

      fec_sets_shmem = store_fec_sets + ctx->round_robin_id*fec_set_cnt;
    } else {
      ulong fec_sets_obj_id = fd_pod_query_ulong( topo->props, "fec_sets", ULONG_MAX );
      FD_TEST( fec_sets_obj_id!=ULONG_MAX );

      ulong fec_sets_sz = fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.sz", fec_sets_obj_id );
      FD_TEST( fec_sets_sz>=fec_sets_required_cnt*sizeof(fd_fec_set_t) );

      fd_fec_set_t * fec_sets = fd_topo_obj_laddr( topo, fec_sets_obj_id );
      FD_TEST( fec_sets );

      fec_sets_shmem = fec_sets + ctx->round_robin_id*fec_set_cnt;
    }

    ulong rnonce_ss_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "rnonce_ss" );
    FD_TEST( rnonce_ss_id!=ULONG_MAX );
    memcpy( ctx->repair_nonce_ss, fd_topo_obj_laddr( topo, rnonce_ss_id ), sizeof(fd_rnonce_ss_t) );
  }
  if( FD_UNLIKELY( !fec_sets_shmem ) ) FD_LOG_ERR(( "missing FEC-set backing memory" ));

  if( FD_UNLIKELY( !tile->shred.fec_resolver_depth ) ) FD_LOG_ERR(( "fec_resolver_depth not set" ));
  if( FD_UNLIKELY( !tile->shred.shred_listen_port  ) ) FD_LOG_ERR(( "shred_listen_port not set" ));

  void * _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()            );
  void * _resolver = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_resolver_align(),          fec_resolver_footprint             );
  void * _shredder = FD_SCRATCH_ALLOC_APPEND( l, fd_shredder_align(),              fd_shredder_footprint()            );

  fd_fec_set_t * fec_sets  = (fd_fec_set_t *)fec_sets_shmem;

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ushort expected_shred_version = tile->shred.expected_shred_version;

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  /* populate ctx */
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];
  FD_TEST( sign_out->mtu==32UL );
  ctx->sign_out_mem    = topo->workspaces[ topo->objs[ sign_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->sign_out_chunk0 = fd_dcache_compact_chunk0( ctx->sign_out_mem, sign_out->dcache );
  ctx->sign_out_wmark  = fd_dcache_compact_wmark ( ctx->sign_out_mem, sign_out->dcache, sign_out->mtu );
  ctx->sign_out_chunk  = ctx->sign_out_chunk0;

  ctx->bench_max_shred_idx           = tile->shred.bench_max_shreds_per_block;
  ulong shred_limit                  = tile->shred.max_shreds_per_block;
  ctx->shred_limit                   = shred_limit;
  fd_fec_set_t * resolver_sets       = fec_sets + fec_exposure + FD_SHRED_SIGN_PEND_MAX;
  ctx->shredder = NONNULL( fd_shredder_join     ( fd_shredder_new     ( _shredder ) ) );
  ctx->resolver = NONNULL( fd_fec_resolver_join ( fd_fec_resolver_new ( _resolver,
                                                                        tile->shred.fec_resolver_depth, 1UL,
                                                                        fec_exposure+1UL,
                                                                        128UL * tile->shred.fec_resolver_depth,
                                                                        tile->shred.slot_max,
                                                                        resolver_sets,
                                                                        ctx->resolver_seed ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );
  ctx->new_root    = 0UL;
  ctx->slot_max    = tile->shred.slot_max;
  ctx->future_slot = 0UL;

  if( FD_LIKELY( !!expected_shred_version ) ) {
    fd_shredder_set_shred_version    ( ctx->shredder, expected_shred_version );
    fd_fec_resolver_set_shred_version( ctx->resolver, expected_shred_version );
  }

  ctx->fec_sets = fec_sets;

  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci, ctx->identity_key, ctx->shred_dest_seed ) );

  ctx->net_id   = (ushort)0;

  fd_ip4_udp_hdr_init( ctx->data_shred_net_hdr,   FD_SHRED_MIN_SZ, 0, tile->shred.shred_listen_port );
  fd_ip4_udp_hdr_init( ctx->parity_shred_net_hdr, FD_SHRED_MAX_SZ, 0, tile->shred.shred_listen_port );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY(      !strcmp( link->name, "net_shred"    ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in[ i ].net_rx, link->dcache );
      continue; /* only net_rx needs to be set in this case. */
    }
    else if( FD_LIKELY( !strcmp( link->name, "poh_shred"     ) ) ) ctx->in_kind[ i ] = IN_KIND_POH;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "sign_shred"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "replay_slot"   ) ) ) ctx->in_kind[ i ] = IN_KIND_ROOTEDR;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_ciaddr" ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;

    else FD_LOG_ERR(( "shred tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( !!link->mtu ) ) {
      ctx->in[ i ].mem    = link_wksp->wksp;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    }
  }

  fd_topo_link_t const * net_out = &topo->links[ tile->out_link_id[ NET_OUT_IDX ] ];

  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  if( FD_LIKELY( ctx->shred_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * shred_out = &topo->links[ tile->out_link_id[ ctx->shred_out_idx ] ];
    ctx->shred_out_mem         = topo->workspaces[ topo->objs[ shred_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->shred_out_chunk0      = fd_dcache_compact_chunk0( ctx->shred_out_mem, shred_out->dcache );
    ctx->shred_out_wmark       = fd_dcache_compact_wmark ( ctx->shred_out_mem, shred_out->dcache, shred_out->mtu );
    ctx->shred_out_chunk       = ctx->shred_out_chunk0;
    FD_TEST( fd_dcache_compact_is_safe( ctx->shred_out_mem, shred_out->dcache, shred_out->mtu, shred_out->depth ) );
    /* An unreliable consumer ignores credits, so the dcache must hold
       a full STEM_BURST beyond the mcache depth. */
    FD_TEST( shred_out->burst>=FD_SHRED_STEM_BURST );
  }

  ctx->poh_in_expect_seq = 0UL;

  ctx->sign_pend_head = 0UL;
  ctx->sign_pend_cnt  = 0UL;
  ctx->sign_seq       = 0UL;

  ctx->shredder_fec_set_idx = 0UL;
  ctx->shredder_max_fec_set_idx = fec_exposure + FD_SHRED_SIGN_PEND_MAX;

  ctx->chained_merkle_root = NULL;
  memset( ctx->out_merkle_roots, 0, sizeof(ctx->out_merkle_roots) );

  for( ulong i=0UL; i<FD_SHRED_BATCH_FEC_SETS_MAX; i++ ) { ctx->send_fec_set_idx[ i ] = ULONG_MAX; }
  ctx->send_fec_set_cnt = 0UL;

  ctx->shred_buffer_sz  = 0UL;
  memset( ctx->shred_buffer, 0xFF, FD_NET_MTU );

  fd_histf_join( fd_histf_new( ctx->metrics->batch_sz,             FD_MHIST_MIN(         SHRED, BATCH_SIZE_BYTES           ),
                                                                   FD_MHIST_MAX(         SHRED, BATCH_SIZE_BYTES           ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->batch_microblock_cnt, FD_MHIST_MIN(         SHRED, MICROBLOCK_PER_BATCH       ),
                                                                   FD_MHIST_MAX(         SHRED, MICROBLOCK_PER_BATCH       ) ) );
  fd_histf_join( fd_metrics_histf_new_ns( ctx->metrics->shredding_timing,     FD_MHIST_EDGES_NS( SHRED, BATCH_SHRED_DURATION_NANOS ) ) );
  fd_histf_join( fd_metrics_histf_new_ns( ctx->metrics->add_shred_timing,     FD_MHIST_EDGES_NS( SHRED, ADD_SHRED_DURATION_NANOS ) ) );
  fd_histf_join( fd_metrics_histf_new_ns( ctx->metrics->fec_fallback_write_timing, FD_MHIST_EDGES_NS( SHRED, STORE_FEC_SYNC_SPILL_DURATION_NANOS ) ) );
  fd_histf_join( fd_metrics_histf_new_ns( ctx->metrics->store_insert_park_timing,  FD_MHIST_EDGES_NS( SHRED, STORE_FEC_INSERT_PARK_DURATION_NANOS ) ) );
  memset( ctx->metrics->shred_processing_result, '\0', sizeof(ctx->metrics->shred_processing_result) );
  ctx->metrics->invalid_block_id_cnt         = 0UL;
  ctx->metrics->shred_rejected_unchained_cnt = 0UL;
  ctx->metrics->repair_rcv_cnt               = 0UL;
  ctx->metrics->repair_rcv_bytes             = 0UL;
  ctx->metrics->turbine_rcv_cnt              = 0UL;
  ctx->metrics->turbine_rcv_bytes            = 0UL;
  ctx->metrics->bad_nonce                    = 0UL;
  ctx->metrics->fec_fallback_write_cnt       = 0UL;
  ctx->metrics->fec_fallback_write_bytes     = 0UL;
  ctx->metrics->store_insert_park_cnt        = 0UL;

  ctx->pending_batch.microblock_cnt = 0UL;
  ctx->pending_batch.pos            = 0UL;
  ctx->pending_batch.slot           = 0UL;
  memset( ctx->pending_batch.payload, 0, sizeof(ctx->pending_batch.payload) );

  memset( ctx->epoch_schedule, 0, sizeof(ctx->epoch_schedule) );
  for( ulong i=0UL; i<FD_SHRED_FEATURES_ACTIVATION_SLOT_CNT; i++ ) {
    ctx->features_activation->slots[i] = FD_SHRED_FEATURES_ACTIVATION_SLOT_DISABLED;
  }
  ctx->prev_max_shred_idx               = ctx->shred_limit;
  ctx->current_max_shred_idx            = ctx->shred_limit;
  ctx->next_max_shred_idx               = ctx->shred_limit;
  ctx->current_max_shred_idx_start_slot = 0UL;
  ctx->next_max_shred_idx_start_slot    = ULONG_MAX;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  memset( ctx->block_ids, 0, sizeof(ctx->block_ids) );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  populate_sock_filter_policy_fd_shred_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->disk_fd );
  return sock_filter_policy_fd_shred_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->disk_fd>=0 ) )
    out_fds[ out_cnt++ ] = ctx->disk_fd;
  return out_cnt;
}

/* One stem iteration finishes at most one FEC set on shred_out: 32
   data shreds and a completion, after at most an eviction and a shred
   on the network path.  PoH input only publishes sign requests, at
   most one per FEC set of a batch. */
#define STEM_BURST FD_SHRED_STEM_BURST

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

/* When leader, poh_shred carries a stream of one microblock per frag
   and the other links are near empty; keep draining it. */
#define STEM_STICKY_POLL_MAX (16UL)

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
