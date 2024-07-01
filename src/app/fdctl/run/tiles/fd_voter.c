/* Store tile manages a blockstore and serves requests to repair and replay. */

#define _GNU_SOURCE

#include "../../../../disco/tiles.h"

#include "generated/voter_seccomp.h"
#include "../../../../flamenco/repair/fd_repair.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../util/fd_util.h"
#include "../../../../choreo/fd_choreo.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../disco/tvu/fd_store.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/runtime/fd_runtime.h"
#include "../../../../disco/fd_disco.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

struct fd_voter_tile_ctx {
  fd_pubkey_t identity_key[ 1 ];

  fd_stake_ci_t * stake_ci;
  ulong *         current_slot;
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;

  ulong       stake_in_idx;
  fd_wksp_t * stake_in_mem;
  ulong       stake_in_chunk0;
  ulong       stake_in_wmark;

  ulong       contact_in_idx;
  fd_wksp_t * contact_in_mem;
  ulong       contact_in_chunk0;
  ulong       contact_in_wmark;

  ulong       replay_in_idx;
  fd_wksp_t * replay_in_mem;
  ulong       replay_in_chunk0;
  ulong       replay_in_wmark;

  ulong       poh_in_idx;
  fd_wksp_t * poh_in_mem;
  ulong       poh_in_chunk0;
  ulong       poh_in_wmark;

  ulong            gossip_out_idx;
  fd_frag_meta_t * gossip_out_mcache;
  ulong *          gossip_out_sync;
  ulong            gossip_out_depth;
  ulong            gossip_out_seq;

  fd_wksp_t * gossip_out_mem;
  ulong       gossip_out_chunk0;
  ulong       gossip_out_wmark;
  ulong       gossip_out_chunk;

  ulong            pack_out_idx;
  fd_frag_meta_t * pack_out_mcache;
  ulong *          pack_out_sync;
  ulong            pack_out_depth;
  ulong            pack_out_seq;

  fd_wksp_t * pack_out_mem;
  ulong       pack_out_chunk0;
  ulong       pack_out_wmark;
  ulong       pack_out_chunk;

  ulong            net_out_idx;
  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;


  ulong                sign_in_idx;
  ulong                sign_out_idx; 
  fd_keyguard_client_t keyguard_client[ 1 ];
};
typedef struct fd_voter_tile_ctx fd_voter_tile_ctx_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 4UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_voter_tile_ctx_t), sizeof(fd_voter_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_voter_tile_ctx_t) );
}

static inline void
handle_new_cluster_contact_info( fd_voter_tile_ctx_t * ctx,
                                 uchar const *         buf,
                                 ulong                 buf_sz ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = buf_sz;

  if( dest_cnt >= MAX_SHRED_DESTS )
    FD_LOG_ERR(( "Cluster nodes had %lu destinations, which was more than the max of %lu", dest_cnt, MAX_SHRED_DESTS ));

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header );
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
finalize_new_cluster_contact_info( fd_voter_tile_ctx_t * ctx ) {
  fd_stake_ci_dest_add_fini( ctx->stake_ci, ctx->new_dest_cnt );
}

static long last_log = 0L;

static void
after_credit( void *             _ctx,
	            fd_mux_context_t * mux_ctx FD_PARAM_UNUSED,
              int *              opt_poll_in FD_PARAM_UNUSED ) {
  fd_voter_tile_ctx_t * ctx = (fd_voter_tile_ctx_t *)_ctx;
  
  long now = fd_log_wallclock();
  if( now - last_log >= (long)1e9 ) {
    last_log = now;
    
    ulong current_slot = fd_fseq_query( ctx->current_slot );
    FD_LOG_WARNING(( "voter - slot: %lu", current_slot ));

    fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, current_slot );
    if( FD_UNLIKELY( !lsched      ) ) { FD_LOG_WARNING(("QQQQ1")); return; }

    fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, current_slot );
    if( FD_UNLIKELY( !slot_leader ) ) { FD_LOG_WARNING(("QQQQ2")); return; } /* Count this as bad slot too */
    
    FD_LOG_WARNING(( "voter 2 - leader: %32J", slot_leader->uc ));

    fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, current_slot );
    fd_shred_dest_idx_t sdest_idx = fd_shred_dest_pubkey_to_idx( sdest, slot_leader );
    if( FD_UNLIKELY( sdest_idx==FD_SHRED_DEST_NO_DEST ) ) {
      return;
    }
    fd_shred_dest_weighted_t * dest = fd_shred_dest_idx_to_dest( sdest, sdest_idx );

    FD_LOG_WARNING(( "voter 3 - dest: " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( dest->ip4 ), dest->port ));

  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq        FD_PARAM_UNUSED,
             ulong  sig        FD_PARAM_UNUSED,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter FD_PARAM_UNUSED ) {
  fd_voter_tile_ctx_t * ctx = (fd_voter_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->sign_in_idx ) ) {
    FD_LOG_CRIT(( "signing tile send out of band fragment" ));
  }

  if( FD_UNLIKELY( in_idx==ctx->stake_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_in_chunk0 || chunk>ctx->stake_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_in_chunk0, ctx->stake_in_wmark ));
    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->stake_in_mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
        FD_LOG_WARNING(( "XQQQQQQQQ2" ));

  }

  if( FD_UNLIKELY( in_idx==ctx->contact_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->contact_in_chunk0 || chunk>ctx->contact_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->contact_in_chunk0, ctx->contact_in_wmark ));
    }
    
    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->contact_in_mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry, sz );
    FD_LOG_WARNING(( "XQQQQQQQQ" ));
  }

}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq          FD_PARAM_UNUSED,
            ulong *            opt_sig      FD_PARAM_UNUSED,
            ulong *            opt_chunk    FD_PARAM_UNUSED,
            ulong *            opt_sz       FD_PARAM_UNUSED,
            ulong *            opt_tsorig   FD_PARAM_UNUSED,
            int *              opt_filter   FD_PARAM_UNUSED,
            fd_mux_context_t * mux          FD_PARAM_UNUSED ) {
  fd_voter_tile_ctx_t * ctx = (fd_voter_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->contact_in_idx ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  }

  if( FD_UNLIKELY( in_idx==ctx->stake_in_idx ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( in_idx==ctx->replay_in_idx ) ) {

  }
}

static void
privileged_init( fd_topo_t *      topo  FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_voter_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_voter_tile_ctx_t), sizeof(fd_voter_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->voter.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t *)fd_keyload_load( tile->voter.identity_key_path, /* pubkey only: */ 1 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  fd_flamenco_boot( NULL, NULL );

  if( FD_UNLIKELY( tile->out_link_id_primary != ULONG_MAX ) )
    FD_LOG_ERR(( "voter has a primary output link" ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_voter_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_voter_tile_ctx_t), sizeof(fd_voter_tile_ctx_t) );
  // TODO: set the lo_mark_slot to the actual snapshot slot!
  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() ), ctx->identity_key ) );

  ulong current_slot_obj_id = fd_pod_query_ulong( topo->props, "current_slot", ULONG_MAX );
  FD_TEST( current_slot_obj_id!=ULONG_MAX );
  ctx->current_slot = fd_fseq_join( fd_topo_obj_laddr( topo, current_slot_obj_id ) );

  /* Set up stake input */
  ctx->stake_in_idx = fd_topo_find_tile_in_link( topo, tile, "stake_out", 0 );
  FD_TEST( ctx->stake_in_idx!=ULONG_MAX );
  fd_topo_link_t * stake_in_link = &topo->links[ tile->in_link_id[ ctx->stake_in_idx ] ];
  ctx->stake_in_mem    = topo->workspaces[ topo->objs[ stake_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_in_chunk0 = fd_dcache_compact_chunk0( ctx->stake_in_mem, stake_in_link->dcache );
  ctx->stake_in_wmark  = fd_dcache_compact_wmark( ctx->stake_in_mem, stake_in_link->dcache, stake_in_link->mtu );

  /* Set up contact input */
  ctx->contact_in_idx = fd_topo_find_tile_in_link( topo, tile, "gossip_voter", 0 );
  FD_TEST( ctx->contact_in_idx!=ULONG_MAX );
  fd_topo_link_t * contact_in_link = &topo->links[ tile->in_link_id[ ctx->contact_in_idx ] ];
  ctx->contact_in_mem    = topo->workspaces[ topo->objs[ contact_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->contact_in_chunk0 = fd_dcache_compact_chunk0( ctx->contact_in_mem, contact_in_link->dcache );
  ctx->contact_in_wmark  = fd_dcache_compact_wmark( ctx->contact_in_mem, contact_in_link->dcache, contact_in_link->mtu );

  /* Set up replay tile input */
  ctx->replay_in_idx = fd_topo_find_tile_in_link( topo, tile, "replay_voter", 0 );
  FD_TEST( ctx->replay_in_idx!=ULONG_MAX );
  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ ctx->replay_in_idx ] ];
  ctx->replay_in_mem    = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in_link->dcache );
  ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in_link->dcache, replay_in_link->mtu );

  /* Set up repair request output */
  ctx->gossip_out_idx = fd_topo_find_tile_out_link( topo, tile, "voter_gossip", 0 );
  FD_TEST( ctx->gossip_out_idx!=ULONG_MAX );
  fd_topo_link_t * gossip_out_link = &topo->links[ tile->out_link_id[ ctx->gossip_out_idx ] ];
  ctx->gossip_out_mcache = gossip_out_link->mcache;
  ctx->gossip_out_sync   = fd_mcache_seq_laddr( ctx->gossip_out_mcache );
  ctx->gossip_out_depth  = fd_mcache_depth( ctx->gossip_out_mcache );
  ctx->gossip_out_seq    = fd_mcache_seq_query( ctx->gossip_out_sync );
  ctx->gossip_out_mem    = topo->workspaces[ topo->objs[ gossip_out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->gossip_out_chunk0 = fd_dcache_compact_chunk0( ctx->gossip_out_mem, gossip_out_link->dcache );
  ctx->gossip_out_wmark  = fd_dcache_compact_wmark ( ctx->gossip_out_mem, gossip_out_link->dcache, gossip_out_link->mtu );
  ctx->gossip_out_chunk  = ctx->gossip_out_chunk0;

  /* Set up pack output */
  ctx->pack_out_idx = fd_topo_find_tile_out_link( topo, tile, "voter_pack", 0 );
  FD_TEST( ctx->pack_out_idx!=ULONG_MAX );
  fd_topo_link_t * pack_out_link = &topo->links[ tile->out_link_id[ ctx->pack_out_idx ] ];
  ctx->pack_out_mcache = pack_out_link->mcache;
  ctx->pack_out_sync   = fd_mcache_seq_laddr( ctx->pack_out_mcache );
  ctx->pack_out_depth  = fd_mcache_depth( ctx->pack_out_mcache );
  ctx->pack_out_seq    = fd_mcache_seq_query( ctx->pack_out_sync );
  ctx->pack_out_mem    = topo->workspaces[ topo->objs[ pack_out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_out_chunk0 = fd_dcache_compact_chunk0( ctx->pack_out_mem, pack_out_link->dcache );
  ctx->pack_out_wmark  = fd_dcache_compact_wmark ( ctx->pack_out_mem, pack_out_link->dcache, pack_out_link->mtu );
  ctx->pack_out_chunk  = ctx->pack_out_chunk0;

  /* Set up net output */
  ctx->net_out_idx = fd_topo_find_tile_out_link( topo, tile, "voter_net", 0 );
  FD_TEST( ctx->net_out_idx!=ULONG_MAX );
  fd_topo_link_t * net_out_link = &topo->links[ tile->out_link_id[ ctx->net_out_idx ] ];
  ctx->net_out_mcache = net_out_link->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out_link->dcache );
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out_link->dcache, net_out_link->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;
  

  /* Set up keyguard */
  ctx->sign_in_idx  = fd_topo_find_tile_in_link( topo, tile, "sign_voter", 0 );
  ctx->sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "voter_sign", 0 );
  FD_TEST( ctx->sign_in_idx==( tile->in_cnt-1 ) );

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id[ ctx->sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ ctx->sign_out_idx ] ];

  if ( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) )==NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }
}


static ulong
populate_allowed_seccomp( void *               scratch FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_voter( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_voter_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch     FD_PARAM_UNUSED,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_voter = {
  .name                     = "voter",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
