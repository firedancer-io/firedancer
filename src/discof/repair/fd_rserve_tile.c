/* fd_rserve_tile serves incoming repair requests from other nodes */

#include "fd_rserve.h"
#include "fd_repair.h"
#include "generated/fd_rserve_tile_seccomp.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco_base.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../util/net/fd_net_headers.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/store/fd_ledger.h"
#include "../../util/pod/fd_pod.h"
#include "../../disco/store/fd_store.h"
#include "../../ballet/fd_ballet.h"

#define IN_KIND_NET    (0)
#define IN_KIND_SHRED  (1)

#define MAX_IN_LINKS 32

#define FD_RSERVE_MAX_PACKET_SIZE 1232

#define FD_SIGNED_REPAIR_TIME_WINDOW

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  };
  fd_net_rx_bounds_t net_rx;
} in_ctx_t;

typedef struct ctx {
  fd_net_rx_bounds_t net_rx;

  uchar buffer[ FD_NET_MTU ];

  uint     in_kind [ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  uint        net_out_idx;
  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  uint        shred_out_idx;
  fd_wksp_t * shred_out_mem;
  ulong       shred_out_chunk0;
  ulong       shred_out_wmark;
  ulong       shred_out_chunk;

  fd_rserve_t * rserve;
  fd_keyswitch_t * keyswitch;
  fd_pubkey_t identity_public_key;
  int is_halting_signing;

  fd_ledger_t * ledger;
  fd_store_t * store;

  /* Used for verifying incoming requests, and signing outgoing responses. */
  fd_sha512_t sha512[1];

  fd_ip4_udp_hdrs_t serve_hdr[1];
  ushort            net_id;
} ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),    sizeof(ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_ledger_align(), fd_ledger_footprint( tile->rserve.max_slots ) );
  l = FD_LAYOUT_APPEND( l, fd_rserve_align(), fd_rserve_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

// static void FD_FN_UNUSED
// send_packet( ctx_t * ctx,
//              fd_stem_context_t    * stem,
//              uint                   dst_ip_addr,
//              ushort                 dst_port,
//              uint                   src_ip_addr,
//              uchar const *          payload,
//              ulong                  payload_sz,
//              ulong                  tsorig ) {
//   uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
//   fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
//   *hdr = *ctx->serve_hdr;

//   fd_ip4_hdr_t * ip4 = hdr->ip4;
//   ip4->saddr       = src_ip_addr;
//   ip4->daddr       = dst_ip_addr;
//   ip4->net_id      = fd_ushort_bswap( ctx->net_id++ );
//   ip4->check       = 0U;
//   ip4->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
//   ip4->check       = fd_ip4_hdr_check_fast( ip4 );

//   fd_udp_hdr_t * udp = hdr->udp;
//   udp->net_dport = dst_port;
//   udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
//   fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );
//   hdr->udp->check = 0U;

//   ulong tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
//   ulong sig       = fd_disco_netmux_sig( dst_ip_addr, dst_port, dst_ip_addr, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
//   ulong packet_sz = payload_sz + sizeof(fd_ip4_udp_hdrs_t);
//   ulong chunk     = ctx->net_out_chunk;
//   fd_stem_publish( stem, ctx->net_out_idx, sig, chunk, packet_sz, 0UL, tsorig, tspub );
//   ctx->net_out_chunk = fd_dcache_compact_next( chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
// }

static inline int
before_frag( ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  if( FD_LIKELY( ctx->is_halting_signing && in_kind==IN_KIND_NET ) ) return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_RSERVE;
  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) return fd_disco_shred_out_msg_type( sig )!=FD_SHRED_OUT_MSG_TYPE_SHRED;
  /* TODO: can we check and discard CODE shreds in here, before after_frag() ? */
  return 0;
}

static inline void
during_frag( ctx_t                * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  in_ctx_t const * in_ctx  = &ctx->in_links[ in_idx ];


  if( FD_LIKELY( in_kind==IN_KIND_NET ) ) {
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */
    uchar const * pkt = fd_net_rx_translate_frag( &in_ctx->net_rx, chunk, ctl, sz );
    fd_memcpy( ctx->buffer, pkt, sz );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) {
    uchar const * dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    if( FD_LIKELY( sz > 0 ) ) fd_memcpy( ctx->buffer, dcache_entry, sz );
    return;
  }

  FD_LOG_ERR(( "Frag from unknown link (kind=%u in_idx=%lu)", in_kind, in_idx ));
}

static inline void
after_frag( ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq FD_PARAM_UNUSED,
            ulong                  sig FD_PARAM_UNUSED,
            ulong                  sz,
            ulong                  tsorig FD_PARAM_UNUSED,
            ulong                  tspub FD_PARAM_UNUSED,
            fd_stem_context_t *    stem FD_PARAM_UNUSED ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  if( FD_LIKELY( in_kind==IN_KIND_NET ) ) {
    uchar * payload; ulong payload_sz;
    if( FD_UNLIKELY( !fd_ip4_udp_hdr_strip( ctx->buffer, sz, &payload, &payload_sz, NULL, NULL, NULL ) ) ) {
      FD_LOG_WARNING(( "rserve: malformed packet (sz=%lu)", sz ));
      return;
    }

    if( FD_UNLIKELY( payload_sz<4 ) ) return;
    uint tag = FD_LOAD( uint, payload );

    switch (tag) {
      case FD_REPAIR_KIND_SHRED: {
        FD_LOG_NOTICE(("got shred message: %lu", payload_sz));
        if( FD_UNLIKELY( payload_sz!=160UL ) ) return;

        fd_repair_msg_t const * msg = (fd_repair_msg_t const *)payload;
        fd_repair_shred_req_t const * request = &msg->shred;

        if( FD_UNLIKELY( !fd_pubkey_eq( &ctx->identity_public_key, &request->to ) ) ) {
          /* The message wasn't intended for us, ignore. */
          return;
        }


        long current = fd_log_wallclock();
        (void)current;
        /* check timestamp */

        /* TODO: check the IP */
        // {
        //   char buf[ FD_BASE58_ENCODED_32_SZ ]; ulong msg_sz;
        //   fd_base58_encode_32( request->from.uc, &msg_sz, buf );
        //   FD_LOG_NOTICE(( "from: %s", buf ));
        // }
        // {
        //   char buf[ FD_BASE58_ENCODED_32_SZ ]; ulong msg_sz;
        //   fd_base58_encode_32( request->to.uc, &msg_sz, buf );
        //   FD_LOG_NOTICE(( "dest pubkey %s", buf ));
        // }

        (void)request;

        /* TODO: verify signature */

        if( FD_UNLIKELY( fd_pubkey_eq( &ctx->identity_public_key, &request->from ) ) ) {
          /* We've received our own repair request, ignore. */
          return;
        }

        /* TODO: fd_ledger_query( ) */
        /* TODO: send response */

        return;
      }
    }

    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) {
    fd_shred_t const * shred = (fd_shred_t const *)ctx->buffer;
    /* Skip input code shreds, we only store data shreds. */
    if( !fd_shred_is_data( fd_shred_type( shred->variant ) ) ) return;

    // ulong slot = fd_disco_shred_out_shred_sig_slot( sig );
    // uint index = fd_disco_shred_out_shred_sig_shred_idx( sig );

    // /* The shred tile will have inserted */
    // fd_hash_t mr = FD_LOAD( fd_hash_t, (uchar const *)fd_type_pun_const( ctx->buffer ) + FD_SHRED_DATA_HEADER_SZ );

    // uchar buffer[ FD_SHRED_MIN_SZ ];
    // (void)buffer;

    // FD_STORE_SLOCK_BEGIN( ctx->store ) {
    //   fd_store_fec_t const * set = fd_store_query( ctx->store, &mr );
    //   if( FD_UNLIKELY( !set ) ) {
    //     /* Something bad must have happened, and the rserve process was stalled
    //        for long enough that the replay tile has removed the entry from the store.

    //        This brings up some questions regarding liveness, and if enough stake
    //        behaves in a similar manner it is possible certain blocks become
    //        un-repairable, but for now we will simply log a metric/warning and move
    //        on. It is valid for us to not have the requested shred.

    //        TODO: There are several solutions possible to mitigate this, such
    //        as reference counting the store entries or structuring the pipeline
    //        in a way where the repair server is guarnteed to have read the entry
    //        before replay is allowed to remove it.*/
    //     FD_LOG_WARNING(( "store query not found (slot=%lu, idx=%u)", slot, index ));
    //   }

    //   FD_LOG_NOTICE(("total size: %lu, each size: %lu, expected: %lu", set->data_sz, set->data_sz / 32, FD_SHRED_DATA_PAYLOAD_MAX ));
    // } FD_STORE_SLOCK_END;

    // FD_TEST( set ); /* TODO: I do not believe this is sound, this tile could have stalled and the replay tile consumed the store entry and removed it. */

    // (void)set;

    // FD_LOG_NOTICE(( "rserve: got data shred_out message" ));

    // fd_ledger_insert( ctx->ledger, ctx->buffer, FD_SHRED_MIN_SZ, slot, shred_index );

    // FD_LOG_NOTICE(("inserted shred, ledger now contains: %lu", ctx->ledger->cnt ));

    return;
  }
}

static inline void
during_housekeeping( ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: unhalting" ));
    FD_CRIT( ctx->is_halting_signing, "state machine corruption" );
    memcpy( ctx->identity_public_key.uc, ctx->keyswitch->bytes, sizeof(fd_pubkey_t) );
    ctx->is_halting_signing = 0;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ctx->is_halting_signing = 1;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong max_slots = tile->rserve.max_slots;
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  ctx->ledger = FD_SCRATCH_ALLOC_APPEND( l, fd_ledger_align(), fd_ledger_footprint( max_slots  ) );

  ulong ledger_seed;
  FD_TEST( fd_rng_secure( &ledger_seed, sizeof(ulong) ) );

  FD_LOG_NOTICE(( "creating ledger (max_slots=%lu)", max_slots ));
  ctx->ledger = fd_ledger_join( fd_ledger_new( ctx->ledger, max_slots, tile->rserve.ledger_path, ledger_seed ) );
  if( FD_UNLIKELY( !ctx->ledger ) ) FD_LOG_ERR(( "failed to initialize ledger" ));

  uchar const * identity_public_key = fd_keyload_load( tile->repair.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_public_key.uc, identity_public_key, sizeof(fd_pubkey_t) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong max_slots = tile->rserve.max_slots;
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),    sizeof(ctx_t) );
                FD_SCRATCH_ALLOC_APPEND( l, fd_ledger_align(), fd_ledger_footprint( max_slots ) );
  ctx->rserve = FD_SCRATCH_ALLOC_APPEND( l, fd_rserve_align(), fd_rserve_footprint() );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() )==(ulong)scratch + scratch_footprint( tile ) );

  (void)ctx->ledger; /* Initialized in privileged_init */
  ctx->rserve    = fd_rserve_join   ( fd_rserve_new( ctx->rserve ) );
  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  ctx->is_halting_signing = 0;
  ctx->net_id = (ushort)0;
  fd_ip4_udp_hdr_init( ctx->serve_hdr, FD_RSERVE_MAX_PACKET_SIZE, 0, tile->rserve.repair_serve_listen_port );
  fd_sha512_new( ctx->sha512 );

  FD_TEST( tile->in_cnt>=1UL );
  for( ulong in_idx=0UL; in_idx<tile->in_cnt; in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if( 0==strcmp( link->name, "net_rserve" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in_links[ in_idx ].net_rx, link->dcache );
      continue;
    }
    else if( 0==strcmp( link->name, "shred_out"  ) ) ctx->in_kind[ in_idx ] = IN_KIND_SHRED;
    else FD_LOG_ERR(( "rserve tile has unexpected input link: %s", link->name ));

    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;
  }

  ctx->net_out_idx = UINT_MAX;
  for( uint out_idx=0U; out_idx<tile->out_cnt; out_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];
    if( 0==strcmp( link->name, "rserve_net" ) ) {
      if( ctx->net_out_idx!=UINT_MAX ) continue; /* only use the first net link */
      ctx->net_out_idx    = out_idx;
      ctx->net_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, link->dcache );
      ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, link->dcache, link->mtu );
      ctx->net_out_chunk  = ctx->net_out_chunk0;
    } else {
      FD_LOG_ERR(( "rserve tile has unexpected output link: %s", link->name ));
    }
  }
  if( FD_UNLIKELY( ctx->net_out_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing rserve_net output link" ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_rserve_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_rserve_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG before_frag
#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_rserve = {
  .name                     = "rserve",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
