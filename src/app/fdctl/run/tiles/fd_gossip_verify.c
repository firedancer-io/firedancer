/* Gossip verify tile sits before the gossip (dedup?) tile to verify incoming
   gossip packets */
#define _GNU_SOURCE

#include "../../../../disco/tiles.h"

#include "../../../../disco/fd_disco.h"
#include "../../../../flamenco/gossip/fd_gossip.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/store/util.h"
#include "../../../../flamenco/runtime/fd_system_ids.h"
#include "../../../../util/fd_util.h"
#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"
#include "../../../../util/net/fd_net_headers.h"

// FIXME: separate seccomp policy for gossip_verify?
#include "generated/gossip_seccomp.h"

#define NET_IN_IDX      0

#define GOSSIP_OUT_IDX  0

#define GOSSIP_VERIFY_SUCCESS  0
#define GOSSIP_VERIFY_FAILED  -1
#define GOSSIP_VERIFY_DEDUP   -2

#define GOSSIP_VERIFY_SCRATCH_MAX (1UL<<20UL)
#define GOSSIP_VERIFY_SCRATCH_DEPTH (4UL)

#define PACKET_DATA_SIZE 1232

struct fd_gossip_verify_tile_ctx {
  ulong          round_robin_idx;
  ulong          round_robin_cnt;
  fd_pubkey_t    identity_public_key[1];

  fd_wksp_t *     net_in_mem;
  ulong           net_in_chunk;
  ulong           net_in_wmark;

  fd_frag_meta_t * gossip_out_mcache;
  ulong *          gossip_out_sync;
  ulong            gossip_out_depth;
  ulong            gossip_out_seq;

  fd_wksp_t *     gossip_out_mem;
  ulong           gossip_out_chunk0;
  ulong           gossip_out_wmark;
  ulong           gossip_out_chunk;

  fd_mux_context_t * mux;
};

typedef struct fd_gossip_verify_tile_ctx fd_gossip_verify_tile_ctx_t;

static int
fd_gossip_verify( uchar const *                 msg,
                  ulong                         msg_sz,
                  fd_signature_t *              signature,
                  fd_pubkey_t *                 pubkey ) {
  fd_sha512_t sha[1];
  if( fd_ed25519_verify( msg, msg_sz, signature->uc, pubkey->key, sha ) ) {
    FD_LOG_WARNING(( "received gossip packet with invalid signature" ));
    return GOSSIP_VERIFY_FAILED;
  }
  return GOSSIP_VERIFY_SUCCESS;
}

static int
fd_gossip_verify_crds_value(  fd_pubkey_t *     pubkey,
                              fd_crds_value_t * crd,
                              fd_pubkey_t *     my_pubkey ) {
/* Grab pubkey from crds value */
  switch (crd->data.discriminant) {
  case fd_crds_data_enum_contact_info_v1:
    pubkey = &crd->data.inner.contact_info_v1.id;
    break;
  case fd_crds_data_enum_vote:
    pubkey = &crd->data.inner.vote.from;
    break;
  case fd_crds_data_enum_lowest_slot:
    pubkey = &crd->data.inner.lowest_slot.from;
    break;
  case fd_crds_data_enum_snapshot_hashes:
    pubkey = &crd->data.inner.snapshot_hashes.from;
    break;
  case fd_crds_data_enum_accounts_hashes:
    pubkey = &crd->data.inner.accounts_hashes.from;
    break;
  case fd_crds_data_enum_epoch_slots:
    pubkey = &crd->data.inner.epoch_slots.from;
    break;
  case fd_crds_data_enum_version_v1:
    pubkey = &crd->data.inner.version_v1.from;
    break;
  case fd_crds_data_enum_version_v2:
    pubkey = &crd->data.inner.version_v2.from;
    break;
  case fd_crds_data_enum_node_instance:
    pubkey = &crd->data.inner.node_instance.from;
    break;
  case fd_crds_data_enum_duplicate_shred:
    pubkey = &crd->data.inner.duplicate_shred.from;
    break;
  case fd_crds_data_enum_incremental_snapshot_hashes:
    pubkey = &crd->data.inner.incremental_snapshot_hashes.from;
    break;
  case fd_crds_data_enum_contact_info_v2:
    pubkey = &crd->data.inner.contact_info_v2.from;
    break;
  default:
    // FIXME: this deviates slightly from flamenco/gossip.c's fd_gossip_recv_crds_value
    return GOSSIP_VERIFY_FAILED;
  }
  if(memcmp(pubkey->uc, my_pubkey->uc, 32U) == 0)
    /* Ignore my own messages. Dedup case?? */
    return GOSSIP_VERIFY_FAILED;
  
  /* FIXME: use scratch instead? Is this region memset every time? */
  uchar buf[PACKET_DATA_SIZE];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + PACKET_DATA_SIZE;

  if( fd_crds_data_encode( &crd->data, &ctx ) ) {
    FD_LOG_ERR(("fd_crds_value_encode failed"));
    return GOSSIP_VERIFY_FAILED;
  }

  if( fd_gossip_verify( buf, (ulong)((uchar*)ctx.data - buf), &crd->signature, pubkey ) ) {
    return GOSSIP_VERIFY_FAILED;
  }

  return GOSSIP_VERIFY_SUCCESS;
}

static void
fd_gossip_verify_crds_list( fd_crds_value_t * crds,
                            ulong             crds_len,
                            fd_pubkey_t     * pubkey,
                            fd_pubkey_t     * my_pubkey ) {
  for( ulong i = 0; i < crds_len; ++i ) {
    if( fd_gossip_verify_crds_value( pubkey, &crds[i], my_pubkey ) ) {
      // TODO: filter/mark invalid crds. Is clobbering the discriminant enough?
      crds[i].data.discriminant = UINT_MAX;
    }
  }
  return;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}


FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_verify_tile_ctx_t), sizeof(fd_gossip_verify_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( GOSSIP_VERIFY_SCRATCH_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( GOSSIP_VERIFY_SCRATCH_DEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_gossip_verify_tile_ctx_t) );
}

static void
before_frag( void * _ctx      FD_PARAM_UNUSED,
             ulong  in_idx    FD_PARAM_UNUSED,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  fd_gossip_verify_tile_ctx_t * ctx = (fd_gossip_verify_tile_ctx_t *)_ctx;

  if( FD_LIKELY( seq % ctx->round_robin_cnt != ctx->round_robin_idx ) ) {
    *opt_filter = 1;
    return;
  }

  if( fd_disco_netmux_sig_proto( sig ) != DST_PROTO_GOSSIP ) {
    *opt_filter = 1;
    return;
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx    FD_PARAM_UNUSED,
             ulong  seq       FD_PARAM_UNUSED,
             ulong  sig       FD_PARAM_UNUSED,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  fd_gossip_verify_tile_ctx_t * ctx = (struct fd_gossip_verify_tile_ctx *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->net_in_chunk || chunk>ctx->net_in_wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->net_in_chunk, ctx->net_in_wmark ));
    *opt_filter = 1;
    return;
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->net_in_mem, chunk );
  uchar * dst = fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );

  fd_memcpy( dst, dcache_entry, sz );
}

static void
after_frag( void *             _ctx,
            ulong              in_idx     FD_PARAM_UNUSED,
            ulong              seq        FD_PARAM_UNUSED,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig FD_PARAM_UNUSED,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  fd_gossip_verify_tile_ctx_t * ctx = (fd_gossip_verify_tile_ctx_t *)_ctx;


  ctx->mux = mux;
  ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
  fd_net_hdrs_t * hdr = (fd_net_hdrs_t *) fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );

  uchar * udp_payload = (uchar *)hdr + hdr_sz;
  ulong payload_sz = (*opt_sz - hdr_sz);

  if( FD_UNLIKELY( payload_sz > FD_NET_MTU ) ) {
    FD_LOG_ERR(( "gossip_verify payload_sz %lu > FD_NET_MTU %lu", payload_sz, FD_NET_MTU ));
  }

  /* GOSSIP VERIFY LOGIC STARTS HERE */
  // ulong sig = 0UL; // figure out what to do with this
  FD_SCRATCH_SCOPE_BEGIN {
    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = udp_payload,
      .dataend = udp_payload + payload_sz,
      .valloc  = fd_scratch_virtual()
    };
    fd_gossip_msg_t gossip_msg[1];
    if( fd_gossip_msg_decode( gossip_msg, &decode_ctx ) ) {
      FD_LOG_ERR(( "fd_gossip_msg_decode failed" ));
      *opt_filter = 1;
      return;
    }

    int res = 0;


    /* NOTE: pull req packets are skipped */
    switch( gossip_msg->discriminant ) {
    case fd_gossip_msg_enum_pull_resp: {
      fd_gossip_pull_resp_t * pull_resp = &gossip_msg->inner.pull_resp;
      fd_gossip_verify_crds_list( pull_resp->crds,
                                  pull_resp->crds_len,
                                  &pull_resp->pubkey,
                                  ctx->identity_public_key );
      break;
    }
    case fd_gossip_msg_enum_push_msg: {
      fd_gossip_push_msg_t * push_msg = &gossip_msg->inner.push_msg;
      fd_gossip_verify_crds_list( push_msg->crds,
                                  push_msg->crds_len,
                                  &push_msg->pubkey,
                                  ctx->identity_public_key );
      break;
    }
    break;
    case fd_gossip_msg_enum_prune_msg: {
      fd_gossip_prune_msg_t * prune_msg = &gossip_msg->inner.prune_msg;
      /* FIXME: put this in a separate inline function */
      /* Confirm destination */
      if( memcmp( prune_msg->data.destination.uc, ctx->identity_public_key->uc, 32U ) != 0 ) {
        res = GOSSIP_VERIFY_DEDUP;
      }

      /* Verify signature */
      fd_gossip_prune_sign_data_t signdata;
      signdata.pubkey = prune_msg->data.pubkey;
      signdata.prunes_len = prune_msg->data.prunes_len;
      signdata.prunes = prune_msg->data.prunes;
      signdata.destination = prune_msg->data.destination;
      signdata.wallclock = prune_msg->data.wallclock;
      
      /* FIXME: use scratch space */
      uchar buf[PACKET_DATA_SIZE];
      fd_bincode_encode_ctx_t ctx;
      ctx.data = buf;
      ctx.dataend = buf + PACKET_DATA_SIZE;
      if ( fd_gossip_prune_sign_data_encode( &signdata, &ctx ) ) {
        res = GOSSIP_VERIFY_FAILED;
        break;
      }
      res = fd_gossip_verify( buf,
                              (ulong)((uchar*)ctx.data - buf),
                              &prune_msg->data.signature,
                              &prune_msg->data.pubkey );
      break;
    }
    /* TODO: Check if safe to cast both messages to fd_gossip_ping_t */
    case fd_gossip_msg_enum_ping: 
    case fd_gossip_msg_enum_pong: {
      fd_gossip_ping_t * ping = &gossip_msg->inner.ping;
      res = fd_gossip_verify( ping->token.uc,
                              32UL,
                              &ping->signature,
                              &ping->from );
      break;
    }
    }
  
    if( FD_UNLIKELY( res != GOSSIP_VERIFY_SUCCESS ) ) {
      *opt_filter = 1;
      return;
    }

  } FD_SCRATCH_SCOPE_END;

  /* GOSSIP VERIFY LOGIC ENDS HERE, assuming returned on fail */
  *opt_chunk = ctx->gossip_out_chunk;
  ctx->gossip_out_chunk = fd_dcache_compact_next( ctx->gossip_out_chunk, *opt_sz, ctx->gossip_out_chunk0, ctx->gossip_out_wmark );
}

static void
privileged_init( fd_topo_t      * topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile,
                 void           * scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_verify_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_verify_tile_ctx_t), sizeof(fd_gossip_verify_tile_ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->gossip.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_public_key, identity_key, sizeof(fd_pubkey_t) );
}

static void
unprivileged_init( fd_topo_t      * topo,
                   fd_topo_tile_t * tile,
                   void           * scratch ) {
  if( FD_UNLIKELY( tile->in_cnt != 1UL ||
                   strcmp( topo->links[ tile->in_link_id[ NET_IN_IDX ] ].name, "net_gspvfy" ) ) ) {
    FD_LOG_ERR(( "gossip_verify tile has none or unexpected input links %lu %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ||
                   strcmp( topo->links[ tile->out_link_id_primary ].name, "gspvfy_gossi" ) ) ) {
    FD_LOG_ERR(( "gossip_verify tile has none or unexpected output links %lu %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_link_id_primary==ULONG_MAX ) ) {
    FD_LOG_ERR(( "gossip_verify tile has no primary output link" ));
  }

  /* Scratch mem setup */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_verify_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_verify_tile_ctx_t), sizeof(fd_gossip_verify_tile_ctx_t) );
  
  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( GOSSIP_VERIFY_SCRATCH_MAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( GOSSIP_VERIFY_SCRATCH_DEPTH ) );

  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, GOSSIP_VERIFY_SCRATCH_MAX, GOSSIP_VERIFY_SCRATCH_DEPTH );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  fd_topo_link_t * gossip_out = &topo->links[ tile->out_link_id_primary ];

  ctx->gossip_out_mcache = gossip_out->mcache;
  ctx->gossip_out_sync = fd_mcache_seq_laddr( ctx->gossip_out_mcache );
  ctx->gossip_out_depth = fd_mcache_depth( ctx->gossip_out_mcache );
  ctx->gossip_out_seq = fd_mcache_seq_query( ctx->gossip_out_sync );
  ctx->gossip_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( gossip_out->dcache ), gossip_out->dcache );
  ctx->gossip_out_mem = topo->workspaces[ topo->objs[ gossip_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->gossip_out_wmark = fd_dcache_compact_wmark( ctx->gossip_out_mem, gossip_out->dcache, gossip_out->mtu );
  ctx->gossip_out_chunk = ctx->gossip_out_chunk0;

  fd_topo_link_t * net_in = &topo->links[ tile->in_link_id[ NET_IN_IDX ] ];

  ctx->net_in_mem = topo->workspaces[ topo->objs[ net_in->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_in_chunk = fd_dcache_compact_chunk0( ctx->net_in_mem, net_in->dcache );
  ctx->net_in_wmark = fd_dcache_compact_wmark( ctx->net_in_mem, net_in->dcache, net_in->mtu );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > ( (ulong)scratch + scratch_footprint( tile ) ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }
}

static ulong
populate_allowed_seccomp( void *               scratch FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_gossip( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_gossip_instr_cnt;
}


static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}


fd_topo_run_tile_t fd_tile_gossip_verify = {
  .name                     = "gspvfy",
  .mux_flags                = FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
