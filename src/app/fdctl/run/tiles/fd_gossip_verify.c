#include "tiles.h"
// #include "fd_verify.h"

#include "generated/verify_seccomp.h"

#include "../../../../disco/quic/fd_tpu.h"
#include "../../../../flamenco/types/fd_bincode.h"
#include "../../../../flamenco/types/fd_types.h"
#include "../../../../util/net/fd_eth.h"

#include <linux/unistd.h>

#define GOSSIP_VERIFY_SUCCESS  0
#define GOSSIP_VERIFY_FAILED  -1
#define GOSSIP_VERIFY_DEDUP   -2

#define GOSSIP_VERIFY_SCRATCH_MAX (1UL<<20UL)
#define GOSSIP_VERIFY_SCRATCH_DEPTH (4UL)


typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_gossip_verify_in_ctx_t;

typedef struct {
    fd_sha512_t *             sha[ FD_TXN_ACTUAL_SIG_MAX ];
    fd_gossip_verify_in_ctx_t in[ 32 ];
    fd_wksp_t *               out_mem;
    ulong                     out_chunk0;
    ulong                     out_wmark;
    ulong                     out_chunk;
    ushort                    gossip_listen_port;
    
    ulong                     round_robin_cnt;
    ulong                     round_robin_id;
} fd_gossip_verify_ctx_t;

static int
gossip_verify( fd_gossip_verify_ctx_t * ctx,
               uchar const *            msg,
               ulong                    msg_sz,
               fd_signature_t *         signature,
               fd_pubkey_t *            pubkey ) {

  int res = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signature->uc, pubkey->uc, ctx->sha, 1 );
  if( FD_UNLIKELY( res != FD_ED25519_SUCCESS ) ) {
    return GOSSIP_VERIFY_FAILED;
  }

  return GOSSIP_VERIFY_SUCCESS;
}

/* The verify tile is a wrapper around the mux tile, that also verifies
   incoming transaction signatures match the data being signed.
   Non-matching transactions are filtered out of the frag stream. */

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_sha512_align();
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_gossip_verify_ctx_t ), sizeof( fd_gossip_verify_ctx_t ) );
  for( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_sha512_align(), fd_sha512_footprint() );
  }
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( GOSSIP_VERIFY_SCRATCH_DEPTH ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( GOSSIP_VERIFY_SCRATCH_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_gossip_verify_ctx_t ) );
}

static fd_pubkey_t *
get_pubkey_from_crds( fd_crds_value_t * crd ) {
  fd_pubkey_t * pubkey;
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
    default:
      return NULL;
  }
  return pubkey;
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;

  fd_gossip_verify_ctx_t * ctx = (fd_gossip_verify_ctx_t *)_ctx;

  if( FD_UNLIKELY( seq % ctx->round_robin_cnt != ctx->round_robin_id ) ) {
    *opt_filter = 1;
    return;
  }

  ushort dst_port    = fd_disco_netmux_sig_port( sig );
  ushort src_tile    = fd_disco_netmux_sig_src_tile( sig );

  if( FD_UNLIKELY( src_tile!=SRC_TILE_NET ) ) {
    *opt_filter = 1;
    return;
  }

  if ( FD_UNLIKELY( dst_port != ctx->gossip_listen_port ) ) {
    *opt_filter = 1;
    return;
  }
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( void * _ctx,
             ulong in_idx,
             ulong seq,
             ulong sig,
             ulong chunk,
             ulong sz,
             int * opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_gossip_verify_ctx_t * ctx = (fd_gossip_verify_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz > FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  fd_memcpy( dst, src, sz );
}

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_sig;
  (void)opt_tsorig;
  (void)mux;

  fd_gossip_verify_ctx_t * ctx = (fd_gossip_verify_ctx_t *)_ctx;

  ulong network_hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );

  uchar * udp_payload = ((uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk ) + network_hdr_sz);
  ulong payload_sz = (*opt_sz - network_hdr_sz);

    /* Make sure payload_sz is valid */
  if( FD_UNLIKELY( payload_sz > FD_NET_MTU ) ) {
    FD_LOG_ERR( ("invalid payload_sz(%x)", payload_sz) );
  }

  ulong sig = 0;
  FD_SCRATCH_SCOPE_BEGIN {
    fd_bincode_decode_ctx_t decode_ctx = { .data = udp_payload, .dataend = udp_payload + payload_sz, .valloc = fd_scratch_virtual() };
    fd_gossip_msg_t gmsg[1];
    if ( FD_BINCODE_SUCCESS != fd_gossip_msg_decode( gmsg, &decode_ctx ) ) {
      FD_LOG_ERR(( "Gossip message decode failed" ));
    }
    int res = 0;

    fd_signature_t * signature = NULL;

    fd_pubkey_t    * pubkey    = NULL;
    switch ( gmsg->discriminant ) {
      case fd_gossip_msg_enum_pull_req: {
        signature = &gmsg->inner.pull_req.value.signature;
        fd_crds_value_t * crd = &gmsg->inner.pull_req.value;

        uchar buf[FD_ETH_PAYLOAD_MAX];
        fd_bincode_encode_ctx_t encode_ctx;
        encode_ctx.data = buf;
        encode_ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
        if ( fd_crds_data_encode( &crd->data, &encode_ctx ) ) {
          FD_LOG_ERR(("fd_crds_data_encode failed"));
        }

        pubkey = get_pubkey_from_crds( crd );
        res |= gossip_verify( ctx, buf, (ulong)((uchar*)encode_ctx.data - buf), signature, pubkey );
        sig = signature->ul[0];
        break;
      }
      case fd_gossip_msg_enum_pull_resp: {
        fd_gossip_pull_resp_t * pull_resp = &gmsg->inner.pull_resp;
        for (ulong i = 0; i < pull_resp->crds_len; ++i) {
          signature = &pull_resp->crds[i].signature;
          fd_crds_value_t * crd = &pull_resp->crds[i];

          uchar buf[FD_ETH_PAYLOAD_MAX];
          fd_bincode_encode_ctx_t encode_ctx;
          encode_ctx.data = buf;
          encode_ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
          if ( fd_crds_data_encode( &crd->data, &encode_ctx ) ) {
            FD_LOG_ERR(("fd_crds_data_encode failed"));
          }

          pubkey = get_pubkey_from_crds( crd );
          if (!pubkey)
            pubkey = &pull_resp->pubkey;
          res |= gossip_verify( ctx, buf, (ulong)((uchar*)encode_ctx.data - buf), signature, pubkey );
          sig ^= signature->ul[0];
        }
        break;
      }
      case fd_gossip_msg_enum_push_msg: {
        fd_gossip_push_msg_t * push_msg = &gmsg->inner.push_msg;
        for (ulong i = 0; i < push_msg->crds_len; ++i) {
          signature = &push_msg->crds[i].signature;
          fd_crds_value_t * crd = &push_msg->crds[i];

          uchar buf[FD_ETH_PAYLOAD_MAX];
          fd_bincode_encode_ctx_t encode_ctx;
          encode_ctx.data = buf;
          encode_ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
          if ( fd_crds_data_encode( &crd->data, &encode_ctx ) ) {
            FD_LOG_ERR(("fd_crds_data_encode failed"));
          }

          pubkey = get_pubkey_from_crds( crd );
          if (!pubkey)
            pubkey = &push_msg->pubkey;
          res |= gossip_verify( ctx, buf, (ulong)((uchar*)encode_ctx.data - buf), signature, pubkey );
          sig ^= signature->ul[0];
        }
        break;
      }
      case fd_gossip_msg_enum_prune_msg: {
        signature = &gmsg->inner.prune_msg.data.signature;
        pubkey    = &gmsg->inner.prune_msg.pubkey;
        uchar buf[FD_ETH_PAYLOAD_MAX];
        fd_bincode_encode_ctx_t encode_ctx;
        encode_ctx.data = buf;
        encode_ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;

        fd_gossip_prune_msg_t * msg = &gmsg->inner.prune_msg;
        fd_gossip_prune_sign_data_t signdata;
        signdata.pubkey = msg->data.pubkey;
        signdata.prunes_len = msg->data.prunes_len;
        signdata.prunes = msg->data.prunes;
        signdata.destination = msg->data.destination;
        signdata.wallclock = msg->data.wallclock;

        if ( fd_gossip_prune_sign_data_encode( &signdata, &encode_ctx ) ) {
          FD_LOG_ERR(("fd_gossip_prune_sign_data_encode failed"));
          return;
        }

        res |= gossip_verify( ctx, buf, (ulong)((uchar*)encode_ctx.data - buf), signature, pubkey );
        sig = signature->ul[0];
        break;
      }
      case fd_gossip_msg_enum_ping: {
        signature = &gmsg->inner.ping.signature;
        pubkey    = &gmsg->inner.ping.from;
        res |= gossip_verify( ctx, gmsg->inner.ping.token.uc, 32UL, signature, pubkey );
        sig = signature->ul[0];
        break;
      }
      case fd_gossip_msg_enum_pong: {
        signature = &gmsg->inner.pong.signature;
        pubkey    = &gmsg->inner.pong.from;
        res |= gossip_verify( ctx, gmsg->inner.pong.token.uc, 32UL, signature, pubkey );
        sig = signature->ul[0];
        break;
      }
    }

    if( FD_UNLIKELY( res != GOSSIP_VERIFY_SUCCESS ) ) {
      *opt_filter = 1;
      return;
    }
  } FD_SCRATCH_SCOPE_END;

  *opt_filter = 0;
  *opt_chunk = ctx->out_chunk;

  // Adding first 8 bytes of signature for gossip dedup
  FD_STORE( ulong, udp_payload + payload_sz, sig);
  *opt_sz += sizeof(ulong);
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, *opt_sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gossip_verify_ctx_t ), sizeof( fd_gossip_verify_ctx_t ) );

  for ( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    ctx->sha[i] = sha;
  }

  ulong * scratch_fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( GOSSIP_VERIFY_SCRATCH_DEPTH ) );
  uchar * scratch_smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( GOSSIP_VERIFY_SCRATCH_MAX ) );
  fd_scratch_attach( scratch_smem, scratch_fmem, GOSSIP_VERIFY_SCRATCH_MAX, GOSSIP_VERIFY_SCRATCH_DEPTH );

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ link->wksp_id ];

    ctx->in[i].mem = link_wksp->wksp;
    if( FD_UNLIKELY( link->kind==FD_TOPO_LINK_KIND_QUIC_TO_VERIFY ) ) {
      ctx->in[i].chunk0 = fd_laddr_to_chunk( ctx->in[i].mem, link->dcache );
      ctx->in[i].wmark  = ctx->in[i].chunk0 + (link->depth+link->burst-1) * FD_TPU_REASM_CHUNK_MTU;
    } else {
      ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
      ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    }
  }

  ctx->out_mem    = topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;
  ctx->gossip_listen_port = tile->gossip_verify.gossip_listen_port;

  ctx->round_robin_cnt = fd_topo_tile_kind_cnt( topo, tile->kind );
  ctx->round_robin_id = tile->kind_id;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_verify( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_verify_instr_cnt;
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

fd_tile_config_t fd_tile_gossip_verify = {
  .mux_flags                = FD_MUX_FLAG_COPY, /* must copy frags for tile isolation and security */
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .mux_before_frag          = before_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = NULL,
  .unprivileged_init        = unprivileged_init,
};
