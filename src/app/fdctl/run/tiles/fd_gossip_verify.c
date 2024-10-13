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

struct fd_gossip_verify_tile_ctx {
  ulong          round_robin_idx;
  ulong          round_robin_cnt;

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
    FD_LOG_ERR(( "fd_ed25519_verify failed" ));
    return -1;
  }
  return 0;
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_gossip_verify_tile_ctx_t) );
}

static void
before_frag( void * _ctx      FD_PARAM_UNUSED,
             ulong  in_idx    FD_PARAM_UNUSED,
             ulong  seq       FD_PARAM_UNUSED,
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
            ulong *            opt_chunk  FD_PARAM_UNUSED,
            ulong *            opt_sz     FD_PARAM_UNUSED,
            ulong *            opt_tsorig FD_PARAM_UNUSED,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  fd_gossip_verify_tile_ctx_t * ctx = (fd_gossip_verify_tile_ctx_t *)_ctx;


  ctx->mux = mux;
  ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
  fd_net_hdrs_t * hdr = (fd_net_hdrs_t *) fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );


  // fd_gossip_peer_addr_t peer_addr;
  // peer_addr.l    = 0;
  // peer_addr.addr = FD_LOAD( uint, hdr->ip4->saddr_c );
  // peer_addr.port = hdr->udp->net_sport;

  // uchar * gossip_msg = ctx->gossip_verify_buffer + hdr_sz;
  uchar * udp_payload = (uchar *)hdr + hdr_sz;
  ulong payload_sz = (*opt_sz - hdr_sz);

  if( FD_UNLIKELY( payload_sz > FD_NET_MTU ) ) {
    FD_LOG_ERR(( "gossip_verify payload_sz %lu > FD_NET_MTU %lu", payload_sz, FD_NET_MTU ));
  }

  /* GOSSIP VERIFY LOGIC STARTS HERE*/
  ulong sig = 0UL;
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

    fd_signature_t * signature = NULL;
    fd_pubkey_t    * pubkey    = NULL;

    /* NOTE: pull req packets are skipped */
    switch( gossip_msg->discriminant ){
      case fd_gossip_msg_enum_pull_resp:
      // fallthrough
      case fd_gossip_msg_enum_push_msg:
      // TODO: verify crds
      break;
      case fd_gossip_msg_enum_prune_msg:
      // TODO: verify prune msg
      break;
      case fd_gossip_msg_enum_ping:
      // TODO: check if can fallthrough
      break;
      case fd_gossip_msg_enum_pong:
      // TODO
      break;
  }
  
  if( FD_UNLIKELY( res != GOSSIP_VERIFY_SUCCESS ) ) {
    *opt_filter = 1;
    return;
  }






  } FD_SCRATCH_SCOPE_END;



  /* GOSSIP VERIFY LOGIC ENDS HERE, assuming returned on fail */
  ctx->gossip_out_chunk = fd_dcache_compact_next( ctx->gossip_out_chunk, *opt_sz, ctx->gossip_out_chunk0, ctx->gossip_out_wmark );

}

/* DO WE NEED FLOW CONTROL HERE? PROBABLY??? */
// static void
// after_credit( void *             _ctx,
//               fd_mux_context_t * mux_ctx,
//               int *              opt_poll_in ) {

// }

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
  .name                     = "gossip_verify",
  .mux_flags                = FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
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