#define _GNU_SOURCE
#include "../../../../disco/tiles.h"

#include <sys/socket.h>

#include "generated/nettx_seccomp.h"

#include "../../../../disco/metrics/fd_metrics.h"

#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"

#include <errno.h>
#include <netinet/in.h>

#define MAX_NETTX_INS (32UL)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_nettx_in_ctx_t;

typedef struct {
  int send_fd;

  ulong round_robin_id;
  ulong round_robin_cnt;

  ulong                   frame_start;
  ulong                   frame_cnt;
  struct sockaddr_storage addr[ 1024 ];
  struct iovec            iov[ 1024 ];
  struct mmsghdr          hdr[ 2048 ];
  uchar                   frame[ 1024 ][ FD_NET_MTU ];

  ulong             in_cnt;
  fd_nettx_in_ctx_t in[ MAX_NETTX_INS ];

  struct {
    ulong tx_cnt;
    ulong tx_sz;
  } metrics;
} fd_nettx_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_nettx_ctx_t), sizeof(fd_nettx_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_nettx_ctx_t * ctx ) {
  if( FD_LIKELY( !ctx->frame_cnt ) ) return;

  FD_LOG_WARNING(( "Got out2 packet, size: %lu", (ctx->hdr+ctx->frame_start)->msg_hdr.msg_iov->iov_len ));

  FD_LOG_HEXDUMP_WARNING(( "frame", (ctx->hdr+ctx->frame_start)->msg_hdr.msg_iov->iov_base, (ctx->hdr+ctx->frame_start)->msg_hdr.msg_iov->iov_len ));

  int sent_cnt = sendmmsg( ctx->send_fd, ctx->hdr+ctx->frame_start, (uint)ctx->frame_cnt, MSG_DONTWAIT );
  if( FD_UNLIKELY( -1==sent_cnt && errno!=EAGAIN ) ) {
    FD_LOG_ERR(( "sendmmsg failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  }
  FD_TEST( sent_cnt ); /* Should not be zero, -1 indicates error */

  ctx->frame_start = (ctx->frame_start+(ulong)sent_cnt)%1024UL;
  ctx->frame_cnt -= (ulong)sent_cnt;

  FD_LOG_WARNING(( "sent %d packets", sent_cnt ));
}

static inline void
metrics_write( fd_nettx_ctx_t * ctx ) {
  FD_MCNT_SET( NET_TX_TILE, SENT_PACKETS, ctx->metrics.tx_cnt );
  FD_MCNT_SET( NET_TX_TILE, SENT_BYTES,   ctx->metrics.tx_sz  );
}

static void
after_credit( fd_nettx_ctx_t *    ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)stem;

  if( FD_LIKELY( ctx->frame_cnt<1024UL ) ) return;

  *charge_busy = 1;

  FD_LOG_HEXDUMP_WARNING(( "frame", (ctx->hdr+ctx->frame_start)->msg_hdr.msg_iov, (ctx->hdr+ctx->frame_start)->msg_hdr.msg_iovlen ));

  int sent_cnt = sendmmsg( ctx->send_fd, ctx->hdr+ctx->frame_start, (uint)ctx->frame_cnt, MSG_DONTWAIT );
  if( FD_UNLIKELY( -1==sent_cnt && errno==EAGAIN ) ) {
    /* Internal frame buffer is full and couldn't send anything, we are
       now backpressured by the socket and shouldn't poll any more. */
    *opt_poll_in = 2;
  } else if( FD_UNLIKELY( -1==sent_cnt ) ) {
    FD_LOG_ERR(( "sendmmsg failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  }
  FD_TEST( sent_cnt ); /* Should not be zero, -1 indicates error */

  ctx->frame_start = (ctx->frame_start+(ulong)sent_cnt)%1024UL;
  ctx->frame_cnt -= (ulong)sent_cnt;

  FD_LOG_WARNING(( "sent %d packets", sent_cnt ));
}

static inline int
before_frag( fd_nettx_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig ) {
  (void)in_idx;
  (void)seq;

  return fd_disco_netmux_sig_dst_ip( sig )%ctx->round_robin_cnt != ctx->round_robin_id;
}

static inline void
during_frag( fd_nettx_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig,
             ulong            chunk,
             ulong            sz ) {
  (void)in_idx;
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );

  ulong frame_idx = (ctx->frame_start+ctx->frame_cnt)%1024UL;
  fd_memcpy( ctx->frame[ frame_idx ], src, sz );
}

static inline void
after_frag( fd_nettx_ctx_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               chunk,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)tsorig;
  (void)stem;

  ulong frame_idx = (ctx->frame_start+ctx->frame_cnt)%1024UL;
  struct mmsghdr * hdr         = ctx->hdr+frame_idx;
  struct sockaddr_in * saddr4  = fd_type_pun( hdr->msg_hdr.msg_name );

  uchar const *        frame    = ctx->frame[ frame_idx ];
  uchar const *        cur      = frame;
  fd_eth_hdr_t const * eth_hdr  = fd_type_pun_const( cur );  cur += sizeof(fd_eth_hdr_t);
  fd_ip4_hdr_t const * ip4_hdr  = fd_type_pun_const( cur );  cur += FD_IP4_GET_IHL( *ip4_hdr )<<2;
  fd_udp_hdr_t const * udp_hdr  = fd_type_pun_const( cur );  cur += sizeof(fd_udp_hdr_t);
  memcpy( &saddr4->sin_addr.s_addr, &ip4_hdr->daddr_c, 4UL );
  saddr4->sin_port = udp_hdr->net_dport;

  uchar const *        data     = cur;
  long                 data_sz = (long)sz - (long)((ulong)cur - (ulong)frame);
  FD_LOG_WARNING(( "Got out packet, size: %lu", data_sz ));
  if( FD_UNLIKELY( eth_hdr->net_type!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ||
                   FD_IP4_GET_VERSION( *ip4_hdr ) != 4 ||
                   ip4_hdr->protocol!=IPPROTO_UDP ||
                   sz>FD_NET_MTU ||
                   data_sz<0 ) ) {
    FD_LOG_ERR(( "malformed packet" ));
  }

  FD_LOG_HEXDUMP_WARNING(( "frame", ctx->frame[ frame_idx ], sz ));
  FD_LOG_HEXDUMP_WARNING(( "frame2", data, (ulong)data_sz ));

  ctx->iov[ frame_idx ].iov_base = (void*)data;
  ctx->iov[ frame_idx ].iov_len  = (ulong)data_sz;

  ctx->frame_cnt++;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_nettx_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_nettx_ctx_t), sizeof(fd_nettx_ctx_t) );

  ctx->send_fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( -1==ctx->send_fd ) ) FD_LOG_ERR(( "socket failed (%d-%s)", errno, fd_io_strerror( errno ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_nettx_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_nettx_ctx_t), sizeof(fd_nettx_ctx_t) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_id  = tile->kind_id;

  fd_memset( ctx->hdr, 0, sizeof(ctx->hdr) );
  for( ulong i=0UL; i<1024UL; i++ ) {
    ctx->hdr[ i ].msg_hdr.msg_name    = ctx->addr+i;
    struct sockaddr_in * saddr4       = fd_type_pun( ctx->addr+i );
    saddr4->sin_family                = AF_INET;
    ctx->hdr[ i ].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
    ctx->hdr[ i ].msg_hdr.msg_iov     = ctx->iov+i;
    ctx->hdr[ i ].msg_hdr.msg_iovlen  = 1;

    ctx->hdr[ 1024UL+i ].msg_hdr.msg_name = ctx->addr+i;
    ctx->hdr[ 1024UL+i ].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
    ctx->hdr[ 1024UL+i ].msg_hdr.msg_iov     = ctx->iov+i;
    ctx->hdr[ 1024UL+i ].msg_hdr.msg_iovlen  = 1;
  }

  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "nettx tile in link cnt is zero" ));
  if( FD_UNLIKELY( tile->in_cnt>MAX_NETTX_INS ) ) FD_LOG_ERR(( "nettx tile in link cnt %lu exceeds MAX_NETTX_INS %lu", tile->in_cnt, MAX_NETTX_INS ));
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "net tile in link does not have a normal MTU" ));

    ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_nettx_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_nettx_ctx_t ), sizeof( fd_nettx_ctx_t ) );

  populate_sock_filter_policy_nettx( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->send_fd );
  return sock_filter_policy_nettx_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_nettx_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_nettx_ctx_t ), sizeof( fd_nettx_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->send_fd;

  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_nettx_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_nettx_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_nettx = {
  .name                     = "nettx",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
