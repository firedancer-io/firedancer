#define _GNU_SOURCE
#include "fd_circq.h"
#include "fd_event_client.h"

#include "../fd_txn_m.h"
#include "../metrics/fd_metrics.h"
#include "../net/fd_net_tile.h"
#include "../../discof/genesis/fd_genesi_tile.h"
#include "../keyguard/fd_keyload.h"
#include "../topo/fd_topo.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/pb/fd_pb_encode.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "generated/fd_event_tile_seccomp.h"

#define GRPC_BUF_MAX (2048UL<<10UL) /* 2 MiB */

extern char const firedancer_version_string[];

#define IN_KIND_SHRED  (0)
#define IN_KIND_DEDUP  (1)
#define IN_KIND_SIGN   (2)
#define IN_KIND_GENESI (3)
#define IN_KIND_IPECHO (4)

union fd_event_tile_in {
  struct {
    fd_wksp_t * mem;
    ulong       mtu;
    ulong       chunk0;
    ulong       wmark;
  };
  fd_net_rx_bounds_t net_rx;
};

typedef union fd_event_tile_in fd_event_tile_in_t;

struct fd_event_tile {
  fd_circq_t * circq;
  fd_event_client_t * client;

  fd_topo_t const * topo;

  int tile_shutdown_rendered[ FD_TOPO_MAX_TILES ];

  ulong idle_cnt;

  ulong boot_id;
  ulong machine_id;
  ulong instance_id;
  ulong seed;

  ulong chunk;

  ushort shred_source_port;
  ulong shred_buf_sz;
  uchar shred_buf[ FD_NET_MTU ];

  uchar identity_pubkey[ 32UL ];

  fd_keyguard_client_t keyguard_client[1];
  fd_rng_t rng[1];

  fd_netdb_fds_t netdb_fds[1];

  ulong in_cnt;
  int in_kind[ 64UL ];
  fd_event_tile_in_t in[ 64UL ];
};

typedef struct fd_event_tile fd_event_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_event_tile_t), sizeof(fd_event_tile_t)                   );
  l = FD_LAYOUT_APPEND( l, fd_event_client_align(),  fd_event_client_footprint( GRPC_BUF_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_circq_align(),         fd_circq_footprint( 1UL<<30UL )           ); /* 1GiB circq for events */
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_event_tile_t * ctx ) {
  FD_MGAUGE_SET( EVENT, EVENT_QUEUE_COUNT, ctx->circq->cnt );
  FD_MCNT_SET( EVENT, EVENT_QUEUE_DROPS, ctx->circq->metrics.drop_cnt );
  FD_MGAUGE_SET( EVENT, EVENT_QUEUE_BYTES_USED, fd_circq_bytes_used( ctx->circq ) );
  FD_MGAUGE_SET( EVENT, EVENT_QUEUE_BYTES_CAPACITY, ctx->circq->size );

  fd_event_client_metrics_t const * metrics = fd_event_client_metrics( ctx->client );
  FD_MCNT_SET( EVENT, EVENTS_SENT,         metrics->events_sent );
  FD_MCNT_SET( EVENT, EVENTS_ACKED,        metrics->events_acked );
  FD_MCNT_SET( EVENT, BYTES_WRITTEN,       metrics->bytes_written );
  FD_MCNT_SET( EVENT, BYTES_READ,          metrics->bytes_read );
  FD_MGAUGE_SET( EVENT, CONNECTION_STATE,  fd_event_client_state( ctx->client ) );
}

static void
before_credit( fd_event_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  ctx->idle_cnt++;
  if( FD_LIKELY( ctx->idle_cnt<2UL*ctx->in_cnt ) ) return;
  ctx->idle_cnt = 0UL;

  fd_event_client_poll( ctx->client, charge_busy );
}

static void
during_frag( fd_event_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             sz,
             ulong             ctl ) {
  (void)seq; (void)sig; (void)ctl;

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_SHRED: {
      uchar const * dcache_entry = fd_net_rx_translate_frag( &ctx->in[ in_idx ].net_rx, chunk, ctl, sz );
      ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
      FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */
      fd_udp_hdr_t const * udp_hdr = (fd_udp_hdr_t const *)( dcache_entry + hdr_sz - sizeof(fd_udp_hdr_t) );
      ctx->shred_source_port = fd_ushort_bswap( udp_hdr->net_sport );
      // TODO: SHOULD BE RELIABLE. MAKE XDP TILE RELIABLE FIRST.
      fd_memcpy( ctx->shred_buf, dcache_entry+hdr_sz, sz-hdr_sz );
      ctx->shred_buf_sz = sz-hdr_sz;
      break;
    }
    case IN_KIND_DEDUP:
    case IN_KIND_GENESI:
    case IN_KIND_IPECHO:
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      ctx->chunk = chunk;
      break;
    default:
      FD_LOG_ERR(( "unexpected in_kind %d %lu", ctx->in_kind[ in_idx ], in_idx ));
  }
}

static void
after_frag( fd_event_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sz; (void)tsorig; (void)stem;

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_SHRED: {
      FD_TEST( ctx->shred_buf_sz<=FD_NET_MTU );
      /* TODO: Currently no way to find a tight bound for the buffer
         size here, but 4096 is guaranteed to fit since sz<=FD_NET_MTU.
         Need to have the schema generator spit out max sizes for
         messages. */
      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 4096UL );
      FD_TEST( buffer );

      uint ip_addr = fd_disco_netmux_sig_ip( sig );
      uint source_port = ctx->shred_source_port;
      int protocol;
      switch( fd_disco_netmux_sig_proto( sig ) ) {
        case DST_PROTO_SHRED:
          protocol = 0;
          break;
        case DST_PROTO_REPAIR:
          protocol = 1;
          break;
        default:
          // TODO: Leader shreds?
          FD_LOG_ERR(( "unexpected proto %lu in sig %lu", fd_disco_netmux_sig_proto( sig ), sig ));
      }

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_frag_meta_ts_decomp( tspub, fd_tickcount() );
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 4096UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 2U ); /* Shred */
      fd_pb_push_bytes( encoder, 1U, &ip_addr, 4UL );
      fd_pb_push_uint32( encoder, 2U, source_port );
      fd_pb_push_int32( encoder, 3U, protocol );
      fd_pb_push_bytes( encoder, 4U, ctx->shred_buf, ctx->shred_buf_sz );
      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );
      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );
      break;
    }
    case IN_KIND_DEDUP:
      FD_TEST( sz<=FD_TPU_PARSED_MTU );
      /* See comment above about buffer size. */
      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 4096UL );
      FD_TEST( buffer );

      fd_txn_m_t * txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, ctx->chunk );
      FD_TEST( txnm->payload_sz<=FD_TPU_MTU );

      int protocol = 0;
      switch( txnm->source_tpu ) {
        case FD_TXN_M_TPU_SOURCE_QUIC:   protocol = 1; break;
        case FD_TXN_M_TPU_SOURCE_UDP:    protocol = 2; break;
        case FD_TXN_M_TPU_SOURCE_GOSSIP: protocol = 3; break;
        case FD_TXN_M_TPU_SOURCE_BUNDLE: protocol = 4; break;
        case FD_TXN_M_TPU_SOURCE_SEND:   protocol = 5; break;
        default:
          FD_LOG_ERR(( "unexpected source_tpu %u", txnm->source_tpu ));
      }

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_frag_meta_ts_decomp( tspub, fd_tickcount() );
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 4096UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 1U ); /* Txn */
      fd_pb_push_bytes( encoder, 1U, &txnm->source_ipv4, 4UL );
      fd_pb_push_uint32( encoder, 2U, 0U ); /* TODO: source port .. */
      fd_pb_push_int32( encoder, 3U, protocol );
      fd_pb_push_uint64( encoder, 4U, txnm->block_engine.bundle_id );
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) {
        fd_pb_push_uint32( encoder, 5U, (uint)txnm->block_engine.bundle_txn_cnt );
        fd_pb_push_uint32( encoder, 6U, txnm->block_engine.commission );
        fd_pb_push_bytes( encoder, 7U, txnm->block_engine.commission_pubkey, 32UL );
      } else {
        fd_pb_push_uint32( encoder, 5U, 0U );
        fd_pb_push_uint32( encoder, 6U, 0U );
        uchar zero_pubkey[32UL] = {0};
        fd_pb_push_bytes( encoder, 7U, zero_pubkey, 32UL );
      }
      fd_pb_push_bytes( encoder, 8U, fd_txn_m_payload( txnm ), txnm->payload_sz );

      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );
      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );

      break;
    case IN_KIND_GENESI: {
      uchar const * src = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, ctx->chunk );
      if( FD_LIKELY( sig==GENESI_SIG_BOOTSTRAP_COMPLETED ) ) {
        fd_event_client_init_genesis_hash( ctx->client, src+sizeof(fd_lthash_value_t) );
      } else {
        fd_event_client_init_genesis_hash( ctx->client, src );
      }
      break;
    }
    case IN_KIND_IPECHO:
      FD_TEST( sig && sig<=USHORT_MAX );
      fd_event_client_init_shred_version( ctx->client, (ushort)sig );
      break;
    default:
      FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_tile_t), sizeof(fd_event_tile_t) );

  if( FD_UNLIKELY( !strcmp( tile->event.identity_key_path, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));
  const uchar * identity_key = fd_keyload_load( tile->event.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_pubkey, identity_key, 32UL );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );
  FD_TEST( fd_rng_secure( &ctx->instance_id, 8UL ) );

#define FD_EVENT_ID_SEED 0x812CAFEBABEFEEE0UL

  char _boot_id[ 36 ];
  int boot_id_fd = open( "/proc/sys/kernel/random/boot_id", O_RDONLY );
  if( FD_UNLIKELY( -1==boot_id_fd ) ) FD_LOG_ERR(( "open(/proc/sys/kernel/random/boot_id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( 36UL!=read( boot_id_fd, _boot_id, 36UL ) ) ) FD_LOG_ERR(( "read(/proc/sys/kernel/random/boot_id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( boot_id_fd ) ) ) FD_LOG_ERR(( "close(/proc/sys/kernel/random/boot_id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  ctx->boot_id = fd_hash( FD_EVENT_ID_SEED, _boot_id, 36UL );

  char _machine_id[ 32 ];
  int machine_id_fd = open( "/etc/machine-id", O_RDONLY );
  if( FD_UNLIKELY( -1==machine_id_fd ) ) FD_LOG_ERR(( "open(/etc/machine-id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( 32UL!=read( machine_id_fd, _machine_id, 32UL ) ) ) FD_LOG_ERR(( "read(/etc/machine-id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( machine_id_fd ) ) ) FD_LOG_ERR(( "close(/etc/machine-id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  ctx->machine_id = fd_hash( FD_EVENT_ID_SEED, _machine_id, 32UL );

  if( FD_UNLIKELY( !fd_netdb_open_fds( ctx->netdb_fds ) ) ) {
    FD_LOG_ERR(( "fd_netdb_open_fds failed" ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_tile_t), sizeof(fd_event_tile_t)                  );
  void * _event_client  = FD_SCRATCH_ALLOC_APPEND( l, fd_event_client_align(),  fd_event_client_footprint( GRPC_BUF_MAX) );
  void * _circq         = FD_SCRATCH_ALLOC_APPEND( l, fd_circq_align(),         fd_circq_footprint( 1UL<<30UL )          );

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_event", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "event_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
          sign_out->mcache,
          sign_out->dcache,
          sign_in->mcache,
          sign_in->dcache,
          sign_out->mtu ) ) ) ) {
    FD_LOG_ERR(( "failed to construct keyguard" ));
  }

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0U, ctx->seed ) ) );

  ctx->circq = fd_circq_join( fd_circq_new( _circq, 1UL<<30UL /* 1GiB */ ) );
  FD_TEST( ctx->circq );

  ctx->client = fd_event_client_join( fd_event_client_new( _event_client,
                                                           ctx->keyguard_client,
                                                           ctx->rng,
                                                           ctx->circq,
                                                           2*(1UL<<20UL) /* 2 MiB */,
                                                           tile->event.url,
                                                           ctx->identity_pubkey,
                                                           firedancer_version_string,
                                                           ctx->instance_id,
                                                           ctx->boot_id,
                                                           ctx->machine_id,
                                                           GRPC_BUF_MAX ) );
  FD_TEST( ctx->client );

  ctx->topo = topo;
  fd_memset( ctx->tile_shutdown_rendered, 0, sizeof(ctx->tile_shutdown_rendered) );

  ctx->idle_cnt = 0UL;

  ctx->in_cnt = tile->in_cnt;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "net_shred"         ) ) ) {
      fd_net_rx_bounds_init( &ctx->in[ i ].net_rx, link->dcache );
      ctx->in_kind[ i ] = IN_KIND_SHRED;
      continue; /* only net_rx needs to be set in this case. */
    } else if( FD_LIKELY( !strcmp( link->name, "dedup_resolv" ) ) ) ctx->in_kind[ i ] = IN_KIND_DEDUP;
    else if( FD_LIKELY( !strcmp( link->name, "sign_event"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else if( FD_LIKELY( !strcmp( link->name, "genesi_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESI;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else FD_LOG_ERR(( "event tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ i ].mem = link_wksp->wksp;
    ctx->in[ i ].mtu = link->mtu;
    if( FD_UNLIKELY( ctx->in[ i ].mtu ) ) {
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    } else {
      ctx->in[ i ].chunk0 = 0UL;
      ctx->in[ i ].wmark  = 0UL;
    }
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
  fd_event_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  populate_sock_filter_policy_fd_event_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)ctx->netdb_fds->etc_hosts,
      (uint)ctx->netdb_fds->etc_resolv_conf );
  return sock_filter_policy_fd_event_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_event_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->netdb_fds->etc_hosts >= 0 ) )
    out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_hosts;
  out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_resolv_conf;
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY ((long)10e6) /* 10ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_event_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_event_tile_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_event = {
  .name                     = "event",
  .rlimit_file_cnt          = 5UL, /* stderr, logfile, /etc/hosts, /etc/resolv.conf, and socket to the server */
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
};
