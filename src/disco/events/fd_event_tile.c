#define _GNU_SOURCE
#include "fd_circq.h"
#include "fd_event_client.h"

#include "../fd_txn_m.h"
#include "../fd_clock_tile.h"
#include "../metrics/fd_metrics.h"
#include "../net/fd_net_tile.h"
#include "../../discof/genesis/fd_genesi_tile.h"
#include "generated/fd_event_gen.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyswitch.h"
#include "../topo/fd_topo.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/http/fd_url.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/pb/fd_pb_encode.h"
#include "../../tango/tempo/fd_tempo.h"

#if FD_HAS_OPENSSL
#include "../../util/alloc/fd_alloc.h"
#include "../../waltz/openssl/fd_openssl.h"
#include "../../waltz/openssl/fd_openssl_tile.h"
#include <openssl/ssl.h>
#endif

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

/* Sized so the event workspace (circq + ~24 MiB client/ctx + 64 MiB
   OpenSSL loose) fits in one gigantic page. */
#define EVENT_CIRCQ_SZ ((1UL<<30UL)-(96UL<<20UL))

#define IN_KIND_SHRED  (0)
#define IN_KIND_DEDUP  (1)
#define IN_KIND_SIGN   (2)
#define IN_KIND_GENESI (3)
#define IN_KIND_IPECHO (4)
#define IN_KIND_EVENT  (5)

#define FD_EVENT_TYPE_TXN         1
#define FD_EVENT_TYPE_SHRED       2
#define FD_EVENT_TYPE_SIGNED_VOTE 3

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

  fd_keyswitch_t * keyswitch;

  ulong idle_cnt;

  ulong boot_id;
  ulong machine_id;
  ulong instance_id;
  ulong seed;

  ulong chunk;

  ushort shred_source_port;
  ulong shred_buf_sz;
  uchar shred_buf[ FD_NET_MTU ];

  ulong event_type;
  ulong event_sz;
  uchar event_buf[ FD_EVENT_GEN_STRUCT_MAX ];

  uchar identity_pubkey[ 32UL ];

  int use_tls;
#if FD_HAS_OPENSSL
  SSL_CTX * ssl_ctx;
#endif

  fd_keyguard_client_t keyguard_client[1];
  fd_rng_t rng[1];

  fd_netdb_fds_t netdb_fds[1];

  fd_clock_tile_t clock[1];

  ulong in_cnt;
  int in_kind[ 64UL ];
  fd_event_tile_in_t in[ 64UL ];
};

typedef struct fd_event_tile fd_event_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong a = alignof( fd_event_tile_t );
  a = fd_ulong_max( a, fd_event_client_align() );
  a = fd_ulong_max( a, fd_circq_align() );
# if FD_HAS_OPENSSL
  a = fd_ulong_max( a, fd_alloc_align() );
# endif
  return a;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_event_tile_t), sizeof(fd_event_tile_t)                   );
  l = FD_LAYOUT_APPEND( l, fd_event_client_align(),  fd_event_client_footprint( GRPC_BUF_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_circq_align(),         fd_circq_footprint( EVENT_CIRCQ_SZ )      );
# if FD_HAS_OPENSSL
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),          fd_alloc_footprint()                     );
# endif
  return FD_LAYOUT_FINI( l, scratch_align() );
}

# if FD_HAS_OPENSSL
FD_FN_CONST static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  /* Extra workspace memory for OpenSSL dynamic allocations */
  return 1UL<<26UL; /* 64 MiB */
}
# endif

static inline void
metrics_write( fd_event_tile_t * ctx ) {
  FD_MGAUGE_SET( EVENT, QUEUE_DEPTH, ctx->circq->cnt );
  FD_MGAUGE_SET( EVENT, QUEUE_UNSENT, fd_circq_unsent_cnt( ctx->circq ) );
  FD_MCNT_SET( EVENT, QUEUE_DROPPED, ctx->circq->metrics.drop_cnt );
  FD_MGAUGE_SET( EVENT, QUEUE_BYTES_USED, fd_circq_bytes_used( ctx->circq ) );
  FD_MGAUGE_SET( EVENT, QUEUE_BYTES_CAPACITY, ctx->circq->size );

  fd_event_client_metrics_t const * metrics = fd_event_client_metrics( ctx->client );
  FD_MCNT_SET( EVENT, SENT,          metrics->events_sent );
  FD_MCNT_SET( EVENT, ACKED,         metrics->events_acked );
  FD_MGAUGE_SET( EVENT, LAST_ACKED_ID, metrics->last_acked_id );
  FD_MCNT_SET( EVENT, BYTES_WRITTEN,       metrics->bytes_written );
  FD_MCNT_SET( EVENT, BYTES_READ,          metrics->bytes_read );
  FD_MCNT_SET( EVENT, AUTH_FAILED,         metrics->auth_fail_cnt );
  FD_MCNT_SET( EVENT, INVALID_MESSAGE,     metrics->invalid_msg_cnt );
  FD_MCNT_SET( EVENT, CONN_ATTEMPT,        metrics->connect_attempt_cnt );
  FD_MCNT_SET( EVENT, HANDSHAKE_TIMEOUT,   metrics->handshake_timeout_cnt );

  FD_MGAUGE_SET( EVENT, CONN_STATE,        fd_event_client_state( ctx->client ) );
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
  (void)seq; (void)ctl;

  fd_event_tile_in_t const * in = &ctx->in[ in_idx ];
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
      if( FD_UNLIKELY( chunk<in->chunk0 || chunk>in->wmark || sz>in->mtu ) )
        FD_LOG_CRIT(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in->chunk0, in->wmark ));
      ctx->chunk = chunk;
      break;
    case IN_KIND_EVENT: {
      if( FD_UNLIKELY( chunk<in->chunk0 || chunk>in->wmark || sz>in->mtu ) )
        FD_LOG_CRIT(( "chunk %lu corrupt, not in range [%lu,%lu]", chunk, in->chunk0, in->wmark ));
      fd_memcpy( ctx->event_buf, fd_chunk_to_laddr_const( in->mem, chunk ), sz );
      ctx->event_type = sig;
      ctx->event_sz   = sz;
      break;
    }
    default:
      FD_LOG_CRIT(( "unexpected in_kind %d %lu", ctx->in_kind[ in_idx ], in_idx ));
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
  (void)sz; (void)tsorig; (void)stem;

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
          protocol = 1;
          break;
        case DST_PROTO_REPAIR:
          protocol = 2;
          break;
        default:
          // TODO: Leader shreds?
          FD_LOG_ERR(( "unexpected proto %lu in sig %lu", fd_disco_netmux_sig_proto( sig ), sig ));
      }

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_clock_tile_tickcount_to_wallclock( ctx->clock,
        fd_clock_tile_tickcount_decomp( ctx->clock, tspub ) );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 4096UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_push_uint64( encoder, 3U, seq ); /* link_seq */
      fd_pb_push_uint64( encoder, 4U, (ulong)timestamp_nanos );

      fd_pb_submsg_open( encoder, 5U ); /* Event */
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
        case FD_TXN_M_TPU_SOURCE_TXSEND: protocol = 5; break;
        default:
          FD_LOG_ERR(( "unexpected source_tpu %u", txnm->source_tpu ));
      }

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_clock_tile_tickcount_to_wallclock( ctx->clock,
        fd_clock_tile_tickcount_decomp( ctx->clock, tspub ) );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 4096UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_push_uint64( encoder, 3U, seq ); /* link_seq */
      fd_pb_push_uint64( encoder, 4U, (ulong)timestamp_nanos );

      fd_pb_submsg_open( encoder, 5U ); /* Event */
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
      fd_genesis_meta_t const * genesis_meta = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, ctx->chunk );
      fd_event_client_init_genesis( ctx->client, genesis_meta );
      break;
    }
    case IN_KIND_IPECHO:
      FD_TEST( sig && sig<=USHORT_MAX );
      fd_event_client_init_shred_version( ctx->client, (ushort)sig );
      break;
    case IN_KIND_EVENT: {
      long timestamp_nanos = fd_clock_tile_tickcount_to_wallclock( ctx->clock, fd_clock_tile_tickcount_decomp( ctx->clock, tspub ) );
      fd_event_serialize_by_type( ctx->event_type, ctx->circq, ctx->client, timestamp_nanos, seq, ctx->event_buf, ctx->event_sz );
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_tile_t),  sizeof(fd_event_tile_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_event_client_align(),  fd_event_client_footprint( GRPC_BUF_MAX ) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_circq_align(),         fd_circq_footprint( EVENT_CIRCQ_SZ )      );
# if FD_HAS_OPENSSL
  void * alloc_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  (void)alloc_mem;
# endif

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  if( FD_UNLIKELY( !strcmp( tile->event.identity_key_path, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));
  const uchar * identity_key = fd_keyload_load( tile->event.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_pubkey, identity_key, 32UL );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );
  FD_TEST( fd_rng_secure( &ctx->instance_id, 8UL ) );

  FD_LOG_INFO(( "event instance_id=%lu", ctx->instance_id ));

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

  /* Detect TLS from the URL scheme */
  fd_url_t url[ 1UL ];
  ushort   port;
  _Bool    is_ssl = 0;
  if( FD_UNLIKELY( fd_url_parse_endpoint( url, tile->event.url, strlen( tile->event.url ), &port, &is_ssl, "[tiles.event.url]" ) ) ) {
    FD_LOG_ERR(( "Could not parse [tiles.event.url]" ));
  }
  ctx->use_tls = is_ssl;

# if FD_HAS_OPENSSL
  ctx->ssl_ctx = NULL;
  if( ctx->use_tls ) {
    fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), tile->kind_id );
    if( FD_UNLIKELY( !alloc ) ) FD_LOG_ERR(( "fd_alloc_new failed" ));
    fd_ossl_tile_init( alloc );

    SSL_CTX * ssl_ctx = SSL_CTX_new( TLS_client_method() );
    if( FD_UNLIKELY( !ssl_ctx ) ) FD_LOG_ERR(( "SSL_CTX_new failed" ));

    if( FD_UNLIKELY( !SSL_CTX_set_mode( ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY ) ) )
      FD_LOG_ERR(( "SSL_CTX_set_mode failed" ));

    if( FD_UNLIKELY( !SSL_CTX_set_min_proto_version( ssl_ctx, TLS1_3_VERSION ) ) )
      FD_LOG_ERR(( "SSL_CTX_set_min_proto_version(ssl_ctx,TLS1_3_VERSION) failed" ));

    if( FD_UNLIKELY( 0!=SSL_CTX_set_alpn_protos( ssl_ctx, (uchar const *)"\x02h2", 3 ) ) )
      FD_LOG_ERR(( "SSL_CTX_set_alpn_protos failed" ));

    fd_ossl_load_certs( ssl_ctx ); /* also sets SSL_VERIFY_PEER */

    ctx->ssl_ctx = ssl_ctx;
  }
# else
  if( FD_UNLIKELY( ctx->use_tls ) ) {
    FD_LOG_ERR(( "TLS requested for event service (https:// URL) but this build "
                 "does not include OpenSSL. Re-run ./deps.sh and do a clean rebuild." ));
  }
# endif
}

static int
link_is_event_report( fd_topo_t const * topo,
                      ulong             link_id ) {
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( topo->tiles[ i ].event_link_id==link_id ) ) return 1;
  }
  return 0;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_tile_t), sizeof(fd_event_tile_t)                   );
  void * _event_client  = FD_SCRATCH_ALLOC_APPEND( l, fd_event_client_align(),  fd_event_client_footprint( GRPC_BUF_MAX ) );
  void * _circq         = FD_SCRATCH_ALLOC_APPEND( l, fd_circq_align(),         fd_circq_footprint( EVENT_CIRCQ_SZ )      );
# if FD_HAS_OPENSSL
  FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
# endif

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_event", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "event_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t const * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
          sign_out->mcache,
          sign_out->dcache,
          sign_in->mcache,
          sign_in->dcache,
          sign_out->mtu ) ) ) ) {
    FD_LOG_ERR(( "failed to construct keyguard" ));
  }

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0U, ctx->seed ) ) );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ctx->circq = fd_circq_join( fd_circq_new( _circq, EVENT_CIRCQ_SZ ) );
  FD_TEST( ctx->circq );

  void * ssl_ctx_ptr = NULL;
# if FD_HAS_OPENSSL
  ssl_ctx_ptr = ctx->ssl_ctx;
# endif

  ctx->client = fd_event_client_join( fd_event_client_new( _event_client,
                                                           ctx->keyguard_client,
                                                           ctx->rng,
                                                           ctx->circq,
                                                           2*(1UL<<20UL) /* 2 MiB */,
                                                           tile->event.url,
                                                           ctx->identity_pubkey,
                                                           fd_version_cstr,
                                                           fd_commit_ref_cstr,
                                                           tile->event.action,
                                                           ctx->instance_id,
                                                           ctx->boot_id,
                                                           ctx->machine_id,
                                                           GRPC_BUF_MAX,
                                                           ctx->use_tls,
                                                           ssl_ctx_ptr ) );
  FD_TEST( ctx->client );

  ctx->topo = topo;
  fd_memset( ctx->tile_shutdown_rendered, 0, sizeof(ctx->tile_shutdown_rendered) );

  ctx->idle_cnt = 0UL;

  FD_TEST( tile->in_cnt<=sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  int have_genesi = 0;
  int have_ipecho = 0;
  ulong polled_in_idx = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "net_shred"         ) ) ) {
      fd_net_rx_bounds_init( &ctx->in[ polled_in_idx ].net_rx, link->dcache );
      ctx->in_kind[ polled_in_idx ] = IN_KIND_SHRED;
      polled_in_idx++;
      continue; /* only net_rx needs to be set in this case. */
    }
    else if( FD_LIKELY( !strcmp( link->name, "dedup_resolv" ) ) ) ctx->in_kind[ polled_in_idx ] = IN_KIND_DEDUP;
    else if( FD_LIKELY( !strcmp( link->name, "genesi_out"   ) ) ) { ctx->in_kind[ polled_in_idx ] = IN_KIND_GENESI; have_genesi = 1; }
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"   ) ) ) { ctx->in_kind[ polled_in_idx ] = IN_KIND_IPECHO; have_ipecho = 1; }
    else if( FD_LIKELY( link_is_event_report( topo, link->id ) ) ) {
      ctx->in_kind[ polled_in_idx ] = IN_KIND_EVENT;
      FD_TEST( link->mtu<=sizeof(ctx->event_buf) );
    }
    else FD_LOG_ERR(( "event tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ polled_in_idx ].mem = link_wksp->wksp;
    ctx->in[ polled_in_idx ].mtu = link->mtu;
    if( FD_UNLIKELY( ctx->in[ polled_in_idx ].mtu ) ) {
      ctx->in[ polled_in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ polled_in_idx ].mem, link->dcache );
      ctx->in[ polled_in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in[ polled_in_idx ].mem, link->dcache, link->mtu );
    } else {
      ctx->in[ polled_in_idx ].chunk0 = 0UL;
      ctx->in[ polled_in_idx ].wmark  = 0UL;
    }
    polled_in_idx++;
  }
  ctx->in_cnt = polled_in_idx;

  if( FD_UNLIKELY( !have_genesi ) ) {
    fd_genesis_meta_t meta[1]; fd_memset( meta, 0, sizeof(meta) );
    fd_memcpy( meta->genesis_hash.uc, tile->event.genesis_hash, 32UL );
    fd_event_client_init_genesis( ctx->client, meta );
  }
  if( FD_UNLIKELY( !have_ipecho ) ) {
    fd_event_client_init_shred_version( ctx->client, tile->event.shred_version );
  }

  fd_clock_tile_init( ctx->clock );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
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

static void
during_housekeeping( fd_event_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) {
    fd_clock_tile_recal( ctx->clock );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: switching identity" ));
    memcpy( ctx->identity_pubkey, ctx->keyswitch->bytes, 32UL );
    fd_event_client_set_identity( ctx->client, ctx->identity_pubkey );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

#define STEM_BURST (1UL)
#define STEM_LAZY ((long)10e6) /* 10ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_event_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_event_tile_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_event = {
  .name                     = "event",
  .rlimit_file_cnt          = 5UL, /* stderr, logfile, /etc/hosts, /etc/resolv.conf, and socket to the server */
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
# if FD_HAS_OPENSSL
  .loose_footprint          = loose_footprint,
# endif
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
};
