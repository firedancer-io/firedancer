#define _GNU_SOURCE
#include "fd_circq.h"
#include "fd_event_client.h"

#include "../fd_txn_m.h"
#include "../metrics/fd_metrics.h"
#include "../net/fd_net_tile.h"
#include "../../discof/genesis/fd_genesi_tile.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyswitch.h"
#include "../topo/fd_topo.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/http/fd_url.h"
#include "../../util/cstr/fd_cstr.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/pb/fd_pb_encode.h"
#include "../../tango/tempo/fd_tempo.h"
#include "../../flamenco/capture/fd_capture_ctx.h"

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

extern char const firedancer_version_string[];

#define IN_KIND_SHRED    (0)
#define IN_KIND_DEDUP    (1)
#define IN_KIND_SIGN     (2)
#define IN_KIND_GENESI   (3)
#define IN_KIND_IPECHO   (4)
#define IN_KIND_ACCOUNT  (5)
#define IN_KIND_BANK     (6)
#define IN_KIND_STAKE    (7)
#define IN_KIND_VOTE     (8)
#define IN_KIND_CVOTE    (9)
#define IN_KIND_RTXN     (10)
#define IN_KIND_RBLK     (11)

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

  uchar identity_pubkey[ 32UL ];

  int use_tls;
#if FD_HAS_OPENSSL
  SSL_CTX * ssl_ctx;
#endif

  fd_keyguard_client_t keyguard_client[1];
  fd_rng_t rng[1];

  fd_netdb_fds_t netdb_fds[1];

  long   reference_wallclock;
  long   reference_tickcount;
  double tick_per_ns;

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
  l = FD_LAYOUT_APPEND( l, fd_circq_align(),         fd_circq_footprint( 1UL<<30UL )           ); /* 1GiB circq for events */
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
  FD_MGAUGE_SET( EVENT, EVENT_QUEUE_COUNT, ctx->circq->cnt );
  FD_MCNT_SET( EVENT, EVENT_QUEUE_DROPS, ctx->circq->metrics.drop_cnt );
  FD_MGAUGE_SET( EVENT, EVENT_QUEUE_BYTES_USED, fd_circq_bytes_used( ctx->circq ) );
  FD_MGAUGE_SET( EVENT, EVENT_QUEUE_BYTES_CAPACITY, ctx->circq->size );

  fd_event_client_metrics_t const * metrics = fd_event_client_metrics( ctx->client );
  FD_MCNT_SET( EVENT, EVENTS_SENT,         metrics->events_sent );
  FD_MCNT_SET( EVENT, EVENTS_ACKED,        metrics->events_acked );
  FD_MCNT_SET( EVENT, BYTES_WRITTEN,       metrics->bytes_written );
  FD_MCNT_SET( EVENT, BYTES_READ,          metrics->bytes_read );
  FD_MCNT_SET( EVENT, AUTH_FAIL,           metrics->auth_fail_cnt );
  FD_MCNT_SET( EVENT, INVALID_MSG,         metrics->invalid_msg_cnt );
  FD_MCNT_SET( EVENT, CONNECT_ATTEMPTS,    metrics->connect_attempt_cnt );
  FD_MCNT_SET( EVENT, HANDSHAKE_TIMEOUTS,  metrics->handshake_timeout_cnt );

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
    case IN_KIND_ACCOUNT:
    case IN_KIND_BANK:
    case IN_KIND_STAKE:
    case IN_KIND_VOTE:
    case IN_KIND_CVOTE:
    case IN_KIND_RTXN:
    case IN_KIND_RBLK:
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
  (void)seq; (void)sz; (void)tsorig; (void)tspub; (void)stem;

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
      long timestamp_nanos = ctx->reference_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tspub, ctx->reference_tickcount ) - ctx->reference_tickcount) / ctx->tick_per_ns);

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 4096UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_push_uint64( encoder, 3U, (ulong)timestamp_nanos );

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
        case FD_TXN_M_TPU_SOURCE_TXSEND: protocol = 5; break;
        default:
          FD_LOG_ERR(( "unexpected source_tpu %u", txnm->source_tpu ));
      }

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = ctx->reference_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tspub, ctx->reference_tickcount ) - ctx->reference_tickcount) / ctx->tick_per_ns);

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 4096UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_push_uint64( encoder, 3U, (ulong)timestamp_nanos );

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
      fd_genesis_meta_t const * genesis_meta = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, ctx->chunk );
      fd_event_client_init_genesis( ctx->client, genesis_meta );
      break;
    }
    case IN_KIND_IPECHO:
      FD_TEST( sig && sig<=USHORT_MAX );
      fd_event_client_init_shred_version( ctx->client, (ushort)sig );
      break;
    case IN_KIND_ACCOUNT: {
      FD_TEST( sz==sizeof(fd_capture_account_event_msg_t) );
      fd_capture_account_event_msg_t const * acct = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk );

      /* Account events are small (~256 B encoded); 512 is plenty. */
      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 512UL );
      FD_TEST( buffer );

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_log_wallclock();
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 512UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 3U ); /* Account */
      fd_pb_push_bytes ( encoder, 1U, acct->pubkey, 32UL );
      fd_pb_push_uint64( encoder, 2U, acct->lamports );
      fd_pb_push_bytes ( encoder, 3U, acct->owner, 32UL );
      fd_pb_push_uint32( encoder, 4U, acct->executable ? 1U : 0U );
      fd_pb_push_uint64( encoder, 5U, acct->slot );
      fd_pb_push_bytes ( encoder, 6U, acct->signature, 64UL );
      fd_pb_push_uint64( encoder, 7U, acct->data_sz );
      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );

      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );
      break;
    }
    case IN_KIND_STAKE: {
      FD_TEST( sz==sizeof(fd_capture_stake_event_msg_t) );
      fd_capture_stake_event_msg_t const * st = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk );

      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 512UL );
      FD_TEST( buffer );

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_log_wallclock();
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 512UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 5U ); /* StakeDelegation */
      fd_pb_push_bytes ( encoder, 1U, st->pubkey,       32UL );
      fd_pb_push_bytes ( encoder, 2U, st->voter_pubkey, 32UL );
      fd_pb_push_uint64( encoder, 3U, st->stake );
      fd_pb_push_uint64( encoder, 4U, st->activation_epoch );
      fd_pb_push_uint64( encoder, 5U, st->deactivation_epoch );
      fd_pb_push_uint64( encoder, 6U, st->credits_observed );
      fd_pb_push_uint64( encoder, 7U, st->slot );
      fd_pb_push_uint32( encoder, 8U, st->removed ? 1U : 0U );
      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );

      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );
      break;
    }
    case IN_KIND_VOTE: {
      FD_TEST( sz==sizeof(fd_capture_vote_event_msg_t) );
      fd_capture_vote_event_msg_t const * v = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk );

      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 512UL );
      FD_TEST( buffer );

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_log_wallclock();
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 512UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 6U ); /* VoteUpdate */
      fd_pb_push_bytes ( encoder, 1U, v->pubkey, 32UL );
      fd_pb_push_uint64( encoder, 2U, v->last_vote_slot );
      fd_pb_push_int64 ( encoder, 3U, v->last_vote_timestamp );
      fd_pb_push_uint64( encoder, 4U, v->slot );
      fd_pb_push_uint32( encoder, 5U, v->invalidated ? 1U : 0U );
      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );

      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );
      break;
    }
    case IN_KIND_CVOTE: {
      FD_TEST( sz==sizeof(fd_capture_vote_txn_event_msg_t) );
      fd_capture_vote_txn_event_msg_t const * cv = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk );

      /* Conservatively allocate 1024 B for the encoded message
         (envelope ~50, base fields ~200, tower up to 32 entries × ~20 B each = 640). */
      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 1024UL );
      FD_TEST( buffer );

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_log_wallclock();
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 1024UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 7U ); /* VoteTransaction */
      fd_pb_push_bytes ( encoder, 1U, cv->vote_account, 32UL );
      fd_pb_push_bytes ( encoder, 2U, cv->voter,        32UL );
      fd_pb_push_bytes ( encoder, 3U, cv->bank_hash,    32UL );
      fd_pb_push_bytes ( encoder, 4U, cv->block_id,     32UL );
      fd_pb_push_uint64( encoder, 5U, cv->slot );
      fd_pb_push_uint64( encoder, 6U, cv->root_slot );
      fd_pb_push_int64 ( encoder, 7U, cv->timestamp );
      fd_pb_push_uint32( encoder, 8U, cv->has_root      ? 1U : 0U );
      fd_pb_push_uint32( encoder, 9U, cv->has_timestamp ? 1U : 0U );
      fd_pb_push_uint32( encoder, 10U, cv->has_block_id ? 1U : 0U );
      fd_pb_push_uint32( encoder, 11U, (uint)cv->ix_variant );
      for( ulong li=0UL; li<cv->lockouts_cnt; li++ ) {
        fd_pb_submsg_open( encoder, 12U ); /* tower entry */
        fd_pb_push_uint64( encoder, 1U, cv->lockouts[ li ].slot );
        fd_pb_push_uint32( encoder, 2U, cv->lockouts[ li ].confirmation_count );
        fd_pb_submsg_close( encoder );
      }
      fd_pb_push_bytes ( encoder, 13U, cv->signature, 64UL );
      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );

      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );
      break;
    }
    case IN_KIND_RTXN: {
      FD_TEST( sz==sizeof(fd_capture_runtime_txn_event_msg_t) );
      fd_capture_runtime_txn_event_msg_t const * rt = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk );

      /* Worst case: ~12 KiB account_diffs + 2 × ~4 KiB writable/readonly
         account lists + ~50 B envelope.  32 KiB is comfortable. */
      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 32768UL );
      FD_TEST( buffer );

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_log_wallclock();
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 32768UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 8U ); /* RuntimeTxn */

      fd_pb_push_bytes ( encoder, 1U,  rt->signature, 64UL );
      fd_pb_push_uint64( encoder, 2U,  rt->slot );
      fd_pb_push_uint64( encoder, 3U,  rt->txn_idx );
      fd_pb_push_bytes ( encoder, 4U,  rt->blockhash, 32UL );
      fd_pb_push_uint32( encoder, 5U,  rt->is_simple_vote ? 1U : 0U );
      fd_pb_push_uint32( encoder, 6U,  rt->is_bundle      ? 1U : 0U );
      fd_pb_push_uint64( encoder, 7U,  rt->bundle_id );
      fd_pb_push_uint32( encoder, 8U,  rt->is_committable ? 1U : 0U );
      fd_pb_push_uint32( encoder, 9U,  rt->is_fees_only   ? 1U : 0U );
      fd_pb_push_uint32( encoder, 10U, rt->txn_err );
      fd_pb_push_uint32( encoder, 11U, rt->exec_err );
      fd_pb_push_uint32( encoder, 12U, rt->exec_err_kind );
      fd_pb_push_uint32( encoder, 13U, rt->exec_err_idx );
      fd_pb_push_uint32( encoder, 14U, rt->custom_err );
      fd_pb_push_uint64( encoder, 15U, rt->compute_unit_limit );
      fd_pb_push_uint64( encoder, 16U, rt->compute_unit_price );
      fd_pb_push_uint64( encoder, 17U, rt->compute_units_consumed );
      fd_pb_push_uint32( encoder, 18U, rt->heap_size );
      fd_pb_push_uint64( encoder, 19U, rt->loaded_accounts_data_size );
      fd_pb_push_uint64( encoder, 20U, rt->loaded_accounts_data_size_limit );
      fd_pb_push_int64 ( encoder, 21U, rt->accounts_resize_delta );
      fd_pb_push_uint32( encoder, 22U, rt->num_builtin_instrs );
      fd_pb_push_uint32( encoder, 23U, rt->num_non_builtin_instrs );
      fd_pb_push_uint64( encoder, 24U, rt->execution_fee );
      fd_pb_push_uint64( encoder, 25U, rt->priority_fee );
      fd_pb_push_uint64( encoder, 26U, rt->tips );
      fd_pb_push_uint32( encoder, 27U, rt->signature_count );
      fd_pb_push_uint32( encoder, 28U, rt->cost_signature );
      fd_pb_push_uint32( encoder, 29U, rt->cost_write_lock );
      fd_pb_push_uint32( encoder, 30U, rt->cost_data_bytes );
      fd_pb_push_uint32( encoder, 31U, rt->cost_programs_execution );
      fd_pb_push_uint32( encoder, 32U, rt->cost_loaded_accounts_data_size );
      fd_pb_push_uint64( encoder, 33U, rt->cost_allocated_accounts_data_size );
      fd_pb_push_int64 ( encoder, 34U, rt->prep_start_ns );
      fd_pb_push_int64 ( encoder, 35U, rt->load_start_ns );
      fd_pb_push_int64 ( encoder, 36U, rt->exec_start_ns );
      fd_pb_push_int64 ( encoder, 37U, rt->commit_start_ns );

      ulong diff_cnt = rt->account_diff_cnt;
      if( diff_cnt > FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNT_DIFFS ) diff_cnt = FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNT_DIFFS;
      for( ulong di=0UL; di<diff_cnt; di++ ) {
        fd_capture_runtime_txn_account_diff_t const * d = &rt->account_diffs[ di ];
        fd_pb_submsg_open( encoder, 38U ); /* RuntimeTxnAccountDiff entry */
        fd_pb_push_bytes ( encoder, 1U, d->pubkey, 32UL );
        fd_pb_push_bytes ( encoder, 2U, d->owner,  32UL );
        fd_pb_push_uint64( encoder, 3U, d->lamports );
        fd_pb_push_uint64( encoder, 4U, d->data_sz );
        fd_pb_push_uint32( encoder, 5U, d->executable   ? 1U : 0U );
        fd_pb_push_uint32( encoder, 6U, d->stake_update ? 1U : 0U );
        fd_pb_push_uint32( encoder, 7U, d->vote_update  ? 1U : 0U );
        fd_pb_push_uint32( encoder, 8U, d->new_vote     ? 1U : 0U );
        fd_pb_push_uint32( encoder, 9U, d->rm_vote      ? 1U : 0U );
        fd_pb_submsg_close( encoder );
      }

      fd_pb_push_bytes( encoder, 39U, rt->dispatch_fec_mr, 32UL );

      ulong w_cnt = rt->writable_accounts_cnt;
      if( w_cnt > FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNTS ) w_cnt = FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNTS;
      for( ulong i = 0UL; i < w_cnt; i++ ) {
        fd_pb_submsg_open( encoder, 40U ); /* RuntimeTxnAccount entry — writable */
        fd_pb_push_bytes ( encoder, 1U, rt->writable_accounts[ i ], 32UL );
        fd_pb_submsg_close( encoder );
      }

      ulong r_cnt = rt->readonly_accounts_cnt;
      if( r_cnt > FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNTS ) r_cnt = FD_CAPTURE_RUNTIME_TXN_MAX_ACCOUNTS;
      for( ulong i = 0UL; i < r_cnt; i++ ) {
        fd_pb_submsg_open( encoder, 41U ); /* RuntimeTxnAccount entry — readonly */
        fd_pb_push_bytes ( encoder, 1U, rt->readonly_accounts[ i ], 32UL );
        fd_pb_submsg_close( encoder );
      }

      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );

      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );
      break;
    }
    case IN_KIND_RBLK: {
      FD_TEST( sz==sizeof(fd_capture_runtime_block_event_msg_t) );
      fd_capture_runtime_block_event_msg_t const * rb = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk );

      /* Worst case: ~58 KiB wire + ~3 sub-message tags per diff entry +
         envelope.  Round up to 65536 B for the circq slot. */
      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 65536UL );
      FD_TEST( buffer );

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_log_wallclock();
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 65536UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 9U ); /* RuntimeBlock */

      fd_pb_push_uint64( encoder, 1U,  rb->slot );
      fd_pb_push_bytes ( encoder, 2U,  rb->block_id, 32UL );
      fd_pb_push_uint64( encoder, 3U,  rb->parent_slot );
      fd_pb_push_bytes ( encoder, 4U,  rb->parent_block_id, 32UL );
      fd_pb_push_uint32( encoder, 5U,  rb->epoch );
      fd_pb_push_bytes ( encoder, 6U,  rb->leader, 32UL );
      fd_pb_push_uint32( encoder, 7U,  rb->block_produced ? 1U : 0U );
      fd_pb_push_bytes ( encoder, 8U,  rb->bank_hash,                 32UL );
      fd_pb_push_bytes ( encoder, 9U,  rb->prev_bank_hash,            32UL );
      fd_pb_push_bytes ( encoder, 10U, rb->accounts_lt_hash_checksum, 32UL );
      fd_pb_push_bytes ( encoder, 11U, rb->poh_hash,                  32UL );
      fd_pb_push_bytes ( encoder, 12U, rb->blockhash,                 32UL );
      fd_pb_push_uint32( encoder, 13U, rb->num_transactions );
      fd_pb_push_uint32( encoder, 14U, rb->num_successful_txns );
      fd_pb_push_uint32( encoder, 15U, rb->num_failed_txns );
      fd_pb_push_uint64( encoder, 16U, rb->num_signatures );
      fd_pb_push_uint32( encoder, 17U, rb->ticks_in_block );
      fd_pb_push_uint64( encoder, 18U, rb->tick_height );
      fd_pb_push_uint64( encoder, 19U, rb->fees_collected );
      fd_pb_push_uint64( encoder, 20U, rb->priority_fees_total );
      fd_pb_push_uint64( encoder, 21U, rb->compute_units_consumed );
      fd_pb_push_uint64( encoder, 22U, rb->capitalization );
      fd_pb_push_uint64( encoder, 23U, rb->total_effective_stake );
      fd_pb_push_uint64( encoder, 24U, rb->total_activating_stake );
      fd_pb_push_uint64( encoder, 25U, rb->total_deactivating_stake );
      fd_pb_push_uint64( encoder, 26U, rb->total_epoch_stake );
      fd_pb_push_uint64( encoder, 27U, rb->transaction_count );
      fd_pb_push_uint64( encoder, 28U, rb->fees_burned );
      fd_pb_push_uint64( encoder, 29U, rb->leader_fee_reward );

      /* Five Nested account-diff loops — tags 30, 31, 32, 33, 34 */
      ulong sysvar_cnt = rb->sysvar_diffs_cnt;
      if( sysvar_cnt > FD_CAPTURE_RUNTIME_BLOCK_SYSVAR_DIFFS_MAX ) sysvar_cnt = FD_CAPTURE_RUNTIME_BLOCK_SYSVAR_DIFFS_MAX;
      for( ulong di=0UL; di<sysvar_cnt; di++ ) {
        fd_capture_runtime_block_account_diff_t const * d = &rb->sysvar_diffs[ di ];
        fd_pb_submsg_open( encoder, 30U );
        fd_pb_push_bytes ( encoder, 1U, d->pubkey, 32UL );
        fd_pb_push_bytes ( encoder, 2U, d->owner,  32UL );
        fd_pb_push_uint64( encoder, 3U, d->lamports );
        fd_pb_push_uint64( encoder, 4U, d->data_sz );
        fd_pb_push_uint32( encoder, 5U, d->executable ? 1U : 0U );
        fd_pb_submsg_close( encoder );
      }
      ulong vr_cnt = rb->vote_reward_diffs_cnt;
      if( vr_cnt > FD_CAPTURE_RUNTIME_BLOCK_VOTE_REWARD_DIFFS_MAX ) vr_cnt = FD_CAPTURE_RUNTIME_BLOCK_VOTE_REWARD_DIFFS_MAX;
      for( ulong di=0UL; di<vr_cnt; di++ ) {
        fd_capture_runtime_block_account_diff_t const * d = &rb->vote_reward_diffs[ di ];
        fd_pb_submsg_open( encoder, 31U );
        fd_pb_push_bytes ( encoder, 1U, d->pubkey, 32UL );
        fd_pb_push_bytes ( encoder, 2U, d->owner,  32UL );
        fd_pb_push_uint64( encoder, 3U, d->lamports );
        fd_pb_push_uint64( encoder, 4U, d->data_sz );
        fd_pb_push_uint32( encoder, 5U, d->executable ? 1U : 0U );
        fd_pb_submsg_close( encoder );
      }
      ulong sr_cnt = rb->stake_reward_diffs_cnt;
      if( sr_cnt > FD_CAPTURE_RUNTIME_BLOCK_STAKE_REWARD_DIFFS_MAX ) sr_cnt = FD_CAPTURE_RUNTIME_BLOCK_STAKE_REWARD_DIFFS_MAX;
      for( ulong di=0UL; di<sr_cnt; di++ ) {
        fd_capture_runtime_block_account_diff_t const * d = &rb->stake_reward_diffs[ di ];
        fd_pb_submsg_open( encoder, 32U );
        fd_pb_push_bytes ( encoder, 1U, d->pubkey, 32UL );
        fd_pb_push_bytes ( encoder, 2U, d->owner,  32UL );
        fd_pb_push_uint64( encoder, 3U, d->lamports );
        fd_pb_push_uint64( encoder, 4U, d->data_sz );
        fd_pb_push_uint32( encoder, 5U, d->executable ? 1U : 0U );
        fd_pb_submsg_close( encoder );
      }
      ulong fr_cnt = rb->fee_reward_diffs_cnt;
      if( fr_cnt > FD_CAPTURE_RUNTIME_BLOCK_FEE_REWARD_DIFFS_MAX ) fr_cnt = FD_CAPTURE_RUNTIME_BLOCK_FEE_REWARD_DIFFS_MAX;
      for( ulong di=0UL; di<fr_cnt; di++ ) {
        fd_capture_runtime_block_account_diff_t const * d = &rb->fee_reward_diffs[ di ];
        fd_pb_submsg_open( encoder, 33U );
        fd_pb_push_bytes ( encoder, 1U, d->pubkey, 32UL );
        fd_pb_push_bytes ( encoder, 2U, d->owner,  32UL );
        fd_pb_push_uint64( encoder, 3U, d->lamports );
        fd_pb_push_uint64( encoder, 4U, d->data_sz );
        fd_pb_push_uint32( encoder, 5U, d->executable ? 1U : 0U );
        fd_pb_submsg_close( encoder );
      }
      ulong oth_cnt = rb->other_diffs_cnt;
      if( oth_cnt > FD_CAPTURE_RUNTIME_BLOCK_OTHER_DIFFS_MAX ) oth_cnt = FD_CAPTURE_RUNTIME_BLOCK_OTHER_DIFFS_MAX;
      for( ulong di=0UL; di<oth_cnt; di++ ) {
        fd_capture_runtime_block_account_diff_t const * d = &rb->other_diffs[ di ];
        fd_pb_submsg_open( encoder, 34U );
        fd_pb_push_bytes ( encoder, 1U, d->pubkey, 32UL );
        fd_pb_push_bytes ( encoder, 2U, d->owner,  32UL );
        fd_pb_push_uint64( encoder, 3U, d->lamports );
        fd_pb_push_uint64( encoder, 4U, d->data_sz );
        fd_pb_push_uint32( encoder, 5U, d->executable ? 1U : 0U );
        fd_pb_submsg_close( encoder );
      }
      ulong fec_cnt = rb->fec_merkle_roots_cnt;
      if( fec_cnt > FD_CAPTURE_RUNTIME_BLOCK_FEC_MRS_MAX ) fec_cnt = FD_CAPTURE_RUNTIME_BLOCK_FEC_MRS_MAX;
      for( ulong i=0UL; i<fec_cnt; i++ ) {
        fd_pb_submsg_open( encoder, 35U );  /* RuntimeBlockFecMr entry */
        fd_pb_push_bytes ( encoder, 1U, rb->fec_merkle_roots[ i ], 32UL );
        fd_pb_submsg_close( encoder );
      }

      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );

      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );
      break;
    }
    case IN_KIND_BANK: {
      FD_TEST( sz==sizeof(fd_capture_bank_event_msg_t) );
      fd_capture_bank_event_msg_t const * bank = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk );

      /* Bank-hash events encode to ~200 B; 512 is plenty. */
      uchar * buffer = fd_circq_push_back( ctx->circq, 1UL, 512UL );
      FD_TEST( buffer );

      ulong event_id = fd_event_client_id_reserve( ctx->client );
      long timestamp_nanos = fd_log_wallclock();
      long timestamp_seconds = timestamp_nanos / 1000000000L;
      int  timestamp_subsec_nanos = (int)( timestamp_nanos % 1000000000L );

      fd_pb_encoder_t encoder[1];
      fd_pb_encoder_init( encoder, buffer, 512UL );

      FD_TEST( ctx->circq->cursor_push_seq );
      fd_pb_push_uint64( encoder, 1U, ctx->circq->cursor_push_seq-1UL );
      fd_pb_push_uint64( encoder, 2U, event_id );
      fd_pb_submsg_open( encoder, 3U );
      if( FD_LIKELY( timestamp_seconds ) ) fd_pb_push_int64( encoder, 1U, timestamp_seconds );
      if( FD_LIKELY( timestamp_subsec_nanos ) ) fd_pb_push_int32( encoder, 2U, timestamp_subsec_nanos );
      fd_pb_submsg_close( encoder );

      fd_pb_submsg_open( encoder, 4U ); /* Event */
      fd_pb_submsg_open( encoder, 4U ); /* BankHash */
      fd_pb_push_bytes ( encoder, 1U, bank->bank_hash,                 32UL );
      fd_pb_push_bytes ( encoder, 2U, bank->prev_bank_hash,            32UL );
      fd_pb_push_bytes ( encoder, 3U, bank->accounts_lt_hash_checksum, 32UL );
      fd_pb_push_bytes ( encoder, 4U, bank->poh_hash,                  32UL );
      fd_pb_push_uint64( encoder, 5U, bank->slot );
      fd_pb_push_uint64( encoder, 6U, bank->signature_cnt );
      fd_pb_submsg_close( encoder );
      fd_pb_submsg_close( encoder );

      fd_circq_resize_back( ctx->circq, fd_pb_encoder_out_sz( encoder ) );
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_tile_t),  sizeof(fd_event_tile_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_event_client_align(),  fd_event_client_footprint( GRPC_BUF_MAX ) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_circq_align(),         fd_circq_footprint( 1UL<<30UL )           );
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

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_tile_t), sizeof(fd_event_tile_t)                   );
  void * _event_client  = FD_SCRATCH_ALLOC_APPEND( l, fd_event_client_align(),  fd_event_client_footprint( GRPC_BUF_MAX ) );
  void * _circq         = FD_SCRATCH_ALLOC_APPEND( l, fd_circq_align(),         fd_circq_footprint( 1UL<<30UL )           );
# if FD_HAS_OPENSSL
  FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
# endif

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

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ctx->circq = fd_circq_join( fd_circq_new( _circq, 1UL<<30UL /* 1GiB */ ) );
  FD_TEST( ctx->circq );

  void * ssl_ctx_ptr = NULL;
# if FD_HAS_OPENSSL
  ssl_ctx_ptr = ctx->ssl_ctx;
# endif

  /* Rewrite the URL to hardcode port 7878 regardless of the port in
     the configured URL. */
  fd_url_t _url[ 1UL ];
  ushort   _port;
  _Bool    _is_ssl = 0;
  if( FD_UNLIKELY( fd_url_parse_endpoint( _url, tile->event.url, strlen( tile->event.url ), &_port, &_is_ssl, "[tiles.event.url]" ) ) ) {
    FD_LOG_ERR(( "Could not parse [tiles.event.url]" ));
  }
  char url_buf[ 512UL ];
  FD_TEST( fd_cstr_printf_check( url_buf, sizeof(url_buf), NULL, "%.*s%.*s:7878%.*s",
                                 (int)_url->scheme_len, _url->scheme,
                                 (int)_url->host_len,   _url->host,
                                 (int)_url->tail_len,   _url->tail ) );

  ctx->client = fd_event_client_join( fd_event_client_new( _event_client,
                                                           ctx->keyguard_client,
                                                           ctx->rng,
                                                           ctx->circq,
                                                           2*(1UL<<20UL) /* 2 MiB */,
                                                           url_buf,
                                                           ctx->identity_pubkey,
                                                           firedancer_version_string,
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

  int has_genesi_in = 0;
  int has_ipecho_in = 0;
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
    else if( FD_LIKELY( !strcmp( link->name, "genesi_out"   ) ) ) { ctx->in_kind[ i ] = IN_KIND_GENESI; has_genesi_in = 1; }
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"   ) ) ) { ctx->in_kind[ i ] = IN_KIND_IPECHO; has_ipecho_in = 1; }
    else if( FD_LIKELY( !strcmp( link->name, "event_repl"   ) ) ) ctx->in_kind[ i ] = IN_KIND_ACCOUNT;
    else if( FD_LIKELY( !strcmp( link->name, "event_execrp" ) ) ) ctx->in_kind[ i ] = IN_KIND_ACCOUNT;
    else if( FD_LIKELY( !strcmp( link->name, "event_bank"   ) ) ) ctx->in_kind[ i ] = IN_KIND_BANK;
    else if( FD_LIKELY( !strcmp( link->name, "event_stake"  ) ) ) ctx->in_kind[ i ] = IN_KIND_STAKE;
    else if( FD_LIKELY( !strcmp( link->name, "event_vote"   ) ) ) ctx->in_kind[ i ] = IN_KIND_VOTE;
    else if( FD_LIKELY( !strcmp( link->name, "event_cvote"  ) ) ) ctx->in_kind[ i ] = IN_KIND_CVOTE;
    else if( FD_LIKELY( !strcmp( link->name, "event_rtxn"   ) ) ) ctx->in_kind[ i ] = IN_KIND_RTXN;
    else if( FD_LIKELY( !strcmp( link->name, "event_rblk"   ) ) ) ctx->in_kind[ i ] = IN_KIND_RBLK;
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

  ctx->tick_per_ns         = fd_tempo_tick_per_ns( NULL );
  ctx->reference_wallclock = fd_log_wallclock();
  ctx->reference_tickcount = fd_tickcount();

  /* Default-init genesis and shred_version when their input links are
     not wired (e.g. in backtest), so the gRPC client can still proceed
     to connect/auth/stream. */
  if( FD_UNLIKELY( !has_genesi_in ) ) {
    fd_genesis_meta_t empty_meta = {0};
    fd_event_client_init_genesis( ctx->client, &empty_meta );
  }
  if( FD_UNLIKELY( !has_ipecho_in ) ) {
    fd_event_client_init_shred_version( ctx->client, 0 );
  }

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
  ctx->reference_wallclock = fd_log_wallclock();
  ctx->reference_tickcount = fd_tickcount();

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
