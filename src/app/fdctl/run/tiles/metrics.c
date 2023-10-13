#include "../../fdctl.h"
#include "../run.h"

#include "../../../../disco/fd_disco.h"
#include "../../../../disco/metrics/fd_ssl.h"
#include "../../../../disco/metrics/fd_metrics_impl.h"

#include <linux/unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define METRICS_TAG 0x8bf72a57ca2947b7UL

/* ssl_init must be called in init() because it must execute outside the sandbox */
static void
ssl_init( void ) {
  /* none of the below functions return a useful value */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
}

#define SSL_STATE_SZ 2
/* double buffer because we are not servicing more than two connections at a time */
ssl_service_state_t ssl_state[SSL_STATE_SZ];

/* append_datapoints converts datapoints into InfluxDB line protocol lines which get appended to append_buffer for
 * later posting to metrics.solana.com.  It returns the remaining capacity of append_buffer. tile_name and idx are
 * used to tag the measurement */
static ulong
append_datapoints( char *       append_buffer,
                   ulong        append_buffer_capacity,
                   char * const tile_name,
                   ulong        idx,
                   Datapoint *  datapoints,
                   ulong        datapoints_sz ) {
  metrics_kv_t tags[] = {
      { .key   = "host_id",
         .value = "" },     /* strncpy below from fd_log_host() */
      { .key   = "tile",
          .value = "" },    /* snprintf below */
      { .key   = "index",
          .value = "" },    /* snprintf below */
  };
  strncpy(  tags[ 0 ].value, fd_log_host(), sizeof( tags[ 0 ].value ) - 1 );
  strncpy(  tags[ 1 ].value, tile_name,     sizeof( tags[ 1 ].value ) - 1 );
  snprintf( tags[ 2 ].value, sizeof( tags[ 2 ].value ), "%ld", idx );

  long ts = fd_log_wallclock();
  for( ulong i=0; i<datapoints_sz; i++ ) {
    char data[ 4096 ];
    int ret = fd_metrics_format( data, sizeof( data ), tile_name, tags, sizeof( tags )/sizeof( tags[0] ), &datapoints[i], 1, ts++ );
    if( FD_UNLIKELY( ret<0 || ret>=(int)sizeof( data ) ) ) {
      FD_LOG_WARNING(( "snprintf error %d", ret ));
      return 0;
    }
    ulong line_sz = strlen( data ) + 1;
    if( FD_UNLIKELY( append_buffer_capacity <= line_sz ) ) {
      FD_LOG_WARNING(( "append_buffer_capacity %lu <= %lu", append_buffer_capacity, strlen( data ) + 1 ));
      return 0;
    }
    strncat( append_buffer, data, append_buffer_capacity - 1 );
    append_buffer_capacity -= line_sz;
  }
  return append_buffer_capacity;
}

/* metrics_ctx_t is required because the contents of the strcut are used in the run function but need to be initialized
   in the init function */
typedef struct {
  ulong  depth;
  ulong  quic_count;
  ulong  bank_count;
  ulong  verify_count;
  ulong  buffer_size;
  ulong  data_buffer_sz;
  char * data_buffer;
  ulong  post_buffer_sz;
  char * post_buffer;
  const char * server;
  const char * user_pass;
  const char * db;
  ulong post_interval_ms;
  ulong in_cnt;
  metrics_t * metrics;
} metrics_ctx_t;

/* metrics_init must be called in init() because it must execute outside the sandbox.
   workspace_pod_join must be executed outside the sandbox. */
void
metrics_init( fd_tile_args_t const * args, metrics_ctx_t * ctx ) {
  const uchar * tile_pod   = args->wksp_pod[ 0 ];
  const uchar * quic_pod   = args->wksp_pod[ 1 ];
  const uchar * verify_pod = args->wksp_pod[ 2 ];
  const uchar * dedup_pod  = args->wksp_pod[ 3 ];
  const uchar * pack_pod   = args->wksp_pod[ 4 ];
  const uchar * bank_pod   = args->wksp_pod[ 5 ];

  ctx->depth = fd_pod_query_ulong( tile_pod, "depth", 0UL );
  if( FD_UNLIKELY( !ctx->depth ) ) FD_LOG_ERR(( "depth must be set" ));

  ctx->quic_count = fd_pod_query_ulong( tile_pod, "quic_count", 0UL );
  if( FD_UNLIKELY( !ctx->quic_count ) ) FD_LOG_ERR(( "quic_count must be set" ));

  ctx->bank_count = fd_pod_query_ulong( tile_pod, "bank_count", 0UL );
  if( FD_UNLIKELY( !ctx->bank_count ) ) FD_LOG_ERR(( "bank_count must be set" ));

  ctx->verify_count = fd_pod_query_ulong( tile_pod, "verify_count", 0UL );
  if( FD_UNLIKELY( !ctx->verify_count ) ) FD_LOG_ERR(( "verify_count must be set" ));

  ctx->buffer_size = fd_pod_query_ulong( tile_pod, "buffer_size", 0UL );
  if( FD_UNLIKELY( !ctx->buffer_size ) ) FD_LOG_ERR(( "buffer_size must be set" ));

  for( ulong i=0; i<SSL_STATE_SZ; i++ ) {
    ulong  data_buf_sz = ctx->buffer_size;
    char * data_buf = fd_wksp_alloc_laddr( fd_wksp_containing( tile_pod ), 1, data_buf_sz, METRICS_TAG );
    if( FD_UNLIKELY( !data_buf ) ) FD_LOG_ERR(( "data_buf must be set" ));

    /* The post buffer is larger than the data buffer to allow for the HTTP headers */
    ulong  tx_buf_sz = ctx->buffer_size + 1000;
    char * tx_buf = fd_wksp_alloc_laddr( fd_wksp_containing( tile_pod ), 1, tx_buf_sz, METRICS_TAG );
    if( FD_UNLIKELY( !tx_buf_sz ) ) FD_LOG_ERR(( "tx_buf_sz must be set" ));

    ssl_service_init( &ssl_state[i], data_buf, data_buf_sz, tx_buf, tx_buf_sz );
  }

  ctx->server = fd_pod_query_cstr( tile_pod, "server", NULL );
  if( FD_UNLIKELY( !ctx->server ) ) FD_LOG_ERR(( "server must be set" ));

  ctx->user_pass = fd_pod_query_cstr( tile_pod, "user_pass", NULL );
  if( FD_UNLIKELY( !ctx->user_pass ) ) FD_LOG_ERR(( "user_pass must be set" ));

  ctx->db = fd_pod_query_cstr( tile_pod, "db", NULL );
  if( FD_UNLIKELY( !ctx->db ) ) FD_LOG_ERR(( "db must be set" ));

  ctx->post_interval_ms = fd_pod_query_ulong( tile_pod, "post_interval_ms", 0UL );
  if( FD_UNLIKELY( !ctx->post_interval_ms ) ) FD_LOG_ERR(( "post_interval_ms must be set" ));

  ctx->in_cnt = ctx->bank_count + ctx->quic_count + ctx->verify_count + 2; /* +2 for dedup and pack */

  ctx->metrics = fd_wksp_alloc_laddr( fd_wksp_containing( tile_pod ), alignof( metrics_ctx_t ), ctx->in_cnt * sizeof( metrics_ctx_t ), METRICS_TAG );
  if( FD_UNLIKELY( !ctx->metrics ) ) FD_LOG_ERR(( "metrics must be set %lu", ctx->in_cnt ));
  ulong idx = 0;

  /* quic */
  for( ulong i = 0; i < ctx->quic_count; i++ ) {
    metrics_boot_unmanaged( quic_pod, metrics_quic, i, &ctx->metrics[ idx++ ] );
  }

  /* verify */
  for( ulong i = 0; i < ctx->verify_count; i++ ) {
    metrics_boot_unmanaged( verify_pod, metrics_verify, i, &ctx->metrics[ idx++ ] );
  }

  /* dedup */
  metrics_boot_unmanaged( dedup_pod, metrics_dedup, 0, &ctx->metrics[ idx++ ] );

  /* pack */
  metrics_boot_unmanaged( pack_pod, metrics_pack,   0, &ctx->metrics[ idx++ ] );

  /* bank */
  for( ulong i = 0; i < ctx->bank_count; i++ ) {
    metrics_boot_unmanaged( bank_pod, metrics_bank, i, &ctx->metrics[ idx++ ] );
  }
}

/* metrics_ctx_t is required because the contents of the strcut are used in the run function but need to be initialized
   in the init function */
metrics_ctx_t ctx;

static void
init( fd_tile_args_t * args ) {
  (void)args;
  /* calling fd_tempo_tick_per_ns requires nanosleep, it is cached with
     a FD_ONCE */
  fd_tempo_tick_per_ns( NULL );

  ssl_init();
  metrics_init( args, &ctx );
}

static void
run( fd_tile_args_t * args ) {
  const uchar * tile_pod   = args->wksp_pod[ 0 ];

  SSL_CTX * ssl_ctx = SSL_CTX_new(TLS_client_method());
  /* this should never happen, if it does the tile is unhealthy and unable to operate so exit */
  if( FD_UNLIKELY( ssl_ctx == NULL ) ) {
    FD_LOG_WARNING(( "SSL_CTX_new failed" ));
  }

  /* Join the IPC objects needed this tile instance */
  FD_LOG_INFO(( "joining cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( tile_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc ) != FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  ulong * cnc_diag = ( ulong * ) fd_cnc_app_laddr( cnc );
  cnc_diag[ FD_APP_CNC_DIAG_PID ] = ( ulong ) args->pid;

  /* Setup local objects used by this tile */
  long lazy = fd_pod_query_long( tile_pod, "lazy", 0L );
  FD_LOG_INFO(( "configuring flow control (lazy %li)", lazy ));
  if( FD_UNLIKELY( lazy <= 0L ) ) lazy = fd_tempo_lazy_default( ctx.depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, ( float ) fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = ( uint ) fd_tile_id(); /* TODO: LML is this a good seed? */
  FD_LOG_INFO(( "creating rng (seed %u)", seed ));
  fd_rng_t _rng[1];
  fd_rng_t *rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng )) FD_LOG_ERR(( "fd_rng_join failed" ));

  FD_LOG_INFO(( "metrics run" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  long cnc_service_deadline = fd_tickcount();
  long metrics_service_deadline = fd_tickcount();

  ulong     metrics_idx = 0;
  ulong     ssl_idx = 0;
  ulong     num_datapoints = 0;
  Datapoint datapoints[ctx.depth];
  for( ;; ) {
    long now = fd_tickcount();
    metrics_t * metric = &ctx.metrics[ metrics_idx ];

    /* Service the SSL connections */
    for( ulong i=0; i<SSL_STATE_SZ; i++ ) {
      do {
        /* If the connection is active service it */
        if( FD_LIKELY( ssl_state[ i ].conn.ssl_bio ) ) {
          ssl_service( &ssl_state[ i ] );
        }
        /* If the connection is done, reinitialize it */
        if( FD_UNLIKELY( ssl_state[ i ].rx_done ) ) {
          ssl_service_reinit( &ssl_state[ i ] );
        }
      } while( ssl_state[ i ].conn.ssl_bio && !ssl_state[ i ].rx_done);
    }

    /* Periodically post metrics */
    if( FD_UNLIKELY( metrics_service_deadline <= now ) ) {
      if( FD_LIKELY( strlen( ssl_state[ssl_idx].data_buf ) ) ) {
        fd_ssl_send_data( ctx.server, ctx.user_pass, ctx.db, ssl_ctx, &ssl_state[ssl_idx] );
      }
      ssl_idx++;
      ssl_idx %= SSL_STATE_SZ;
      metrics_service_deadline = now + (long)ctx.post_interval_ms*1000000 + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Read available datapoints from the tile then queue up the next one */
    for( ulong i = 0; i < ctx.depth; i++ ) {
      uint tag;
      ulong value;
      metrics_status_t status = metrics_pop_unmanaged( metric, &tag, &value );
      switch( status ) {
        case METRICS_STATUS_OK:
          fd_metrics_tag_value_to_datapoint( tag, value, &datapoints[ num_datapoints ] );
          num_datapoints++;
          break;
        case METRICS_STATUS_EMPTY:
          goto loop_break;
        case METRICS_STATUS_OVERRUN:
          FD_LOG_WARNING(( "metrics overrun %s", metrics_tile_names[ metric->tile ] ));
          break;
        case METRICS_STATUS_UNINITIALIZED:
          FD_LOG_WARNING(( "metrics uninitialized %s", metrics_tile_names[ metric->tile ] ));
          goto loop_break;
      }
    }
    loop_break:

    /* If we have new datapoints append them now */
    if( FD_LIKELY( num_datapoints ) ) {
      ssl_state[ssl_idx].data_buf_capacity = append_datapoints( ssl_state[ssl_idx].data_buf,
                                                                ssl_state[ssl_idx].data_buf_capacity,
                                                                metrics_tile_names[ metric->tile ],
                                                                metric->idx,
                                                                datapoints,
                                                                num_datapoints );
      num_datapoints = 0;

      /* The buffer is filled, post metrics on the next iteration */
      if( FD_UNLIKELY( !ssl_state[ssl_idx].data_buf_capacity ) ) {
        metrics_service_deadline = now;
      }
    }

    /* Advance to the next tile */
    metrics_idx++;
    metrics_idx %= ctx.in_cnt;

    /* Check for CNC signals */
    if( FD_UNLIKELY( cnc_service_deadline <= now )) {
      fd_cnc_heartbeat( cnc, now );
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s != FD_CNC_SIGNAL_RUN )) {
        if( FD_LIKELY( s == FD_CNC_SIGNAL_HALT )) break;
        if( FD_UNLIKELY( s != FD_MUX_CNC_SIGNAL_ACK )) {
          char buf[FD_CNC_SIGNAL_CSTR_BUF_MAX];
          FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        }
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN);
      }
      cnc_service_deadline = now + ( long ) fd_tempo_async_reload( rng, async_min );
    }
  }
}

/* These are all required for openssl, many due to nonblocking mode */
static long allow_syscalls[] = {
  __NR_bind,
  __NR_close,
  __NR_connect,
  __NR_fstat,
  __NR_fsync,
  __NR_getpid,
  __NR_getrandom,
  __NR_getsockname,
  __NR_getsockopt,
  __NR_ioctl,
  __NR_openat,
  __NR_poll,
  __NR_read,
  __NR_recvmsg,
  __NR_select,
  __NR_sendto,
  __NR_setsockopt,
  __NR_shutdown,
  __NR_socket,
  __NR_write,
};

static ulong
allow_fds( fd_tile_args_t * args,
           ulong out_fds_sz,
           int * out_fds ) {
  (void)args;
  if( FD_UNLIKELY( out_fds_sz < 2 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  return 2;
}

static workspace_kind_t allow_workspaces[] = {
    wksp_metrics,
    wksp_metrics_quic,
    wksp_metrics_verify,
    wksp_metrics_dedup,
    wksp_metrics_pack,
    wksp_metrics_bank,
};

fd_tile_config_t metrics = {
    .name              = "metrics",
    .allow_workspaces_cnt = sizeof(allow_workspaces)/sizeof(allow_workspaces[ 0 ]),
    .allow_workspaces     = allow_workspaces,
    .allow_syscalls_cnt   = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
    .allow_syscalls    = allow_syscalls,
    .allow_fds         = allow_fds,
    .init              = init,
    .run               = run,
    .sandbox_mode      = SANDBOX_MODE_METRICS,
};
