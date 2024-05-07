#include "tiles.h"

#include "generated/metric_seccomp.h"

#include "../../../../ballet/http/picohttpparser.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <stdio.h>

#define MAX_CONNS 128

/* The metric tile reads metrics updates from other tiles, maybe
   presents them on a local HTTP endpoint, and maybe uploads them to
   a server InfluxDB endpoint. */

typedef struct {
  ulong bytes_read;
  char input[ 1024UL ];

  ulong output_len;
  char output[ 16777216UL ];
  ulong bytes_written;
} fd_metric_connection_t;

typedef struct {
  fd_topo_t * topo;

  int socket_fd;

  fd_metric_connection_t conns[ MAX_CONNS ];
  struct pollfd            fds[ MAX_CONNS+1 ];

  ulong conn_id;
} fd_metric_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_metric_ctx_t ) );
}

static void
close_conn( fd_metric_ctx_t * ctx,
            ulong             idx ) {
  if( FD_UNLIKELY( -1==close( ctx->fds[ idx ].fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, strerror( errno ) ));
  ctx->fds[ idx ].fd = -1;
}

static void
accept_conns( fd_metric_ctx_t * ctx ) {
  for(;;) {
    int fd = accept( ctx->socket_fd, NULL, NULL );

    if( FD_UNLIKELY( -1==fd ) ) {
      if( FD_LIKELY( EAGAIN==errno ) ) break;
      else if( FD_LIKELY( ENETDOWN==errno || EPROTO==errno || ENOPROTOOPT==errno || EHOSTDOWN==errno ||
                          ENONET==errno || EHOSTUNREACH==errno || EOPNOTSUPP==errno || ENETUNREACH==errno ) ) continue;
      else FD_LOG_ERR(( "accept failed (%i-%s)", errno, strerror( errno ) ));
    }

    /* Just evict oldest connection if it's still alive, they were too slow. */
    if( FD_UNLIKELY( -1!=ctx->fds[ ctx->conn_id ].fd ) ) close_conn( ctx, ctx->conn_id );

    ctx->fds[ ctx->conn_id ].fd = fd;
    ctx->conns[ ctx->conn_id ] = (fd_metric_connection_t){
      .bytes_read    = 0UL,
      .bytes_written = 0UL,
      .output_len    = 0UL,
    };
    ctx->conn_id = (ctx->conn_id + 1) % MAX_CONNS;
  }
}

#define PRINT( ... ) (__extension__({                  \
    int n = snprintf( *out, *out_len, __VA_ARGS__ );   \
    if( FD_UNLIKELY( n<0 ) ) return -1;                \
    if( FD_UNLIKELY( (ulong)n>=*out_len ) ) return -1; \
    *out += n; *out_len -= (ulong)n;                   \
    n;                                                 \
  }))

#define PRINT_LINK_IN  (0)
#define PRINT_LINK_OUT (1)
#define PRINT_TILE     (2)

static ulong
find_producer_out_idx( fd_topo_t *      topo,
                       fd_topo_tile_t * producer,
                       fd_topo_tile_t * consumer,
                       ulong            consumer_in_idx ) {
  /* This finds all reliable consumers of the producers primary output,
     and then returns the position of the consumer (specified by tile
     and index of the in of that tile) in that list. The list ordering
     is not important, except that it matches the ordering of fseqs
     provided to the mux tile, so that metrics written for each link
     index are retrieved at the same index here.

     This is why we only count reliable links, because the mux tile only
     looks at and writes producer side diagnostics (is the link slow)
     for reliable links. */

  ulong count = 0UL;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0; j<consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ] == producer->out_link_id_primary && consumer_tile->in_link_reliable[ j ] ) ) {
        if( FD_UNLIKELY( consumer==consumer_tile && consumer_in_idx==j ) ) return count;
        count++;
      }
    }
  }
  return ULONG_MAX;
}

static long
prometheus_print1( fd_topo_t *               topo,
                   char **                   out,
                   ulong *                   out_len,
                   char const *              tile_name,
                   ulong                     metrics_cnt,
                   fd_metrics_meta_t const * metrics,
                   int                       print_mode ) {
  for( ulong i=0; i<metrics_cnt; i++ ) {
    fd_metrics_meta_t const * metric = &metrics[ i ];
    PRINT( "# HELP %s %s\n# TYPE %s %s\n", metric->name, metric->desc, metric->name, fd_metrics_meta_type_str( metric ) );

    for( ulong j=0; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ j ];
      if( FD_LIKELY( tile_name!=NULL && strcmp( tile->name, tile_name ) ) ) continue;

      if( FD_LIKELY( metric->type==FD_METRICS_TYPE_COUNTER || metric->type==FD_METRICS_TYPE_GAUGE ) ) {
        if( FD_LIKELY( print_mode==PRINT_TILE ) ) {
          ulong value = *(fd_metrics_tile( tile->metrics ) + metric->offset);
          PRINT( "%s{kind=\"%s\",kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, value );
        } else {
          if( FD_LIKELY( print_mode==PRINT_LINK_IN ) ) {
            for( ulong k=0; k<tile->in_cnt; k++ ) {
              fd_topo_link_t * link = &topo->links[ tile->in_link_id[ k ] ];
              ulong value = *(fd_metrics_link_in( tile->metrics, k ) + metric->offset );
              PRINT( "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, link->name, link->kind_id, value );
            }
          } else if( FD_LIKELY( print_mode==PRINT_LINK_OUT ) ) {
            for( ulong k=0; k<tile->in_cnt; k++ ) {
              fd_topo_link_t * link = &topo->links[ tile->in_link_id[ k ] ];
              if( FD_UNLIKELY( !tile->in_link_reliable[ k ] ) ) continue;

              ulong producer_idx = fd_topo_find_link_producer( topo, link );
              if( FD_UNLIKELY( producer_idx==ULONG_MAX ) ) continue;
              
              fd_topo_tile_t * producer = &topo->tiles[ producer_idx ];
              if( FD_UNLIKELY( producer->out_link_id_primary!=link->id ) ) continue;

              /* This index needs to line up with what the mux tile thinks the index is
                 of that tile in its consumer list. */
              ulong producer_out_idx = find_producer_out_idx( topo, producer, tile, k );
              ulong value = *(fd_metrics_link_out( producer->metrics, producer_out_idx ) + metric->offset );

              PRINT( "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->kind_id, link->name, link->kind_id, value );
            }
          }
        }
      } else if( FD_LIKELY( metric->type==FD_METRICS_TYPE_HISTOGRAM ) ) {
        fd_histf_t hist[1];
        if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_SECONDS ) )
          FD_TEST( fd_histf_new( hist, fd_metrics_convert_seconds_to_ticks( metric->histogram.seconds.min ), fd_metrics_convert_seconds_to_ticks ( metric->histogram.seconds.max ) ) );
        else if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_NONE ) )
          FD_TEST( fd_histf_new( hist, metric->histogram.none.min, metric->histogram.none.max ) );
        else FD_LOG_ERR(( "unknown histogram converter %i", metric->histogram.converter ));

        ulong value = 0;
        char value_str[ 64 ];
        for( ulong k=0; k<FD_HISTF_BUCKET_CNT; k++ ) {
          value += *(fd_metrics_tile( tile->metrics ) + metric->offset + k);

          char * le;
          char le_str[ 64 ];
          if( FD_UNLIKELY( k==FD_HISTF_BUCKET_CNT-1UL ) ) le = "+Inf";
          else {
            ulong edge = fd_histf_right( hist, k );
            if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_SECONDS ) ) {
              double edgef = fd_metrics_convert_ticks_to_seconds( edge-1 );
              FD_TEST( fd_cstr_printf_check( le_str, sizeof( le_str ), NULL, "%.17g", edgef ) );
            } else {
              FD_TEST( fd_cstr_printf_check( le_str, sizeof( le_str ), NULL, "%lu", edge-1 ) );
            }
            le = le_str;
          }

          FD_TEST( fd_cstr_printf_check( value_str, sizeof( value_str ), NULL, "%lu", value ));
          PRINT( "%s_bucket{kind=\"%s\",kind_id=\"%lu\",le=\"%s\"} %s\n", metric->name, tile->name, tile->kind_id, le, value_str );
        }

        char sum_str[ 64 ];
        if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_SECONDS ) ) {
          double sumf = fd_metrics_convert_ticks_to_seconds( *(fd_metrics_tile( tile->metrics ) + metric->offset + FD_HISTF_BUCKET_CNT) );
          FD_TEST( fd_cstr_printf_check( sum_str, sizeof( sum_str ), NULL, "%.17g", sumf ) );
        } else {
          FD_TEST( fd_cstr_printf_check( sum_str, sizeof( sum_str ), NULL, "%lu", *(fd_metrics_tile( tile->metrics ) + metric->offset + FD_HISTF_BUCKET_CNT) ));
        }

        PRINT( "%s_sum{kind=\"%s\",kind_id=\"%lu\"} %s\n", metric->name, tile->name, tile->kind_id, sum_str );
        PRINT( "%s_count{kind=\"%s\",kind_id=\"%lu\"} %s\n", metric->name, tile->name, tile->kind_id, value_str );
      }
    }

    if( FD_LIKELY( i!=metrics_cnt-1 ) ) PRINT( "\n" );
  }

  return 0;
}

static long
prometheus_print( fd_topo_t * topo,
                  char **     out,
                  ulong *     out_len ) {
  ulong start_len = *out_len;

  PRINT( "HTTP/1.1 200 OK\r\nContent-Length: " );
  char * content_len = *out;

  /* Stuff a bunch of whitespace so we can replace with the real Content-Length later.
     Enough whitespace to print ULONG_MAX. */
  PRINT( "                     \r\nContent-Type: text/plain; version=0.0.4\r\n\r\n" );
  ulong content_start = (ulong)(start_len - *out_len);

  long result = prometheus_print1( topo, out, out_len, NULL, FD_METRICS_ALL_TOTAL, FD_METRICS_ALL, PRINT_TILE );
  if( FD_UNLIKELY( result<0 ) ) return result;
  PRINT( "\n" );
  result = prometheus_print1( topo, out, out_len, NULL, FD_METRICS_ALL_LINK_IN_TOTAL, FD_METRICS_ALL_LINK_IN, PRINT_LINK_IN );
  if( FD_UNLIKELY( result<0 ) ) return result;
  PRINT( "\n" );
  result = prometheus_print1( topo, out, out_len, NULL, FD_METRICS_ALL_LINK_OUT_TOTAL, FD_METRICS_ALL_LINK_OUT, PRINT_LINK_OUT );
  if( FD_UNLIKELY( result<0 ) ) return result;
  PRINT( "\n" );
  result = prometheus_print1( topo, out, out_len, "quic", FD_METRICS_QUIC_TOTAL, FD_METRICS_QUIC, PRINT_TILE );
  if( FD_UNLIKELY( result<0 ) ) return result;
  PRINT( "\n" );
  result = prometheus_print1( topo, out, out_len, "pack", FD_METRICS_PACK_TOTAL, FD_METRICS_PACK, PRINT_TILE );
  if( FD_UNLIKELY( result<0 ) ) return result;
  PRINT( "\n" );
  result = prometheus_print1( topo, out, out_len, "bank", FD_METRICS_BANK_TOTAL, FD_METRICS_BANK, PRINT_TILE );
  if( FD_UNLIKELY( result<0 ) ) return result;
  PRINT( "\n" );
  result = prometheus_print1( topo, out, out_len, "poh", FD_METRICS_POH_TOTAL, FD_METRICS_POH, PRINT_TILE );
  if( FD_UNLIKELY( result<0 ) ) return result;
  PRINT( "\n" );
  result = prometheus_print1( topo, out, out_len, "shred", FD_METRICS_SHRED_TOTAL, FD_METRICS_SHRED, PRINT_TILE );
  if( FD_UNLIKELY( result<0 ) ) return result;
  PRINT( "\n" );
  result = prometheus_print1( topo, out, out_len, "store", FD_METRICS_STORE_TOTAL, FD_METRICS_STORE, PRINT_TILE );
  if( FD_UNLIKELY( result<0 ) ) return result;

  /* Now backfill Content-Length */
  ulong printed;
  if( FD_UNLIKELY( !fd_cstr_printf_check( content_len, 21, &printed, "%lu", start_len - *out_len - content_start ) ) ) return -1;
  content_len[ printed ] = ' '; /* Clear NUL terminator */

  return (long)(start_len - *out_len);
}

static long
http_404_print( char ** out,
                ulong * out_len ) {
  ulong start_len = *out_len;
  PRINT( "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" );
  return (long)(start_len - *out_len);
}

static long
http_400_print( char ** out,
                ulong * out_len ) {
  ulong start_len = *out_len;
  PRINT( "HTTP/1.1 400 Internal Server Error\r\nContent-Length: 0\r\n\r\n" );
  return (long)(start_len - *out_len);
}


static void
read_conn( fd_metric_ctx_t * ctx,
           ulong             idx ) {
  fd_metric_connection_t * conn = &ctx->conns[ idx ];
  if( FD_UNLIKELY( conn->bytes_read==ULONG_MAX ) ) return; /* Connection now in write mode, no need to read more. */

  long sz = read( ctx->fds[ idx ].fd, conn->input + conn->bytes_read, sizeof( conn->input ) - conn->bytes_read );
  if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data to read, continue. */
  else if( FD_UNLIKELY( !sz || (-1==sz && errno==ECONNRESET) ) ) {
    close_conn( ctx, idx ); /* EOF, peer closed connection */
    return;
  }
  else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  /* New data was read... process it */
  conn->bytes_read += (ulong)sz;
  if( FD_UNLIKELY( conn->bytes_read == sizeof( conn->input ) ) ) {
    close_conn( ctx, idx ); /* Input buffer full, request too long, terminate connection */
    return;
  }

  char const * method;
  ulong method_len;
  char const * path;
  ulong path_len;
  int minor_version;
  struct phr_header headers[ 32 ];
  ulong num_headers = 32UL;
  int result = phr_parse_request( conn->input,
                                  conn->bytes_read,
                                  &method, &method_len,
                                  &path, &path_len,
                                  &minor_version,
                                  headers, &num_headers,
                                  conn->bytes_read - (ulong)sz );
  if( FD_UNLIKELY( -2==result ) ) return; /* Request still partial, wait for more data */
  else if( FD_UNLIKELY( -1==result ) ) {
    /* Invalid request, terminate connection */
    close_conn( ctx, idx ); /* Malformed HTTP request, terminate connection */
    return;
  }

  char * out = conn->output;
  ulong out_len = sizeof( conn->output );

  /* Well formed request, process it */
  int valid = method_len==3 && !strncmp( method, "GET", method_len ) && path_len==8 && !strncmp( path, "/metrics", path_len );
  long printed = 0;
  if( FD_UNLIKELY( !valid ) ) printed = http_404_print( &out, &out_len );
  else {
    printed = prometheus_print( ctx->topo, &out, &out_len );
    if( FD_UNLIKELY( -1==printed ) ) {
      FD_LOG_WARNING(( "unable to print metrics to HTTP endpoint" ));
      printed = http_400_print( &out, &out_len );
    }
  }

  if( FD_UNLIKELY( -1==printed ) ) {
    FD_LOG_WARNING(( "internal server error" ));
    close_conn( ctx, idx );
    return;
  }

  conn->bytes_read = ULONG_MAX; /* Mark connection as ready to write, no longer readable. */
  conn->output_len = (ulong)printed;
  conn->bytes_written = 0UL;
}

static void
write_conn( fd_metric_ctx_t *        ctx,
            ulong                    idx ) {
  fd_metric_connection_t * conn = &ctx->conns[ idx ];
  if( FD_UNLIKELY( conn->bytes_read!=ULONG_MAX ) ) return; /* No data staged for write yet. */

  long sz = write( ctx->fds[ idx ].fd, conn->output + conn->bytes_written, conn->output_len - conn->bytes_written );
  if( FD_UNLIKELY( -1==sz && (errno==EAGAIN || errno==EINTR) ) ) return; /* No data to write, continue. */
  if( FD_UNLIKELY( -1==sz && (errno==EPIPE || errno==ECONNRESET) ) ) {
    close_conn( ctx, idx ); /* Peer closed connection */
    return;
  }
  if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "write failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  conn->bytes_written += (ulong)sz;
  if( FD_UNLIKELY( conn->bytes_written==conn->output_len ) ) {
    close_conn( ctx, idx ); /* All data written, close connection gracefully. */
  }
}

static void
before_credit( void *             _ctx,
               fd_mux_context_t * mux ) {
  (void)mux;

  fd_metric_ctx_t * ctx = (fd_metric_ctx_t *)_ctx;

  int nfds = poll( ctx->fds, MAX_CONNS+1, 0 );
  if( FD_UNLIKELY( 0==nfds ) ) return;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, strerror( errno ) ));

  /* Poll existing connections for new data. */
  for( ulong i=0; i<MAX_CONNS+1; i++ ) {
    if( FD_UNLIKELY( -1==ctx->fds[ i ].fd ) ) continue;
    if( FD_UNLIKELY( i==MAX_CONNS ) ) {
      accept_conns( ctx );
    } else {
      if( FD_LIKELY( ctx->fds[ i ].revents & POLLIN ) ) read_conn( ctx, i );
      if( FD_LIKELY( ctx->fds[ i ].revents & POLLOUT ) ) write_conn( ctx, i );
      /* No need to handle POLLHUP, read() will return 0 soon enough. */
    }
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  int sockfd = socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, strerror( errno ) ));

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval ) ) ) )
    FD_LOG_ERR(( "setsockopt failed (%i-%s)", errno, strerror( errno ) ));
  
  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( tile->metric.prometheus_listen_port ),
    .sin_addr.s_addr = INADDR_ANY,
  };

  if( FD_UNLIKELY( -1==bind( sockfd, fd_type_pun( &addr ), sizeof( addr ) ) ) ) FD_LOG_ERR(( "bind failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( -1==listen( sockfd, 128 ) ) ) FD_LOG_ERR(( "listen failed (%i-%s)", errno, strerror( errno ) ));

  ctx->socket_fd = sockfd;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  ctx->topo = topo;

  ctx->conn_id = 0;
  for( ulong i=0; i<MAX_CONNS; i++ ) {
    ctx->fds[ i ].fd = -1;
    ctx->fds[ i ].events = POLLIN | POLLOUT;
  }

  ctx->fds[ MAX_CONNS ].fd = ctx->socket_fd;
  ctx->fds[ MAX_CONNS ].events = POLLIN | POLLOUT;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_LOG_NOTICE(( "Prometheus metrics endpoint listening on port %u", tile->metric.prometheus_listen_port ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  populate_sock_filter_policy_metric( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->socket_fd );
  return sock_filter_policy_metric_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->socket_fd; /* listen socket */
  return out_cnt;
}

static void
run( fd_topo_t *             topo,
     fd_topo_tile_t *        tile,
     void *                  scratch,
     fd_cnc_t *              cnc,
     ulong                   in_cnt,
     fd_frag_meta_t const ** in_mcache,
     ulong **                in_fseq,
     fd_frag_meta_t *        mcache,
     ulong                   out_cnt,
     ulong **                out_fseq ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  fd_mux_callbacks_t callbacks = {
    .before_credit = before_credit,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}

fd_topo_run_tile_t fd_tile_metric = {
  .name                     = "metric",
  .rlimit_file_cnt          = MAX_CONNS+1UL,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = run,
};
