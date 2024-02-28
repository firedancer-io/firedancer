#include "fd_metric_tile.h"

#include "generated/fd_metric_tile_seccomp.h"

#include "../../../ballet/http/picohttpparser.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <stdio.h>
#include <errno.h>

static fd_metric_tile_args_t
args_from_pod( uchar const * pod,
               char const *  id ) {
  fd_metric_tile_args_t args = {
    .prometheus_listen_port = fd_pod_query_ushort( fd_pod_query_subpod( pod, id ), "prometheus_listen_port", 0UL ),
  };
  FD_TEST( args.prometheus_listen_port );
  return args;
}

FD_FN_CONST ulong
fd_metric_tile_align( void ) {
  return FD_METRIC_TILE_ALIGN;
}

FD_FN_PURE ulong
fd_metric_tile_footprint( fd_metric_tile_args_t const * args ) {
  (void)args;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_metric_tile_t ), sizeof( fd_metric_tile_t ) );
  return FD_LAYOUT_FINI( l, fd_metric_tile_align() );
}

ulong
fd_metric_seccomp_policy( void *               shmetric,
                          struct sock_filter * out,
                          ulong                out_cnt ) {
  FD_SCRATCH_ALLOC_INIT( l, shmetric );
  fd_metric_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_tile_t ), sizeof( fd_metric_tile_t ) );

  populate_sock_filter_policy_fd_metric_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->socket_fd );
  return sock_filter_policy_fd_metric_tile_instr_cnt;
}

ulong
fd_metric_allowed_fds( void * shmetric,
                       int *  out,
                       ulong  out_cnt ) {
  FD_SCRATCH_ALLOC_INIT( l, shmetric );
  fd_metric_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_tile_t ), sizeof( fd_metric_tile_t ) );

  if( FD_UNLIKELY( out_cnt<3UL ) ) FD_LOG_ERR(( "out_cnt %lu", out_cnt ));

  ulong out_idx = 0;
  out[ out_idx++ ] = 2; /* stderr */
  out[ out_idx++ ] = ctx->socket_fd; /* listen socket */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out[ out_idx++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_idx;
}

static void
close_conn( fd_metric_tile_t * ctx,
            ulong              idx ) {
  if( FD_UNLIKELY( -1==close( ctx->fds[ idx ].fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, strerror( errno ) ));
  ctx->fds[ idx ].fd = -1;
}

static void
accept_conns( fd_metric_tile_t * ctx ) {
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
    ctx->conns[ ctx->conn_id ] = (fd_metric_tile_connection_t){
      .bytes_read    = 0UL,
      .bytes_written = 0UL,
      .output_len    = 0UL,
    };
    ctx->conn_id = (ctx->conn_id + 1UL) % FD_METRIC_TILE_MAX_CONNS;
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

static long
prometheus_print1( fd_topo_t const *         topo,
                   char **                   out,
                   ulong *                   out_len,
                   char const *              tile_name,
                   ulong                     metrics_cnt,
                   fd_metrics_meta_t const * metrics,
                   int                       print_mode ) {
  for( ulong i=0UL; i<metrics_cnt; i++ ) {
    fd_metrics_meta_t const * metric = &metrics[ i ];
    PRINT( "# HELP %s %s\n# TYPE %s %s\n", metric->name, metric->desc, metric->name, fd_metrics_meta_type_str( metric ) );

    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t const * tile = topo->tiles[ j ];
      if( FD_LIKELY( tile_name && strcmp( tile_name, tile->name ) ) ) continue;

      ulong * tile_metrics = tile->metrics;

      if( FD_LIKELY( metric->type==FD_METRICS_TYPE_COUNTER || metric->type==FD_METRICS_TYPE_GAUGE ) ) {
        if( FD_LIKELY( print_mode==PRINT_TILE ) ) {
          ulong value = *(fd_metrics_tile( tile_metrics ) + metric->offset);
          PRINT( "%s{kind=\"%s\",kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->tidx, value );
        } else {
          if( FD_LIKELY( print_mode==PRINT_LINK_IN ) ) {
            ulong link_in_idx = 0UL;
            for( ulong k=0UL; k<tile->in_cnt; k++ ) {
              fd_topo_link_in_t const * link_in = tile->in[ k ];
              if( FD_UNLIKELY( !link_in->polled ) ) continue;
              ulong value = *(fd_metrics_link_in( tile_metrics, link_in_idx ) + metric->offset );
              PRINT( "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->tidx, link_in->link->name, link_in->link->lidx, value );
              link_in_idx++;
            }
          } else if( FD_LIKELY( print_mode==PRINT_LINK_OUT ) ) {
            for( ulong k=0UL; k<tile->in_cnt; k++ ) {
              fd_topo_link_in_t const * link_in = tile->in[ k ];
              if( FD_UNLIKELY( !link_in->reliable ) ) continue;

              if( FD_UNLIKELY( link_in->producer->primary_output!=link_in->link ) ) continue;

              /* This finds all reliable link_ins of the link, and then
                 returns the position of the given link_in in that list.
                 The list ordering is not important, except that it
                 matches the ordering of fseqs provided to the mux tile,
                 so that metrics written for each link index are
                 retrieved at the same index here.

                 This is why we only count reliable links, because the
                 mux tile only looks at and writes producer side
                 diagnostics (is the link slow) for reliable links. */

              ulong link_in_idx_for_link = 0UL;
              for( ulong l=0UL; l<link_in->link->link_in_cnt; l++ ) {
                fd_topo_link_in_t const * consumer = link_in->link->link_ins[ l ];
                if( FD_UNLIKELY( !consumer->reliable ) ) continue;
                if( FD_UNLIKELY( consumer==link_in ) ) break;
                link_in_idx_for_link++;
              }
              ulong value = *(fd_metrics_link_out( link_in->producer->metrics, link_in_idx_for_link ) + metric->offset );

              PRINT( "%s{kind=\"%s\",kind_id=\"%lu\",link_kind=\"%s\",link_kind_id=\"%lu\"} %lu\n", metric->name, tile->name, tile->tidx, link_in->link->name, link_in->link->lidx, value );
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
          value += *(fd_metrics_tile( tile_metrics ) + metric->offset + k);

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

          FD_TEST( fd_cstr_printf_check( value_str, sizeof( value_str ), NULL, "%lu", value ) );
          PRINT( "%s_bucket{kind=\"%s\",kind_id=\"%lu\",le=\"%s\"} %s\n", metric->name, tile->name, tile->tidx, le, value_str );
        }

        char sum_str[ 64 ];
        if( FD_LIKELY( metric->histogram.converter==FD_METRICS_CONVERTER_SECONDS ) ) {
          double sumf = fd_metrics_convert_ticks_to_seconds( *(fd_metrics_tile( tile_metrics ) + metric->offset + FD_HISTF_BUCKET_CNT) );
          FD_TEST( fd_cstr_printf_check( sum_str, sizeof( sum_str ), NULL, "%.17g", sumf ) );
        } else {
          FD_TEST( fd_cstr_printf_check( sum_str, sizeof( sum_str ), NULL, "%lu", *(fd_metrics_tile( tile_metrics ) + metric->offset + FD_HISTF_BUCKET_CNT) ) );
        }

        PRINT( "%s_sum{kind=\"%s\",kind_id=\"%lu\"} %s\n", metric->name, tile->name, tile->tidx, sum_str );
        PRINT( "%s_count{kind=\"%s\",kind_id=\"%lu\"} %s\n", metric->name, tile->name, tile->tidx, value_str );
      }
    }

    if( FD_LIKELY( i!=metrics_cnt-1 ) ) PRINT( "\n" );
  }

  return 0;
}

static long
prometheus_print( fd_topo_t const *     topo,
                  char **               out,
                  ulong *               out_len ) {
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

  /* Now backfill Content-Length */
  int printed = snprintf( content_len, 21, "%lu", start_len - *out_len - content_start );
  if( FD_UNLIKELY( printed<0 ) ) return -1;
  if( FD_UNLIKELY( (ulong)printed>=21 ) ) return -1;
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
read_conn( fd_metric_tile_t * ctx,
           ulong              idx ) {
  fd_metric_tile_connection_t * conn = &ctx->conns[ idx ];
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
write_conn( fd_metric_tile_t * ctx,
            ulong              idx ) {
  fd_metric_tile_connection_t * conn = &ctx->conns[ idx ];
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

  fd_metric_tile_t * ctx = (fd_metric_tile_t *)_ctx;

  int nfds = poll( ctx->fds, FD_METRIC_TILE_MAX_CONNS+1UL, 0 );
  if( FD_UNLIKELY( 0==nfds ) ) return;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, strerror( errno ) ));

  /* Poll existing connections for new data. */
  for( ulong i=0; i<FD_METRIC_TILE_MAX_CONNS+1UL; i++ ) {
    if( FD_UNLIKELY( -1==ctx->fds[ i ].fd ) ) continue;
    if( FD_UNLIKELY( i==FD_METRIC_TILE_MAX_CONNS ) ) {
      accept_conns( ctx );
    } else {
      if( FD_LIKELY( ctx->fds[ i ].revents & POLLIN ) ) read_conn( ctx, i );
      if( FD_LIKELY( ctx->fds[ i ].revents & POLLOUT ) ) write_conn( ctx, i );
      /* No need to handle POLLHUP, read() will return 0 soon enough. */
    }
  }
}

void
fd_metric_tile_join_privileged( void *        shmetric,
                                uchar const * pod,
                                char const *  id ) {
  fd_metric_tile_args_t args = args_from_pod( pod, id );

  FD_SCRATCH_ALLOC_INIT( l, shmetric );
  fd_metric_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_tile_t ), sizeof( fd_metric_tile_t ) );

  int sockfd = socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, strerror( errno ) ));

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval ) ) ) )
    FD_LOG_ERR(( "setsockopt failed (%i-%s)", errno, strerror( errno ) ));
  
  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( args.prometheus_listen_port ),
    .sin_addr.s_addr = INADDR_ANY,
  };

  if( FD_UNLIKELY( -1==bind( sockfd, fd_type_pun( &addr ), sizeof( addr ) ) ) ) FD_LOG_ERR(( "bind failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( -1==listen( sockfd, 128 ) ) ) FD_LOG_ERR(( "listen failed (%i-%s)", errno, strerror( errno ) ));

  ctx->socket_fd = sockfd;
}

fd_metric_tile_t *
fd_metric_tile_join( void *        shmetric,
                     uchar const * pod,
                     char const *  id ) {
  fd_metric_tile_args_t args = args_from_pod( pod, id );

  FD_SCRATCH_ALLOC_INIT( l, shmetric );
  fd_metric_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_tile_t ), sizeof( fd_metric_tile_t ) );

  ctx->conn_id = 0UL;
  for( ulong i=0; i<FD_METRIC_TILE_MAX_CONNS; i++ ) {
    ctx->fds[ i ].fd = -1;
    ctx->fds[ i ].events = POLLIN | POLLOUT;
  }

  ctx->fds[ FD_METRIC_TILE_MAX_CONNS ].fd = ctx->socket_fd;
  ctx->fds[ FD_METRIC_TILE_MAX_CONNS ].events = POLLIN | POLLOUT;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)shmetric + fd_metric_tile_footprint( &args ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)shmetric - fd_metric_tile_footprint( &args ), scratch_top, (ulong)shmetric + fd_metric_tile_footprint( &args ) ));

  FD_LOG_NOTICE(( "Prometheus metrics endpoint listening on port %u", args.prometheus_listen_port ));
  return ctx;
}

void
fd_metric_run( fd_metric_tile_t *      ctx,
               fd_cnc_t *              cnc,
               ulong                   in_cnt,
               fd_frag_meta_t const ** in_mcache,
               ulong **                in_fseq,
               fd_frag_meta_t *        mcache,
               ulong                   out_cnt,
               ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .before_credit       = before_credit,
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
