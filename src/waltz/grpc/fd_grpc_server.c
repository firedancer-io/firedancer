#define _GNU_SOURCE /* accept4 */

#include "fd_grpc_server_private.h"
#include "../h2/fd_hpack_wr.h"
#include "../../util/fd_util.h"
#include <limits.h>

#if FD_HAS_HOSTED
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../h2/fd_h2_rbuf_sock.h"
#endif

/* HPACK static table indices used by the response encoder
   (RFC 7541 Appendix A) */

#define FD_GRPC_SERVER_HPACK_STATUS_200  (8UL)
#define FD_GRPC_SERVER_HPACK_STATUS      (8UL)  /* :status, literal value */
#define FD_GRPC_SERVER_HPACK_CONTENT_TYPE (31UL)

#define FD_GRPC_SERVER_CONTENT_TYPE "application/grpc"

/* A peer may reset FD_GRPC_SERVER_RESET_MAX streams in one window
   before the connection is closed. */

#define FD_GRPC_SERVER_RESET_WINDOW_NANOS (1000000000L)
#define FD_GRPC_SERVER_RESET_MAX          (100UL)

/* Room kept free in a connection's send ring for the control frames
   that fd_h2 generates on its own (SETTINGS, PING, WINDOW_UPDATE,
   GOAWAY, RST_STREAM). */

#define FD_GRPC_SERVER_TX_RESERVE (128UL)

/* How long a closing connection waits for its GOAWAY to drain */

#define FD_GRPC_SERVER_CLOSE_TIMEOUT_NANOS (10L*1000L*1000L*1000L)

FD_FN_CONST static inline fd_grpc_server_stream_t *
fd_grpc_server_stream_from_h2( fd_h2_stream_t * h2 ) {
  return (fd_grpc_server_stream_t *)h2;
}

FD_FN_CONST static inline fd_grpc_server_conn_t *
fd_grpc_server_conn_from_h2( fd_h2_conn_t * h2 ) {
  return (fd_grpc_server_conn_t *)h2->ctx;
}

/* Parameters *********************************************************/

fd_grpc_server_params_t *
fd_grpc_server_params_default( fd_grpc_server_params_t * params ) {
  *params = (fd_grpc_server_params_t) {
    .max_conn_cnt             = 16UL,
    .max_stream_cnt           = 8UL,
    .max_request_msg_sz       = 16UL<<10,
    .stream_tx_queue_sz       = 64UL<<10,
    .max_msg_sz               = 64UL<<10,
    .large_msg_slot_cnt       = 0UL,
    .conn_rx_buf_sz           = 32UL<<10,
    .conn_tx_buf_sz           = 64UL<<10,
    .max_frame_sz             = 16384UL,
    .conn_rx_wnd_sz           = 1UL<<20,
    .stream_rx_wnd_sz         = 256UL<<10,
    .idle_timeout_nanos       = 300L*1000L*1000L*1000L,
    .handshake_timeout_nanos  = 10L*1000L*1000L*1000L,
    .large_drain_timeout_nanos= 30L*1000L*1000L*1000L,
    .response_timeout_nanos   = 0L,
    .compression              = FD_GRPC_SERVER_COMPRESSION_ZSTD,
    .compression_min_sz       = 1024UL,
    .compression_level        = 1,
    .seed                     = 0UL
  };
  return params;
}

int
fd_grpc_server_compression_level_max( void ) {
  return ZSTD_maxCLevel();
}

static int
fd_grpc_server_params_valid( fd_grpc_server_params_t const * p ) {
# define CHECK(c) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "invalid fd_grpc_server param: " #c )); return 0; } } while(0)
  CHECK( p->max_conn_cnt      >=1UL && p->max_conn_cnt      <=4096UL );
  CHECK( p->max_stream_cnt    >=1UL && p->max_stream_cnt    <= 256UL );
  CHECK( p->max_request_msg_sz>=1UL && p->max_request_msg_sz < (1UL<<31) );
  CHECK( p->stream_tx_queue_sz>=64UL && p->stream_tx_queue_sz<=(1UL<<31) );
  CHECK( p->max_msg_sz        >=p->stream_tx_queue_sz && p->max_msg_sz<(1UL<<31) );
  CHECK( p->large_msg_slot_cnt<=256UL );
  CHECK( p->max_frame_sz      >=16384UL && p->max_frame_sz  < (1UL<<24) );
  CHECK( p->conn_rx_buf_sz    >=p->max_frame_sz+9UL && p->conn_rx_buf_sz<=(1UL<<30) );
  CHECK( p->conn_tx_buf_sz    >=p->max_frame_sz+9UL+FD_GRPC_SERVER_TX_RESERVE && p->conn_tx_buf_sz<=(1UL<<30) );
  CHECK( p->conn_rx_wnd_sz    >=65535UL && p->conn_rx_wnd_sz  <(1UL<<31) );
  CHECK( p->stream_rx_wnd_sz  >=65535UL && p->stream_rx_wnd_sz<(1UL<<31) );
  CHECK( p->compression==FD_GRPC_SERVER_COMPRESSION_NONE ||
         p->compression==FD_GRPC_SERVER_COMPRESSION_ZSTD );
  CHECK( p->compression_level>=1 && p->compression_level<=ZSTD_maxCLevel() );
  CHECK( p->idle_timeout_nanos      >=0L );
  CHECK( p->handshake_timeout_nanos >=0L );
  CHECK( p->large_drain_timeout_nanos>=0L );
  CHECK( p->response_timeout_nanos  >=0L );
# undef CHECK
  return 1;
}

/* Memory layout ******************************************************/

ulong
fd_grpc_server_align( void ) {
  return FD_GRPC_SERVER_ALIGN;
}

static ulong
fd_grpc_server_hpack_scratch_sz( fd_grpc_server_params_t const * p ) {
  /* A Huffman coded literal needs up to twice its encoded size, and a
     dynamic table entry up to FD_HPACK_DTABLE_SZ_MAX bytes.  The
     scratch cursor is reset after every header, so it only has to hold
     the largest single header. */
  ulong max_header_list_sz = p->max_frame_sz;
  return 2UL*max_header_list_sz + 2UL*FD_HPACK_DTABLE_SZ_MAX;
}

static ulong
fd_grpc_server_compress_out_sz( fd_grpc_server_params_t const * p ) {
  if( p->compression==FD_GRPC_SERVER_COMPRESSION_NONE ) return 0UL;
  /* Every message that goes through a send queue fits it, prefix
     included, so this bounds the compressed form of any of them. */
  return ZSTD_compressBound( p->stream_tx_queue_sz );
}

static ulong
fd_grpc_server_decompress_out_sz( fd_grpc_server_params_t const * p ) {
  if( p->compression==FD_GRPC_SERVER_COMPRESSION_NONE ) return 0UL;
  return p->max_request_msg_sz;
}

static ulong
fd_grpc_server_zarena_sz( fd_grpc_server_params_t const * p ) {
  if( p->compression==FD_GRPC_SERVER_COMPRESSION_NONE ) return 0UL;
  return FD_GRPC_SERVER_ZSTD_MEM( p->compression_level );
}

/* fd_grpc_server_large_slot_sz is the bytes one large send slot holds,
   which is the largest response message plus its length prefix. */

static ulong
fd_grpc_server_large_slot_sz( fd_grpc_server_params_t const * p ) {
  return p->max_msg_sz + sizeof(fd_grpc_hdr_t);
}

ulong
fd_grpc_server_footprint( fd_grpc_server_params_t const * params ) {
  if( FD_UNLIKELY( !fd_grpc_server_params_valid( params ) ) ) return 0UL;
  ulong conn_cnt   = params->max_conn_cnt;
  ulong stream_cnt = params->max_conn_cnt * params->max_stream_cnt;
  ulong zmem       = fd_grpc_server_zarena_sz( params );
  ulong large_cnt  = params->large_msg_slot_cnt;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_t),        sizeof(fd_grpc_server_t)                      );
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_conn_t),   conn_cnt  *sizeof(fd_grpc_server_conn_t)       );
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_stream_t), stream_cnt*sizeof(fd_grpc_server_stream_t)     );
  l = FD_LAYOUT_APPEND( l, 128UL,                            conn_cnt  *params->conn_rx_buf_sz             );
  l = FD_LAYOUT_APPEND( l, 128UL,                            conn_cnt  *params->conn_tx_buf_sz             );
  l = FD_LAYOUT_APPEND( l, 128UL,                            stream_cnt*params->max_request_msg_sz         );
  l = FD_LAYOUT_APPEND( l, 128UL,                            stream_cnt*params->stream_tx_queue_sz         );
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_large_t),  large_cnt *sizeof(fd_grpc_server_large_t)     );
  l = FD_LAYOUT_APPEND( l, 128UL,                            large_cnt *fd_grpc_server_large_slot_sz( params ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_h2_hdr_matcher_t),     sizeof(fd_h2_hdr_matcher_t)                   );
  l = FD_LAYOUT_APPEND( l, 128UL,                            params->max_frame_sz                          );
  l = FD_LAYOUT_APPEND( l, 128UL,                            fd_grpc_server_hpack_scratch_sz( params )     );
  l = FD_LAYOUT_APPEND( l, 128UL,                            fd_grpc_server_compress_out_sz  ( params )    );
  l = FD_LAYOUT_APPEND( l, 128UL,                            fd_grpc_server_decompress_out_sz( params )    );
  l = FD_LAYOUT_APPEND( l, 128UL,                            zmem                                          );
  l = FD_LAYOUT_APPEND( l, 16UL,                             16UL*( conn_cnt+1UL )                         );
  return FD_LAYOUT_FINI( l, FD_GRPC_SERVER_ALIGN );
}

/* Compressor *********************************************************/

/* fd_grpc_server_zstd_init emplaces the compression and decompression
   contexts in the server's arena.  zstd never allocates once it is
   given a static workspace: a context that needs more memory than the
   workspace holds fails the operation instead. */

static int
fd_grpc_server_zstd_init( fd_grpc_server_t * server ) {
  if( server->params.compression==FD_GRPC_SERVER_COMPRESSION_NONE ) return 1;

  ulong bound = ZSTD_compressBound( server->params.stream_tx_queue_sz );
  if( FD_UNLIKELY( bound > server->compress_out_sz ) ) {
    FD_LOG_WARNING(( "compressor output buffer too small (need %lu, have %lu)",
                     bound, server->compress_out_sz ));
    return 0;
  }

  ulong cctx_sz = fd_ulong_align_up( ZSTD_estimateCCtxSize( server->params.compression_level ), 128UL );
  ulong dctx_sz = fd_ulong_align_up( ZSTD_estimateDCtxSize(),                                  128UL );
  if( FD_UNLIKELY( cctx_sz+dctx_sz > server->zarena_sz ) ) {
    FD_LOG_WARNING(( "zstd arena too small (need %lu bytes, have %lu)",
                     cctx_sz+dctx_sz, server->zarena_sz ));
    return 0;
  }

  server->cctx = ZSTD_initStaticCCtx( server->zarena,           cctx_sz );
  server->dctx = ZSTD_initStaticDCtx( server->zarena + cctx_sz, dctx_sz );
  if( FD_UNLIKELY( !server->cctx || !server->dctx ) ) {
    FD_LOG_WARNING(( "failed to init zstd contexts in a %lu byte arena", server->zarena_sz ));
    server->cctx = NULL;
    server->dctx = NULL;
    return 0;
  }
  return 1;
}

/* Object lifecycle ***************************************************/

static void
fd_grpc_server_matcher_init( fd_h2_hdr_matcher_t * matcher,
                             ulong                 seed ) {
  fd_h2_hdr_matcher_init( matcher, seed );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_SERVER_HDR_TIMEOUT,          "grpc-timeout"         );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_SERVER_HDR_ENCODING,         "grpc-encoding"        );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_SERVER_HDR_ACCEPT_ENCODING,  "grpc-accept-encoding" );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_SERVER_HDR_TE,               "te"                   );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_SERVER_HDR_CONNECTION,       "connection"           );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_SERVER_HDR_KEEP_ALIVE,       "keep-alive"           );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_SERVER_HDR_PROXY_CONNECTION, "proxy-connection"     );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_SERVER_HDR_UPGRADE,          "upgrade"              );
}

void *
fd_grpc_server_new( void *                             mem,
                    fd_grpc_server_params_t const *    params,
                    fd_grpc_server_callbacks_t const * callbacks,
                    void *                             app_ctx ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_GRPC_SERVER_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !callbacks ) ) {
    FD_LOG_WARNING(( "NULL callbacks" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_grpc_server_footprint( params ) ) ) return NULL;

  ulong conn_cnt     = params->max_conn_cnt;
  ulong stream_cnt   = params->max_conn_cnt * params->max_stream_cnt;
  ulong hpack_sz     = fd_grpc_server_hpack_scratch_sz( params );
  ulong compress_sz  = fd_grpc_server_compress_out_sz  ( params );
  ulong decompress_sz= fd_grpc_server_decompress_out_sz( params );
  ulong zmem         = fd_grpc_server_zarena_sz( params );
  ulong large_cnt    = params->large_msg_slot_cnt;
  ulong large_slot_sz= fd_grpc_server_large_slot_sz( params );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_grpc_server_t *        server     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_t),        sizeof(fd_grpc_server_t)                  );
  fd_grpc_server_conn_t *   conn       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_conn_t),   conn_cnt  *sizeof(fd_grpc_server_conn_t)   );
  fd_grpc_server_stream_t * stream     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_stream_t), stream_cnt*sizeof(fd_grpc_server_stream_t) );
  uchar *                   rx_buf     = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            conn_cnt  *params->conn_rx_buf_sz         );
  uchar *                   tx_buf     = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            conn_cnt  *params->conn_tx_buf_sz         );
  uchar *                   msg_buf    = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            stream_cnt*params->max_request_msg_sz     );
  uchar *                   queue_buf  = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            stream_cnt*params->stream_tx_queue_sz     );
  fd_grpc_server_large_t *  large      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_large_t),  large_cnt *sizeof(fd_grpc_server_large_t) );
  uchar *                   large_buf  = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            large_cnt *large_slot_sz                  );
  void *                    matcher    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_h2_hdr_matcher_t),     sizeof(fd_h2_hdr_matcher_t)               );
  uchar *                   frame_scr  = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            params->max_frame_sz                      );
  uchar *                   hpack_scr  = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            hpack_sz                                  );
  uchar *                   comp_out   = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            compress_sz                               );
  uchar *                   decomp_out = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            decompress_sz                             );
  uchar *                   zarena     = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            zmem                                      );
  void *                    pollfd_mem = FD_SCRATCH_ALLOC_APPEND( l, 16UL,                             16UL*( conn_cnt+1UL )                     );
  FD_SCRATCH_ALLOC_FINI( l, FD_GRPC_SERVER_ALIGN );

  fd_memset( server, 0, sizeof(fd_grpc_server_t) );
  fd_memset( conn,   0, conn_cnt  *sizeof(fd_grpc_server_conn_t)   );
  fd_memset( stream, 0, stream_cnt*sizeof(fd_grpc_server_stream_t) );

  server->params         = *params;
  server->callbacks             = callbacks;
  server->app_ctx            = app_ctx;
  server->conn           = conn;
  server->matcher        = matcher;
  server->frame_scratch  = frame_scr;
  server->hpack_scratch  = hpack_scr;
  server->compress_out    = comp_out;
  server->compress_out_sz = compress_sz;
  server->decompress_out  = decomp_out;
  server->zarena          = zarena;
  server->zarena_sz       = zmem;
  server->pollfd_mem     = pollfd_mem;
  server->listen_fd      = -1;
  server->large          = large_cnt ? large : NULL;
  server->large_slot_sz  = large_slot_sz;

  for( ulong i=0UL; i<large_cnt; i++ ) {
    large[ i ] = (fd_grpc_server_large_t){ .buf = large_buf + i*large_slot_sz };
  }

  for( ulong i=0UL; i<conn_cnt; i++ ) {
    fd_grpc_server_conn_t * c = conn+i;
    c->server   = server;
    c->stream   = stream   + i*params->max_stream_cnt;
    c->sock     = -1;
    fd_h2_rbuf_init( c->rbuf_rx, rx_buf + i*params->conn_rx_buf_sz, params->conn_rx_buf_sz );
    fd_h2_rbuf_init( c->rbuf_tx, tx_buf + i*params->conn_tx_buf_sz, params->conn_tx_buf_sz );
    for( ulong j=0UL; j<params->max_stream_cnt; j++ ) {
      fd_grpc_server_stream_t * s = c->stream+j;
      ulong k = i*params->max_stream_cnt + j;
      s->conn      = c;
      s->msg_buf   = msg_buf + k*params->max_request_msg_sz;
      s->large_idx = -1L;
      fd_h2_rbuf_init( s->tx_queue, queue_buf + k*params->stream_tx_queue_sz, params->stream_tx_queue_sz );
    }
  }

  fd_grpc_server_matcher_init( matcher, params->seed );
  if( FD_UNLIKELY( !fd_grpc_server_zstd_init( server ) ) ) return NULL;

  FD_COMPILER_MFENCE();
  server->magic = FD_GRPC_SERVER_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_grpc_server_t *
fd_grpc_server_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  fd_grpc_server_t * server = mem;
  if( FD_UNLIKELY( server->magic!=FD_GRPC_SERVER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return server;
}

void *
fd_grpc_server_leave( fd_grpc_server_t * server ) {
  return server;
}

void *
fd_grpc_server_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  fd_grpc_server_t * server = mem;
  if( FD_UNLIKELY( server->magic!=FD_GRPC_SERVER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  /* The zstd contexts live in the caller's memory region, so there is
     nothing to release but the pointers to them. */
  server->cctx = NULL;
  server->dctx = NULL;
# if FD_HAS_HOSTED
  for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
    fd_grpc_server_conn_t * c = server->conn+i;
    if( c->sock>=0 ) close( c->sock );
    c->sock = -1;
  }
  if( server->listen_fd>=0 ) close( server->listen_fd );
# endif
  server->listen_fd = -1;
  FD_COMPILER_MFENCE();
  server->magic = 0UL;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_grpc_server_metrics_t const *
fd_grpc_server_metrics( fd_grpc_server_t const * server ) {
  return &server->metrics;
}

/* HPACK response encoding ********************************************/

static ulong
fd_grpc_server_wr_indexed( uchar * out,
                           ulong   idx ) {
  out[0] = FD_HPACK_INDEXED_SHORT( idx );
  return 1UL;
}

/* fd_grpc_server_wr_hdr_idx writes a literal header without indexing
   whose name is HPACK static table entry name_idx. */

static ulong
fd_grpc_server_wr_hdr_idx( uchar *      out,
                           ulong        name_idx,
                           char const * value,
                           ulong        value_len ) {
  ulong sz = fd_hpack_wr_varint( out, 0x00U, 0x0fU, name_idx );
  sz += fd_hpack_wr_varint( out+sz, 0x00U, 0x7fU, value_len );
  fd_memcpy( out+sz, value, value_len );
  return sz+value_len;
}

/* fd_grpc_server_wr_hdr writes a literal header without indexing whose
   name is spelled out. */

static ulong
fd_grpc_server_wr_hdr( uchar *      out,
                       char const * name,
                       ulong        name_len,
                       char const * value,
                       ulong        value_len ) {
  ulong sz = 1UL;
  out[0] = 0x00;
  sz += fd_hpack_wr_varint( out+sz, 0x00U, 0x7fU, name_len );
  fd_memcpy( out+sz, name, name_len );
  sz += name_len;
  sz += fd_hpack_wr_varint( out+sz, 0x00U, 0x7fU, value_len );
  fd_memcpy( out+sz, value, value_len );
  return sz+value_len;
}

#define FD_GRPC_SERVER_WR_HDR(out,name,value) \
  fd_grpc_server_wr_hdr( (out), (name), sizeof(name)-1, (value), sizeof(value)-1 )

/* fd_grpc_server_pct_encode percent-encodes in_len bytes for use in a
   grpc-message trailer: bytes outside [0x20,0x7e] and '%' become %XX.
   Stops at the last character that fits out_max bytes.  Returns the
   number of bytes written. */

static ulong
fd_grpc_server_pct_encode( char *       out,
                           ulong        out_max,
                           char const * in,
                           ulong        in_len ) {
  static char const hex[] = "0123456789ABCDEF";
  ulong o = 0UL;
  for( ulong i=0UL; i<in_len; i++ ) {
    uchar c = (uchar)in[i];
    if( FD_LIKELY( c>=0x20 && c<=0x7e && c!='%' ) ) {
      if( FD_UNLIKELY( o+1UL>out_max ) ) break;
      out[ o++ ] = (char)c;
    } else {
      if( FD_UNLIKELY( o+3UL>out_max ) ) break;
      out[ o++ ] = '%';
      out[ o++ ] = hex[ c>>4   ];
      out[ o++ ] = hex[ c&0x0f ];
    }
  }
  return o;
}

static ulong
fd_grpc_server_wr_uint( char * out,
                        uint   value ) {
  char tmp[ 10 ];
  ulong n = 0UL;
  do {
    tmp[ n++ ] = (char)( '0' + (value%10U) );
    value /= 10U;
  } while( value );
  for( ulong i=0UL; i<n; i++ ) out[i] = tmp[n-1UL-i];
  return n;
}

/* Streams ************************************************************/

/* fd_grpc_server_large_release returns the stream's large send slot to
   the pool, whether or not the message in it was fully sent. */

static void
fd_grpc_server_large_release( fd_grpc_server_stream_t * stream ) {
  if( FD_LIKELY( stream->large_idx<0L ) ) return;
  fd_grpc_server_large_t * slot = stream->conn->server->large + stream->large_idx;
  slot->busy = 0;
  slot->sz   = 0UL;
  slot->off  = 0UL;
  stream->large_idx   = -1L;
  stream->tx_pre_slot = 0UL;
}

/* fd_grpc_server_large_free returns 1 if the pool has a slot to hand
   out. */

FD_FN_PURE static int
fd_grpc_server_large_free( fd_grpc_server_t const * server ) {
  for( ulong i=0UL; i<server->params.large_msg_slot_cnt; i++ ) {
    if( !server->large[ i ].busy ) return 1;
  }
  return 0;
}

static void
fd_grpc_server_stream_release( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_large_release( stream );
  stream->state         = FD_GRPC_SERVER_STREAM_FREE;
  stream->flags         = 0U;
  stream->ctx           = NULL;
  stream->msg_sz        = 0UL;
  stream->msg_rem       = 0UL;
  stream->msg_hdr_sz    = 0UL;
  stream->tx_blocked_sz = 0UL;
  stream->tx_msg_pending= 0UL;
  stream->tx_head_rem   = 0UL;
  stream->tx_queue_hi   = 0UL;
  stream->tx_pre_slot   = 0UL;
  stream->fin_status    = 0U;
  stream->fin_msg_len   = 0U;
  stream->path_len      = 0;
  stream->deadline      = LONG_MAX;
  stream->resp_deadline = LONG_MAX;
  stream->tx_wnd_debt   = 0L;
  fd_h2_rbuf_init( stream->tx_queue, stream->tx_queue->buf0, stream->tx_queue->bufsz );
  fd_h2_stream_init( stream->h2 );
}

/* fd_grpc_server_stream_end reports a stream to the app if it ever
   accepted it, and returns the slot to the pool. */

static void
fd_grpc_server_stream_end( fd_grpc_server_stream_t * stream,
                           int                       reason ) {
  fd_grpc_server_conn_t * conn   = stream->conn;
  fd_grpc_server_t *      server = conn->server;
  if( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN ) {
    stream->flags &= ~FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN;
    server->callbacks->stream_close( server->app_ctx, stream, reason );
  }
  fd_grpc_server_stream_release( stream );
}

static fd_grpc_server_stream_t *
fd_grpc_server_stream_acquire( fd_grpc_server_conn_t * conn ) {
  ulong stream_max = conn->server->params.max_stream_cnt;
  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t * s = conn->stream+i;
    if( s->state==FD_GRPC_SERVER_STREAM_FREE ) {
      fd_grpc_server_stream_release( s );
      s->state = FD_GRPC_SERVER_STREAM_HEADERS;
      return s;
    }
  }
  return NULL;
}

void *
fd_grpc_server_stream_ctx( fd_grpc_server_stream_t const * stream ) {
  return stream->ctx;
}

void
fd_grpc_server_stream_set_ctx( fd_grpc_server_stream_t * stream,
                               void *                    ctx ) {
  stream->ctx = ctx;
}

uint
fd_grpc_server_stream_id( fd_grpc_server_stream_t const * stream ) {
  return stream->h2->stream_id;
}

fd_grpc_server_conn_t *
fd_grpc_server_stream_conn( fd_grpc_server_stream_t const * stream ) {
  return stream->conn;
}

FD_FN_PURE int
fd_grpc_server_msg_needs_large( fd_grpc_server_stream_t const * stream,
                                ulong                           msg_sz ) {
  return msg_sz > stream->tx_queue->bufsz - sizeof(fd_grpc_hdr_t);
}

ulong
fd_grpc_server_stream_tx_queue_hi( fd_grpc_server_stream_t const * stream ) {
  return stream->tx_queue_hi;
}

ulong
fd_grpc_server_stream_tx_free_sz( fd_grpc_server_stream_t const * stream ) {
  ulong msg_max = stream->conn->server->params.stream_tx_queue_msg_max;
  if( FD_UNLIKELY( msg_max && stream->tx_msg_pending>=msg_max ) ) return 0UL;
  ulong free_sz = fd_h2_rbuf_free_sz( stream->tx_queue );
  return free_sz<sizeof(fd_grpc_hdr_t) ? 0UL : free_sz-sizeof(fd_grpc_hdr_t);
}

/* Response generation ************************************************/

/* fd_grpc_server_tx_hdrs writes a HEADERS frame with the given field
   block.  Assumes the send ring has room. */

static void
fd_grpc_server_tx_hdrs( fd_grpc_server_stream_t * stream,
                        uchar const *             block,
                        ulong                     block_sz,
                        int                       end_stream ) {
  fd_grpc_server_conn_t * conn = stream->conn;
  uint flags = FD_H2_FLAG_END_HEADERS;
  if( end_stream ) flags |= FD_H2_FLAG_END_STREAM;
  fd_h2_tx( conn->rbuf_tx, block, block_sz, FD_H2_FRAME_TYPE_HEADERS, flags, stream->h2->stream_id );
}

static ulong
fd_grpc_server_gen_resp_hdrs( fd_grpc_server_stream_t * stream,
                              uchar *                   out ) {
  ulong sz = fd_grpc_server_wr_indexed( out, FD_GRPC_SERVER_HPACK_STATUS_200 );
  sz += fd_grpc_server_wr_hdr_idx( out+sz, FD_GRPC_SERVER_HPACK_CONTENT_TYPE,
                                   FD_GRPC_SERVER_CONTENT_TYPE, sizeof(FD_GRPC_SERVER_CONTENT_TYPE)-1UL );
  if( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TX_ZSTD ) {
    sz += FD_GRPC_SERVER_WR_HDR( out+sz, "grpc-encoding", "zstd" );
  }
  /* The encodings the server accepts on request messages */
  if( stream->conn->server->dctx ) {
    sz += FD_GRPC_SERVER_WR_HDR( out+sz, "grpc-accept-encoding", "zstd" );
  } else {
    sz += FD_GRPC_SERVER_WR_HDR( out+sz, "grpc-accept-encoding", "identity" );
  }
  return sz;
}

static ulong
fd_grpc_server_gen_trailers( fd_grpc_server_stream_t * stream,
                             uchar *                   out ) {
  char status[ 10 ];
  ulong status_len = fd_grpc_server_wr_uint( status, stream->fin_status );
  ulong sz = fd_grpc_server_wr_hdr( out, "grpc-status", 11UL, status, status_len );
  if( stream->fin_msg_len ) {
    char msg[ 3UL*FD_GRPC_SERVER_MSG_MAX ];
    ulong msg_len = fd_grpc_server_pct_encode( msg, sizeof(msg), stream->fin_msg, stream->fin_msg_len );
    sz += fd_grpc_server_wr_hdr( out+sz, "grpc-message", 12UL, msg, msg_len );
  }
  return sz;
}

/* fd_grpc_server_stream_abort takes an HTTP/2 stream out of service,
   telling the peer with a RST_STREAM frame if the send ring has room
   for one.  Either way the stream leaves the conn's concurrency
   count. */

static void
fd_grpc_server_stream_abort( fd_grpc_server_stream_t * stream,
                             uint                      h2_err ) {
  fd_grpc_server_conn_t * conn = stream->conn;
  if( FD_LIKELY( fd_h2_rbuf_free_sz( conn->rbuf_tx )>=sizeof(fd_h2_rst_stream_t) ) ) {
    fd_h2_stream_error( stream->h2, conn->h2, conn->rbuf_tx, h2_err );
  } else {
    fd_h2_stream_reset( stream->h2, conn->h2 );
  }
}

/* fd_grpc_server_tx_http_status responds to a request that is not a
   gRPC call with a headers-only HTTP response, as the gRPC HTTP/2
   mapping prescribes.  Releases the stream. */

static void
fd_grpc_server_tx_http_status( fd_grpc_server_stream_t * stream,
                               char const *              status,
                               ulong                     status_len ) {
  fd_grpc_server_conn_t * conn   = stream->conn;
  fd_grpc_server_t *      server = conn->server;
  uchar block[ 32 ];
  ulong block_sz = fd_grpc_server_wr_hdr_idx( block, FD_GRPC_SERVER_HPACK_STATUS, status, status_len );

  if( FD_LIKELY( fd_h2_rbuf_free_sz( conn->rbuf_tx ) >= block_sz+9UL+sizeof(fd_h2_rst_stream_t)+FD_GRPC_SERVER_TX_RESERVE ) ) {
    fd_grpc_server_tx_hdrs( stream, block, block_sz, 1 );
    fd_h2_stream_close_tx( stream->h2, conn->h2 );
    if( stream->h2->state!=FD_H2_STREAM_STATE_CLOSED ) {
      fd_grpc_server_stream_abort( stream, FD_H2_SUCCESS );
    }
  } else {
    /* No room to explain: reset the stream instead */
    fd_grpc_server_stream_abort( stream, FD_H2_ERR_REFUSED_STREAM );
  }
  server->metrics.request_error_cnt++;
  fd_grpc_server_stream_end( stream, FD_GRPC_SERVER_CLOSE_FINISHED );
}

/* fd_grpc_server_stream_malformed rejects a request that violates the
   HTTP/2 or gRPC request rules with a stream error. */

static void
fd_grpc_server_stream_malformed( fd_grpc_server_stream_t * stream,
                                 uint                      h2_err ) {
  fd_grpc_server_t * server = stream->conn->server;
  fd_grpc_server_stream_abort( stream, h2_err );
  server->metrics.request_error_cnt++;
  fd_grpc_server_stream_end( stream, FD_GRPC_SERVER_CLOSE_ABORTED );
}

void
fd_grpc_server_finish( fd_grpc_server_stream_t * stream,
                       uint                      grpc_status,
                       char const *              grpc_msg,
                       ulong                     msg_len ) {
  if( FD_UNLIKELY( stream->state==FD_GRPC_SERVER_STREAM_FREE ||
                   stream->state==FD_GRPC_SERVER_STREAM_FINISH ) ) return;
  stream->fin_status  = grpc_status;
  stream->fin_msg_len = 0U;
  if( grpc_msg && msg_len ) {
    msg_len = fd_ulong_min( msg_len, FD_GRPC_SERVER_MSG_MAX );
    fd_memcpy( stream->fin_msg, grpc_msg, msg_len );
    stream->fin_msg_len = (uint)msg_len;
  }
  stream->state  = FD_GRPC_SERVER_STREAM_FINISH;
  stream->flags &= ~( FD_GRPC_SERVER_STREAM_FLAG_TX_BLOCKED | FD_GRPC_SERVER_STREAM_FLAG_TX_LARGE );
}

#define FD_GRPC_SERVER_FINISH(stream,status,lit) \
  fd_grpc_server_finish( (stream), (status), (lit), sizeof(lit)-1UL )

int
fd_grpc_server_send( fd_grpc_server_stream_t * stream,
                     void const *              msg,
                     ulong                     msg_sz,
                     uint                      flags ) {
  if( FD_UNLIKELY( stream->state!=FD_GRPC_SERVER_STREAM_ACTIVE ) ) return FD_GRPC_SERVER_ERR_CLOSED;
  fd_grpc_server_conn_t * conn   = stream->conn;
  fd_grpc_server_t *      server = conn->server;

  uchar const * payload    = msg;
  ulong         payload_sz = msg_sz;
  uint          compressed = 0U;

  int want_zstd = ( !!( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TX_ZSTD ) ) &
                  ( !( flags & FD_GRPC_SERVER_SEND_NO_COMPRESS )       ) &
                  ( msg_sz >= server->params.compression_min_sz        ) &
                  ( !!server->cctx                                     );
  if( FD_UNLIKELY( msg_sz > server->params.max_msg_sz ) ) return FD_GRPC_SERVER_ERR_TOOBIG;

  /* A message that no send queue could hold takes a slot of the large
     send pool instead. */
  if( FD_UNLIKELY( fd_grpc_server_msg_needs_large( stream, msg_sz ) ) ) {
    if( FD_UNLIKELY( !server->params.large_msg_slot_cnt ) ) return FD_GRPC_SERVER_ERR_TOOBIG;
    /* One oversized message per stream is in flight at a time, and
       the pool is shared, so a second one waits.  Only that message
       waits: everything that fits the queue still goes out behind it,
       in order. */
    long idx = -1L;
    if( FD_LIKELY( stream->large_idx<0L ) ) {
      for( ulong i=0UL; i<server->params.large_msg_slot_cnt; i++ ) {
        if( !server->large[ i ].busy ) { idx = (long)i; break; }
      }
    }
    if( FD_UNLIKELY( idx<0L ) ) {
      stream->flags        |= FD_GRPC_SERVER_STREAM_FLAG_TX_BLOCKED | FD_GRPC_SERVER_STREAM_FLAG_TX_LARGE;
      stream->tx_blocked_sz = 0UL;
      server->metrics.tx_large_busy_cnt++;
      return FD_GRPC_SERVER_ERR_AGAIN;
    }

    fd_grpc_server_large_t * slot = server->large + idx;
    uchar *                  out  = slot->buf + sizeof(fd_grpc_hdr_t);
    ulong                    room = server->large_slot_sz - sizeof(fd_grpc_hdr_t);

    if( want_zstd ) {
      /* A message whose compressed form does not fit the slot, which is
         only as large as the plaintext, goes out uncompressed. */
      ulong out_sz = ZSTD_compressCCtx( server->cctx, out, room, msg, msg_sz,
                                        server->params.compression_level );
      if( FD_LIKELY( !ZSTD_isError( out_sz ) && out_sz<msg_sz ) ) {
        payload_sz = out_sz;
        compressed = 1U;
      }
    }
    if( !compressed ) {
      fd_memcpy( out, msg, msg_sz );
      payload_sz = msg_sz;
    }

    fd_grpc_hdr_t hdr = {
      .compressed = (uchar)compressed,
      .msg_sz     = fd_uint_bswap( (uint)payload_sz )
    };
    memcpy( slot->buf, &hdr, sizeof(fd_grpc_hdr_t) );
    slot->sz          = payload_sz + sizeof(fd_grpc_hdr_t);
    slot->off         = 0UL;
    slot->busy        = 1;
    stream->large_idx   = idx;
    stream->large_nanos = server->now;
    /* The queue bytes that were already there go out in front of the
       slot; whatever is queued from now on goes out behind it. */
    stream->tx_pre_slot = fd_h2_rbuf_used_sz( stream->tx_queue );

    server->metrics.tx_msg_cnt++;
    server->metrics.tx_large_msg_cnt++;
    server->metrics.tx_byte_cnt      += msg_sz;
    server->metrics.tx_byte_cnt_wire += payload_sz;
    if( compressed ) server->metrics.tx_msg_compressed_cnt++;
    return FD_GRPC_SERVER_SUCCESS;
  }

  if( want_zstd ) {
    ulong out_sz = ZSTD_compressCCtx( server->cctx, server->compress_out, server->compress_out_sz,
                                      msg, msg_sz, server->params.compression_level );
    if( FD_UNLIKELY( ZSTD_isError( out_sz ) ) ) {
      FD_LOG_WARNING(( "zstd compress failed (%s)", ZSTD_getErrorName( out_sz ) ));
      return FD_GRPC_SERVER_ERR_INTERNAL;
    }
    if( FD_LIKELY( out_sz<msg_sz ) ) {
      payload    = server->compress_out;
      payload_sz = out_sz;
      compressed = 1U;
    }
  }

  ulong frame_sz = payload_sz + sizeof(fd_grpc_hdr_t);
  ulong msg_max  = server->params.stream_tx_queue_msg_max;
  if( FD_UNLIKELY( ( frame_sz > fd_h2_rbuf_free_sz( stream->tx_queue ) ) |
                   ( ( !!msg_max ) & ( stream->tx_msg_pending>=msg_max ) ) ) ) {
    stream->flags        |= FD_GRPC_SERVER_STREAM_FLAG_TX_BLOCKED;
    stream->tx_blocked_sz = frame_sz;
    server->metrics.tx_queue_full_cnt++;
    return FD_GRPC_SERVER_ERR_AGAIN;
  }

  fd_grpc_hdr_t hdr = {
    .compressed = (uchar)compressed,
    .msg_sz     = fd_uint_bswap( (uint)payload_sz )
  };
  fd_h2_rbuf_push( stream->tx_queue, &hdr, sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_push( stream->tx_queue, payload, payload_sz );
  if( !stream->tx_msg_pending ) stream->tx_head_rem = frame_sz;
  stream->tx_msg_pending++;
  stream->tx_queue_hi = fd_ulong_max( stream->tx_queue_hi,
                                      fd_h2_rbuf_used_sz( stream->tx_queue ) );

  server->metrics.tx_msg_cnt++;
  server->metrics.tx_byte_cnt      += msg_sz;
  server->metrics.tx_byte_cnt_wire += payload_sz;
  if( compressed ) server->metrics.tx_msg_compressed_cnt++;
  return FD_GRPC_SERVER_SUCCESS;
}

/* fd_grpc_server_queue_copy_out copies sz bytes of a send queue,
   starting off bytes into what it holds, which may wrap. */

static void
fd_grpc_server_queue_copy_out( fd_h2_rbuf_t * queue,
                               ulong          off,
                               uchar *        out,
                               ulong          sz ) {
  ulong chunk0, chunk1;
  uchar const * p = fd_h2_rbuf_peek_used( queue, &chunk0, &chunk1 );
  ulong got = 0UL;
  if( off<chunk0 ) {
    got = fd_ulong_min( sz, chunk0-off );
    memcpy( out, p+off, got );
    off = chunk0;
  }
  if( got<sz ) memcpy( out+got, queue->buf0 + ( off-chunk0 ), sz-got );
}

/* fd_grpc_server_queue_drained accounts for the next sz bytes of the
   send queue going out: it retires the messages they complete.  It
   runs before those bytes are consumed, so that the length prefix of
   each message it crosses is still in the queue, at the offset the
   ones before it end on. */

static void
fd_grpc_server_queue_drained( fd_grpc_server_stream_t * stream,
                              ulong                     sz ) {
  ulong off = 0UL;
  while( sz ) {
    ulong d = fd_ulong_min( sz, stream->tx_head_rem );
    stream->tx_head_rem -= d;
    sz                  -= d;
    off                 += d;
    if( FD_UNLIKELY( !d ) ) break; /* accounting lost track; nothing to retire */
    if( stream->tx_head_rem ) continue;

    stream->tx_msg_pending--;
    if( !stream->tx_msg_pending ) break;

    uchar hdr[ sizeof(fd_grpc_hdr_t) ];
    fd_grpc_server_queue_copy_out( stream->tx_queue, off, hdr, sizeof(fd_grpc_hdr_t) );
    stream->tx_head_rem = sizeof(fd_grpc_hdr_t) +
                          (ulong)fd_uint_bswap( FD_LOAD( uint, hdr+1 ) );
  }
}

/* fd_grpc_server_stream_flush moves as much of one stream's pending
   response bytes into the connection's send ring as flow control
   allows: the send queue first, then the large send slot the stream
   holds, which is the order they were sent in.  Emits at most one DATA
   frame so that concurrent streams take turns, whichever source it
   comes from.  Returns 1 if it made progress. */

static int
fd_grpc_server_stream_flush( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_conn_t * conn    = stream->conn;
  fd_h2_conn_t *          h2      = conn->h2;
  fd_h2_rbuf_t *          rbuf_tx = conn->rbuf_tx;
  uchar block[ FD_GRPC_SERVER_HDR_BUF_MAX ];
  int progress = 0;

  if( FD_UNLIKELY( h2->flags & FD_H2_CONN_FLAGS_DEAD ) ) return 0;
  if( FD_UNLIKELY( stream->h2->state==FD_H2_STREAM_STATE_CLOSED ||
                   stream->h2->state==FD_H2_STREAM_STATE_ILLEGAL ) ) return 0;

  fd_grpc_server_large_t * large = stream->large_idx>=0L ? conn->server->large + stream->large_idx : NULL;
  ulong queue_sz  = fd_h2_rbuf_used_sz( stream->tx_queue );
  ulong large_rem = large ? large->sz - large->off : 0UL;
  ulong pending   = queue_sz + large_rem;

  if( !( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_RESP_HDRS ) ) {
    if( !pending && stream->state!=FD_GRPC_SERVER_STREAM_FINISH ) return 0;

    if( !pending && stream->state==FD_GRPC_SERVER_STREAM_FINISH ) {
      /* Trailers-Only response */
      ulong block_sz = fd_grpc_server_gen_resp_hdrs( stream, block );
      block_sz += fd_grpc_server_gen_trailers( stream, block+block_sz );
      if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < block_sz+9UL+sizeof(fd_h2_rst_stream_t)+FD_GRPC_SERVER_TX_RESERVE ) ) return 0;
      fd_grpc_server_tx_hdrs( stream, block, block_sz, 1 );
      goto finished;
    }

    ulong block_sz = fd_grpc_server_gen_resp_hdrs( stream, block );
    if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < block_sz+9UL+FD_GRPC_SERVER_TX_RESERVE ) ) return 0;
    fd_grpc_server_tx_hdrs( stream, block, block_sz, 0 );
    stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RESP_HDRS;
    progress = 1;
  }

  if( pending ) {
    ulong quota   = fd_ulong_min( h2->tx_wnd, stream->h2->tx_wnd );
    ulong buf_spc = fd_h2_rbuf_free_sz( rbuf_tx );
    buf_spc = buf_spc < 9UL+FD_GRPC_SERVER_TX_RESERVE ? 0UL : buf_spc-9UL-FD_GRPC_SERVER_TX_RESERVE;

    /* tx_pre_slot bytes first, then the slot, then the rest of the
       queue.  The slot is contiguous, so only the queue needs
       chunking. */
    int           from_queue = queue_sz && ( stream->tx_pre_slot || !large_rem );
    uchar const * chunk;
    ulong         chunk_sz;
    if( from_queue ) {
      ulong chunk0, chunk1;
      chunk    = fd_h2_rbuf_peek_used( stream->tx_queue, &chunk0, &chunk1 );
      chunk_sz = stream->tx_pre_slot ? fd_ulong_min( chunk0, stream->tx_pre_slot ) : chunk0;
    } else {
      chunk    = large->buf + large->off;
      chunk_sz = large_rem;
    }

    ulong payload_sz = fd_ulong_min( quota, chunk_sz );
    /**/  payload_sz = fd_ulong_min( payload_sz, buf_spc );
    /**/  payload_sz = fd_ulong_min( payload_sz, h2->peer_settings.max_frame_size );
    if( payload_sz ) {
      fd_h2_tx_prepare( h2, rbuf_tx, FD_H2_FRAME_TYPE_DATA, 0U, stream->h2->stream_id );
      fd_h2_rbuf_push( rbuf_tx, chunk, payload_sz );
      fd_h2_tx_commit( h2, rbuf_tx );
      if( from_queue ) {
        fd_grpc_server_queue_drained( stream, payload_sz );
        fd_h2_rbuf_skip( stream->tx_queue, payload_sz );
        if( stream->tx_pre_slot ) stream->tx_pre_slot -= payload_sz;
      }
      else {
        large->off += payload_sz;
        large_rem  -= payload_sz;
        stream->large_nanos = stream->conn->server->now;
      }
      h2->tx_wnd         -= (uint)payload_sz;
      stream->h2->tx_wnd -= (uint)payload_sz;
      pending            -= payload_sz;
      progress = 1;
    }
  }

  /* A large message that went out whole frees its slot right away, so
     that the next one does not wait for the call to end. */
  if( large && !large_rem ) fd_grpc_server_large_release( stream );

  if( !pending && stream->state==FD_GRPC_SERVER_STREAM_FINISH ) {
    ulong block_sz = fd_grpc_server_gen_trailers( stream, block );
    if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < block_sz+9UL+sizeof(fd_h2_rst_stream_t)+FD_GRPC_SERVER_TX_RESERVE ) ) return progress;
    fd_grpc_server_tx_hdrs( stream, block, block_sz, 1 );
    goto finished;
  }

  return progress;

finished:
  fd_h2_stream_close_tx( stream->h2, conn->h2 );
  if( stream->h2->state!=FD_H2_STREAM_STATE_CLOSED ) {
    /* The client has not finished its request.  The response is
       complete, so tear the stream down (RFC 9113 Section 8.1). */
    fd_grpc_server_stream_abort( stream, FD_H2_SUCCESS );
  }
  fd_grpc_server_stream_end( stream, FD_GRPC_SERVER_CLOSE_FINISHED );
  return 1;
}

/* Request headers ****************************************************/

/* fd_grpc_server_hdr_name_valid returns 1 if name is a valid HTTP/2
   field name: non-empty, lowercase, and made of token characters
   (RFC 9113 Section 8.2.1).  A leading colon is allowed for
   pseudo-headers. */

static int
fd_grpc_server_hdr_name_valid( char const * name,
                               ulong        name_len ) {
  if( FD_UNLIKELY( !name_len ) ) return 0;
  for( ulong i=0UL; i<name_len; i++ ) {
    uchar c = (uchar)name[i];
    if( c==':' ) {
      if( FD_UNLIKELY( i ) ) return 0; /* colon is only valid in front */
      continue;
    }
    int ok = ( c>='a' && c<='z' ) || ( c>='0' && c<='9' ) ||
             c=='!' || c=='#' || c=='$' || c=='%' || c=='&' || c=='\'' ||
             c=='*' || c=='+' || c=='-' || c=='.' || c=='^' || c=='_'  ||
             c=='`' || c=='|' || c=='~';
    if( FD_UNLIKELY( !ok ) ) return 0;
  }
  return 1;
}

/* fd_grpc_server_hdr_value_valid rejects the field value characters
   that RFC 9113 Section 8.2.1 forbids. */

static int
fd_grpc_server_hdr_value_valid( char const * value,
                                ulong        value_len ) {
  for( ulong i=0UL; i<value_len; i++ ) {
    uchar c = (uchar)value[i];
    if( FD_UNLIKELY( c==0x00 || c=='\n' || c=='\r' ) ) return 0;
  }
  if( FD_UNLIKELY( value_len && ( value[0]==' ' || value[0]=='\t' ||
                                  value[value_len-1UL]==' ' || value[value_len-1UL]=='\t' ) ) ) return 0;
  return 1;
}

/* fd_grpc_server_parse_timeout parses a grpc-timeout value into
   nanoseconds.  Returns LONG_MAX if the value is malformed, which the
   caller treats as "no deadline". */

static long
fd_grpc_server_parse_timeout( char const * value,
                              ulong        value_len ) {
  if( FD_UNLIKELY( value_len<2UL || value_len>9UL ) ) return LONG_MAX;
  ulong digits = 0UL;
  for( ulong i=0UL; i<value_len-1UL; i++ ) {
    uchar c = (uchar)value[i];
    if( FD_UNLIKELY( c<'0' || c>'9' ) ) return LONG_MAX;
    digits = digits*10UL + (ulong)( c-'0' );
  }
  long mul;
  switch( value[ value_len-1UL ] ) {
  case 'H': mul = 3600L*1000L*1000L*1000L; break;
  case 'M': mul =   60L*1000L*1000L*1000L; break;
  case 'S': mul =        1000L*1000L*1000L; break;
  case 'm': mul =              1000L*1000L; break;
  case 'u': mul =                    1000L; break;
  case 'n': mul =                       1L; break;
  default: return LONG_MAX;
  }
  if( FD_UNLIKELY( digits > (ulong)( LONG_MAX/mul ) ) ) return LONG_MAX;
  return (long)digits*mul;
}

/* fd_grpc_server_list_has returns 1 if the comma separated list in
   value contains item (ignoring spaces). */

static int
fd_grpc_server_list_has( char const * value,
                         ulong        value_len,
                         char const * item,
                         ulong        item_len ) {
  ulong i = 0UL;
  while( i<value_len ) {
    while( i<value_len && ( value[i]==' ' || value[i]==',' || value[i]=='\t' ) ) i++;
    ulong j = i;
    while( j<value_len && value[j]!=',' ) j++;
    ulong end = j;
    while( end>i && ( value[end-1UL]==' ' || value[end-1UL]=='\t' ) ) end--;
    if( end-i==item_len && fd_memeq( value+i, item, item_len ) ) return 1;
    i = j+1UL;
  }
  return 0;
}

/* Bits of the pseudo-header set */

#define FD_GRPC_SERVER_PSEUDO_METHOD    (1U<<0)
#define FD_GRPC_SERVER_PSEUDO_SCHEME    (1U<<1)
#define FD_GRPC_SERVER_PSEUDO_PATH      (1U<<2)
#define FD_GRPC_SERVER_PSEUDO_AUTHORITY (1U<<3)

/* fd_grpc_server_rx_request_hdrs validates a request field block and
   hands the request to the app. */

static void
fd_grpc_server_rx_request_hdrs( fd_grpc_server_stream_t * stream,
                                uchar const *             block,
                                ulong                     block_sz ) {
  fd_grpc_server_conn_t * conn   = stream->conn;
  fd_grpc_server_t *      server = conn->server;
  fd_h2_conn_t *          h2     = conn->h2;

  stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_HDRS_DONE;

  fd_hpack_rd_t hpack_rd[1];
  if( FD_UNLIKELY( !fd_hpack_rd_init_dtable( hpack_rd, block, block_sz, &h2->rx_hpack ) ) ) {
    fd_h2_conn_error( h2, FD_H2_ERR_COMPRESSION );
    return;
  }

  uint  pseudo_seen  = 0U;
  int   regular_seen = 0;
  int   malformed    = 0;
  int   content_type = 0;
  int   method_post  = 0;
  int   scheme_ok    = 0;
  ulong scratch_sz   = fd_grpc_server_hpack_scratch_sz( &server->params );
  ulong decoded_sz   = 0UL;
  ulong max_header_list_sz = server->params.max_frame_sz;

  while( !fd_hpack_rd_done( hpack_rd ) ) {
    uchar *     scratch = server->hpack_scratch;
    fd_h2_hdr_t hdr[1];
    uint err = fd_hpack_rd_next( hpack_rd, hdr, &scratch, server->hpack_scratch+scratch_sz );
    if( FD_UNLIKELY( err ) ) {
      fd_h2_conn_error( h2, err );
      return;
    }
    /* RFC 9113 Section 6.5.2: the header list size limit is on the
       decoded size, which a dynamic table reference can expand far
       beyond the wire size. */
    decoded_sz += hdr->name_len + hdr->value_len + 32UL;
    if( FD_UNLIKELY( decoded_sz > max_header_list_sz ) ) {
      fd_h2_conn_error( h2, FD_H2_ERR_ENHANCE_YOUR_CALM );
      return;
    }
    char const * name      = hdr->name;
    ulong        name_len  = hdr->name_len;
    char const * value     = hdr->value;
    ulong        value_len = hdr->value_len;

    if( FD_UNLIKELY( !fd_grpc_server_hdr_name_valid ( name,  name_len  ) ||
                     !fd_grpc_server_hdr_value_valid( value, value_len ) ) ) {
      malformed = 1;
      continue;
    }

    int id = fd_h2_hdr_match( server->matcher, name, name_len, hdr->hint );

    if( name[0]==':' ) {
      if( FD_UNLIKELY( regular_seen ) ) { malformed = 1; continue; }
      uint bit;
      switch( id ) {
      case FD_H2_HDR_METHOD:    bit = FD_GRPC_SERVER_PSEUDO_METHOD;    break;
      case FD_H2_HDR_SCHEME:    bit = FD_GRPC_SERVER_PSEUDO_SCHEME;    break;
      case FD_H2_HDR_PATH:      bit = FD_GRPC_SERVER_PSEUDO_PATH;      break;
      case FD_H2_HDR_AUTHORITY: bit = FD_GRPC_SERVER_PSEUDO_AUTHORITY; break;
      default:
        /* Unknown or response pseudo-header */
        malformed = 1;
        continue;
      }
      if( FD_UNLIKELY( pseudo_seen & bit ) ) { malformed = 1; continue; }
      pseudo_seen |= bit;

      switch( id ) {
      case FD_H2_HDR_METHOD:
        method_post = ( value_len==4UL ) && fd_memeq( value, "POST", 4UL );
        break;
      case FD_H2_HDR_SCHEME:
        scheme_ok = ( ( value_len==4UL ) && fd_memeq( value, "http",  4UL ) ) ||
                    ( ( value_len==5UL ) && fd_memeq( value, "https", 5UL ) );
        break;
      case FD_H2_HDR_PATH:
        if( FD_UNLIKELY( !value_len ) ) { malformed = 1; break; }
        /* Longer than any route, so it is left empty and matches none */
        if( FD_UNLIKELY( value_len>FD_GRPC_SERVER_PATH_MAX ) ) break;
        stream->path_len = (ushort)value_len;
        fd_memcpy( stream->path, value, stream->path_len );
        break;
      default:
        break;
      }
      continue;
    }

    regular_seen = 1;

    switch( id ) {
    case FD_H2_HDR_TRANSFER_ENCODING:
    case FD_GRPC_SERVER_HDR_CONNECTION:
    case FD_GRPC_SERVER_HDR_KEEP_ALIVE:
    case FD_GRPC_SERVER_HDR_PROXY_CONNECTION:
    case FD_GRPC_SERVER_HDR_UPGRADE:
      /* Connection-specific header fields are forbidden
         (RFC 9113 Section 8.2.2) */
      malformed = 1;
      continue;
    case FD_GRPC_SERVER_HDR_TE:
      if( FD_UNLIKELY( value_len!=8UL || !fd_memeq( value, "trailers", 8UL ) ) ) malformed = 1;
      continue;
    case FD_H2_HDR_CONTENT_TYPE:
      content_type = ( value_len>=sizeof(FD_GRPC_SERVER_CONTENT_TYPE)-1UL ) &&
                     fd_memeq( value, FD_GRPC_SERVER_CONTENT_TYPE, sizeof(FD_GRPC_SERVER_CONTENT_TYPE)-1UL );
      continue;
    case FD_GRPC_SERVER_HDR_TIMEOUT: {
      long timeout = fd_grpc_server_parse_timeout( value, value_len );
      if( timeout!=LONG_MAX ) stream->deadline = fd_long_sat_add( server->now, timeout );
      continue;
    }
    case FD_GRPC_SERVER_HDR_ENCODING:
      if( ( value_len==4UL ) && fd_memeq( value, "zstd", 4UL ) ) {
        stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RX_ZSTD;
      }
      continue;
    case FD_GRPC_SERVER_HDR_ACCEPT_ENCODING:
      if( ( server->params.compression==FD_GRPC_SERVER_COMPRESSION_ZSTD ) &&
          fd_grpc_server_list_has( value, value_len, "zstd", 4UL ) ) {
        stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_TX_ZSTD;
      }
      continue;
    default:
      break;
    }

    server->callbacks->stream_hdr( server->app_ctx, stream, name, name_len, value, value_len );
    if( FD_UNLIKELY( stream->state==FD_GRPC_SERVER_STREAM_FREE ) ) return;
  }

  uint pseudo_need = FD_GRPC_SERVER_PSEUDO_METHOD |
                     FD_GRPC_SERVER_PSEUDO_SCHEME |
                     FD_GRPC_SERVER_PSEUDO_PATH;
  if( FD_UNLIKELY( ( pseudo_seen & pseudo_need )!=pseudo_need ) ) malformed = 1;
  if( FD_UNLIKELY( !scheme_ok ) ) malformed = 1;

  if( FD_UNLIKELY( malformed ) ) {
    fd_grpc_server_stream_malformed( stream, FD_H2_ERR_PROTOCOL );
    return;
  }
  if( FD_UNLIKELY( !method_post ) ) {
    fd_grpc_server_tx_http_status( stream, "405", 3UL );
    return;
  }
  if( FD_UNLIKELY( !content_type ) ) {
    fd_grpc_server_tx_http_status( stream, "415", 3UL );
    return;
  }

  if( FD_UNLIKELY( stream->state==FD_GRPC_SERVER_STREAM_FINISH ) ) {
    stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RX_DROP;
    return;
  }
  stream->state = FD_GRPC_SERVER_STREAM_ACTIVE;
  int kind = server->callbacks->stream_open( server->app_ctx, stream, stream->path, stream->path_len );
  if( FD_UNLIKELY( stream->state==FD_GRPC_SERVER_STREAM_FREE ) ) return; /* handler closed the conn */
  if( FD_UNLIKELY( kind==FD_GRPC_SERVER_REJECT ) ) {
    server->metrics.stream_reject_cnt++;
    if( stream->state!=FD_GRPC_SERVER_STREAM_FINISH ) {
      FD_GRPC_SERVER_FINISH( stream, FD_GRPC_STATUS_UNIMPLEMENTED, "unknown method" );
    }
    stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RX_DROP;
    return;
  }

  server->metrics.stream_open_cnt++;
  stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN;
  if( server->params.response_timeout_nanos>0L ) {
    stream->resp_deadline = fd_long_sat_add( server->now, server->params.response_timeout_nanos );
  }
  if( kind==FD_GRPC_SERVER_ACCEPT_UNARY ) stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_UNARY;
}

/* gRPC message framing ***********************************************/

static void
fd_grpc_server_rx_fin( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_t * server = stream->conn->server;
  if( FD_UNLIKELY( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_RX_FIN ) ) return;
  stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RX_FIN;

  if( FD_UNLIKELY( ( stream->state==FD_GRPC_SERVER_STREAM_ACTIVE  ) &
                   ( !( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_RX_DROP ) ) &
                   ( ( stream->msg_hdr_sz | stream->msg_rem )!=0UL ) ) ) {
    FD_GRPC_SERVER_FINISH( stream, FD_GRPC_STATUS_INTERNAL, "incomplete message" );
    return;
  }
  if( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN ) {
    server->callbacks->stream_half_close( server->app_ctx, stream );
  }
}

/* fd_grpc_server_rx_reject ends the call with the given status and
   discards the rest of the request. */

static void
fd_grpc_server_rx_reject( fd_grpc_server_stream_t * stream,
                          uint                      grpc_status,
                          char const *              msg,
                          ulong                     msg_len ) {
  stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RX_DROP;
  fd_grpc_server_finish( stream, grpc_status, msg, msg_len );
  stream->conn->server->metrics.request_error_cnt++;
}

#define FD_GRPC_SERVER_RX_REJECT(stream,status,lit) \
  fd_grpc_server_rx_reject( (stream), (status), (lit), sizeof(lit)-1UL )

/* fd_grpc_server_decompress expands a zstd coded request message into
   the server's decompression buffer.  The output is hard bounded by
   max_request_msg_sz, both up front for a frame that declares its
   content size and again by the destination capacity, which is what
   bounds a frame that does not declare one.  Returns FD_GRPC_STATUS_OK
   and points out at the plaintext on success,
   FD_GRPC_STATUS_RESOURCE_EXHAUSTED if the message expands past the
   bound, or FD_GRPC_STATUS_INTERNAL if the frame is corrupt,
   truncated, or followed by trailing bytes. */

static uint
fd_grpc_server_decompress( fd_grpc_server_t * server,
                           uchar const *      in,
                           ulong              in_sz,
                           uchar const **     out,
                           ulong *            out_sz ) {
  ulong bound = server->params.max_request_msg_sz;

  unsigned long long content_sz = ZSTD_getFrameContentSize( in, in_sz );
  if( FD_UNLIKELY( content_sz==ZSTD_CONTENTSIZE_ERROR ) ) return FD_GRPC_STATUS_INTERNAL;
  if( FD_UNLIKELY( ( content_sz!=ZSTD_CONTENTSIZE_UNKNOWN ) &
                   ( content_sz>(unsigned long long)bound ) ) ) {
    return FD_GRPC_STATUS_RESOURCE_EXHAUSTED;
  }

  /* The length prefix delimits exactly one frame.  Anything past the
     first frame, whether a second frame or junk, is a framing error. */
  ulong frame_sz = ZSTD_findFrameCompressedSize( in, in_sz );
  if( FD_UNLIKELY( ZSTD_isError( frame_sz ) || frame_sz!=in_sz ) ) return FD_GRPC_STATUS_INTERNAL;

  ulong sz = ZSTD_decompressDCtx( server->dctx, server->decompress_out, bound, in, in_sz );
  if( FD_UNLIKELY( ZSTD_isError( sz ) ) ) {
    if( ZSTD_getErrorCode( sz )==ZSTD_error_dstSize_tooSmall ) {
      return FD_GRPC_STATUS_RESOURCE_EXHAUSTED;
    }
    return FD_GRPC_STATUS_INTERNAL;
  }

  *out    = server->decompress_out;
  *out_sz = sz;
  return FD_GRPC_STATUS_OK;
}

/* fd_grpc_server_rx_msg hands a fully reassembled request message to the
   handler, decompressing it first if it is zstd coded. */

static void
fd_grpc_server_rx_msg( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_t * server = stream->conn->server;
  uchar const *      msg    = stream->msg_buf;
  ulong              msg_sz = stream->msg_sz;

  stream->msg_hdr_sz = 0UL;
  stream->msg_sz     = 0UL;

  if( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_RX_MSG_ZSTD ) {
    stream->flags &= ~FD_GRPC_SERVER_STREAM_FLAG_RX_MSG_ZSTD;
    uint status = fd_grpc_server_decompress( server, msg, msg_sz, &msg, &msg_sz );
    if( FD_UNLIKELY( status==FD_GRPC_STATUS_RESOURCE_EXHAUSTED ) ) {
      FD_GRPC_SERVER_RX_REJECT( stream, status, "grpc: received message larger than max" );
      return;
    }
    if( FD_UNLIKELY( status!=FD_GRPC_STATUS_OK ) ) {
      FD_GRPC_SERVER_RX_REJECT( stream, status, "grpc: failed to decompress message" );
      return;
    }
  }

  server->metrics.rx_msg_cnt++;
  if( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN ) {
    server->callbacks->stream_msg( server->app_ctx, stream, msg, msg_sz );
  }
}

static void
fd_grpc_server_rx_msg_hdr( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_t * server = stream->conn->server;
  uchar compressed = stream->msg_hdr[0];
  uint  msg_sz     = fd_uint_bswap( FD_LOAD( uint, stream->msg_hdr+1 ) );

  if( FD_UNLIKELY( compressed>1 ) ) {
    FD_GRPC_SERVER_RX_REJECT( stream, FD_GRPC_STATUS_INTERNAL, "invalid compressed flag" );
    return;
  }
  if( FD_UNLIKELY( compressed ) ) {
    if( FD_UNLIKELY( !server->dctx ) ) {
      /* Compression is turned off, so the server advertises
         grpc-accept-encoding: identity and has no decompressor */
      FD_GRPC_SERVER_RX_REJECT( stream, FD_GRPC_STATUS_UNIMPLEMENTED,
                                "grpc: compressed requests are not supported" );
      return;
    }
    if( FD_UNLIKELY( !( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_RX_ZSTD ) ) ) {
      /* The only encoding the server can decode is the one the request
         has to name in grpc-encoding */
      FD_GRPC_SERVER_RX_REJECT( stream, FD_GRPC_STATUS_UNIMPLEMENTED,
                                "grpc: unsupported message encoding" );
      return;
    }
    stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RX_MSG_ZSTD;
  }
  /* The length prefix counts the coded bytes, which are reassembled in
     the stream's request buffer.  The plaintext is bounded separately
     when it is decompressed. */
  if( FD_UNLIKELY( msg_sz > server->params.max_request_msg_sz ) ) {
    FD_GRPC_SERVER_RX_REJECT( stream, FD_GRPC_STATUS_RESOURCE_EXHAUSTED,
                              "grpc: received message larger than max" );
    return;
  }
  stream->msg_rem = msg_sz;
  stream->msg_sz  = 0UL;
  if( !msg_sz ) fd_grpc_server_rx_msg( stream );
}

static void
fd_grpc_server_rx_data( fd_grpc_server_stream_t * stream,
                        uchar const *             data,
                        ulong                     data_sz ) {
  fd_grpc_server_t * server = stream->conn->server;
  server->metrics.rx_byte_cnt += data_sz;

  while( data_sz ) {
    if( FD_UNLIKELY( stream->state!=FD_GRPC_SERVER_STREAM_ACTIVE ||
                     ( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_RX_DROP ) ) ) return;

    if( stream->msg_hdr_sz < sizeof(fd_grpc_hdr_t) ) {
      ulong take = fd_ulong_min( sizeof(fd_grpc_hdr_t)-stream->msg_hdr_sz, data_sz );
      fd_memcpy( stream->msg_hdr+stream->msg_hdr_sz, data, take );
      stream->msg_hdr_sz += take;
      data               += take;
      data_sz            -= take;
      if( stream->msg_hdr_sz==sizeof(fd_grpc_hdr_t) ) fd_grpc_server_rx_msg_hdr( stream );
      continue;
    }

    ulong take = fd_ulong_min( stream->msg_rem, data_sz );
    fd_memcpy( stream->msg_buf+stream->msg_sz, data, take );
    stream->msg_sz  += take;
    stream->msg_rem -= take;
    data            += take;
    data_sz         -= take;
    if( !stream->msg_rem ) fd_grpc_server_rx_msg( stream );
  }
}

/* fd_h2 callbacks ****************************************************/

static fd_h2_stream_t *
fd_grpc_server_cb_stream_create( fd_h2_conn_t * h2,
                                 uint           stream_id ) {
  (void)stream_id;
  fd_grpc_server_conn_t * conn = fd_grpc_server_conn_from_h2( h2 );
  if( FD_UNLIKELY( !conn->active || conn->server->shutdown || ( conn->flags & FD_GRPC_SERVER_CONN_FLAG_GOAWAY ) ) ) return NULL;
  fd_grpc_server_stream_t * stream = fd_grpc_server_stream_acquire( conn );
  if( FD_UNLIKELY( !stream ) ) return NULL;
  return stream->h2;
}

static fd_h2_stream_t *
fd_grpc_server_cb_stream_query( fd_h2_conn_t * h2,
                                uint           stream_id ) {
  fd_grpc_server_conn_t * conn = fd_grpc_server_conn_from_h2( h2 );
  ulong stream_max = conn->server->params.max_stream_cnt;
  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t * s = conn->stream+i;
    if( ( s->state!=FD_GRPC_SERVER_STREAM_FREE ) & ( s->h2->stream_id==stream_id ) ) return s->h2;
  }
  return NULL;
}

/* fd_grpc_server_conn_closing marks a connection for release once its
   send ring drains or the close timeout passes, whichever first. */

static void
fd_grpc_server_conn_closing( fd_grpc_server_conn_t * conn ) {
  conn->flags      |= FD_GRPC_SERVER_CONN_FLAG_CLOSING;
  conn->close_nanos = conn->server->now + FD_GRPC_SERVER_CLOSE_TIMEOUT_NANOS;
}

static void
fd_grpc_server_cb_conn_final( fd_h2_conn_t * h2,
                              uint           h2_err,
                              int            closed_by ) {
  (void)h2_err; (void)closed_by;
  fd_grpc_server_conn_t * conn = fd_grpc_server_conn_from_h2( h2 );
  ulong stream_max = conn->server->params.max_stream_cnt;
  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t * s = conn->stream+i;
    if( s->state!=FD_GRPC_SERVER_STREAM_FREE ) {
      fd_grpc_server_stream_end( s, FD_GRPC_SERVER_CLOSE_CONN_LOST );
    }
  }
  fd_grpc_server_conn_closing( conn );
}

/* fd_grpc_server_rx_discard_hdrs decodes a request trailer block
   without keeping any of it.  Returns 0 if the block is invalid, after
   ending the stream or the conn. */

static int
fd_grpc_server_rx_discard_hdrs( fd_grpc_server_conn_t *   conn,
                                fd_grpc_server_stream_t * stream,
                                uchar const *             block,
                                ulong                     block_sz ) {
  fd_grpc_server_t *      server = conn->server;
  fd_h2_conn_t *          h2     = conn->h2;
  int                     malformed = 0;
  fd_hpack_rd_t hpack_rd[1];
  if( FD_UNLIKELY( !fd_hpack_rd_init_dtable( hpack_rd, block, block_sz, &h2->rx_hpack ) ) ) {
    fd_h2_conn_error( h2, FD_H2_ERR_COMPRESSION );
    return 0;
  }
  ulong scratch_sz = fd_grpc_server_hpack_scratch_sz( &server->params );
  ulong decoded_sz = 0UL;
  ulong max_header_list_sz = server->params.max_frame_sz;
  while( !fd_hpack_rd_done( hpack_rd ) ) {
    uchar *     scratch = server->hpack_scratch;
    fd_h2_hdr_t hdr[1];
    uint err = fd_hpack_rd_next( hpack_rd, hdr, &scratch, server->hpack_scratch+scratch_sz );
    if( FD_UNLIKELY( err ) ) {
      fd_h2_conn_error( h2, err );
      return 0;
    }
    decoded_sz += hdr->name_len + hdr->value_len + 32UL;
    if( FD_UNLIKELY( decoded_sz > max_header_list_sz ) ) {
      fd_h2_conn_error( h2, FD_H2_ERR_ENHANCE_YOUR_CALM );
      return 0;
    }
    /* RFC 9113 Section 8.1: trailers carry no pseudo-headers.
       Processing malformed waits the end of the loop, so the full
       decoding happens. */
    if( FD_UNLIKELY( !hdr->name_len || hdr->name[0]==':' ||
                     !fd_grpc_server_hdr_name_valid ( hdr->name,  hdr->name_len  ) ||
                     !fd_grpc_server_hdr_value_valid( hdr->value, hdr->value_len ) ) ) {
      malformed = 1;
    }
  }
  if( FD_UNLIKELY( malformed ) ) {
    if( stream ) fd_grpc_server_stream_malformed( stream, FD_H2_ERR_PROTOCOL );
    return 0;
  }
  return 1;
}

static void
fd_grpc_server_cb_headers( fd_h2_conn_t *   h2,
                           fd_h2_stream_t * h2_stream,
                           void const *     data,
                           ulong            data_sz,
                           ulong            flags ) {
  fd_grpc_server_stream_t * stream = fd_grpc_server_stream_from_h2( h2_stream );

  /* One frame carries one whole field block.  A peer that splits one
     across CONTINUATION frames is refused rather than reassembled. */
  if( FD_UNLIKELY( !( flags & FD_H2_FLAG_END_HEADERS ) ) ) {
    fd_h2_conn_error( h2, FD_H2_ERR_COMPRESSION );
    return;
  }

  /* The stream was refused, we still need to update the decoder state,
     but can terminate immediately. */
  if( FD_UNLIKELY( !stream ) ) {
    fd_grpc_server_rx_discard_hdrs( fd_grpc_server_conn_from_h2( h2 ), NULL, data, data_sz );
    return;
  }

  int end_stream = !!( flags & FD_H2_FLAG_END_STREAM );
  if( FD_UNLIKELY( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_HDRS_DONE ) ) {
    /* Request trailers carry no gRPC metadata.  They are decoded so
       that the HPACK dynamic table stays in sync, then dropped. */
    if( FD_UNLIKELY( !fd_grpc_server_rx_discard_hdrs( stream->conn, stream, data, data_sz ) ) ) return;
    if( FD_UNLIKELY( !end_stream ) ) {
      fd_grpc_server_stream_malformed( stream, FD_H2_ERR_PROTOCOL );
      return;
    }
    fd_grpc_server_rx_fin( stream );
    return;
  }
  fd_grpc_server_rx_request_hdrs( stream, data, data_sz );
  if( FD_UNLIKELY( stream->state==FD_GRPC_SERVER_STREAM_FREE ) ) return;
  if( end_stream ) fd_grpc_server_rx_fin( stream );
}

static void
fd_grpc_server_cb_data( fd_h2_conn_t *   h2,
                        fd_h2_stream_t * h2_stream,
                        void const *     data,
                        ulong            data_sz,
                        ulong            flags ) {
  fd_grpc_server_conn_t *   conn   = fd_grpc_server_conn_from_h2( h2 );
  fd_grpc_server_stream_t * stream = fd_grpc_server_stream_from_h2( h2_stream );
  if( FD_UNLIKELY( !( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_HDRS_DONE ) ) ) {
    /* DATA before the request headers were complete */
    fd_h2_conn_error( conn->h2, FD_H2_ERR_PROTOCOL );
    return;
  }
  fd_grpc_server_rx_data( stream, data, data_sz );
  /* A handler that closed the connection leaves a free slot with
     cleared flags, which rx_fin ignores. */
  if( flags & FD_H2_FLAG_END_STREAM ) fd_grpc_server_rx_fin( stream );
}

static void
fd_grpc_server_cb_rst_stream( fd_h2_conn_t *   h2,
                              fd_h2_stream_t * h2_stream,
                              uint             error_code,
                              int              closed_by ) {
  (void)h2;
  fd_grpc_server_stream_t * stream = fd_grpc_server_stream_from_h2( h2_stream );
  fd_grpc_server_conn_t *   conn   = stream->conn;
  fd_grpc_server_t *        server = conn->server;
  int reason = closed_by                  ? FD_GRPC_SERVER_CLOSE_CANCELLED :
               error_code==FD_H2_SUCCESS  ? FD_GRPC_SERVER_CLOSE_FINISHED  :
                                            FD_GRPC_SERVER_CLOSE_ABORTED;
  fd_grpc_server_stream_end( stream, reason );
  if( !closed_by ) return;

  /* A reset frees the concurrency slot at once, so max_concurrent_streams
     bounds what is open and not how fast a peer churns (RFC 9113 uses a
     GOAWAY for this, CVE-2023-44487). */
  if( server->now - conn->reset_nanos > FD_GRPC_SERVER_RESET_WINDOW_NANOS ) {
    conn->reset_nanos = server->now;
    conn->reset_cnt   = 0UL;
  }
  conn->reset_cnt++;
  if( FD_UNLIKELY( conn->reset_cnt>FD_GRPC_SERVER_RESET_MAX ) ) {
    server->metrics.reset_flood_cnt++;
    fd_h2_conn_error( conn->h2, FD_H2_ERR_ENHANCE_YOUR_CALM );
    fd_grpc_server_conn_closing( conn );
  }
}

static void
fd_grpc_server_cb_window_update( fd_h2_conn_t * h2,
                                 uint           increment ) {
  (void)h2; (void)increment;
}

static void
fd_grpc_server_cb_stream_window_update( fd_h2_conn_t *   h2,
                                        fd_h2_stream_t * h2_stream,
                                        uint             increment ) {
  (void)h2; (void)increment;
  /* Repay the shrink deficit before the new credit counts */
  fd_grpc_server_stream_t * stream = fd_grpc_server_stream_from_h2( h2_stream );
  long repay = fd_long_min( stream->tx_wnd_debt, (long)h2_stream->tx_wnd );
  if( FD_UNLIKELY( repay>0L ) ) {
    h2_stream->tx_wnd   -= (uint)repay;
    stream->tx_wnd_debt -= repay;
  }
}

static void
fd_grpc_server_cb_initial_window_update( fd_h2_conn_t * h2,
                                         long           delta ) {
  fd_grpc_server_conn_t * conn = fd_grpc_server_conn_from_h2( h2 );
  ulong stream_max = conn->server->params.max_stream_cnt;
  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t * s = conn->stream+i;
    if( s->state==FD_GRPC_SERVER_STREAM_FREE ) continue;
    /* A shrink below the credit already consumed leaves the effective
       window negative, which pauses the stream rather than failing it
       (RFC 9113 Section 6.9.2).  tx_wnd is unsigned, so the deficit is
       carried in tx_wnd_debt and repaid out of later WINDOW_UPDATEs. */
    long wnd = (long)s->h2->tx_wnd - s->tx_wnd_debt + delta;
    if( FD_UNLIKELY( wnd>0x7fffffffL ) ) {
      fd_h2_conn_error( h2, FD_H2_ERR_FLOW_CONTROL );
      return;
    }
    s->h2->tx_wnd  = (uint)fd_long_max(  wnd, 0L );
    s->tx_wnd_debt =       fd_long_max( -wnd, 0L );
  }
}

static fd_h2_callbacks_t const fd_grpc_server_h2_callbacks = {
  .stream_create         = fd_grpc_server_cb_stream_create,
  .stream_query          = fd_grpc_server_cb_stream_query,
  .conn_established      = fd_h2_noop_conn_established,
  .conn_final            = fd_grpc_server_cb_conn_final,
  .headers               = fd_grpc_server_cb_headers,
  .data                  = fd_grpc_server_cb_data,
  .rst_stream            = fd_grpc_server_cb_rst_stream,
  .window_update         = fd_grpc_server_cb_window_update,
  .stream_window_update  = fd_grpc_server_cb_stream_window_update,
  .initial_window_update = fd_grpc_server_cb_initial_window_update,
  .ping_ack              = fd_h2_noop_ping_ack
};

/* Connections ********************************************************/

static void
fd_grpc_server_conn_release( fd_grpc_server_conn_t * conn ) {
  fd_grpc_server_t * server = conn->server;
  conn->active = 0U;
  ulong stream_max = server->params.max_stream_cnt;
  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t * s = conn->stream+i;
    if( s->state!=FD_GRPC_SERVER_STREAM_FREE ) {
      fd_grpc_server_stream_end( s, FD_GRPC_SERVER_CLOSE_CONN_LOST );
    }
  }
# if FD_HAS_HOSTED
  if( conn->sock>=0 ) close( conn->sock );
# endif
  conn->sock   = -1;
  conn->flags  = 0U;
  conn->h2->flags = FD_H2_CONN_FLAGS_DEAD;
  server->callbacks->conn_close( server->app_ctx, conn );
  conn->ctx = NULL;
  server->conn_cnt--;
  server->metrics.conn_close_cnt++;
}

void
fd_grpc_server_conn_close( fd_grpc_server_conn_t * conn ) {
  if( FD_UNLIKELY( !conn->active ) ) return;
  fd_grpc_server_conn_release( conn );
}

void *
fd_grpc_server_conn_ctx( fd_grpc_server_conn_t const * conn ) {
  return conn->ctx;
}

void
fd_grpc_server_conn_set_ctx( fd_grpc_server_conn_t * conn,
                             void *                  ctx ) {
  conn->ctx = ctx;
}

int
fd_grpc_server_conn_is_open( fd_grpc_server_conn_t const * conn ) {
  return !!conn->active;
}

int
fd_grpc_server_conn_fd( fd_grpc_server_conn_t const * conn ) {
  return conn->sock;
}

/* fd_grpc_server_conn_init claims a connection slot and brings up the
   HTTP/2 state machine.  Returns NULL if no slot is free or the app
   rejected the connection.  Owns sock from here on: a failed init
   closes it. */

static fd_grpc_server_conn_t *
fd_grpc_server_conn_init( fd_grpc_server_t * server,
                          int                sock,
                          long               now ) {
  fd_grpc_server_params_t const * params = &server->params;

  fd_grpc_server_conn_t * conn = NULL;
  if( FD_LIKELY( !server->shutdown ) ) {
    for( ulong i=0UL; i<params->max_conn_cnt; i++ ) {
      if( !server->conn[i].active ) { conn = server->conn+i; break; }
    }
  }
  if( FD_UNLIKELY( !conn ) ) {
#   if FD_HAS_HOSTED
    if( sock>=0 ) close( sock );
#   endif
    return NULL;
  }

  conn->active     = 1U;
  conn->flags      = 0U;
  conn->sock       = sock;
  conn->ctx        = NULL;
  conn->rr_idx     = 0U;
  conn->preface_rem= (uint)sizeof(fd_h2_client_preface);
  conn->open_nanos  = now;
  conn->rx_nanos    = now;
  conn->tx_nanos    = now;
  conn->reset_nanos = now;
  conn->reset_cnt   = 0UL;
  conn->close_nanos= LONG_MAX;
  for( ulong i=0UL; i<params->max_stream_cnt; i++ ) fd_grpc_server_stream_release( conn->stream+i );

  uchar * rx_buf = conn->rbuf_rx->buf0;
  uchar * tx_buf = conn->rbuf_tx->buf0;
  fd_h2_rbuf_init( conn->rbuf_rx, rx_buf, params->conn_rx_buf_sz );
  fd_h2_rbuf_init( conn->rbuf_tx, tx_buf, params->conn_tx_buf_sz );

  if( FD_UNLIKELY( !fd_h2_conn_init_server( conn->h2 ) ) ) {
    conn->active = 0U;
    conn->sock   = -1;
#   if FD_HAS_HOSTED
    if( sock>=0 ) close( sock );
#   endif
    return NULL;
  }
  conn->h2->ctx                                   = conn;
  conn->h2->self_settings.max_concurrent_streams  = (uint)params->max_stream_cnt;
  conn->h2->self_settings.max_frame_size          = (uint)params->max_frame_sz;
  ulong max_header_list_sz = params->max_frame_sz;
  conn->h2->self_settings.max_header_list_size    = (uint)max_header_list_sz;
  conn->h2->self_settings.initial_window_size     = (uint)params->stream_rx_wnd_sz;
  fd_h2_conn_rx_wnd_set( conn->h2, (uint)params->conn_rx_wnd_sz );

  server->conn_cnt++;
  server->metrics.conn_open_cnt++;

  if( FD_UNLIKELY( server->callbacks->conn_open( server->app_ctx, conn ) ) ) {
    fd_grpc_server_conn_close( conn );
    return NULL;
  }
  if( FD_UNLIKELY( !conn->active ) ) return NULL;
  return conn;
}

/* fd_grpc_server_conn_preface consumes the 24 byte client connection
   preface (RFC 9113 Section 3.4) that must precede the first frame.
   Returns 1 once it is complete, 0 while bytes are missing, and -1 if
   the peer is not an HTTP/2 client, in which case the connection is
   already released. */

static int
fd_grpc_server_conn_preface( fd_grpc_server_conn_t * conn ) {
  while( conn->preface_rem ) {
    ulong avail = fd_h2_rbuf_used_sz( conn->rbuf_rx );
    if( !avail ) return 0;
    ulong off  = sizeof(fd_h2_client_preface) - conn->preface_rem;
    ulong take = fd_ulong_min( avail, conn->preface_rem );
    uchar tmp[ sizeof(fd_h2_client_preface) ];
    fd_h2_rbuf_pop_copy( conn->rbuf_rx, tmp, take );
    if( FD_UNLIKELY( !fd_memeq( tmp, fd_h2_client_preface+off, take ) ) ) {
      conn->server->metrics.request_error_cnt++;
      fd_grpc_server_conn_release( conn );
      return -1;
    }
    conn->preface_rem -= (uint)take;
  }
  return 1;
}

/* fd_grpc_server_conn_goaway announces that the connection will not
   accept new streams. */

static void
fd_grpc_server_conn_goaway( fd_grpc_server_conn_t * conn,
                            uint                    h2_err ) {
  if( conn->flags & FD_GRPC_SERVER_CONN_FLAG_GOAWAY ) return;
  if( FD_UNLIKELY( conn->h2->flags & FD_H2_CONN_FLAGS_DEAD ) ) return;
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( conn->rbuf_tx )<sizeof(fd_h2_goaway_t)+FD_GRPC_SERVER_TX_RESERVE ) ) return;
  uint last_stream_id = conn->h2->rx_stream_next>=2U ? conn->h2->rx_stream_next-2U : 0U;
  fd_h2_tx_goaway( conn->rbuf_tx, last_stream_id, h2_err );
  conn->flags |= FD_GRPC_SERVER_CONN_FLAG_GOAWAY;
}

/* fd_grpc_server_conn_flush drains the per-stream send queues into the
   connection's send ring, taking turns between streams. */

static void
fd_grpc_server_conn_flush( fd_grpc_server_conn_t * conn ) {
  fd_grpc_server_t * server     = conn->server;
  ulong              stream_max = server->params.max_stream_cnt;

  /* RFC 9113 Section 6.9.2 fixes the initial connection receive window
     at 65535 bytes and offers no setting to change it, so the rest of
     the window the server offers is granted by a WINDOW_UPDATE frame
     once its own SETTINGS frame is on the wire. */
  if( FD_UNLIKELY( !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_WND_INIT ) ) &&
      !( conn->h2->flags & ( FD_H2_CONN_FLAGS_SERVER_INITIAL |
                             FD_H2_CONN_FLAGS_CLIENT_INITIAL ) ) ) {
    conn->flags |= FD_GRPC_SERVER_CONN_FLAG_WND_INIT;
    if( conn->h2->rx_wnd < conn->h2->rx_wnd_max ) conn->h2->flags |= FD_H2_CONN_FLAGS_WINDOW_UPDATE;
  }

  fd_h2_tx_control( conn->h2, conn->rbuf_tx, &fd_grpc_server_h2_callbacks );
  if( FD_UNLIKELY( !conn->active ) ) return;

  for(;;) {
    int progress = 0;
    for( ulong i=0UL; i<stream_max; i++ ) {
      ulong idx = ( conn->rr_idx + i ) % stream_max;
      fd_grpc_server_stream_t * s = conn->stream+idx;
      if( ( s->state!=FD_GRPC_SERVER_STREAM_ACTIVE ) &
          ( s->state!=FD_GRPC_SERVER_STREAM_FINISH ) ) continue;
      progress |= fd_grpc_server_stream_flush( s );
    }
    conn->rr_idx = (uint)( ( conn->rr_idx+1UL ) % stream_max );
    if( !progress ) break;
  }

  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t * s = conn->stream+i;
    if( s->state!=FD_GRPC_SERVER_STREAM_ACTIVE ) continue;
    if( !( s->flags & FD_GRPC_SERVER_STREAM_FLAG_TX_BLOCKED ) ) continue;
    /* A stream still draining a large message cannot take anything,
       and one that asked for a slot waits until the pool has one. */
    if( s->large_idx>=0L ) continue;
    if( ( s->flags & FD_GRPC_SERVER_STREAM_FLAG_TX_LARGE ) &&
        !fd_grpc_server_large_free( server ) ) continue;
    if( fd_h2_rbuf_free_sz( s->tx_queue ) < s->tx_blocked_sz ) continue;
    if( server->params.stream_tx_queue_msg_max &&
        s->tx_msg_pending>=server->params.stream_tx_queue_msg_max ) continue;
    s->flags &= ~( FD_GRPC_SERVER_STREAM_FLAG_TX_BLOCKED | FD_GRPC_SERVER_STREAM_FLAG_TX_LARGE );
    s->tx_blocked_sz = 0UL;
    server->callbacks->stream_writable( server->app_ctx, s );
    if( FD_UNLIKELY( !conn->active ) ) return;
  }
}

static void
fd_grpc_server_conn_timers( fd_grpc_server_conn_t * conn,
                            long                    now ) {
  fd_grpc_server_t *              server = conn->server;
  fd_grpc_server_params_t const * params = &server->params;
  ulong                           stream_max = params->max_stream_cnt;

  ulong active_cnt = 0UL;
  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t * s = conn->stream+i;
    if( s->state==FD_GRPC_SERVER_STREAM_FREE ) continue;
    active_cnt++;
    if( ( s->state==FD_GRPC_SERVER_STREAM_ACTIVE                 ) &
        ( !!( s->flags & FD_GRPC_SERVER_STREAM_FLAG_UNARY )             ) &
        ( s->deadline <= now                                      ) ) {
      server->metrics.deadline_exceeded_cnt++;
      FD_GRPC_SERVER_FINISH( s, FD_GRPC_STATUS_DEADLINE_EXCEEDED, "deadline exceeded" );
    }
    if( ( s->state==FD_GRPC_SERVER_STREAM_ACTIVE                 ) &
        ( !( s->flags & FD_GRPC_SERVER_STREAM_FLAG_RESP_HDRS )   ) &
        ( s->resp_deadline <= now                                ) ) {
      server->metrics.deadline_exceeded_cnt++;
      FD_GRPC_SERVER_FINISH( s, FD_GRPC_STATUS_DEADLINE_EXCEEDED, "no response" );
    }
    if( ( s->large_idx>=0L                                          ) &
        ( params->large_drain_timeout_nanos>0L                      ) &
        ( now - s->large_nanos > params->large_drain_timeout_nanos  ) ) {
      server->metrics.large_drain_timeout_cnt++;
      fd_grpc_server_stream_abort( s, FD_H2_ERR_CANCEL );
      fd_grpc_server_stream_end( s, FD_GRPC_SERVER_CLOSE_ABORTED );
    }
  }

  if( FD_UNLIKELY( ( params->handshake_timeout_nanos>0L                      ) &
                   ( !!( conn->h2->flags & FD_H2_CONN_FLAGS_HANDSHAKING )    ) &
                   ( now - conn->open_nanos > params->handshake_timeout_nanos ) ) ) {
    server->metrics.handshake_timeout_cnt++;
    fd_grpc_server_conn_release( conn );
    return;
  }

  /* Output the peer never takes, which an open stream would otherwise
     keep alive forever.  A healthy subscriber drains, so its send ring
     empties even when it sends nothing back. */
  if( ( params->idle_timeout_nanos>0L                           ) &
      ( !!fd_h2_rbuf_used_sz( conn->rbuf_tx )                   ) &
      ( !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING )     ) &
      ( now - conn->tx_nanos > params->idle_timeout_nanos       ) ) {
    server->metrics.idle_timeout_cnt++;
    fd_grpc_server_conn_closing( conn );
    return;
  }

  if( ( params->idle_timeout_nanos>0L                          ) &
      ( !active_cnt                                            ) &
      ( !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING )         ) &
      ( now - conn->rx_nanos > params->idle_timeout_nanos       ) ) {
    server->metrics.idle_timeout_cnt++;
    fd_grpc_server_conn_closing( conn );
  }
}

void
fd_grpc_server_service( fd_grpc_server_t * server,
                        long               now_nanos ) {
  server->now = now_nanos;
  ulong conn_max = server->params.max_conn_cnt;
  for( ulong i=0UL; i<conn_max; i++ ) {
    fd_grpc_server_conn_t * conn = server->conn+i;
    if( !conn->active ) continue;
    fd_grpc_server_conn_timers( conn, now_nanos );
    if( !conn->active ) continue;
    fd_grpc_server_conn_flush( conn );
    if( !conn->active ) continue;
    if( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING ) {
      fd_grpc_server_conn_goaway( conn, FD_H2_SUCCESS );
      if( fd_h2_rbuf_is_empty( conn->rbuf_tx ) || conn->close_nanos<=now_nanos ) fd_grpc_server_conn_release( conn );
    }
  }
}

int
fd_grpc_server_tx_pending( fd_grpc_server_t const * server ) {
  for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
    fd_grpc_server_conn_t const * conn = server->conn+i;
    if( !( conn->active && conn->sock>=0 ) ) continue;
    if( fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) return 1;
  }
  return 0;
}

void
fd_grpc_server_shutdown( fd_grpc_server_t * server ) {
  /* The listening socket stays open, since a caller may run under a
     policy that forbids closing it.  Polling stops offering it, and
     fd_grpc_server_conn_init closes anything already accepted. */
  server->shutdown = 1;
  ulong conn_max   = server->params.max_conn_cnt;
  ulong stream_max = server->params.max_stream_cnt;
  for( ulong i=0UL; i<conn_max; i++ ) {
    fd_grpc_server_conn_t * conn = server->conn+i;
    if( !conn->active ) continue;
    fd_grpc_server_conn_goaway( conn, FD_H2_SUCCESS );
    for( ulong j=0UL; j<stream_max; j++ ) {
      fd_grpc_server_stream_t * s = conn->stream+j;
      if( s->state==FD_GRPC_SERVER_STREAM_FREE ) continue;
      /* Queued messages are dropped: a shutdown must not wait on a
         client that is not reading. */
      fd_grpc_server_large_release( s );
      /* The counters describe what the ring holds, so they go with it:
         a message header is only ever read back under tx_msg_pending. */
      fd_h2_rbuf_init( s->tx_queue, s->tx_queue->buf0, s->tx_queue->bufsz );
      s->tx_msg_pending = 0UL;
      s->tx_head_rem    = 0UL;
      s->tx_blocked_sz  = 0UL;
      if( s->state==FD_GRPC_SERVER_STREAM_ACTIVE ) {
        FD_GRPC_SERVER_FINISH( s, FD_GRPC_STATUS_UNAVAILABLE, "server is shutting down" );
      }
    }
    fd_grpc_server_conn_closing( conn );
  }
  fd_grpc_server_service( server, server->now );
}

int
fd_grpc_server_is_idle( fd_grpc_server_t const * server ) {
  return !server->conn_cnt;
}

/* Direct transport ***************************************************/

fd_grpc_server_conn_t *
fd_grpc_server_conn_open_direct( fd_grpc_server_t * server,
                                 long               now_nanos ) {
  server->now = now_nanos;
  return fd_grpc_server_conn_init( server, -1, now_nanos );
}

ulong
fd_grpc_server_conn_push_rx( fd_grpc_server_conn_t * conn,
                             void const *            data,
                             ulong                   sz,
                             long                    now_nanos ) {
  fd_grpc_server_t * server = conn->server;
  server->now = now_nanos;
  if( FD_UNLIKELY( !conn->active ) ) return 0UL;
  ulong take = fd_ulong_min( sz, fd_h2_rbuf_free_sz( conn->rbuf_rx ) );
  if( take ) {
    fd_h2_rbuf_push( conn->rbuf_rx, data, take );
    conn->rx_nanos = now_nanos;
  }
  if( FD_UNLIKELY( fd_grpc_server_conn_preface( conn )<=0 ) ) return take;
  fd_h2_rx( conn->h2, conn->rbuf_rx, conn->rbuf_tx,
            server->frame_scratch, server->params.max_frame_sz,
            &fd_grpc_server_h2_callbacks );
  if( FD_LIKELY( conn->active ) ) fd_grpc_server_conn_flush( conn );
  return take;
}

ulong
fd_grpc_server_conn_pop_tx( fd_grpc_server_conn_t * conn,
                            void *                  out,
                            ulong                   out_sz ) {
  if( FD_UNLIKELY( !conn->active ) ) return 0UL;
  ulong take = fd_ulong_min( out_sz, fd_h2_rbuf_used_sz( conn->rbuf_tx ) );
  if( take ) {
    fd_h2_rbuf_pop_copy( conn->rbuf_tx, out, take );
    conn->tx_nanos = conn->server->now;
  }
  return take;
}

/* Sockets ************************************************************/

#if FD_HAS_HOSTED

/* The layout reserves 16 bytes per descriptor slot */
FD_STATIC_ASSERT( sizeof(struct pollfd)<=16UL, layout );

int
fd_grpc_server_listen( fd_grpc_server_t * server,
                       uint               ip4_addr,
                       ushort             port ) {
  if( FD_UNLIKELY( server->listen_fd>=0 ) ) {
    FD_LOG_WARNING(( "fd_grpc_server is already listening" ));
    return -1;
  }
  int sock = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP );
  if( FD_UNLIKELY( sock<0 ) ) {
    FD_LOG_WARNING(( "socket(AF_INET,SOCK_STREAM,IPPROTO_TCP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }
  int one = 1;
  if( FD_UNLIKELY( 0!=setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int) ) ) ) {
    FD_LOG_WARNING(( "setsockopt(SO_REUSEADDR) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( sock );
    return -1;
  }
  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_addr        = { .s_addr = ip4_addr },
    .sin_port        = fd_ushort_bswap( port )
  };
  if( FD_UNLIKELY( 0!=bind( sock, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) ) ) ) {
    FD_LOG_WARNING(( "bind(:%hu) failed (%i-%s)", port, errno, fd_io_strerror( errno ) ));
    close( sock );
    return -1;
  }
  if( FD_UNLIKELY( 0!=listen( sock, (int)server->params.max_conn_cnt ) ) ) {
    FD_LOG_WARNING(( "listen() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( sock );
    return -1;
  }
  server->listen_fd = sock;
  return sock;
}

ulong
fd_grpc_server_fd_cnt( fd_grpc_server_t const * server ) {
  ulong cnt = server->listen_fd>=0 ? 1UL : 0UL;
  for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
    if( server->conn[i].active && server->conn[i].sock>=0 ) cnt++;
  }
  return cnt;
}

int
fd_grpc_server_fd( fd_grpc_server_t const * server,
                   ulong                    idx ) {
  ulong cur = 0UL;
  if( server->listen_fd>=0 ) {
    if( !idx ) return server->listen_fd;
    cur = 1UL;
  }
  for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
    fd_grpc_server_conn_t const * conn = server->conn+i;
    if( !( conn->active && conn->sock>=0 ) ) continue;
    if( cur==idx ) return conn->sock;
    cur++;
  }
  return -1;
}

static void
fd_grpc_server_accept( fd_grpc_server_t * server,
                       long               now ) {
  for(;;) {
    if( FD_UNLIKELY( server->conn_cnt>=server->params.max_conn_cnt ) ) return;
    int sock = accept4( server->listen_fd, NULL, NULL, SOCK_NONBLOCK );
    if( sock<0 ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EWOULDBLOCK ) ) return;
      if( errno==ECONNABORTED || errno==EINTR ) continue;
      /* A listen socket that keeps failing (no descriptors, for one)
         fails on every poll, so the line is logged on the powers of
         two and counted exactly. */
      server->metrics.accept_error_cnt++;
      ulong n = server->metrics.accept_error_cnt;
      if( FD_UNLIKELY( !( n & ( n-1UL ) ) ) )
        FD_LOG_WARNING(( "accept4() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return;
    }
    /* A peer that vanishes is detected by the kernel: keepalive probes
       while the connection is idle, and the user timeout while data is
       in flight, both within about a minute. */
    int one = 1, idle = 20, intvl = 20, cnt = 3, user_timeout_ms = 60000;
    setsockopt( sock, IPPROTO_TCP,  TCP_NODELAY,      &one,             sizeof(int) );
    setsockopt( sock, SOL_SOCKET,   SO_KEEPALIVE,     &one,             sizeof(int) );
    setsockopt( sock, IPPROTO_TCP,  TCP_KEEPIDLE,     &idle,            sizeof(int) );
    setsockopt( sock, IPPROTO_TCP,  TCP_KEEPINTVL,    &intvl,           sizeof(int) );
    setsockopt( sock, IPPROTO_TCP,  TCP_KEEPCNT,      &cnt,             sizeof(int) );
    setsockopt( sock, IPPROTO_TCP,  TCP_USER_TIMEOUT, &user_timeout_ms, sizeof(int) );
    if( FD_UNLIKELY( !fd_grpc_server_conn_init( server, sock, now ) ) ) return;
  }
}

static void
fd_grpc_server_conn_io( fd_grpc_server_conn_t * conn,
                        long                    now ) {
  fd_grpc_server_t * server = conn->server;

  if( fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) {
    int err = fd_h2_rbuf_sendmsg( conn->rbuf_tx, conn->sock, MSG_NOSIGNAL|MSG_DONTWAIT );
    if( FD_UNLIKELY( err && err!=EAGAIN && err!=EWOULDBLOCK && err!=EINTR ) ) {
      fd_grpc_server_conn_release( conn );
      return;
    }
    if( !err ) conn->tx_nanos = now;
  }

  ulong rx_hi0 = conn->rbuf_rx->hi_off;
  int err = fd_h2_rbuf_recvmsg( conn->rbuf_rx, conn->sock, MSG_NOSIGNAL|MSG_DONTWAIT );
  if( FD_UNLIKELY( err && err!=EAGAIN && err!=EWOULDBLOCK && err!=EINTR ) ) {
    fd_grpc_server_conn_release( conn );
    return;
  }
  if( conn->rbuf_rx->hi_off!=rx_hi0 ) conn->rx_nanos = now;

  if( FD_UNLIKELY( fd_grpc_server_conn_preface( conn )<=0 ) ) return;

  fd_h2_rx( conn->h2, conn->rbuf_rx, conn->rbuf_tx,
            server->frame_scratch, server->params.max_frame_sz,
            &fd_grpc_server_h2_callbacks );
  if( FD_UNLIKELY( !conn->active ) ) return;
  fd_grpc_server_conn_flush( conn );
  if( FD_UNLIKELY( !conn->active ) ) return;

  if( fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) {
    ulong tx_lo0 = conn->rbuf_tx->lo_off;
    err = fd_h2_rbuf_sendmsg( conn->rbuf_tx, conn->sock, MSG_NOSIGNAL|MSG_DONTWAIT );
    if( FD_UNLIKELY( err && err!=EAGAIN && err!=EWOULDBLOCK && err!=EINTR ) ) {
      fd_grpc_server_conn_release( conn );
      return;
    }
    if( conn->rbuf_tx->lo_off!=tx_lo0 ) conn->tx_nanos = now;
  }
}

int
fd_grpc_server_poll( fd_grpc_server_t * server,
                     int                timeout_millis ) {
  struct pollfd * pfd     = server->pollfd_mem;
  ulong           pfd_cnt = 0UL;

  /* Move anything the app queued since the last call into the send
     rings, so a connection with pending output asks for POLLOUT. */
  fd_grpc_server_service( server, fd_log_wallclock() );

  /* A full pool stops accepting, which leaves new clients in the
     kernel's backlog until a slot frees. */
  if( server->listen_fd>=0 && !server->shutdown && server->conn_cnt<server->params.max_conn_cnt ) {
    pfd[ pfd_cnt++ ] = (struct pollfd){ .fd = server->listen_fd, .events = POLLIN };
  }
  ulong conn_idx0 = pfd_cnt;
  for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
    fd_grpc_server_conn_t * conn = server->conn+i;
    if( !( conn->active && conn->sock>=0 ) ) continue;
    /* A full receive ring means recvmsg would not be issued, so asking
       for POLLIN would report ready forever with nothing to drain. */
    short events = fd_h2_rbuf_free_sz( conn->rbuf_rx ) ? (short)POLLIN : (short)0;
    if( fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) events = (short)( events|POLLOUT );
    pfd[ pfd_cnt++ ] = (struct pollfd){ .fd = conn->sock, .events = events };
  }

  int ready = poll( pfd, (nfds_t)pfd_cnt, timeout_millis );
  if( FD_UNLIKELY( ready<0 ) ) {
    if( FD_UNLIKELY( errno!=EINTR ) ) {
      server->metrics.poll_error_cnt++;
      ulong n = server->metrics.poll_error_cnt;
      if( FD_UNLIKELY( !( n & ( n-1UL ) ) ) )
        FD_LOG_WARNING(( "poll() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    ready = 0;
  }

  long now = fd_log_wallclock();
  server->now = now;
  if( conn_idx0 && ( pfd[0].revents & (POLLIN|POLLERR|POLLHUP) ) ) {
    fd_grpc_server_accept( server, now );
  }

  ulong pfd_idx = conn_idx0;
  for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
    fd_grpc_server_conn_t * conn = server->conn+i;
    if( !( conn->active && conn->sock>=0 ) ) continue;
    /* Entries are in connection order, so the match is at or after the
       cursor; a connection accepted since the set was built has none. */
    ulong j = pfd_idx;
    while( j<pfd_cnt && pfd[ j ].fd!=conn->sock ) j++;
    if( FD_UNLIKELY( j>=pfd_cnt ) ) continue;
    short revents = pfd[ j ].revents;
    pfd_idx = j+1UL;
    if( !revents ) continue;
    fd_grpc_server_conn_io( conn, now );
  }

  fd_grpc_server_service( server, now );
  return ready;
}

#else /* FD_HAS_HOSTED */

int
fd_grpc_server_listen( fd_grpc_server_t * server,
                       uint               ip4_addr,
                       ushort             port ) {
  (void)server; (void)ip4_addr; (void)port;
  FD_LOG_WARNING(( "fd_grpc_server_listen requires a hosted target" ));
  return -1;
}

ulong
fd_grpc_server_fd_cnt( fd_grpc_server_t const * server ) {
  (void)server;
  return 0UL;
}

int
fd_grpc_server_fd( fd_grpc_server_t const * server,
                   ulong                    idx ) {
  (void)server; (void)idx;
  return -1;
}

int
fd_grpc_server_poll( fd_grpc_server_t * server,
                     int                timeout_millis ) {
  (void)timeout_millis;
  fd_grpc_server_service( server, fd_log_wallclock() );
  return 0;
}

#endif /* FD_HAS_HOSTED */
