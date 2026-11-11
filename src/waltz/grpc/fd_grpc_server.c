#define _GNU_SOURCE /* accept4 */

#include "fd_grpc_server_private.h"
#include "../h2/fd_hpack_wr.h"
#include "../../util/fd_util.h"
#include <limits.h>

#if FD_HAS_HOSTED
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
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

/* The least a connection's own send ring holds: a response header
   block with its frame header and a RST_STREAM, the reserve, and the
   same again so a DATA frame can follow a header block in one pass. */

#define FD_GRPC_SERVER_TX_BUF_MIN (4096UL)
FD_STATIC_ASSERT( FD_GRPC_SERVER_TX_BUF_MIN>=2UL*( FD_GRPC_SERVER_HDR_BUF_MAX+9UL+sizeof(fd_h2_rst_stream_t)+FD_GRPC_SERVER_TX_RESERVE ), tx_buf_min );

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

/* A treap to order streams that have pending output.
   The stream furthest behind is always at the front. */

#define TREAP_NAME      stream_treap
#define TREAP_T         fd_grpc_server_stream_t
#define TREAP_QUERY_T   void *
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; }))
#define TREAP_IDX_T     uint
#define TREAP_PARENT    treap_parent
#define TREAP_LEFT      treap_left
#define TREAP_RIGHT     treap_right
#define TREAP_PRIO      treap_prio
#define TREAP_NEXT      treap_next
#define TREAP_PREV      treap_prev
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_LT(e0,e1) ((e0)->ref_key < (e1)->ref_key)
#include "../../util/tmpl/fd_treap.c"

/* The streams holding reference chunks from the pool, by how many
   they hold; the pool reclaims from the one holding the most. */

#define TREAP_NAME      pool_treap
#define TREAP_T         fd_grpc_server_stream_t
#define TREAP_QUERY_T   void *
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; }))
#define TREAP_IDX_T     uint
#define TREAP_PARENT    pool_parent
#define TREAP_LEFT      pool_left
#define TREAP_RIGHT     pool_right
#define TREAP_PRIO      pool_prio
#define TREAP_NEXT      pool_next
#define TREAP_PREV      pool_prev
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_LT(e0,e1) ((e0)->ref_chunk_cnt < (e1)->ref_chunk_cnt)
#include "../../util/tmpl/fd_treap.c"

#define MAP_NAME              addr_map
#define MAP_T                 fd_grpc_server_addr_t
#define MAP_KEY_T             uint
#define MAP_KEY_NULL          0U
#define MAP_KEY_INVAL(k)      (!(k))
#define MAP_KEY_EQUAL(k0,k1)  ((k0)==(k1))
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(key,seed) ((uint)fd_ulong_hash( (ulong)(key) ^ (seed) ))
#define MAP_MEMOIZE           0
#include "../../util/tmpl/fd_map_dynamic.c"

/* The address table has at least two slots per connection, so it is
   never more than half full. */

static inline int
fd_grpc_server_addr_lg( ulong conn_cnt ) {
  return fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*conn_cnt+2UL ) );
}

static void
fd_grpc_server_conn_release( fd_grpc_server_conn_t * conn );

#if FD_HAS_HOSTED
static void
fd_grpc_server_conn_tx_try( fd_grpc_server_conn_t * conn,
                            long                    now );
static void
fd_grpc_server_conn_arm( fd_grpc_server_conn_t * conn );
static void
fd_grpc_server_refuse( int sock );

static void
fd_grpc_server_listen_arm( fd_grpc_server_t * server,
                           int                armed );
#endif

/* Parameters *********************************************************/

fd_grpc_server_params_t *
fd_grpc_server_params_default( fd_grpc_server_params_t * params ) {
  *params = (fd_grpc_server_params_t) {
    .max_conn_cnt             = 16UL,
    .max_stream_cnt           = 8UL,
    .max_request_msg_sz       = 16UL<<10,
    .request_buf_cnt          = 128UL,
    .tx_ring_sz               = 1UL<<20,
    .stream_tx_ref_max        = 1024UL,
    .tx_ref_pool              = 128UL<<10,
    .max_msg_sz               = 64UL<<10,
    .conn_rx_buf_sz           = 32UL<<10,
    .conn_tx_buf_sz           = 64UL<<10,
    .tx_burst_cnt             = 0UL,
    .tx_burst_sz              = 0UL,
    .max_frame_sz             = 16384UL,
    .conn_rx_wnd_sz           = 1UL<<20,
    .stream_rx_wnd_sz         = 256UL<<10,
    .idle_timeout_nanos       = 300L*1000L*1000L*1000L,
    .handshake_timeout_nanos  = 10L*1000L*1000L*1000L,
    .response_timeout_nanos   = 0L,
    .send_interval_nanos      = 0L,
    .compression              = FD_GRPC_SERVER_COMPRESSION_ZSTD,
    .compression_min_sz       = 1024UL,
    .compression_level        = 1,
    .seed                     = 0UL,
    .web                      = 0,
    .web_index                = NULL,
        .web_index_sz             = 0UL,
    .epoll_fd                 = -1
  };
  return params;
}

int
fd_grpc_server_compression_level_max( void ) {
  return ZSTD_maxCLevel();
}

/* fd_grpc_server_tx_buf_max is the largest send ring a connection can
   have: a burst buffer if there are any, else its own ring. */

static inline ulong
fd_grpc_server_tx_buf_max( fd_grpc_server_params_t const * p ) {
  return p->tx_burst_cnt ? fd_ulong_max( p->conn_tx_buf_sz, p->tx_burst_sz ) : p->conn_tx_buf_sz;
}

/* fd_grpc_server_ref_chunk_cnt is how many reference chunks the server
   has: one per stream and the pool's. */

static inline ulong
fd_grpc_server_ref_chunk_cnt( fd_grpc_server_params_t const * p ) {
  return p->max_conn_cnt*p->max_stream_cnt + ( p->tx_ref_pool+FD_GRPC_SERVER_REF_CHUNK-1UL )/FD_GRPC_SERVER_REF_CHUNK;
}

static int
fd_grpc_server_params_valid( fd_grpc_server_params_t const * p ) {
# define CHECK(c) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "invalid fd_grpc_server param: " #c )); return 0; } } while(0)
  CHECK( p->max_conn_cnt      >=1UL && p->max_conn_cnt      < (1UL<<24) );
  CHECK( p->max_stream_cnt    >=1UL && p->max_stream_cnt    <= 256UL );
  CHECK( p->max_request_msg_sz>=1UL && p->max_request_msg_sz < (1UL<<31) );
  CHECK( p->request_buf_cnt   >=1UL && p->request_buf_cnt    < (1UL<<24) );
  CHECK( p->max_msg_sz        >=1UL && p->max_msg_sz<(1UL<<31) );
  CHECK( p->tx_ring_sz        >=3UL*( p->max_msg_sz+sizeof(fd_grpc_hdr_t) ) && p->tx_ring_sz<=(1UL<<40) );
  CHECK( p->stream_tx_ref_max >=2UL && p->stream_tx_ref_max<=(1UL<<24) );
  CHECK( p->tx_ref_pool       <=(1UL<<31) );
  CHECK( fd_grpc_server_ref_chunk_cnt( p )<(ulong)UINT_MAX ); /* chunks are linked by uint index */
  CHECK( p->max_frame_sz      >=16384UL && p->max_frame_sz  < (1UL<<24) );
  CHECK( p->conn_rx_buf_sz    >=p->max_frame_sz+9UL && p->conn_rx_buf_sz<=(1UL<<30) );
  /* The send ring holds a response header block or a control frame
     with the reserve to spare; DATA frames are cut to the room left. */
  CHECK( p->conn_tx_buf_sz    >=FD_GRPC_SERVER_TX_BUF_MIN && p->conn_tx_buf_sz<=(1UL<<30) );
  CHECK( p->tx_burst_cnt      < (1UL<<24) );
  CHECK( !p->tx_burst_cnt || ( p->tx_burst_sz>=p->conn_tx_buf_sz && p->tx_burst_sz<=(1UL<<30) ) );
  CHECK( p->conn_rx_wnd_sz    >=65535UL && p->conn_rx_wnd_sz  <(1UL<<31) );
  CHECK( p->stream_rx_wnd_sz  >=65535UL && p->stream_rx_wnd_sz<(1UL<<31) );
  CHECK( p->compression==FD_GRPC_SERVER_COMPRESSION_NONE ||
         p->compression==FD_GRPC_SERVER_COMPRESSION_ZSTD );
  CHECK( p->compression_level>=1 && p->compression_level<=ZSTD_maxCLevel() );
  CHECK( p->idle_timeout_nanos      >=0L );
  CHECK( p->handshake_timeout_nanos >=0L );
  CHECK( p->response_timeout_nanos  >=0L );
  CHECK( p->send_interval_nanos     >=0L );
  CHECK( !!p->web_index || !p->web_index_sz );
  CHECK( !p->web || p->web_index_sz<=fd_grpc_server_tx_buf_max( p )-FD_GRPC_WEB_HEAD_MAX );
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
  return ZSTD_compressBound( p->max_msg_sz );
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

ulong
fd_grpc_server_footprint( fd_grpc_server_params_t const * params ) {
  if( FD_UNLIKELY( !fd_grpc_server_params_valid( params ) ) ) return 0UL;
  ulong chunk_cnt  = fd_grpc_server_ref_chunk_cnt( params );
  ulong conn_cnt   = params->max_conn_cnt;
  ulong stream_cnt = params->max_conn_cnt * params->max_stream_cnt;
  ulong zmem       = fd_grpc_server_zarena_sz( params );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_t),        sizeof(fd_grpc_server_t)                      );
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_conn_t),   conn_cnt  *sizeof(fd_grpc_server_conn_t)       );
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_stream_t), stream_cnt*sizeof(fd_grpc_server_stream_t)     );
  l = FD_LAYOUT_APPEND( l, 128UL,                            conn_cnt  *params->conn_rx_buf_sz             );
  l = FD_LAYOUT_APPEND( l, 128UL,                            conn_cnt  *params->conn_tx_buf_sz             );
  l = FD_LAYOUT_APPEND( l, 128UL,                            params->tx_burst_cnt*params->tx_burst_sz      );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                    params->tx_burst_cnt*sizeof(uint)             );
  l = FD_LAYOUT_APPEND( l, 128UL,                            params->request_buf_cnt*params->max_request_msg_sz );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                    params->request_buf_cnt*sizeof(uint)          );
  l = FD_LAYOUT_APPEND( l, alignof(fd_grpc_server_tx_ref_t), chunk_cnt*FD_GRPC_SERVER_REF_CHUNK*sizeof(fd_grpc_server_tx_ref_t) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                    chunk_cnt*sizeof(uint)                        );
  l = FD_LAYOUT_APPEND( l, 128UL,                            params->tx_ring_sz                            );
  l = FD_LAYOUT_APPEND( l, stream_treap_align(),             stream_treap_footprint( stream_cnt )          );
  l = FD_LAYOUT_APPEND( l, pool_treap_align(),               pool_treap_footprint( stream_cnt )            );
  l = FD_LAYOUT_APPEND( l, addr_map_align(),                 addr_map_footprint( fd_grpc_server_addr_lg( conn_cnt ) ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_h2_hdr_matcher_t),     sizeof(fd_h2_hdr_matcher_t)                   );
  l = FD_LAYOUT_APPEND( l, 128UL,                            params->max_frame_sz                          );
  l = FD_LAYOUT_APPEND( l, 128UL,                            fd_grpc_server_hpack_scratch_sz( params )     );
  l = FD_LAYOUT_APPEND( l, 128UL,                            fd_grpc_server_compress_out_sz  ( params )    );
  l = FD_LAYOUT_APPEND( l, 128UL,                            fd_grpc_server_decompress_out_sz( params )    );
  l = FD_LAYOUT_APPEND( l, 128UL,                            zmem                                          );
  l = FD_LAYOUT_APPEND( l, 16UL,                             16UL*FD_GRPC_SERVER_EPOLL_EVENT_MAX           );
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

  ulong bound = ZSTD_compressBound( server->params.max_msg_sz );
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
  ulong chunk_cnt    = fd_grpc_server_ref_chunk_cnt( params );
  ulong hpack_sz     = fd_grpc_server_hpack_scratch_sz( params );
  ulong compress_sz  = fd_grpc_server_compress_out_sz  ( params );
  ulong decompress_sz= fd_grpc_server_decompress_out_sz( params );
  ulong zmem         = fd_grpc_server_zarena_sz( params );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_grpc_server_t *        server     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_t),        sizeof(fd_grpc_server_t)                  );
  fd_grpc_server_conn_t *   conn       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_conn_t),   conn_cnt  *sizeof(fd_grpc_server_conn_t)   );
  fd_grpc_server_stream_t * stream     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_stream_t), stream_cnt*sizeof(fd_grpc_server_stream_t) );
  uchar *                   rx_buf     = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            conn_cnt  *params->conn_rx_buf_sz         );
  uchar *                   tx_buf     = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            conn_cnt  *params->conn_tx_buf_sz         );
  uchar *                   burst_buf  = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            params->tx_burst_cnt*params->tx_burst_sz  );
  uint *                    burst_free = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    params->tx_burst_cnt*sizeof(uint)         );
  uchar *                   req_buf    = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            params->request_buf_cnt*params->max_request_msg_sz );
  uint *                    req_free   = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    params->request_buf_cnt*sizeof(uint)      );
  fd_grpc_server_tx_ref_t * chunks     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_grpc_server_tx_ref_t), chunk_cnt*FD_GRPC_SERVER_REF_CHUNK*sizeof(fd_grpc_server_tx_ref_t) );
  uint *                    chunk_next = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    chunk_cnt*sizeof(uint)                    );
  uchar *                   tx_ring    = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            params->tx_ring_sz                        );
  void *                    treap_mem  = FD_SCRATCH_ALLOC_APPEND( l, stream_treap_align(),             stream_treap_footprint( stream_cnt )      );
  void *                    ptreap_mem = FD_SCRATCH_ALLOC_APPEND( l, pool_treap_align(),               pool_treap_footprint( stream_cnt )        );
  void *                    addr_mem   = FD_SCRATCH_ALLOC_APPEND( l, addr_map_align(),                 addr_map_footprint( fd_grpc_server_addr_lg( conn_cnt ) ) );
  void *                    matcher    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_h2_hdr_matcher_t),     sizeof(fd_h2_hdr_matcher_t)               );
  uchar *                   frame_scr  = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            params->max_frame_sz                      );
  uchar *                   hpack_scr  = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            hpack_sz                                  );
  uchar *                   comp_out   = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            compress_sz                               );
  uchar *                   decomp_out = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            decompress_sz                             );
  uchar *                   zarena     = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                            zmem                                      );
  void *                    ev_mem     = FD_SCRATCH_ALLOC_APPEND( l, 16UL,                             16UL*FD_GRPC_SERVER_EPOLL_EVENT_MAX   );
  FD_SCRATCH_ALLOC_FINI( l, FD_GRPC_SERVER_ALIGN );

  fd_memset( server, 0, sizeof(fd_grpc_server_t) );
  fd_memset( conn,   0, conn_cnt  *sizeof(fd_grpc_server_conn_t)   );
  fd_memset( stream, 0, stream_cnt*sizeof(fd_grpc_server_stream_t) );

  server->params          = *params;
  server->callbacks       = callbacks;
  server->app_ctx         = app_ctx;
  server->conn            = conn;
  server->stream          = stream;
  server->matcher         = matcher;
  server->frame_scratch   = frame_scr;
  server->hpack_scratch   = hpack_scr;
  server->compress_out    = comp_out;
  server->compress_out_sz = compress_sz;
  server->decompress_out  = decomp_out;
  server->zarena          = zarena;
  server->zarena_sz       = zmem;
  server->epoll_events    = ev_mem;
  server->addr_map        = addr_map_join( addr_map_new( addr_mem, fd_grpc_server_addr_lg( conn_cnt ), params->seed ) );
  server->epoll_fd        = params->epoll_fd;
  server->epoll_owned     = 0;
  server->free_head       = 0U;
  server->dirty_head      = UINT_MAX;
  server->dirty_tail      = UINT_MAX;
    server->sweep_cursor    = 0UL;
  server->defer_tick      = LONG_MIN;
  for( ulong l=0UL; l<FD_GRPC_SERVER_DEFER_LAPS;  l++ )
  for( ulong i=0UL; i<FD_GRPC_SERVER_DEFER_WHEEL; i++ ) server->defer_bucket[ l ][ i ] = UINT_MAX;
  server->tx_pending_cnt  = 0UL;
  server->listen_fd       = -1;
  server->listen_rearm_nanos = 0L;
  server->tx_ring         = tx_ring;
  server->tx_ring_sz      = params->tx_ring_sz;

  server->stream_treap = stream_treap_join( stream_treap_new( treap_mem, stream_cnt ) );
  if( FD_UNLIKELY( !server->stream_treap ) ) {
    FD_LOG_WARNING(( "failed to create the stream treap" ));
    return NULL;
  }
  stream_treap_seed( stream, stream_cnt, params->seed );
  server->pool_treap = pool_treap_join( pool_treap_new( ptreap_mem, stream_cnt ) );
  if( FD_UNLIKELY( !server->pool_treap ) ) {
    FD_LOG_WARNING(( "failed to create the pool treap" ));
    return NULL;
  }
  pool_treap_seed( stream, stream_cnt, params->seed^0x9e3779b97f4a7c15UL );

  /* Chunk k starts as stream k's own; the rest form the free list.
     Chunks circulate from then on, only the count per stream is
     fixed. */
  server->ref_chunks         = chunks;
  server->ref_chunk_next     = chunk_next;
  server->ref_chunk_cnt      = chunk_cnt;
  server->ref_chunk_free     = stream_cnt<chunk_cnt ? (uint)stream_cnt : UINT_MAX;
  server->ref_chunk_free_cnt = chunk_cnt-stream_cnt;
  for( ulong k=0UL; k<chunk_cnt; k++ ) chunk_next[ k ] = ( k>=stream_cnt && k+1UL<chunk_cnt ) ? (uint)( k+1UL ) : UINT_MAX;

  server->req_buf      = req_buf;
  server->req_free     = req_free;
  server->req_free_cnt = params->request_buf_cnt;
  server->req_head     = UINT_MAX;
  server->req_tail     = UINT_MAX;
  for( ulong k=0UL; k<params->request_buf_cnt; k++ ) req_free[ k ] = (uint)k;

  server->tx_burst          = burst_buf;
  server->tx_burst_free     = burst_free;
  server->tx_burst_free_cnt = params->tx_burst_cnt;
  for( ulong k=0UL; k<params->tx_burst_cnt; k++ ) burst_free[ k ] = (uint)k;

  for( ulong i=0UL; i<conn_cnt; i++ ) {
    fd_grpc_server_conn_t * c = conn+i;
    c->server     = server;
    c->stream     = stream   + i*params->max_stream_cnt;
    c->sock       = -1;
    c->idx        = (uint)i;
    c->free_next  = i+1UL<conn_cnt ? (uint)( i+1UL ) : UINT_MAX;
    c->dirty_next = UINT_MAX;
    c->defer_next = UINT_MAX;
    c->tx_own     = tx_buf + i*params->conn_tx_buf_sz;
    c->tx_burst   = UINT_MAX;
    fd_h2_rbuf_init( c->rbuf_rx, rx_buf + i*params->conn_rx_buf_sz, params->conn_rx_buf_sz );
    fd_h2_rbuf_init( c->rbuf_tx, c->tx_own, params->conn_tx_buf_sz );
    for( ulong j=0UL; j<params->max_stream_cnt; j++ ) {
      fd_grpc_server_stream_t * s = c->stream+j;
      ulong k = i*params->max_stream_cnt + j;
      s->conn          = c;
      s->ref_head      = (uint)k;
      s->ref_tail      = (uint)k;
      s->ref_chunk_cnt = 1UL;
      s->msg_buf       = NULL;
      s->msg_slot      = UINT_MAX;
      s->req_prev      = UINT_MAX;
      s->req_next      = UINT_MAX;
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
  /* Each live connection is reported closed, stream by stream, and its
     socket closed with it. */
  for( ulong i=0UL; i<server->params.max_conn_cnt; i++ ) {
    if( server->conn[i].active ) fd_grpc_server_conn_release( server->conn+i );
  }
# if FD_HAS_HOSTED
  if( server->listen_fd>=0 ) close( server->listen_fd );
  if( server->epoll_owned && server->epoll_fd>=0 ) close( server->epoll_fd );
# endif
  server->listen_fd = -1;
  server->epoll_fd  = -1;
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

ulong
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

ulong
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

/* fd_grpc_server_conn_mark queues a connection for the next service
   pass: it has bytes to frame or to send, or a state change to act on.
   A connection is on the list once; the flag outlives a release so
   that a recycled slot cannot be linked a second time. */

static void
fd_grpc_server_conn_mark( fd_grpc_server_conn_t * conn ) {
  if( conn->dirty ) return;
  fd_grpc_server_t * server = conn->server;
  conn->dirty      = 1;
  conn->dirty_next = UINT_MAX;
  if( server->dirty_tail==UINT_MAX ) server->dirty_head = conn->idx;
  else server->conn[ server->dirty_tail ].dirty_next = conn->idx;
  server->dirty_tail = conn->idx;
}

/* Streams ************************************************************/

static void
fd_grpc_server_stream_too_slow( fd_grpc_server_stream_t * stream );

static void
fd_grpc_server_rx_reject( fd_grpc_server_stream_t * stream,
                          uint                      grpc_status,
                          char const *              msg,
                          ulong                     msg_len );

/* Reference chunks ***************************************************/

/* fd_grpc_server_ref_chunk_release_head returns the stream's head
   chunk to the pool and moves the head to the next one.  The stream
   must hold more than one chunk and be out of the pool treap. */

static void
fd_grpc_server_ref_chunk_release_head( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_t * server = stream->conn->server;
  uint c = stream->ref_head;
  stream->ref_head = server->ref_chunk_next[ c ];
  stream->ref_chunk_cnt--;
  server->ref_chunk_next[ c ] = server->ref_chunk_free;
  server->ref_chunk_free      = c;
  server->ref_chunk_free_cnt++;
}

/* fd_grpc_server_ref_chunks_release returns every chunk of the stream
   but one, keeping the pool treap in step. */

static void
fd_grpc_server_ref_chunks_release( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_t * server = stream->conn->server;
  if( stream->ref_chunk_cnt<=1UL ) return;
  pool_treap_ele_remove( server->pool_treap, stream, server->stream );
  while( stream->ref_chunk_cnt>1UL ) fd_grpc_server_ref_chunk_release_head( stream );
  stream->ref_tail = stream->ref_head;
}

/* fd_grpc_server_ref_chunk_acquire appends a chunk from the pool to
   the stream's chain.  When the pool is empty, the stream holding the
   most pool chunks is closed for being too slow and gives them back.
   Returns 0 if that stream was this one, or if there is no pool to
   draw on. */

static int
fd_grpc_server_ref_chunk_acquire( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_t * server = stream->conn->server;
  while( FD_UNLIKELY( server->ref_chunk_free==UINT_MAX ) ) {
    pool_treap_rev_iter_t it = pool_treap_rev_iter_init( server->pool_treap, server->stream );
    if( FD_UNLIKELY( pool_treap_rev_iter_done( it ) ) ) {
      server->metrics.tx_too_slow_refs_cnt++;
      fd_grpc_server_stream_too_slow( stream );
      return 0;
    }
    fd_grpc_server_stream_t * victim = pool_treap_rev_iter_ele( it, server->stream );
    server->metrics.tx_too_slow_pool_cnt++;
    fd_grpc_server_stream_too_slow( victim ); /* drops its references, which returns its chunks */
    if( FD_UNLIKELY( victim==stream ) ) return 0;
  }
  uint c = server->ref_chunk_free;
  server->ref_chunk_free = server->ref_chunk_next[ c ];
  server->ref_chunk_free_cnt--;
  server->ref_chunk_next[ c ]                = UINT_MAX;
  server->ref_chunk_next[ stream->ref_tail ] = c;
  stream->ref_tail = c;
  /* The treap is keyed on the count, which is about to change. */
  if( stream->ref_chunk_cnt>1UL ) pool_treap_ele_remove( server->pool_treap, stream, server->stream );
  stream->ref_chunk_cnt++;
  pool_treap_ele_insert( server->pool_treap, stream, server->stream );
  return 1;
}

/* fd_grpc_server_refs_drop forgets a stream's pending output.  The ring
   bytes stay where they are until staging reaches them; only the
   stream's claim on them goes, with the pool chunks it held. */

static void
fd_grpc_server_refs_drop( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_t * server = stream->conn->server;
  if( stream->ref_cnt ) stream_treap_ele_remove( server->stream_treap, stream, server->stream );
  fd_grpc_server_ref_chunks_release( stream );
  stream->ref_idx        = 0UL;
  stream->ref_cnt        = 0UL;
  stream->ref_written    = 0UL;
}

/* Request buffers ****************************************************/

/* fd_grpc_server_conn_addr is the entry counting the connection's
   peer address, NULL for the direct transport. */

static inline fd_grpc_server_addr_t *
fd_grpc_server_conn_addr( fd_grpc_server_conn_t * conn ) {
  if( !conn->peer_ip4 ) return NULL;
  return addr_map_query( conn->server->addr_map, conn->peer_ip4, NULL );
}

/* fd_grpc_server_req_buf_release returns the stream's request buffer,
   if it holds one. */

static void
fd_grpc_server_req_buf_release( fd_grpc_server_stream_t * stream ) {
  if( !stream->msg_buf ) return;
  fd_grpc_server_t * server = stream->conn->server;
  fd_grpc_server_addr_t * a = fd_grpc_server_conn_addr( stream->conn );
  if( a && a->req_cnt ) a->req_cnt--;
  if( stream->req_prev!=UINT_MAX ) server->stream[ stream->req_prev ].req_next = stream->req_next;
  else                             server->req_head                            = stream->req_next;
  if( stream->req_next!=UINT_MAX ) server->stream[ stream->req_next ].req_prev = stream->req_prev;
  else                             server->req_tail                            = stream->req_prev;
  stream->req_prev = UINT_MAX;
  stream->req_next = UINT_MAX;
  server->req_free[ server->req_free_cnt++ ] = stream->msg_slot;
  stream->msg_slot = UINT_MAX;
  stream->msg_buf  = NULL;
}

/* fd_grpc_server_req_buf_acquire lends the stream a request buffer
   for the message arriving on it.  When every buffer is on loan, the
   stream whose message has been arriving the longest is refused and
   gives its buffer up.  Returns 0 if there is no buffer to lend, or
   the stream's address already holds its share of them. */

static int
fd_grpc_server_req_buf_acquire( fd_grpc_server_stream_t * stream ) {
  if( stream->msg_buf ) return 1;
  fd_grpc_server_t * server = stream->conn->server;
  fd_grpc_server_addr_t * a = fd_grpc_server_conn_addr( stream->conn );
  ulong share = fd_ulong_max( 1UL, server->params.request_buf_cnt/FD_GRPC_SERVER_ADDR_SHARE );
  if( a && FD_UNLIKELY( a->req_cnt>=share ) ) { server->metrics.rx_buf_addr_cnt++; return 0; }
  if( FD_UNLIKELY( !server->req_free_cnt ) ) {
    /* The loan taken back is the oldest of the address holding the
       most, so that one address filling the pool costs others nothing
       and a request from a quiet address outlives the churn. */
    fd_grpc_server_stream_t * victim = NULL;
    ulong victim_cnt = 0UL;
    for( uint i=server->req_head; i!=UINT_MAX; i=server->stream[ i ].req_next ) {
      fd_grpc_server_addr_t * va = fd_grpc_server_conn_addr( server->stream[ i ].conn );
      ulong cnt = va ? va->req_cnt : 1UL;
      if( cnt>victim_cnt ) { victim = server->stream + i; victim_cnt = cnt; }
    }
    if( FD_UNLIKELY( !victim ) ) return 0;
    server->metrics.rx_buf_evict_cnt++;
    fd_grpc_server_rx_reject( victim, FD_GRPC_STATUS_RESOURCE_EXHAUSTED, "grpc: too many requests in flight", 33UL );
  }
  if( a ) a->req_cnt++;
  uint slot = server->req_free[ --server->req_free_cnt ];
  stream->msg_slot  = slot;
  stream->msg_buf   = server->req_buf + (ulong)slot*server->params.max_request_msg_sz;
  stream->msg_nanos = server->now;
  uint idx = (uint)( stream - server->stream );
  stream->req_prev = server->req_tail;
  stream->req_next = UINT_MAX;
  if( server->req_tail!=UINT_MAX ) server->stream[ server->req_tail ].req_next = idx;
  else                             server->req_head                            = idx;
  server->req_tail = idx;
  return 1;
}

/* Burst buffers ******************************************************/

/* fd_grpc_server_rbuf_rebase moves an empty ring onto another buffer,
   keeping its offsets. */

static inline void
fd_grpc_server_rbuf_rebase( fd_h2_rbuf_t * rbuf,
                            uchar *        buf,
                            ulong          sz ) {
  rbuf->buf0  = buf;
  rbuf->buf1  = buf+sz;
  rbuf->lo    = buf;
  rbuf->hi    = buf;
  rbuf->bufsz = sz;
}

/* fd_grpc_server_conn_burst_acquire backs the connection's send ring
   with a burst buffer, if one is free and the ring is empty. */

void
fd_grpc_server_conn_burst_acquire( fd_grpc_server_conn_t * conn ) {
  fd_grpc_server_t * server = conn->server;
  if( !server->params.tx_burst_cnt || conn->tx_burst!=UINT_MAX ) return;
  if( fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) return;
  if( FD_UNLIKELY( !server->tx_burst_free_cnt ) ) { server->metrics.tx_burst_miss_cnt++; return; }
  fd_grpc_server_addr_t * a = fd_grpc_server_conn_addr( conn );
  if( a ) {
    ulong share = fd_ulong_max( 1UL, server->params.tx_burst_cnt/FD_GRPC_SERVER_ADDR_SHARE );
    if( FD_UNLIKELY( a->burst_cnt>=share ) ) { server->metrics.tx_burst_miss_cnt++; return; }
    a->burst_cnt++;
  }
  uint slot = server->tx_burst_free[ --server->tx_burst_free_cnt ];
  conn->tx_burst = slot;
  fd_grpc_server_rbuf_rebase( conn->rbuf_tx, server->tx_burst + (ulong)slot*server->params.tx_burst_sz, server->params.tx_burst_sz );
  server->metrics.tx_burst_acquire_cnt++;
}

/* fd_grpc_server_conn_burst_release puts the connection's send ring
   back on its own buffer.  Unless forced, an unsent byte keeps the
   burst buffer. */

static void
fd_grpc_server_conn_burst_release( fd_grpc_server_conn_t * conn,
                                   int                     force ) {
  fd_grpc_server_t * server = conn->server;
  if( conn->tx_burst==UINT_MAX ) return;
  if( !force && fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) return;
  fd_grpc_server_addr_t * a = fd_grpc_server_conn_addr( conn );
  if( a && a->burst_cnt ) a->burst_cnt--;
  server->tx_burst_free[ server->tx_burst_free_cnt++ ] = conn->tx_burst;
  conn->tx_burst = UINT_MAX;
  if( force ) fd_h2_rbuf_init( conn->rbuf_tx, conn->tx_own, server->params.conn_tx_buf_sz ); /* whatever was unsent is discarded with the connection */
  else        fd_grpc_server_rbuf_rebase( conn->rbuf_tx, conn->tx_own, server->params.conn_tx_buf_sz );
}

static void
fd_grpc_server_stream_release( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_refs_drop( stream );
  fd_grpc_server_req_buf_release( stream );
  stream->state         = FD_GRPC_SERVER_STREAM_FREE;
  stream->flags         = 0U;
  stream->ctx           = NULL;
  stream->msg_sz        = 0UL;
  stream->msg_rem       = 0UL;
  stream->msg_hdr_sz    = 0UL;
  stream->ref_hi        = 0UL;
  stream->fin_status    = 0U;
  stream->fin_msg_len   = 0U;
  stream->path_len      = 0;
  stream->deadline      = LONG_MAX;
  stream->resp_deadline = LONG_MAX;
  stream->tx_wnd_debt   = 0L;
  fd_h2_stream_init( stream->h2 );
}

/* fd_grpc_server_stream_end reports a stream to the app if it ever
   accepted it, and returns the slot to the pool. */

void
fd_grpc_server_stream_end( fd_grpc_server_stream_t * stream,
                           int                       reason ) {
  fd_grpc_server_conn_t * conn   = stream->conn;
  fd_grpc_server_t *      server = conn->server;
  if( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN ) {
    stream->flags &= ~FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN;
    stream->state = FD_GRPC_SERVER_STREAM_FINISH; /* sends from the callback are refused */
    server->callbacks->stream_close( server->app_ctx, stream, reason );
    conn->stream_nanos = server->now;
  }
  fd_grpc_server_stream_release( stream );
}

fd_grpc_server_stream_t *
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

ulong
fd_grpc_server_stream_tx_ref_hi( fd_grpc_server_stream_t const * stream ) {
  return stream->ref_hi;
}

void
fd_grpc_server_pool_free( fd_grpc_server_t const * server,
                          ulong *                  ref_chunk_free,
                          ulong *                  request_buf_free,
                          ulong *                  tx_burst_free ) {
  *ref_chunk_free   = server->ref_chunk_free_cnt;
  *request_buf_free = server->req_free_cnt;
  *tx_burst_free    = server->tx_burst_free_cnt;
}

void
fd_grpc_server_pool_capacity( fd_grpc_server_t const * server,
                              ulong *                  ref_chunk_cnt,
                              ulong *                  request_buf_cnt,
                              ulong *                  tx_burst_cnt ) {
  *ref_chunk_cnt   = server->ref_chunk_cnt - server->params.max_conn_cnt*server->params.max_stream_cnt;
  *request_buf_cnt = server->params.request_buf_cnt;
  *tx_burst_cnt    = server->params.tx_burst_cnt;
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
  fd_grpc_server_conn_mark( conn );
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

static void
fd_grpc_server_fin_set( fd_grpc_server_stream_t * stream,
                        uint                      grpc_status,
                        char const *              grpc_msg,
                        ulong                     msg_len );

void
fd_grpc_server_finish( fd_grpc_server_stream_t * stream,
                       uint                      grpc_status,
                       char const *              grpc_msg,
                       ulong                     msg_len ) {
    if( FD_UNLIKELY( stream->state==FD_GRPC_SERVER_STREAM_FREE ||
                   stream->state==FD_GRPC_SERVER_STREAM_FINISH ) ) return;
  fd_grpc_server_fin_set( stream, grpc_status, grpc_msg, msg_len );
  fd_grpc_server_conn_mark( stream->conn );
}

/* fd_grpc_server_fin_set records the status the call ends with and
   queues its trailers, replacing any status set before. */

static void
fd_grpc_server_fin_set( fd_grpc_server_stream_t * stream,
                        uint                      grpc_status,
                        char const *              grpc_msg,
                        ulong                     msg_len ) {
  stream->fin_status  = grpc_status;
  stream->fin_msg_len = 0U;
  if( grpc_msg && msg_len ) {
    msg_len = fd_ulong_min( msg_len, FD_GRPC_SERVER_MSG_MAX );
    fd_memcpy( stream->fin_msg, grpc_msg, msg_len );
    stream->fin_msg_len = (uint)msg_len;
  }
  stream->state  = FD_GRPC_SERVER_STREAM_FINISH;
  fd_grpc_server_conn_mark( stream->conn );
}

#define FD_GRPC_SERVER_FINISH(stream,status,lit) \
  fd_grpc_server_finish( (stream), (status), (lit), sizeof(lit)-1UL )

/* Send ring **********************************************************/

/* Every response message of every stream is staged once in the
   server's send ring and referenced by the streams that carry it.
   stage_off is the virtual offset of the message being staged and only
   ever grows; the byte at virtual offset o lives at
   tx_ring[ o%tx_ring_sz ].  A staged message is physically contiguous,
   so a reference into it never wraps. */

/* fd_grpc_server_stream_drop_output gives up a stream's pending output
   and ends the call with grpc_status, whatever status the app set.
   The claim on the ring is dropped at once, so those bytes can be
   reused; the wire action and the stream_close callback happen on the
   next flush.  A message that is partly on the wire cannot be followed
   by trailers, so the stream is reset instead. */

static void
fd_grpc_server_stream_drop_output( fd_grpc_server_stream_t * stream,
                                   uint                      grpc_status,
                                   char const *              grpc_msg,
                                   ulong                     msg_len ) {
  if( stream->ref_written ) stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_TX_TRUNC;
  fd_grpc_server_refs_drop( stream );
  fd_grpc_server_fin_set( stream, grpc_status, grpc_msg, msg_len );
}

#define FD_GRPC_SERVER_DROP_OUTPUT(stream,status,lit) \
  fd_grpc_server_stream_drop_output( (stream), (status), (lit), sizeof(lit)-1UL )

/* fd_grpc_server_stream_too_slow takes a stream out of service because
   the client did not take its output. */

static void
fd_grpc_server_stream_too_slow( fd_grpc_server_stream_t * stream ) {
  if( FD_UNLIKELY( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TOO_SLOW ) ) return;
  stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_TOO_SLOW;
  FD_GRPC_SERVER_DROP_OUTPUT( stream, FD_GRPC_STATUS_INTERNAL, "grpc: client is too slow" );
  fd_grpc_server_conn_mark( stream->conn );
}

/* fd_grpc_server_evict_until closes every stream whose oldest unsent
   byte lies below off, which is what the ring is about to reuse.  The
   treap orders streams by that offset, so the walk stops at the first
   stream that is far enough along. */

static void
fd_grpc_server_evict_until( fd_grpc_server_t * server,
                            ulong              off ) {
  for(;;) {
    stream_treap_fwd_iter_t it = stream_treap_fwd_iter_init( server->stream_treap, server->stream );
    if( FD_LIKELY( stream_treap_fwd_iter_done( it ) ) ) break;
    fd_grpc_server_stream_t * s = stream_treap_fwd_iter_ele( it, server->stream );
    if( FD_LIKELY( s->ref_key >= off ) ) break;
    server->metrics.tx_too_slow_ring_cnt++;
    fd_grpc_server_stream_too_slow( s ); /* drops its references, which leaves the treap */
  }
}

/* fd_grpc_server_stage_reserve makes room for sz more bytes of the
   message being staged and returns where they go.  A whole message is
   at most max_msg_sz+5 bytes, a third of the ring. */

static uchar *
fd_grpc_server_stage_reserve( fd_grpc_server_t * server,
                              ulong              sz ) {
  ulong ring_sz   = server->tx_ring_sz;
  ulong pos       = server->stage_off % ring_sz;
  ulong remaining = ring_sz - ( pos + server->stage_len );

  if( FD_UNLIKELY( sz>remaining ) ) {
    /* Move what is staged so far to the front of the ring, so that the
       message stays contiguous, and give up the bytes it leaves behind
       so that offsets keep advancing in circular order.  The ring is
       reused from the front for the staged part as well as the new
       bytes, so both are evicted for. */
    ulong stage_end = server->stage_off + remaining + 2UL*server->stage_len + sz;
    fd_grpc_server_evict_until( server, stage_end>=ring_sz ? stage_end-ring_sz : 0UL );
    memmove( server->tx_ring, server->tx_ring+pos, server->stage_len );
    server->stage_off += server->stage_len + remaining;
  } else {
    ulong stage_end = server->stage_off + server->stage_len + sz;
    fd_grpc_server_evict_until( server, stage_end>=ring_sz ? stage_end-ring_sz : 0UL );
  }

  return server->tx_ring + ( server->stage_off % ring_sz ) + server->stage_len;
}

/* fd_grpc_server_stage_append copies sz bytes into the message being
   staged. */

static void
fd_grpc_server_stage_append( fd_grpc_server_t * server,
                             void const *       data,
                             ulong              sz ) {
  fd_memcpy( fd_grpc_server_stage_reserve( server, sz ), data, sz );
  server->stage_len += sz;
}

/* fd_grpc_server_stage_commit ends the message being staged.  The
   streams that took a reference to it keep it until they have sent
   it. */

static void
fd_grpc_server_stage_commit( fd_grpc_server_t * server ) {
  server->stage_off += server->stage_len;
  server->stage_len  = 0UL;
}

/* fd_grpc_server_ref_push appends one message to a stream's pending
   output.  Returns 0 if the stream had no room for it, in which case
   it is closed for being too slow. */

static int
fd_grpc_server_ref_push( fd_grpc_server_stream_t * stream,
                         ulong                     off,
                         ulong                     sz ) {
  fd_grpc_server_t * server  = stream->conn->server;
  ulong              ref_max = server->params.stream_tx_ref_max;

  if( FD_UNLIKELY( stream->ref_cnt>=ref_max ) ) {
    server->metrics.tx_too_slow_refs_cnt++;
    fd_grpc_server_stream_too_slow( stream );
    return 0;
  }

  /* The chain is used from ref_idx of the head chunk through pos.  A
     stream on its own chunk alone with room before ref_idx slides its
     entries to the front, so that it borrows from the pool only once
     it holds a whole chunk's worth; otherwise a pos at the end of the
     chain wants one more chunk. */
  ulong pos = stream->ref_idx + stream->ref_cnt;
  if( FD_UNLIKELY( pos==stream->ref_chunk_cnt*FD_GRPC_SERVER_REF_CHUNK ) ) {
    if( stream->ref_chunk_cnt==1UL && stream->ref_idx ) {
      fd_grpc_server_tx_ref_t * chunk = server->ref_chunks + (ulong)stream->ref_head*FD_GRPC_SERVER_REF_CHUNK;
      memmove( chunk, chunk+stream->ref_idx, stream->ref_cnt*sizeof(fd_grpc_server_tx_ref_t) );
      stream->ref_idx = 0UL;
      pos = stream->ref_cnt;
    } else {
      if( FD_UNLIKELY( !fd_grpc_server_ref_chunk_acquire( stream ) ) ) return 0;
    }
  }
  pos -= ( stream->ref_chunk_cnt-1UL )*FD_GRPC_SERVER_REF_CHUNK;
  server->ref_chunks[ (ulong)stream->ref_tail*FD_GRPC_SERVER_REF_CHUNK + pos ] =
    (fd_grpc_server_tx_ref_t){ .off = off, .len = sz };
  stream->ref_cnt++;
  /* The treap is keyed on the oldest reference, so a stream that had
     none joins it only now that it has one. */
  if( stream->ref_cnt==1UL ) {
    stream->ref_key = off;
    stream_treap_ele_insert( server->stream_treap, stream, server->stream );
  }
  stream->ref_hi = fd_ulong_max( stream->ref_hi, stream->ref_cnt );
  fd_grpc_server_conn_mark( stream->conn );
  return 1;
}

/* fd_grpc_server_stage_msg stages one message, its length prefix and
   payload as one, and returns where it is in the ring through base
   and len. */

static void
fd_grpc_server_stage_msg( fd_grpc_server_t * server,
                          uchar const *      payload,
                          ulong              payload_sz,
                          uint               compressed,
                          ulong *            base,
                          ulong *            len ) {
  fd_grpc_hdr_t hdr = {
    .compressed = (uchar)compressed,
    .msg_sz     = fd_uint_bswap( (uint)payload_sz )
  };
  /* Staging may evict streams that have not sent what the ring is
     about to reuse, the ones being sent to included. */
  fd_grpc_server_stage_append( server, &hdr, sizeof(fd_grpc_hdr_t) );
  if( payload_sz ) fd_grpc_server_stage_append( server, payload, payload_sz );
  *base = server->stage_off;
  *len  = sizeof(fd_grpc_hdr_t)+payload_sz;
  fd_grpc_server_stage_commit( server );
}

/* The forms a message is staged in, which err[ i ] holds for stream i
   until its result is known. */

#define GRPC_SEND_RAW  (1)
#define GRPC_SEND_ZSTD (2)

ulong
fd_grpc_server_send_multi( fd_grpc_server_stream_t ** streams,
                           ulong                      stream_cnt,
                           void const *               msg,
                           ulong                      msg_sz,
                           uint                       flags,
                           int *                      err ) {
  if( FD_UNLIKELY( !stream_cnt ) ) return 0UL;
  fd_grpc_server_t * server = streams[ 0 ]->conn->server;

  if( FD_UNLIKELY( msg_sz > server->params.max_msg_sz ) ) {
    for( ulong i=0UL; i<stream_cnt; i++ ) err[ i ] = FD_GRPC_SERVER_ERR_TOOBIG;
    server->metrics.tx_toobig_cnt += stream_cnt;
    return 0UL;
  }

  int   can_zstd = ( !( flags & FD_GRPC_SERVER_SEND_NO_COMPRESS ) ) &
                   ( msg_sz >= server->params.compression_min_sz  ) &
                   ( !!server->cctx                               );
  ulong raw_cnt  = 0UL;
  ulong zstd_cnt = 0UL;
  for( ulong i=0UL; i<stream_cnt; i++ ) {
    fd_grpc_server_stream_t * stream = streams[ i ];
    if( FD_UNLIKELY( stream->state!=FD_GRPC_SERVER_STREAM_ACTIVE ) ) { err[ i ] = FD_GRPC_SERVER_ERR_CLOSED; continue; }
    int zstd = can_zstd & !!( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TX_ZSTD );
    err[ i ] = zstd ? GRPC_SEND_ZSTD : GRPC_SEND_RAW;
    if( zstd ) zstd_cnt++;
    else       raw_cnt++;
  }

  /* One compression serves every stream that takes it; a compression
     that does not shrink the message sends those streams the raw
     form. */
  ulong zstd_sz = 0UL;
  if( zstd_cnt ) {
    ulong out_sz = ZSTD_compressCCtx( server->cctx, server->compress_out, server->compress_out_sz,
                                      msg, msg_sz, server->params.compression_level );
    if( FD_UNLIKELY( ZSTD_isError( out_sz ) ) ) {
      FD_LOG_WARNING(( "zstd compress failed (%s)", ZSTD_getErrorName( out_sz ) ));
      for( ulong i=0UL; i<stream_cnt; i++ ) if( err[ i ]==GRPC_SEND_ZSTD ) err[ i ] = FD_GRPC_SERVER_ERR_INTERNAL;
      zstd_cnt = 0UL;
    } else if( FD_LIKELY( out_sz<msg_sz ) ) {
      zstd_sz = out_sz;
    } else {
      for( ulong i=0UL; i<stream_cnt; i++ ) if( err[ i ]==GRPC_SEND_ZSTD ) err[ i ] = GRPC_SEND_RAW;
      raw_cnt += zstd_cnt;
      zstd_cnt = 0UL;
    }
  }

  ulong raw_base  = 0UL; ulong raw_len  = 0UL;
  ulong zstd_base = 0UL; ulong zstd_len = 0UL;
  if( raw_cnt  ) fd_grpc_server_stage_msg( server, msg,                  msg_sz,  0U, &raw_base,  &raw_len  );
  if( zstd_cnt ) fd_grpc_server_stage_msg( server, server->compress_out, zstd_sz, 1U, &zstd_base, &zstd_len );

  ulong raw_sent  = 0UL;
  ulong zstd_sent = 0UL;
  for( ulong i=0UL; i<stream_cnt; i++ ) {
    if( err[ i ]!=GRPC_SEND_RAW && err[ i ]!=GRPC_SEND_ZSTD ) continue;
    fd_grpc_server_stream_t * stream = streams[ i ];
    int   zstd = err[ i ]==GRPC_SEND_ZSTD;
    ulong base = zstd ? zstd_base : raw_base;
    ulong len  = zstd ? zstd_len  : raw_len;

    /* The staging above may have closed this very stream for being too
       slow. */
    if( FD_UNLIKELY( stream->state!=FD_GRPC_SERVER_STREAM_ACTIVE ) ) { err[ i ] = FD_GRPC_SERVER_ERR_CLOSED; continue; }
    if( FD_UNLIKELY( !fd_grpc_server_ref_push( stream, base, len ) ) ) { err[ i ] = FD_GRPC_SERVER_ERR_CLOSED; continue; }

    err[ i ] = FD_GRPC_SERVER_SUCCESS;
    server->metrics.tx_msg_cnt++;
    server->metrics.tx_byte_cnt      += msg_sz;
    server->metrics.tx_byte_cnt_wire += len-sizeof(fd_grpc_hdr_t);
    if( zstd ) server->metrics.tx_msg_compressed_cnt++;
    stream->resp_deadline = LONG_MAX;
    if( zstd ) zstd_sent++;
    else       raw_sent++;
  }
  server->metrics.tx_msg_shared_cnt += fd_ulong_max( raw_sent, 1UL )-1UL + fd_ulong_max( zstd_sent, 1UL )-1UL;
  return raw_sent+zstd_sent;
}

int
fd_grpc_server_send( fd_grpc_server_stream_t * stream,
                     void const *              msg,
                     ulong                     msg_sz,
                     uint                      flags ) {
  int err;
  fd_grpc_server_send_multi( &stream, 1UL, msg, msg_sz, flags, &err );
  return err;
}

/* fd_grpc_server_ref_advance records that sz more bytes of the
   stream's oldest reference reached the connection's send ring. */

void
fd_grpc_server_ref_advance( fd_grpc_server_stream_t * stream,
                            ulong                     sz ) {
  fd_grpc_server_t *              server = stream->conn->server;
  fd_grpc_server_tx_ref_t const * ref    = fd_grpc_server_ref_head( stream );
  stream->ref_written   += sz;
  if( stream->ref_written<ref->len ) return;
  /* The stream treap is keyed on the oldest reference, which is about
     to change. */
  stream_treap_ele_remove( server->stream_treap, stream, server->stream );
  stream->ref_idx++;
  stream->ref_cnt--;
  stream->ref_written = 0UL;
  if( stream->ref_idx==FD_GRPC_SERVER_REF_CHUNK ) {
    /* The head chunk is spent: one of several goes back, the last is
       reused from the start. */
    if( stream->ref_chunk_cnt>1UL ) {
      pool_treap_ele_remove( server->pool_treap, stream, server->stream );
      fd_grpc_server_ref_chunk_release_head( stream );
      if( stream->ref_chunk_cnt>1UL ) pool_treap_ele_insert( server->pool_treap, stream, server->stream );
    }
    stream->ref_idx = 0UL;
  } else if( !stream->ref_cnt ) {
    stream->ref_idx = 0UL;
  }
  if( stream->ref_cnt ) {
    stream->ref_key = fd_grpc_server_ref_head( stream )->off;
    stream_treap_ele_insert( server->stream_treap, stream, server->stream );
  } else {
    fd_grpc_server_ref_chunks_release( stream );
  }
}

/* fd_grpc_server_stream_flush moves as much of one stream's pending
   output from the send ring into the connection's send ring as flow
   control allows.  Emits at most one DATA frame, filled with as many
   pending messages as fit, so that concurrent streams take turns.
   Returns 1 if it made progress. */

static int
fd_grpc_server_stream_flush( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_conn_t * conn    = stream->conn;
  fd_grpc_server_t *      server  = conn->server;
  fd_h2_conn_t *          h2      = conn->h2;
  fd_h2_rbuf_t *          rbuf_tx = conn->rbuf_tx;
  uchar block[ FD_GRPC_SERVER_HDR_BUF_MAX ];
  int progress = 0;

  if( FD_UNLIKELY( h2->flags & FD_H2_CONN_FLAGS_DEAD ) ) return 0;
  if( FD_UNLIKELY( stream->h2->state==FD_H2_STREAM_STATE_CLOSED ||
                   stream->h2->state==FD_H2_STREAM_STATE_ILLEGAL ) ) return 0;

  /* A stream that lost its output part way through a message cannot be
     finished with trailers. */
  if( FD_UNLIKELY( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TX_TRUNC ) ) {
    if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<sizeof(fd_h2_rst_stream_t)+FD_GRPC_SERVER_TX_RESERVE ) ) return 0;
    fd_grpc_server_stream_abort( stream, FD_H2_ERR_INTERNAL );
    fd_grpc_server_stream_end( stream, ( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TOO_SLOW )
                                       ? FD_GRPC_SERVER_CLOSE_TOO_SLOW : FD_GRPC_SERVER_CLOSE_ABORTED );
    return 1;
  }

  ulong pending = stream->ref_cnt;

  if( !( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_RESP_HDRS ) ) {
    if( !pending && stream->state!=FD_GRPC_SERVER_STREAM_FINISH ) return 0;

    if( !pending && stream->state==FD_GRPC_SERVER_STREAM_FINISH ) {
      /* Trailers-Only response */
      ulong block_sz = fd_grpc_server_gen_resp_hdrs( stream, block );
      block_sz += fd_grpc_server_gen_trailers( stream, block+block_sz );
      if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < block_sz+9UL+sizeof(fd_h2_rst_stream_t)+FD_GRPC_SERVER_TX_RESERVE ) ) { conn->ring_short = 1; return 0; }
      fd_grpc_server_tx_hdrs( stream, block, block_sz, 1 );
      goto finished;
    }

    ulong block_sz = fd_grpc_server_gen_resp_hdrs( stream, block );
    if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < block_sz+9UL+FD_GRPC_SERVER_TX_RESERVE ) ) { conn->ring_short = 1; return 0; }
    fd_grpc_server_tx_hdrs( stream, block, block_sz, 0 );
    stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RESP_HDRS;
    progress = 1;
  }

  if( pending ) {
    ulong quota   = fd_ulong_min( h2->tx_wnd, stream->h2->tx_wnd );
    ulong buf_spc = fd_h2_rbuf_free_sz( rbuf_tx );
    buf_spc = buf_spc < 9UL+FD_GRPC_SERVER_TX_RESERVE ? 0UL : buf_spc-9UL-FD_GRPC_SERVER_TX_RESERVE;

    ulong frame_max  = fd_ulong_min( fd_ulong_min( quota, buf_spc ), h2->peer_settings.max_frame_size );
    ulong payload_sz = 0UL;
    if( frame_max ) {
      /* Consecutive messages share the frame, so small messages do not
         each cost a frame header on the wire and at the peer. */
      fd_h2_tx_prepare( h2, rbuf_tx, FD_H2_FRAME_TYPE_DATA, 0U, stream->h2->stream_id );
      while( stream->ref_cnt && payload_sz<frame_max ) {
        fd_grpc_server_tx_ref_t const * ref = fd_grpc_server_ref_head( stream );
        /* A staged message is contiguous, so what is left of it is one
           run of bytes. */
        uchar const * chunk    = server->tx_ring + ( ( ref->off + stream->ref_written ) % server->tx_ring_sz );
        ulong         chunk_sz = fd_ulong_min( ref->len - stream->ref_written, frame_max - payload_sz );
        fd_h2_rbuf_push( rbuf_tx, chunk, chunk_sz );
        fd_grpc_server_ref_advance( stream, chunk_sz );
        payload_sz += chunk_sz;
      }
      fd_h2_tx_commit( h2, rbuf_tx );
      pending = stream->ref_cnt;

      h2->tx_wnd         -= (uint)payload_sz;
      stream->h2->tx_wnd -= (uint)payload_sz;
      progress = 1;
    }
    /* Output left behind because the ring filled, not because the
       window closed: the connection asks for a burst buffer on its
       next pass. */
    if( pending && buf_spc<=quota && payload_sz>=buf_spc ) conn->ring_short = 1;
  }

  if( !pending && stream->state==FD_GRPC_SERVER_STREAM_FINISH ) {
    ulong block_sz = fd_grpc_server_gen_trailers( stream, block );
    if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < block_sz+9UL+sizeof(fd_h2_rst_stream_t)+FD_GRPC_SERVER_TX_RESERVE ) ) { conn->ring_short = 1; return progress; }
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
  fd_grpc_server_stream_end( stream,
                             ( stream->flags & FD_GRPC_SERVER_STREAM_FLAG_TOO_SLOW )
                             ? FD_GRPC_SERVER_CLOSE_TOO_SLOW : FD_GRPC_SERVER_CLOSE_FINISHED );
  return 1;
}

/* Request headers ****************************************************/

/* fd_grpc_server_hdr_name_valid returns 1 if name is a valid HTTP/2
   field name: non-empty, lowercase, and made of token characters
   (RFC 9113 Section 8.2.1).  A leading colon is allowed for
   pseudo-headers. */

int
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

int
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

int
fd_grpc_server_transport_hdr( fd_grpc_server_stream_t * stream,
                              char const *              name,
                              ulong                     name_len,
                              char const *              value,
                              ulong                     value_len ) {
  fd_grpc_server_t * server = stream->conn->server;
  if( name_len==12UL && fd_memeq( name, "grpc-timeout", 12UL ) ) {
    long timeout = fd_grpc_server_parse_timeout( value, value_len );
    if( timeout!=LONG_MAX ) stream->deadline = fd_long_sat_add( server->now, timeout );
    return 1;
  }
  if( name_len==13UL && fd_memeq( name, "grpc-encoding", 13UL ) ) {
    if( ( value_len==4UL ) && fd_memeq( value, "zstd", 4UL ) ) {
      stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_RX_ZSTD;
    }
    return 1;
  }
  if( name_len==20UL && fd_memeq( name, "grpc-accept-encoding", 20UL ) ) {
    if( ( server->params.compression==FD_GRPC_SERVER_COMPRESSION_ZSTD ) &&
        fd_grpc_server_list_has( value, value_len, "zstd", 4UL ) ) {
      stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_TX_ZSTD;
    }
    return 1;
  }
  return 0;
}

/* Bits of the pseudo-header set */

#define FD_GRPC_SERVER_PSEUDO_METHOD    (1U<<0)
#define FD_GRPC_SERVER_PSEUDO_SCHEME    (1U<<1)
#define FD_GRPC_SERVER_PSEUDO_PATH      (1U<<2)
#define FD_GRPC_SERVER_PSEUDO_AUTHORITY (1U<<3)

/* fd_grpc_server_stream_start hands a request whose headers are
   processed to the app. */

void
fd_grpc_server_stream_start( fd_grpc_server_stream_t * stream ) {
  fd_grpc_server_t * server = stream->conn->server;
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
  stream->conn->stream_nanos = server->now;
  stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_APP_OPEN;
  if( server->params.response_timeout_nanos>0L ) {
    stream->resp_deadline = fd_long_sat_add( server->now, server->params.response_timeout_nanos );
  }
  if( kind==FD_GRPC_SERVER_ACCEPT_UNARY ) stream->flags |= FD_GRPC_SERVER_STREAM_FLAG_UNARY;
}

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
  if( FD_UNLIKELY( !fd_hpack_rd_init_dtable( hpack_rd, block, block_sz, h2->rx_dtable ) ) ) {
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

    if( fd_grpc_server_transport_hdr( stream, name, name_len, value, value_len ) ) continue;

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

  fd_grpc_server_stream_start( stream );
}

/* gRPC message framing ***********************************************/

void
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
  fd_grpc_server_req_buf_release( stream );
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
  static uchar const empty[ 1 ] = { 0 };
  uchar const *      msg    = stream->msg_buf ? stream->msg_buf : empty;
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
  /* The handler is done with the message, so the buffer can go to the
     next one arriving. */
  fd_grpc_server_req_buf_release( stream );
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
  if( !msg_sz ) { fd_grpc_server_rx_msg( stream ); return; }
  if( FD_UNLIKELY( !fd_grpc_server_req_buf_acquire( stream ) ) ) {
    FD_GRPC_SERVER_RX_REJECT( stream, FD_GRPC_STATUS_RESOURCE_EXHAUSTED, "grpc: too many requests in flight" );
  }
}

void
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

void
fd_grpc_server_conn_closing( fd_grpc_server_conn_t * conn ) {
  /* Arm the close deadline only on the first transition, so that a peer
     that keeps the connection busy while it drains cannot push the
     deadline back indefinitely. */
  if( FD_UNLIKELY( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING ) ) return;
    conn->flags      |= FD_GRPC_SERVER_CONN_FLAG_CLOSING;
  conn->close_nanos = conn->server->now + FD_GRPC_SERVER_CLOSE_TIMEOUT_NANOS;
  fd_grpc_server_conn_mark( conn );
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
  if( FD_UNLIKELY( !fd_hpack_rd_init_dtable( hpack_rd, block, block_sz, h2->rx_dtable ) ) ) {
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
  (void)error_code;
  int reason = closed_by ? FD_GRPC_SERVER_CLOSE_CANCELLED : FD_GRPC_SERVER_CLOSE_ABORTED;
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
  /* Closing the socket drops it from the epoll set. */
  if( conn->sock>=0 ) close( conn->sock );
# endif
  conn->sock   = -1;
  conn->flags  = 0U;
  conn->h2->flags = FD_H2_CONN_FLAGS_DEAD;
  fd_grpc_server_conn_burst_release( conn, 1 );
  if( conn->tx_pending ) { conn->tx_pending = 0; server->tx_pending_cnt--; }
  conn->in_armed  = 0;
  conn->out_armed = 0;
  server->callbacks->conn_close( server->app_ctx, conn );
  conn->ctx = NULL;
  conn->free_next   = server->free_head;
  server->free_head = conn->idx;
  server->conn_cnt--;
  if( conn->peer_ip4 ) {
    fd_grpc_server_addr_t * a = addr_map_query( server->addr_map, conn->peer_ip4, NULL );
    if( FD_LIKELY( a ) && !--a->cnt ) addr_map_remove( server->addr_map, a );
    conn->peer_ip4 = 0U;
  }
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
                          uint               peer_ip4,
                          long               now ) {
  fd_grpc_server_params_t const * params = &server->params;

  fd_grpc_server_conn_t * conn = NULL;
  if( FD_LIKELY( !server->shutdown && server->free_head!=UINT_MAX ) ) {
    conn              = server->conn + server->free_head;
    server->free_head = conn->free_next;
    conn->free_next   = UINT_MAX;
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
  conn->stream_nanos= now;
  conn->peer_ip4    = 0U;
  conn->rx_nanos    = now;
  conn->tx_nanos    = now;
  conn->reset_nanos = now;
  conn->reset_cnt   = 0UL;
  conn->backlog     = 0;
  conn->ring_short  = 0;
  conn->close_nanos = LONG_MAX;
  for( ulong i=0UL; i<params->max_stream_cnt; i++ ) fd_grpc_server_stream_release( conn->stream+i );

  uchar * rx_buf = conn->rbuf_rx->buf0;
  fd_h2_rbuf_init( conn->rbuf_rx, rx_buf, params->conn_rx_buf_sz );
  fd_h2_rbuf_init( conn->rbuf_tx, conn->tx_own, params->conn_tx_buf_sz );

  if( FD_UNLIKELY( !fd_h2_conn_init_server( conn->h2 ) ) ) {
    conn->active = 0U;
    conn->sock   = -1;
#   if FD_HAS_HOSTED
    if( sock>=0 ) close( sock );
#   endif
    conn->free_next   = server->free_head;
    server->free_head = conn->idx;
    return NULL;
  }
  conn->h2->ctx                                   = conn;
  conn->h2->self_settings.max_concurrent_streams  = (uint)params->max_stream_cnt;
  conn->h2->self_settings.max_frame_size          = (uint)params->max_frame_sz;
  ulong max_header_list_sz = params->max_frame_sz;
  conn->h2->self_settings.max_header_list_size    = (uint)max_header_list_sz;
  conn->h2->self_settings.initial_window_size     = (uint)params->stream_rx_wnd_sz;
  conn->h2->self_settings.header_table_size       = FD_HPACK_DTABLE_SZ_MAX;
  conn->h2->rx_dtable = fd_hpack_dtable_init( conn->rx_dtable, FD_HPACK_DTABLE_SZ_MAX );
  fd_h2_conn_rx_wnd_set( conn->h2, (uint)params->conn_rx_wnd_sz );
  conn->in_armed  = 0;
  conn->out_armed = 0;
  server->conn_cnt++;
  server->metrics.conn_open_cnt++;
# if FD_HAS_HOSTED
  if( sock>=0 && server->epoll_fd>=0 ) {
    struct epoll_event ev = { .events = EPOLLIN, .data = { .ptr = conn } };
    if( FD_UNLIKELY( 0!=epoll_ctl( server->epoll_fd, EPOLL_CTL_ADD, sock, &ev ) ) ) {
      server->metrics.poll_error_cnt++;
      ulong n = server->metrics.poll_error_cnt;
      if( FD_UNLIKELY( !( n & ( n-1UL ) ) ) )
        FD_LOG_WARNING(( "epoll_ctl(EPOLL_CTL_ADD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      conn->active    = 0U;
      conn->flags     = 0U;
      conn->h2->flags = FD_H2_CONN_FLAGS_DEAD;
      close( sock );
      conn->sock        = -1;
      conn->free_next   = server->free_head;
      server->free_head = conn->idx;
      server->conn_cnt--;
      server->metrics.conn_close_cnt++;
      return NULL;
    }
    conn->in_armed = 1;
  }
# endif
  if( peer_ip4 ) {
    fd_grpc_server_addr_t * a = addr_map_query( server->addr_map, peer_ip4, NULL );
    if( !a ) { a = addr_map_insert( server->addr_map, peer_ip4 ); a->cnt = 0U; a->req_cnt = 0U; a->burst_cnt = 0U; }
    a->cnt++;
    conn->peer_ip4 = peer_ip4;
  }
  fd_grpc_server_conn_mark( conn );
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
  /* A connection already answered as HTTP/1.1 takes no more input */
  if( FD_UNLIKELY( conn->flags & FD_GRPC_SERVER_CONN_FLAG_HTTP1 ) ) return 0;

  /* A browser cannot open an HTTP/2 cleartext connection, so a request
     line where the preface should be is served over HTTP/1.1 instead of
     being dropped. */
  if( FD_UNLIKELY( conn->server->params.web &&
                   conn->preface_rem==sizeof(fd_h2_client_preface) ) ) {
    ulong avail = fd_h2_rbuf_used_sz( conn->rbuf_rx );
    ulong chunk0, chunk1;
    uchar const * p = fd_h2_rbuf_peek_used( conn->rbuf_rx, &chunk0, &chunk1 );
    ulong n = fd_ulong_min( avail, 4UL );
    if( n && chunk0>=n && ( fd_memeq( p, "GET ", n ) || fd_memeq( p, "POST", n ) ) ) {
      fd_grpc_web_conn_rx( conn );
      return 0;
    }
  }

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
  /* Nothing may precede the server's own SETTINGS */
  if( FD_UNLIKELY( conn->h2->flags & FD_H2_CONN_FLAGS_SERVER_INITIAL ) ) return;
  if( conn->flags & ( FD_GRPC_SERVER_CONN_FLAG_GOAWAY |
                      FD_GRPC_SERVER_CONN_FLAG_HTTP1 ) ) return;
  /* fd_h2 already has a GOAWAY of its own to send */
  if( FD_UNLIKELY( conn->h2->flags & ( FD_H2_CONN_FLAGS_DEAD | FD_H2_CONN_FLAGS_SEND_GOAWAY ) ) ) return;
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( conn->rbuf_tx )<sizeof(fd_h2_goaway_t)+FD_GRPC_SERVER_TX_RESERVE ) ) return;
  uint last_stream_id = conn->h2->rx_stream_next>=2U ? conn->h2->rx_stream_next-2U : 0U;
    fd_h2_tx_goaway( conn->rbuf_tx, last_stream_id, h2_err );
  conn->flags |= FD_GRPC_SERVER_CONN_FLAG_GOAWAY;
  fd_grpc_server_conn_mark( conn );
}

/* fd_grpc_server_conn_flush drains the per-stream send queues into the
   connection's send ring, taking turns between streams. */

static int
fd_grpc_server_conn_flush_control( fd_grpc_server_conn_t * conn ) {
  fd_grpc_server_t * server = conn->server;
  /* An HTTP/1.1 connection carries at most one gRPC-Web call and no
     HTTP/2 state. */
  if( FD_UNLIKELY( conn->flags & FD_GRPC_SERVER_CONN_FLAG_HTTP1 ) ) {
    fd_grpc_web_conn_flush( conn );
    return 0;
  }

  /* While HTTP/1.1 is served, the server's own SETTINGS wait until the
     peer's preface says it is an HTTP/2 client at all; a browser would
     otherwise be sent binary before its request is even read.
     fd_h2_rx emits them itself once the preface is through. */
    if( FD_UNLIKELY( server->params.web && conn->preface_rem ) ) return 0;
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
  return conn->active ? 1 : 0;
}

/* fd_grpc_server_conn_has_output returns 1 if a stream of the
   connection holds output that a flush would frame. */

static int
fd_grpc_server_conn_has_output( fd_grpc_server_conn_t const * conn ) {
  ulong stream_max = conn->server->params.max_stream_cnt;
  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t const * s = conn->stream+i;
    if( s->state==FD_GRPC_SERVER_STREAM_FINISH ) return 1;
    if( s->state==FD_GRPC_SERVER_STREAM_ACTIVE && s->ref_cnt ) return 1;
  }
  return 0;
}

static void
fd_grpc_server_conn_flush( fd_grpc_server_conn_t * conn ) {
  ulong stream_max = conn->server->params.max_stream_cnt;
  /* A connection whose last flush ran out of ring space gets a burst
     buffer to frame more per pass; one held back by the peer's window
     does not. */
  if( conn->ring_short ) {
    conn->ring_short = 0;
    fd_grpc_server_conn_burst_acquire( conn );
  }
  if( !fd_grpc_server_conn_flush_control( conn ) ) return;
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

}

static void
fd_grpc_server_conn_timers( fd_grpc_server_conn_t * conn,
                            long                    now ) {
  fd_grpc_server_t *              server = conn->server;
  fd_grpc_server_params_t const * params = &server->params;
  ulong                           stream_max = params->max_stream_cnt;

  ulong active_cnt  = 0UL;
  int   pending_out = 0;
  for( ulong i=0UL; i<stream_max; i++ ) {
    fd_grpc_server_stream_t * s = conn->stream+i;
    if( s->state==FD_GRPC_SERVER_STREAM_FREE ) continue;
    active_cnt++;
    pending_out |= !!s->ref_cnt;
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
    /* A request message that stops arriving holds a buffer from the
       pool, for this long at most. */
    if( ( !!s->msg_buf                                           ) &
        ( now - s->msg_nanos > FD_GRPC_SERVER_REQUEST_NANOS      ) ) {
      server->metrics.rx_buf_timeout_cnt++;
      FD_GRPC_SERVER_RX_REJECT( s, FD_GRPC_STATUS_DEADLINE_EXCEEDED, "grpc: request message incomplete" );
    }
  }

  if( FD_UNLIKELY( ( params->handshake_timeout_nanos>0L                      ) &
                   ( !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_HTTP1 )       ) &
                   ( !!( conn->h2->flags & FD_H2_CONN_FLAGS_HANDSHAKING )    ) &
                   ( now - conn->open_nanos > params->handshake_timeout_nanos ) ) ) {
    server->metrics.handshake_timeout_cnt++;
    /* Sampled at powers of two.  rx 0 means the peer sent nothing after
       connecting; rx>0 with WAIT_SETTINGS_ACK_0 still set means it sent
       its request but never read our SETTINGS. */
    ulong n = server->metrics.handshake_timeout_cnt;
    if( FD_UNLIKELY( !( n & ( n-1UL ) ) ) )
      FD_LOG_WARNING(( "handshake timeout #%lu: h2 flags 0x%x rx %lu bytes tx %lu bytes, %lu conns",
                       n, (uint)conn->h2->flags, conn->rbuf_rx->hi_off, conn->rbuf_tx->lo_off, server->conn_cnt ));
    fd_grpc_server_conn_release( conn );
    return;
  }

  /* A burst buffer is lent to a connection that keeps sending; one
     whose bytes the kernel has not taken for a while is not, and the
     buffer cannot be taken back while it holds unsent bytes, so the
     connection goes. */
  if( ( conn->tx_burst!=UINT_MAX                                ) &
      ( !!fd_h2_rbuf_used_sz( conn->rbuf_tx )                   ) &
      ( conn->sock>=0                                           ) &
      ( now - conn->tx_nanos > FD_GRPC_SERVER_BURST_STALL_NANOS ) ) {
    server->metrics.tx_burst_stall_cnt++;
    fd_grpc_server_conn_release( conn );
    return;
  }

  /* Output the peer never takes, which an open stream would otherwise
     keep alive forever.  A healthy subscriber drains, so nothing stays
     queued even when it sends nothing back.  Flow control stops the
     stream queues from reaching the send ring, so both count. */
  if( ( params->idle_timeout_nanos>0L                           ) &
      ( ( !!fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) | pending_out  ) &
      ( !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING )     ) &
      ( now - conn->tx_nanos > params->idle_timeout_nanos       ) ) {
    server->metrics.idle_timeout_cnt++;
    fd_grpc_server_conn_closing( conn );
    return;
  }

  /* No stream open: measured from the accept or the last stream, so
     PINGs and other control frames alone hold no slot. */
  if( ( params->idle_timeout_nanos>0L                          ) &
      ( !active_cnt                                            ) &
      ( !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING )         ) &
      ( now - conn->stream_nanos > params->idle_timeout_nanos   ) ) {
    server->metrics.idle_timeout_cnt++;
    fd_grpc_server_conn_closing( conn );
  }
}

static void
fd_grpc_server_service_pass( fd_grpc_server_t * server,
                             long               now_nanos );

void
fd_grpc_server_service( fd_grpc_server_t * server,
                        long               now_nanos ) {
  if( FD_UNLIKELY( server->servicing ) ) return;
  server->servicing = 1;
  fd_grpc_server_service_pass( server, now_nanos );
  server->servicing = 0;
}

static void
fd_grpc_server_service_pass( fd_grpc_server_t * server,
                             long               now_nanos ) {
  server->now = now_nanos;
  if( FD_UNLIKELY( server->listen_rearm_nanos && now_nanos>=server->listen_rearm_nanos ) ) {
    server->listen_rearm_nanos = 0L;
    fd_grpc_server_listen_arm( server, 1 );
  }
  ulong conn_max = server->params.max_conn_cnt;
  /* Timers are seconds apart, so a slice of the table per pass keeps
     the pass bounded while every connection is still visited within a
     few dozen passes.  A small table is swept whole. */
  ulong sweep_n = fd_ulong_min( conn_max, fd_ulong_max( 256UL, conn_max>>6 ) );
  for( ulong k=0UL; k<sweep_n; k++ ) {
    ulong i = server->sweep_cursor;
    server->sweep_cursor = i+1UL<conn_max ? i+1UL : 0UL;
    fd_grpc_server_conn_t * conn = server->conn+i;
    if( !conn->active ) continue;
    fd_grpc_server_conn_timers( conn, now_nanos );
    if( conn->active && ( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING ) ) fd_grpc_server_conn_mark( conn );
  }
  /* The work list holds exactly the connections something happened to
     since the last pass. */
  ulong budget = FD_GRPC_SERVER_SERVICE_BUDGET;
  while( server->dirty_head!=UINT_MAX && budget-- ) {
    fd_grpc_server_conn_t * conn = server->conn + server->dirty_head;
    server->dirty_head = conn->dirty_next;
    if( server->dirty_head==UINT_MAX ) server->dirty_tail = UINT_MAX;
    conn->dirty      = 0;
    conn->dirty_next = UINT_MAX;
    if( !conn->active ) continue;
#   if FD_HAS_HOSTED
    long interval = server->params.send_interval_nanos;
    if( interval>0L && !conn->backlog && !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING ) ) {
      /* Control frames go out now.  Stream output waits for the
         window, so that the messages staged within it are framed
         together and leave in one send.  A connection whose last
         send could not take everything it had is not made to wait:
         the interval coalesces, it does not cap bandwidth. */
      int h2 = fd_grpc_server_conn_flush_control( conn );
      if( !conn->active ) continue;
      if( conn->sock>=0 ) fd_grpc_server_conn_tx_try( conn, now_nanos );
      if( !conn->active ) continue;
      if( !( h2 && fd_grpc_server_conn_has_output( conn ) ) ) fd_grpc_server_conn_burst_release( conn, 0 );
      if( h2 && fd_grpc_server_conn_has_output( conn ) ) {
        if( conn->sock>=0 ) fd_grpc_server_conn_arm( conn );
        if( !conn->deferred ) {
          /* Due at the first tick after now congruent to the slot, and
             after the cursor, so a clock that steps back cannot queue
             behind it */
          ulong width = (ulong)fd_long_max( interval/(long)FD_GRPC_SERVER_DEFER_WHEEL, 1L );
          ulong next  = (ulong)now_nanos/width + 1UL;
          if( server->defer_tick!=LONG_MIN ) next = fd_ulong_max( next, (ulong)( server->defer_tick+1L ) );
          ulong tick  = next + ( ( conn->idx - next ) & ( FD_GRPC_SERVER_DEFER_WHEEL-1UL ) );
          uint * head = &server->defer_bucket[ ( tick/FD_GRPC_SERVER_DEFER_WHEEL ) & ( FD_GRPC_SERVER_DEFER_LAPS-1UL ) ]
                                             [ tick & ( FD_GRPC_SERVER_DEFER_WHEEL-1UL ) ];
          conn->deferred   = 1;
          conn->defer_next = *head;
          *head = conn->idx;
        }
        continue;
      }
      if( conn->sock>=0 ) fd_grpc_server_conn_arm( conn );
      continue;
    }
#   endif
    fd_grpc_server_conn_flush( conn );
    if( !conn->active ) continue;
    int framed = !!fd_h2_rbuf_used_sz( conn->rbuf_tx );
    conn->backlog = (uchar)( ( !!fd_grpc_server_conn_has_output( conn ) ) | ( ( conn->sock>=0 ) & framed ) );
    if( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING ) {
      fd_grpc_server_conn_goaway( conn, FD_H2_SUCCESS );
      if( fd_h2_rbuf_is_empty( conn->rbuf_tx ) || conn->close_nanos<=now_nanos ) {
        fd_grpc_server_conn_release( conn );
        continue;
      }
    }
#   if FD_HAS_HOSTED
    if( conn->sock>=0 ) {
      fd_grpc_server_conn_tx_try( conn, now_nanos );
      if( !conn->active ) continue;
      fd_grpc_server_conn_arm( conn );
    }
#   endif
    /* A pass that framed nothing and left nothing behind: the burst
       buffer goes back.  One that framed something keeps it, so a
       steady heavy stream does not swap buffers on every pass. */
    if( !conn->backlog && !framed ) fd_grpc_server_conn_burst_release( conn, 0 );
  }
#if FD_HAS_HOSTED
  /* A send leaves between 0 and one interval after the data arrived
     and two sends to one connection are an interval apart.  The due
     tick is taken from the clock, not from the cursor, so a cursor
     running behind delays sends and never repeats them.  Draining
     resumes mid-bucket when the budget runs out and visits every
     bucket in turn, so under load each connection is served once per
     lap of the cursor; a pass walks at most a few laps of empty ticks
     when catching up after a quiet spell. */
  long interval = server->params.send_interval_nanos;
  if( interval>0L ) {
    long width = fd_long_max( interval/(long)FD_GRPC_SERVER_DEFER_WHEEL, 1L );
    long cur   = now_nanos/width;
    if( FD_UNLIKELY( server->defer_tick==LONG_MIN ) ) server->defer_tick = cur;
    /* Every bucket is visited within one walk of all the laps, so a
       cursor further behind than that starts there */
    ulong ticks = FD_GRPC_SERVER_DEFER_LAPS*FD_GRPC_SERVER_DEFER_WHEEL;
    if( FD_UNLIKELY( cur-server->defer_tick>(long)ticks ) ) server->defer_tick = cur-(long)ticks;
    /* A clock stepped back past a whole walk restarts the cursor at the
       clock: sends go early rather than waiting for the clock */
    if( FD_UNLIKELY( server->defer_tick-cur>(long)ticks ) ) server->defer_tick = cur;
    budget = FD_GRPC_SERVER_SERVICE_BUDGET;
    while( server->defer_tick<cur && budget && ticks-- ) {
      ulong  tick = (ulong)( server->defer_tick+1L );
      uint * head = &server->defer_bucket[ ( tick/FD_GRPC_SERVER_DEFER_WHEEL ) & ( FD_GRPC_SERVER_DEFER_LAPS-1UL ) ]
                                         [ tick & ( FD_GRPC_SERVER_DEFER_WHEEL-1UL ) ];
      while( *head!=UINT_MAX && budget-- ) {
        fd_grpc_server_conn_t * conn = server->conn + *head;
        *head = conn->defer_next;
        conn->deferred   = 0;
        conn->defer_next = UINT_MAX;
        if( !conn->active ) continue;
        fd_grpc_server_conn_flush( conn );
        if( !conn->active ) continue;
        int framed = !!fd_h2_rbuf_used_sz( conn->rbuf_tx );
        if( conn->sock>=0 ) fd_grpc_server_conn_tx_try( conn, now_nanos );
        if( !conn->active ) continue;
        conn->backlog = (uchar)( ( !!fd_grpc_server_conn_has_output( conn ) ) | ( ( conn->sock>=0 ) & ( !!fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) ) );
        if( conn->backlog )     fd_grpc_server_conn_mark( conn );
        else if( !framed )      fd_grpc_server_conn_burst_release( conn, 0 );
        if( conn->sock>=0 ) fd_grpc_server_conn_arm( conn );
      }
      if( *head!=UINT_MAX ) break;
      server->defer_tick++;
    }
  }
#endif
}

int
fd_grpc_server_tx_pending( fd_grpc_server_t const * server ) {
  return server->tx_pending_cnt>0UL;
}

void
fd_grpc_server_shutdown( fd_grpc_server_t * server ) {
  /* The listening socket stays open, since a caller may run under a
     policy that forbids closing it.  Connections accepted from now on
     are refused with a GOAWAY. */
  server->shutdown = 1;
  ulong conn_max   = server->params.max_conn_cnt;
  ulong stream_max = server->params.max_stream_cnt;
  for( ulong i=0UL; i<conn_max; i++ ) {
    fd_grpc_server_conn_t * conn = server->conn+i;
    if( !conn->active ) continue;
    fd_grpc_server_conn_goaway( conn, FD_H2_SUCCESS );
    fd_grpc_server_conn_mark( conn );
    for( ulong j=0UL; j<stream_max; j++ ) {
      fd_grpc_server_stream_t * s = conn->stream+j;
      if( s->state==FD_GRPC_SERVER_STREAM_FREE ) continue;
      /* Queued messages are dropped: a shutdown must not wait on a
         client that is not reading. */
      if( ( s->state==FD_GRPC_SERVER_STREAM_ACTIVE ) | ( !!s->ref_cnt ) ) {
        FD_GRPC_SERVER_DROP_OUTPUT( s, FD_GRPC_STATUS_UNAVAILABLE, "server is shutting down" );
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
  return fd_grpc_server_conn_init( server, -1, 0U, now_nanos );
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
    if( FD_LIKELY( conn->active ) ) { fd_grpc_server_conn_flush( conn ); fd_grpc_server_conn_mark( conn ); }
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
    fd_grpc_server_conn_mark( conn );
  }
  return take;
}

/* Sockets ************************************************************/

#if FD_HAS_HOSTED

/* The layout reserves 16 bytes per descriptor slot */
FD_STATIC_ASSERT( sizeof(struct epoll_event)<=16UL, layout );

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
  /* Several servers in one process may share the port, in which case
     the kernel spreads incoming connections over them. */
  if( FD_UNLIKELY( 0!=setsockopt( sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(int) ) ) ) {
    FD_LOG_WARNING(( "setsockopt(SO_REUSEPORT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
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
    /* The kernel clamps the backlog to net.core.somaxconn; connections
     beyond the pool are accepted and refused, so the backlog never
     holds a client that nobody will answer. */
  if( FD_UNLIKELY( 0!=listen( sock, 4096 ) ) ) {
    FD_LOG_WARNING(( "listen() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( sock );
    return -1;
  }
    if( server->epoll_fd<0 ) {
    server->epoll_fd = epoll_create1( EPOLL_CLOEXEC );
    if( FD_UNLIKELY( server->epoll_fd<0 ) ) {
      FD_LOG_WARNING(( "epoll_create1 failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      close( sock );
      return -1;
    }
    server->epoll_owned = 1;
  }
  /* The listen socket is the one member with a NULL pointer. */
  struct epoll_event ev = { .events = EPOLLIN, .data = { .ptr = NULL } };
  if( FD_UNLIKELY( 0!=epoll_ctl( server->epoll_fd, EPOLL_CTL_ADD, sock, &ev ) ) ) {
    FD_LOG_WARNING(( "epoll_ctl(EPOLL_CTL_ADD, listen) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
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

/* fd_grpc_server_listen_arm sets whether the listen socket is watched.
   A level-triggered listen socket whose accept keeps failing (no
   descriptors, no memory) is ready on every poll, so it is taken out
   of the set for FD_GRPC_SERVER_LISTEN_REARM_NANOS instead of spinning
   the server and the waker. */

static void
fd_grpc_server_listen_arm( fd_grpc_server_t * server,
                           int                armed ) {
  if( server->epoll_fd<0 ) return;
  struct epoll_event ev = { .events = armed ? EPOLLIN : 0U, .data = { .ptr = NULL } };
  if( FD_UNLIKELY( 0!=epoll_ctl( server->epoll_fd, EPOLL_CTL_MOD, server->listen_fd, &ev ) ) )
    server->metrics.poll_error_cnt++;
}

static void
fd_grpc_server_accept( fd_grpc_server_t * server,
                       long               now ) {
  if( FD_UNLIKELY( server->listen_rearm_nanos ) ) return;
  ulong refused = 0UL;
  for( ulong k=0UL; k<FD_GRPC_SERVER_ACCEPT_BUDGET; k++ ) {
    struct sockaddr_in peer;
    socklen_t          peer_sz = sizeof(peer);
    int sock = accept4( server->listen_fd, fd_type_pun( &peer ), &peer_sz, SOCK_NONBLOCK );
    if( sock<0 ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EWOULDBLOCK ) ) return;
      if( errno==ECONNABORTED || errno==EINTR ) continue;
      /* Logged on the powers of two and counted exactly. */
      server->metrics.accept_error_cnt++;
      ulong n = server->metrics.accept_error_cnt;
      if( FD_UNLIKELY( !( n & ( n-1UL ) ) ) )
        FD_LOG_WARNING(( "accept4() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      server->listen_rearm_nanos = now + FD_GRPC_SERVER_LISTEN_REARM_NANOS;
      fd_grpc_server_listen_arm( server, 0 );
      return;
    }
    if( FD_UNLIKELY( server->shutdown || server->free_head==UINT_MAX ) ) {
      fd_grpc_server_refuse( sock );
      server->metrics.accept_refused_cnt++;
      if( ++refused>=FD_GRPC_SERVER_REFUSE_BUDGET ) return;
      continue;
    }
    uint peer_ip4 = ( peer_sz>=sizeof(peer) && peer.sin_family==AF_INET ) ? peer.sin_addr.s_addr : 0U;
    if( FD_UNLIKELY( server->params.max_conn_per_addr && peer_ip4 ) ) {
      fd_grpc_server_addr_t const * a = addr_map_query( server->addr_map, peer_ip4, NULL );
      if( FD_UNLIKELY( a && a->cnt>=server->params.max_conn_per_addr ) ) {
        fd_grpc_server_refuse( sock );
        server->metrics.accept_refused_addr_cnt++;
        if( ++refused>=FD_GRPC_SERVER_REFUSE_BUDGET ) return;
        continue;
      }
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
    if( FD_UNLIKELY( !fd_grpc_server_conn_init( server, sock, peer_ip4, now ) ) ) return;
  }
}

/* fd_grpc_server_refuse answers a connection the server does not take,
   for lack of a slot or because its address holds its share: the
   server preface and a GOAWAY, so that the client learns it was turned
   away instead of waiting on a silent socket. */

static void
fd_grpc_server_refuse( int sock ) {
  uchar buf[ 9UL+sizeof(fd_h2_goaway_t) ];
  fd_h2_frame_hdr_t settings = {
    .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_SETTINGS, 0UL ),
    .flags       = 0U,
    .r_stream_id = 0U
  };
  fd_h2_goaway_t goaway = {
    .hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_GOAWAY, 8UL ),
      .flags       = 0U,
      .r_stream_id = 0U
    },
    .last_stream_id = 0U,
    .error_code     = fd_uint_bswap( FD_H2_ERR_ENHANCE_YOUR_CALM )
  };
  memcpy( buf,     &settings, 9UL              );
  memcpy( buf+9UL, &goaway,   sizeof(goaway)   );
  struct iovec  iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
  sendmsg( sock, &msg, MSG_NOSIGNAL|MSG_DONTWAIT );
  /* Bytes the client sent while it waited in the backlog would turn
     the close into a reset that can discard the GOAWAY on its side.
     Drained with the same recvmsg call and flags a connection uses,
     which is what the tile's sandbox admits on a client socket. */
  uchar scratch[ 4096 ];
  struct iovec  riov = { .iov_base = scratch, .iov_len = sizeof(scratch) };
  struct msghdr rmsg = { .msg_iov = &riov, .msg_iovlen = 1 };
  for( ulong i=0UL; i<8UL; i++ ) if( recvmsg( sock, &rmsg, MSG_NOSIGNAL|MSG_DONTWAIT )<=0L ) break;
  close( sock );
}

/* fd_grpc_server_conn_tx_try hands the connection's queued bytes to
   the kernel.  A send the kernel refuses leaves the bytes queued and
   the connection counted as pending; EPOLLOUT is armed by
   fd_grpc_server_conn_arm. */

static void
fd_grpc_server_conn_tx_try( fd_grpc_server_conn_t * conn,
                            long                    now ) {
  if( !fd_h2_rbuf_used_sz( conn->rbuf_tx ) ) return;
  ulong tx_lo0 = conn->rbuf_tx->lo_off;
  int err = fd_h2_rbuf_sendmsg( conn->rbuf_tx, conn->sock, MSG_NOSIGNAL|MSG_DONTWAIT );
  if( FD_UNLIKELY( err && err!=EAGAIN && err!=EWOULDBLOCK && err!=EINTR ) ) {
    fd_grpc_server_conn_release( conn );
    return;
  }
    /* Bytes the kernel took free ring space that pending stream output
     may have been waiting for. */
  if( conn->rbuf_tx->lo_off!=tx_lo0 ) { conn->tx_nanos = now; fd_grpc_server_conn_mark( conn ); }
}

/* fd_grpc_server_conn_arm brings the connection's epoll interest in
   line with its rings: readable while the receive ring has room, and
   writable while the send ring holds bytes the kernel has not taken. */

static void
fd_grpc_server_conn_arm( fd_grpc_server_conn_t * conn ) {
  fd_grpc_server_t * server = conn->server;
  int want_in  = fd_h2_rbuf_free_sz( conn->rbuf_rx )>0UL;
  int want_out = fd_h2_rbuf_used_sz( conn->rbuf_tx )>0UL;
  if( want_out!=conn->tx_pending ) {
    conn->tx_pending = (uchar)want_out;
    if( want_out ) server->tx_pending_cnt++; else server->tx_pending_cnt--;
  }
  if( server->epoll_fd<0 ) return;
  if( want_in==conn->in_armed && want_out==conn->out_armed ) return;
  struct epoll_event ev = {
    .events = (uint)( ( want_in ? EPOLLIN : 0U ) | ( want_out ? EPOLLOUT : 0U ) ),
    .data   = { .ptr = conn }
  };
  if( FD_UNLIKELY( 0!=epoll_ctl( server->epoll_fd, EPOLL_CTL_MOD, conn->sock, &ev ) ) ) {
    server->metrics.poll_error_cnt++;
    ulong n = server->metrics.poll_error_cnt;
    if( FD_UNLIKELY( !( n & ( n-1UL ) ) ) )
      FD_LOG_WARNING(( "epoll_ctl(EPOLL_CTL_MOD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return;
  }
  conn->in_armed  = (uchar)want_in;
  conn->out_armed = (uchar)want_out;
}

static void
fd_grpc_server_conn_io( fd_grpc_server_conn_t * conn,
                        long                    now,
                        uint                    events ) {
  fd_grpc_server_t * server = conn->server;
  /* Nothing more can be exchanged on a socket in error or hung up,
     and one with full receive and empty send rings would otherwise
     make no syscall that notices. */
  if( FD_UNLIKELY( events & (uint)( EPOLLERR|EPOLLHUP ) ) ) {
    fd_grpc_server_conn_release( conn );
    return;
  }
  fd_grpc_server_conn_tx_try( conn, now );
  if( FD_UNLIKELY( !conn->active ) ) return;
  ulong rx_hi0 = conn->rbuf_rx->hi_off;
  int err = fd_h2_rbuf_recvmsg( conn->rbuf_rx, conn->sock, MSG_NOSIGNAL|MSG_DONTWAIT );
  if( FD_UNLIKELY( err && err!=EAGAIN && err!=EWOULDBLOCK && err!=EINTR ) ) {
    fd_grpc_server_conn_release( conn );
    return;
  }
  if( conn->rbuf_rx->hi_off!=rx_hi0 ) conn->rx_nanos = now;
  if( FD_UNLIKELY( fd_grpc_server_conn_preface( conn )<=0 ) ) {
    if( conn->active ) fd_grpc_server_conn_arm( conn );
    return;
  }
  fd_h2_rx( conn->h2, conn->rbuf_rx, conn->rbuf_tx,
            server->frame_scratch, server->params.max_frame_sz,
            &fd_grpc_server_h2_callbacks );
  if( FD_UNLIKELY( !conn->active ) ) return;
  /* A connection waiting out the send interval answers control frames
     now and keeps its stream output for its tick */
  if( conn->deferred && !conn->backlog && !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING ) ) fd_grpc_server_conn_flush_control( conn );
  else                                                                                         fd_grpc_server_conn_flush( conn );
  if( FD_UNLIKELY( !conn->active ) ) return;
  fd_grpc_server_conn_tx_try( conn, now );
  if( FD_UNLIKELY( !conn->active ) ) return;
  fd_grpc_server_conn_arm( conn );
}

int
fd_grpc_server_poll( fd_grpc_server_t * server,
                     int                timeout_millis,
                     long               now_nanos ) {
  /* Move anything the app queued since the last call into the send
     rings and on to the kernel. */
  fd_grpc_server_service( server, now_nanos );
  if( FD_UNLIKELY( server->epoll_fd<0 ) ) return 0;
  struct epoll_event * evs = server->epoll_events;
  int total = 0;
  for( ulong batch=0UL; batch<FD_GRPC_SERVER_POLL_BATCH_MAX; batch++ ) {
    int n = epoll_pwait( server->epoll_fd, evs, (int)FD_GRPC_SERVER_EPOLL_EVENT_MAX, timeout_millis, NULL );
    timeout_millis = 0;
    if( FD_UNLIKELY( n<0 ) ) {
      if( FD_UNLIKELY( errno!=EINTR ) ) {
        server->metrics.poll_error_cnt++;
        ulong e = server->metrics.poll_error_cnt;
        if( FD_UNLIKELY( !( e & ( e-1UL ) ) ) )
          FD_LOG_WARNING(( "epoll_wait() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
      break;
    }
    long now = now_nanos;
    server->now = now;
    for( int i=0; i<n; i++ ) {
      fd_grpc_server_conn_t * conn = evs[i].data.ptr;
      if( !conn ) {
        if( FD_LIKELY( server->listen_fd>=0 ) ) fd_grpc_server_accept( server, now );
        continue;
      }
      if( FD_UNLIKELY( !conn->active || conn->sock<0 ) ) continue;
      fd_grpc_server_conn_io( conn, now, evs[i].events );
    }
    total += n;
    if( n<(int)FD_GRPC_SERVER_EPOLL_EVENT_MAX ) break;
  }
  fd_grpc_server_service( server, now_nanos );
  return total;
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
                     int                timeout_millis,
                     long               now_nanos ) {
  (void)timeout_millis;
  fd_grpc_server_service( server, now_nanos );
  return 0;
}

#endif /* FD_HAS_HOSTED */
