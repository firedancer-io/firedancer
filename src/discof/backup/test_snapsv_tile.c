/* Deterministic snapsv tests (mocking io_uring) */

#define FD_TILE_TEST
#include "fd_snapsv_tile.c"
#include "../../disco/topo/fd_topob.h"
#include "../../util/tmpl/fd_unit_test.c"
#include <stdatomic.h>
#include <sys/mman.h>

#define SNAP_MAX  32
#define CONN_MAX  32
#define SQ_DEPTH 128
#define CQ_DEPTH 128

#define SNAP_FILE_SZ (65536UL)
#define SNAP_RES_MAX (SNAP_FILE_SZ+4096UL)

static uchar snap_file[ SNAP_FILE_SZ ];

struct fake_client {
  uchar req[ 2048 ];
  uchar res[ SNAP_RES_MAX ];
  uint  req_sz;
  uint  req_cur;
  uint  res_sz;
  uint  conn_alive:1;
  ulong req_cnt;

# define DEFER_SQE_MAX 32
  fd_io_uring_sqe_t defer_sqe[ DEFER_SQE_MAX ];
  uint              defer_sqe_cnt;
};

typedef struct fake_client fake_client_t;

static fake_client_t *
fake_client_init( fake_client_t * fake ) {
  fake->req_sz        = 0;
  fake->req_cur       = 0;
  fake->res_sz        = 0;
  fake->conn_alive    = 0;
  fake->defer_sqe_cnt = 0;
  fake->req_cnt       = 0;
  return fake;
}

static void
fake_client_post_cqe( fd_io_uring_cq_t * cq,
                      ulong              user_data,
                      int                res,
                      uint               flags ) {
  uint head = atomic_load_explicit( cq->khead, memory_order_relaxed );
  uint tail = atomic_load_explicit( cq->ktail, memory_order_relaxed );
  FD_TEST( tail-head < cq->depth );
  uint mask = cq->depth-1U;
  fd_io_uring_cqe_t * cqe = &cq->cqes[ tail&mask ];
  *cqe = (fd_io_uring_cqe_t) {
    .user_data = user_data,
    .res       = res,
    .flags     = flags
  };
  atomic_store_explicit( cq->ktail, tail+1U, memory_order_release );
}

static void
fake_client_handle_sqe( fake_client_t *     fake,
                        fd_io_uring_sqe_t * sqe,
                        fd_io_uring_cq_t *  cq ) {
  switch( sqe->opcode ) {
  case FD_IORING_OP_NOP:
    break;
  case FD_IORING_OP_ACCEPT:
    if( !fake->conn_alive ) {
      fake->conn_alive = 1;
      fake_client_post_cqe( cq, sqe->user_data, 1, 0U );
    } else {
      FD_TEST( fake->defer_sqe_cnt < DEFER_SQE_MAX );
      fake->defer_sqe[ fake->defer_sqe_cnt++ ] = *sqe;
    }
    break;
  case FD_IORING_OP_RECV:
    FD_TEST( sqe->flags & FD_IOSQE_FIXED_FILE );
    FD_TEST( sqe->len > 0L );
    if( fake->req_cur < fake->req_sz ) {
      ulong len = fd_ulong_min( sqe->len, fake->req_sz - fake->req_cur );
      FD_TEST( len<=INT_MAX );
      if( !(sqe->msg_flags & MSG_TRUNC) ) {
        memcpy( (void *)sqe->addr, fake->req + fake->req_cur, len );
      }
      if( !( sqe->msg_flags & MSG_PEEK ) ) {
        fake->req_cur += (uint)len;
      }
      fake_client_post_cqe( cq, sqe->user_data, (int)len, 0U );
    } else {
      fake_client_post_cqe( cq, sqe->user_data, -1, 0U );
    }
    break;
  case FD_IORING_OP_SEND: {
    FD_TEST( sqe->flags & FD_IOSQE_FIXED_FILE );
    ulong len = fd_ulong_min( sqe->len, sizeof(fake->res)-fake->res_sz );
    FD_TEST( len==sqe->len );
    memcpy( fake->res+fake->res_sz, (void const *)sqe->addr, len );
    fake->res_sz += (uint)len;
    fake_client_post_cqe( cq, sqe->user_data, (int)len, 0U );
    break;
  }
  case FD_IORING_OP_READ_FIXED: {
    FD_TEST( sqe->flags & FD_IOSQE_FIXED_FILE );
    FD_TEST( sqe->fd==(int)FIXED_FD_CNT ); /* pool_idx 0 */
    ulong off = fd_ulong_min( sqe->off, SNAP_FILE_SZ );
    ulong len = fd_ulong_min( sqe->len, SNAP_FILE_SZ-off );
    memcpy( (void *)sqe->addr, snap_file+off, len );
    fake_client_post_cqe( cq, sqe->user_data, (int)len, 0U );
    break;
  }
  case FD_IORING_OP_LINK_TIMEOUT:
    fake_client_post_cqe( cq, sqe->user_data, 0, 0U );
    break;
  case FD_IORING_OP_FUTEX_WAIT:
    fake_client_post_cqe( cq, sqe->user_data, -EAGAIN, 0U );
    break;
  default:
    FD_LOG_CRIT(( "unhandled SQE op type %u", sqe->opcode ));
  }
}

static void
fake_client_drive( fake_client_t *    fake,
                   fd_io_uring_sq_t * sq,
                   fd_io_uring_cq_t * cq ) {
  uint sq_head = atomic_load_explicit( sq->khead, memory_order_relaxed );
  uint sq_mask = sq->depth-1U;
  for(;;) {
    fd_io_uring_sqe_t * sqe = &sq->sqes[ sq_head&sq_mask ];
    if( sqe->opcode==FD_IORING_OP_NOP ) break;
    fake_client_handle_sqe( fake, sqe, cq );
    memset( sqe, 0, sizeof(*sqe) );
    sq_head++;
  }
  atomic_store_explicit( sq->khead, sq_head, memory_order_release );
  sq->sqe_head = sq_head; /* the real submit path does this in after_credit */
}

static void
fake_client_req( fake_client_t * fake,
                 char const *    req ) {
  fake_client_init( fake );
  ulong req_len = strlen( req );
  FD_TEST( req_len < sizeof(fake->req) );
  memcpy( fake->req, req, req_len );
  fake->req_sz = (uint)req_len;
}

static void
fake_client_res( fake_client_t const * fake,
                 char *                res,
                 ulong *               res_len ) {
  FD_TEST( fake->res_sz<=*res_len );
  memcpy( res, fake->res, fake->res_sz );
  *res_len = fake->res_sz;
}

#define OUT_DEPTH (128UL)

struct snapsv_env {
  fd_snapsv_t * ctx;
  fd_wksp_t *   wksp;
  void *        wksp_mem;
  ulong         wksp_sz;

  fd_stem_context_t stem[1];
  fd_stem_tile_in_t stem_in[1];
  ulong             stem_fseq;
  fd_frag_meta_t *  out_mcache[1];
  ulong             out_seq[1];
  ulong             out_depth[1];
  int               out_reliable[1];
};

typedef struct snapsv_env snapsv_env_t;

/* The clock advances by a heartbeat period per step, so that a download
   long enough to span several steps also emits progress events. */

#define STEP_NANOS (FD_SNAPSV_SYNC_PERIOD)

static void
snapsv_step( snapsv_env_t *  env,
             fake_client_t * fake,
             uint            iter ) {
  fd_snapsv_t * ctx = env->ctx;
  long now = (long)iter*STEP_NANOS;
  int charge_busy = 0;
  after_credit_pre( ctx, env->stem, &charge_busy, now );
  fake_client_drive( fake, ctx->ring->sq, ctx->ring->cq );
  after_credit_post( ctx, env->stem, &charge_busy, now );
}

/* curl stops as soon as the response is on the wire, before the send
   completion is reaped. */

static void
curl( snapsv_env_t * env,
      char *         res,
      ulong *        res_len,
      char const *   req ) {
  fd_snapsv_t * ctx = env->ctx;
  fake_client_t fake;
  fake_client_req( &fake, req );
  for( uint iter=0U; iter<1000U && !fake.res_sz; iter++ ) {
    int charge_busy = 0;
    after_credit_pre( ctx, env->stem, &charge_busy, (long)iter*STEP_NANOS );
    fake_client_drive( &fake, ctx->ring->sq, ctx->ring->cq );
    if( fake.res_sz ) break;
    after_credit_post( ctx, env->stem, &charge_busy, (long)iter*STEP_NANOS );
  }
  FD_TEST( fake.res_sz );
  fake_client_res( &fake, res, res_len );
}

/* curl_session runs until the client falls idle, driving the conn through
   its whole lifecycle instead of stopping at the first response.  Needs a
   ring, because the conn teardown drops fds through it. */

static void
curl_session( snapsv_env_t * env,
              char *         res,
              ulong *        res_len,
              char const *   req ) {
  fake_client_t fake;
  fake_client_req( &fake, req );
  for( uint iter=0U; iter<256U; iter++ ) snapsv_step( env, &fake, iter );
  fake_client_res( &fake, res, res_len );
}

static void
snap_name( char        out[ static FD_SNAP_NAME_MAX ],
           ulong       slot,
           ulong       base_slot,
           uchar const hash[ static 32 ],
           int         is_zstd ) {
  char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( hash, NULL, hash_b58 );
  char * p = fd_cstr_init( out );
  if( base_slot!=ULONG_MAX ) {
    p = fd_cstr_append_cstr( p, "incremental-snapshot-" );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, base_slot, fd_ulong_base10_dig_cnt( base_slot ) );
    p = fd_cstr_append_char( p, '-' );
  } else {
    p = fd_cstr_append_cstr( p, "snapshot-" );
  }
  p = fd_cstr_append_ulong_as_text( p, 0, 0, slot, fd_ulong_base10_dig_cnt( slot ) );
  p = fd_cstr_append_char( p, '-' );
  p = fd_cstr_append_cstr( p, hash_b58 );
  p = fd_cstr_append_cstr( p, is_zstd ? ".tar.zst" : ".tar" );
  fd_cstr_fini( p );
}

static snapsv_env_t *
snapsv_env_create( void ) {
  static fd_topo_t topo[1];
  fd_topob_new( topo, "test" );

  ulong  wksp_sz  = 64UL<<20;
  void * wksp_mem = mmap( NULL, wksp_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( wksp_mem!=MAP_FAILED );
  ulong part_max = fd_wksp_part_max_est( wksp_sz, 64UL<<10 );
  ulong data_max = fd_wksp_data_max_est( wksp_sz, part_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( wksp_mem, "snapsv", 1U, part_max, data_max ) );
  FD_TEST( wksp );
  FD_TEST( !fd_shmem_join_anonymous( "snapsv", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, wksp_mem,
                                     FD_SHMEM_NORMAL_PAGE_SZ, wksp_sz>>FD_SHMEM_NORMAL_LG_PAGE_SZ ) );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "snapsv" );
  topo_wksp->wksp = wksp;

  fd_topo_link_t * link = fd_topob_link( topo, "snapmk_out", "snapsv", 128UL, sizeof(fd_snapmk_msg_t), 1UL );
  fd_topo_obj_t * mcache_obj = &topo->objs[ link->mcache_obj_id ];
  void * mcache_mem  = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), 1UL );
  link->mcache       = fd_mcache_join( fd_mcache_new( mcache_mem, 128UL, 0UL, 0UL ) ); FD_TEST( link->mcache );
  mcache_obj->offset = fd_wksp_gaddr_fast( wksp, mcache_mem );

  fd_topo_obj_t * dcache_obj = &topo->objs[ link->dcache_obj_id ];
  ulong  dcache_data_sz = fd_dcache_req_data_sz( sizeof(fd_snapmk_msg_t), 128UL, 1UL, 1 );
  void * dcache_mem     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
  link->dcache          = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) ); FD_TEST( link->dcache );
  dcache_obj->offset    = fd_wksp_gaddr_fast( wksp, dcache_mem );

  fd_topo_link_t * out_link = fd_topob_link( topo, "snapsv_out", "snapsv", OUT_DEPTH, sizeof(fd_snapsv_msg_t), 1UL );
  fd_topo_obj_t * out_mcache_obj = &topo->objs[ out_link->mcache_obj_id ];
  void * out_mcache_mem  = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( OUT_DEPTH, 0UL ), 1UL );
  out_link->mcache       = fd_mcache_join( fd_mcache_new( out_mcache_mem, OUT_DEPTH, 0UL, 0UL ) ); FD_TEST( out_link->mcache );
  out_mcache_obj->offset = fd_wksp_gaddr_fast( wksp, out_mcache_mem );

  fd_topo_obj_t * out_dcache_obj = &topo->objs[ out_link->dcache_obj_id ];
  ulong  out_dcache_data_sz = fd_dcache_req_data_sz( sizeof(fd_snapsv_msg_t), OUT_DEPTH, 1UL, 1 );
  void * out_dcache_mem     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( out_dcache_data_sz, 0UL ), 1UL );
  out_link->dcache          = fd_dcache_join( fd_dcache_new( out_dcache_mem, out_dcache_data_sz, 0UL ) ); FD_TEST( out_link->dcache );
  out_dcache_obj->offset    = fd_wksp_gaddr_fast( wksp, out_dcache_mem );

  fd_topo_tile_t * tile = fd_topob_tile( topo, "snapsv", "snapsv", "snapsv", 0UL, 0, 0, 0, 0 );
  fd_topob_tile_in( topo, "snapsv", 0UL, "snapsv", "snapmk_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapsv", 0UL, "snapsv_out", 0UL );
  tile->snapsv.snap_max             = SNAP_MAX;
  tile->snapsv.conn_max             = CONN_MAX;
  tile->snapsv.send_buffer_size_kib = 4UL;
  tile->snapsv.idle_timeout_millis  = 1000UL;
  tile->snapsv.send_timeout_millis  = 1000UL;

  fd_snapsv_t * ctx = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( tile ), 1UL );
  FD_TEST( ctx );
  topo->objs[ tile->tile_obj_id ].offset = fd_wksp_gaddr_fast( wksp, ctx );
  memset( ctx, 0, sizeof(*ctx) );
  ctx->conn_max              = CONN_MAX;
  ctx->conn0_fd_idx          = FIXED_FD_CNT+SNAP_MAX;
  ctx->accept_addr.ss_family = AF_INET;
  ctx->ring->ioring_fd     = -1;
  ctx->ring->sq->depth     = (uint)snapsv_sq_depth( tile );
  ctx->ring->cq->depth     = (uint)snapsv_cq_depth( tile );
  ctx->ring->sq->khead     = calloc( 4UL, sizeof(atomic_uint) ); FD_TEST( ctx->ring->sq->khead );
  ctx->ring->sq->ktail     = ctx->ring->sq->khead+1;
  ctx->ring->sq->kflags    = ctx->ring->sq->khead+2;
  ctx->ring->sq->kdropped  = ctx->ring->sq->khead+3;
  ctx->ring->sq->sqes      = calloc( ctx->ring->sq->depth, sizeof(fd_io_uring_sqe_t) ); FD_TEST( ctx->ring->sq->sqes );
  ctx->ring->cq->khead     = calloc( 3UL, sizeof(atomic_uint) ); FD_TEST( ctx->ring->cq->khead );
  ctx->ring->cq->ktail     = ctx->ring->cq->khead+1;
  ctx->ring->cq->koverflow = ctx->ring->cq->khead+2;
  ctx->ring->cq->cqes      = calloc( ctx->ring->cq->depth, sizeof(fd_io_uring_cqe_t) ); FD_TEST( ctx->ring->cq->cqes );

  unprivileged_init( topo, tile );

  snapsv_env_t * env = aligned_alloc(
      alignof(snapsv_env_t), fd_ulong_align_up( sizeof(snapsv_env_t), alignof(snapsv_env_t) ) );
  FD_TEST( env );
  *env = (snapsv_env_t) {
    .ctx      = ctx,
    .wksp     = wksp,
    .wksp_mem = wksp_mem,
    .wksp_sz  = wksp_sz
  };

  env->stem_in[0]    = (fd_stem_tile_in_t){ .fseq = &env->stem_fseq };
  env->out_mcache[0] = out_link->mcache;
  env->out_depth[0]  = OUT_DEPTH;
  env->stem[0]       = (fd_stem_context_t) {
    .mcaches      = env->out_mcache,
    .seqs         = env->out_seq,
    .depths       = env->out_depth,
    .out_reliable = env->out_reliable,
    .in           = env->stem_in
  };
  return env;
}

static void
snapsv_env_add_snap( snapsv_env_t * env,
                     ulong          slot,
                     ulong          base_slot,
                     ulong          sz,
                     uchar const    hash[ static 32 ],
                     int            is_zstd ) {
  fd_snapsv_t *     ctx   = env->ctx;
  ulong             chunk = ctx->in[ 0 ].chunk0;
  fd_snapmk_msg_t * msg   = fd_chunk_to_laddr( ctx->in[ 0 ].mem, chunk );
  msg->found = (fd_snapmk_msg_found_t) {
    .slot         = slot,
    .base_slot    = base_slot,
    .sz           = sz,
    .pool_idx     = 0U,
    .fs_timestamp = LONG_MAX
  };
  snap_name( msg->found.name, slot, base_slot, hash, is_zstd );
  returnable_frag( ctx, 0UL, 0UL, FD_SNAPMK_MSG_FOUND, chunk,
                   sizeof(fd_snapmk_msg_found_t), 0UL, 0UL, 0UL, NULL );
}

static void
snapsv_env_del_snap( snapsv_env_t * env,
                     ulong          slot,
                     ulong          base_slot ) {
  fd_snapsv_t *     ctx   = env->ctx;
  ulong             chunk = ctx->in[ 0 ].chunk0;
  fd_snapmk_msg_t * msg   = fd_chunk_to_laddr( ctx->in[ 0 ].mem, chunk );
  msg->deleted = (fd_snapmk_msg_deleted_t) {
    .slot      = slot,
    .base_slot = base_slot,
    .pool_idx  = 0U
  };
  returnable_frag( ctx, 0UL, 0UL, FD_SNAPMK_MSG_DELETED, chunk,
                   sizeof(fd_snapmk_msg_deleted_t), 0UL, 0UL, 0UL, NULL );
}

static void
snapsv_env_destroy( snapsv_env_t * env ) {
  fd_snapsv_t * ctx = env->ctx;
  free( ctx->ring->cq->cqes  );
  free( ctx->ring->cq->khead );
  free( ctx->ring->sq->sqes  );
  free( ctx->ring->sq->khead );
  FD_TEST( !fd_shmem_leave_anonymous( env->wksp, NULL ) );
  munmap( env->wksp_mem, env->wksp_sz );
  free( env );
}

FD_UNIT_TEST( snap_head ) {
  snapsv_env_t * env = snapsv_env_create();
  char res[ 128 ];
  ulong res_len = sizeof(res);
  curl( env, res, &res_len,
      "HEAD / HTTP/1.1\r\n"
      "\r\n" );
  FD_TEST( res_len==45UL );
  FD_TEST( !memcmp( res,
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Length: 0\r\n"
      "\r\n",
      res_len ) );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_get ) {
  snapsv_env_t * env = snapsv_env_create();
  char res[ 128 ];
  ulong res_len = sizeof(res);
  curl( env, res, &res_len,
      "GET /does-not-exist HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "\r\n" );
  FD_TEST( res_len==45UL );
  FD_TEST( !memcmp( res,
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Length: 0\r\n"
      "\r\n",
      res_len ) );
  snapsv_env_destroy( env );
}

static void
expect_res_env( snapsv_env_t * env,
                char const *   req,
                char const *   expected ) {
  char  res[ 256 ];
  ulong res_len = sizeof(res);
  curl( env, res, &res_len, req );
  FD_TEST( res_len==strlen( expected ) );
  FD_TEST( !memcmp( res, expected, res_len ) );
}

static void
expect_res( char const * req,
            char const * expected ) {
  snapsv_env_t * env = snapsv_env_create();
  expect_res_env( env, req, expected );
  snapsv_env_destroy( env );
}

#define RES_404_KEEPALIVE  "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
#define RES_404_CLOSE      "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
#define RES_400_CLOSE      "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

/* Only the request head is consumed off the socket, so a request that
   announces a body has to be refused and the conn closed.  Otherwise the
   body is read back as the next request. */

FD_UNIT_TEST( req_body_rejected ) {
  expect_res(
      "GET / HTTP/1.1\r\n"
      "Content-Length: 5\r\n"
      "\r\n"
      "hello",
      RES_400_CLOSE );
}

FD_UNIT_TEST( req_chunked_rejected ) {
  expect_res(
      "GET / HTTP/1.1\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n",
      RES_400_CLOSE );
}

FD_UNIT_TEST( req_dup_content_length ) {
  expect_res(
      "GET / HTTP/1.1\r\n"
      "Content-Length: 0\r\n"
      "Content-Length: 5\r\n"
      "\r\n",
      RES_400_CLOSE );
}

FD_UNIT_TEST( req_content_length_zero ) {
  expect_res(
      "GET /nope HTTP/1.1\r\n"
      "Content-Length: 0\r\n"
      "\r\n",
      RES_404_KEEPALIVE );
}

FD_UNIT_TEST( req_dup_range ) {
  expect_res(
      "GET /nope HTTP/1.1\r\n"
      "Range: bytes=0-1\r\n"
      "Range: bytes=2-3\r\n"
      "\r\n",
      RES_400_CLOSE );
}

FD_UNIT_TEST( req_connection_close ) {
  expect_res(
      "GET /nope HTTP/1.1\r\n"
      "Connection: keep-alive, close\r\n"
      "\r\n",
      RES_404_CLOSE );
}

FD_UNIT_TEST( req_dup_connection ) {
  expect_res(
      "GET /nope HTTP/1.1\r\n"
      "Connection: close\r\n"
      "Connection: keep-alive\r\n"
      "\r\n",
      RES_400_CLOSE );
}

FD_UNIT_TEST( req_obs_fold ) {
  expect_res(
      "GET /nope HTTP/1.1\r\n"
      "Range: bytes=0-1\r\n"
      " ,bytes=2-3\r\n"
      "\r\n",
      RES_400_CLOSE );
}

FD_UNIT_TEST( req_http10 ) {
  expect_res(
      "GET /nope HTTP/1.0\r\n"
      "\r\n",
      RES_404_CLOSE );
}

FD_UNIT_TEST( req_http10_keepalive ) {
  expect_res(
      "GET /nope HTTP/1.0\r\n"
      "Connection: keep-alive\r\n"
      "\r\n",
      RES_404_KEEPALIVE );
}

static void
expect_redirect( snapsv_env_t * env,
                 char const *   req,
                 char const *   location ) {
  char   expected[ 256 ];
  char * p = fd_cstr_init( expected );
  p = fd_cstr_append_cstr( p, "HTTP/1.1 302 Found\r\nLocation: /" );
  p = fd_cstr_append_cstr( p, location );
  p = fd_cstr_append_cstr( p, "\r\nContent-Length: 0\r\n\r\n" );
  fd_cstr_fini( p );
  expect_res_env( env, req, expected );
}

FD_UNIT_TEST( redirect_full ) {
  snapsv_env_t * env = snapsv_env_create();
  uchar hash[ 32 ]; memset( hash, 0xa1, sizeof(hash) );
  snapsv_env_add_snap( env, 100UL, ULONG_MAX, 4096UL, hash, 1 );

  char name[ FD_SNAP_NAME_MAX ];
  snap_name( name, 100UL, ULONG_MAX, hash, 1 );
  expect_redirect( env, "GET /snapshot.tar.zst HTTP/1.1\r\n\r\n", name );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( redirect_incremental ) {
  snapsv_env_t * env = snapsv_env_create();
  uchar hash[ 32 ]; memset( hash, 0xb2, sizeof(hash) );
  snapsv_env_add_snap( env, 200UL, 100UL, 4096UL, hash, 1 );

  char name[ FD_SNAP_NAME_MAX ];
  snap_name( name, 200UL, 100UL, hash, 1 );
  expect_redirect( env, "GET /incremental-snapshot.tar.bz2 HTTP/1.1\r\n\r\n", name );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( redirect_newest ) {
  snapsv_env_t * env = snapsv_env_create();
  uchar old_hash[ 32 ]; memset( old_hash, 0xc3, sizeof(old_hash) );
  uchar new_hash[ 32 ]; memset( new_hash, 0xd4, sizeof(new_hash) );
  snapsv_env_add_snap( env, 100UL, ULONG_MAX, 4096UL, old_hash, 1 );
  snapsv_env_add_snap( env, 300UL, ULONG_MAX, 4096UL, new_hash, 1 );

  char name[ FD_SNAP_NAME_MAX ];
  snap_name( name, 300UL, ULONG_MAX, new_hash, 1 );
  expect_redirect( env, "GET /snapshot.tar.zst HTTP/1.1\r\n\r\n", name );
  snapsv_env_destroy( env );
}

/* A full snapshot does not satisfy a request for an incremental one. */

FD_UNIT_TEST( redirect_wrong_kind ) {
  snapsv_env_t * env = snapsv_env_create();
  uchar hash[ 32 ]; memset( hash, 0xa1, sizeof(hash) );
  snapsv_env_add_snap( env, 100UL, ULONG_MAX, 4096UL, hash, 1 );
  expect_res_env( env, "GET /incremental-snapshot.tar.zst HTTP/1.1\r\n\r\n", RES_404_KEEPALIVE );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( redirect_no_snapshot ) {
  expect_res( "GET /snapshot.tar.zst HTTP/1.1\r\n\r\n", RES_404_KEEPALIVE );
}

static void
expect_snap_404( char const * req_name,
                 uchar const  registered_hash[ static 32 ],
                 int          registered_zstd ) {
  snapsv_env_t * env = snapsv_env_create();
  snapsv_env_add_snap( env, 100UL, ULONG_MAX, 4096UL, registered_hash, registered_zstd );

  char   req[ 256 ];
  char * p = fd_cstr_init( req );
  p = fd_cstr_append_cstr( p, "GET /" );
  p = fd_cstr_append_cstr( p, req_name );
  p = fd_cstr_append_cstr( p, " HTTP/1.1\r\n\r\n" );
  fd_cstr_fini( p );

  expect_res_env( env, req, RES_404_KEEPALIVE );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_hash_mismatch ) {
  uchar hash[ 32 ]; memset( hash, 0xa1, sizeof(hash) );
  uchar other[ 32 ]; memset( other, 0xa2, sizeof(other) );
  char name[ FD_SNAP_NAME_MAX ];
  snap_name( name, 100UL, ULONG_MAX, other, 1 );
  expect_snap_404( name, hash, 1 );
}

FD_UNIT_TEST( snap_zstd_mismatch ) {
  uchar hash[ 32 ]; memset( hash, 0xa1, sizeof(hash) );
  char name[ FD_SNAP_NAME_MAX ];
  snap_name( name, 100UL, ULONG_MAX, hash, 0 );
  expect_snap_404( name, hash, 1 );
}

FD_UNIT_TEST( snap_deleted ) {
  snapsv_env_t * env = snapsv_env_create();
  uchar hash[ 32 ]; memset( hash, 0xa1, sizeof(hash) );
  snapsv_env_add_snap( env, 100UL, ULONG_MAX, 4096UL, hash, 1 );
  snapsv_env_del_snap( env, 100UL, ULONG_MAX );
  expect_res_env( env, "GET /snapshot.tar.zst HTTP/1.1\r\n\r\n", RES_404_KEEPALIVE );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_unknown_slot ) {
  uchar hash[ 32 ]; memset( hash, 0xa1, sizeof(hash) );
  char name[ FD_SNAP_NAME_MAX ];
  snap_name( name, 999UL, ULONG_MAX, hash, 1 );
  expect_snap_404( name, hash, 1 );
}

static snapsv_env_t *
snap_env( char name[ static FD_SNAP_NAME_MAX ],
          int  is_zstd ) {
  snapsv_env_t * env = snapsv_env_create();
  uchar hash[ 32 ]; memset( hash, 0xa1, sizeof(hash) );
  snapsv_env_add_snap( env, 100UL, ULONG_MAX, SNAP_FILE_SZ, hash, is_zstd );
  snap_name( name, 100UL, ULONG_MAX, hash, is_zstd );
  return env;
}

static void
expect_snap_res( snapsv_env_t * env,
                 char const *   method,
                 char const *   name,
                 char const *   headers,
                 char const *   expected ) {
  char req[ 256 ];
  fd_cstr_printf( req, sizeof(req), NULL, "%s /%s HTTP/1.1\r\n%s\r\n", method, name, headers );
  expect_res_env( env, req, expected );
}

FD_UNIT_TEST( snap_res_zstd ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );
  char expected[ 256 ];
  fd_cstr_printf( expected, sizeof(expected), NULL,
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: application/zstd\r\n"
      "Accept-Ranges: bytes\r\n"
      "Content-Length: %lu\r\n"
      "\r\n", SNAP_FILE_SZ );
  expect_snap_res( env, "GET", name, "", expected );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_res_tar ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 0 );
  char expected[ 256 ];
  fd_cstr_printf( expected, sizeof(expected), NULL,
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: application/x-tar\r\n"
      "Accept-Ranges: bytes\r\n"
      "Content-Length: %lu\r\n"
      "\r\n", SNAP_FILE_SZ );
  expect_snap_res( env, "GET", name, "", expected );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_res_range ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );
  char expected[ 256 ];
  fd_cstr_printf( expected, sizeof(expected), NULL,
      "HTTP/1.1 206 Partial Content\r\n"
      "Content-Type: application/zstd\r\n"
      "Accept-Ranges: bytes\r\n"
      "Content-Range: bytes 10-19/%lu\r\n"
      "Content-Length: 10\r\n"
      "\r\n",
      SNAP_FILE_SZ );
  expect_snap_res( env, "GET", name, "Range: bytes=10-19\r\n", expected );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_res_suffix_range ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );
  char expected[ 256 ];
  fd_cstr_printf( expected, sizeof(expected), NULL,
      "HTTP/1.1 206 Partial Content\r\n"
      "Content-Type: application/zstd\r\n"
      "Accept-Ranges: bytes\r\n"
      "Content-Range: bytes %lu-%lu/%lu\r\n"
      "Content-Length: 100\r\n"
      "\r\n", SNAP_FILE_SZ-100UL, SNAP_FILE_SZ-1UL, SNAP_FILE_SZ );
  expect_snap_res( env, "GET", name, "Range: bytes=-100\r\n", expected );
  snapsv_env_destroy( env );
}

/* A range header on a HEAD request is ignored. */

FD_UNIT_TEST( snap_res_head ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );
  char expected[ 256 ];
  fd_cstr_printf( expected, sizeof(expected), NULL,
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: application/zstd\r\n"
      "Accept-Ranges: bytes\r\n"
      "Content-Length: %lu\r\n"
      "\r\n",
      SNAP_FILE_SZ );
  expect_snap_res( env, "HEAD", name, "Range: bytes=10-19\r\n", expected );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_res_unsatisfiable ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );
  char expected[ 256 ];
  fd_cstr_printf( expected, sizeof(expected), NULL,
      "HTTP/1.1 416 Range Not Satisfiable\r\n"
      "Content-Range: bytes */%lu\r\n"
      "Content-Length: 0\r\n"
      "\r\n", SNAP_FILE_SZ );
  expect_snap_res( env, "GET", name, "Range: bytes=99999-\r\n", expected );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_res_bad_range ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );
  expect_snap_res( env, "GET", name, "Range: items=0-9\r\n",
      "HTTP/1.1 400 Bad Request\r\n"
      "Content-Length: 0\r\n"
      "\r\n" );
  snapsv_env_destroy( env );
}

static void
expect_session( char const * req,
                char const * expected ) {
  snapsv_env_t * env = snapsv_env_create();

  char  res[ 512 ];
  ulong res_len = sizeof(res);
  curl_session( env, res, &res_len, req );
  FD_TEST( res_len==strlen( expected ) );
  FD_TEST( !memcmp( res, expected, res_len ) );

  FD_TEST( !env->ctx->conn_cnt );
  FD_TEST( env->ctx->conn_free_cnt==CONN_MAX-1U ); /* one held by the pending accept */
  FD_TEST( env->ctx->iobuf_free_cnt==2U*CONN_MAX );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( conn_keepalive ) {
  expect_session(
      "GET /nope HTTP/1.1\r\n"
      "\r\n"
      "GET /nope HTTP/1.1\r\n"
      "\r\n",
      RES_404_KEEPALIVE RES_404_KEEPALIVE );
}

/* A conn that asked to be closed must not serve the pipelined request
   that follows. */

FD_UNIT_TEST( conn_close_pipelined ) {
  expect_session(
      "GET /nope HTTP/1.1\r\n"
      "Connection: close\r\n"
      "\r\n"
      "GET /nope HTTP/1.1\r\n"
      "\r\n",
      RES_404_CLOSE );
}

FD_UNIT_TEST( conn_close_after_body_rejected ) {
  expect_session(
      "GET /nope HTTP/1.1\r\n"
      "Content-Length: 5\r\n"
      "\r\n"
      "hello"
      "GET /nope HTTP/1.1\r\n"
      "\r\n",
      RES_400_CLOSE );
}

static char const *
res_body( char const * res,
          ulong        res_len,
          ulong *      out_len ) {
  for( ulong i=0UL; i+4UL<=res_len; i++ ) {
    if( !memcmp( res+i, "\r\n\r\n", 4UL ) ) {
      *out_len = res_len-i-4UL;
      return res+i+4UL;
    }
  }
  FD_LOG_ERR(( "response has no header terminator" ));
}

static void
expect_snap_body( char const * headers,
                  ulong        off,
                  ulong        sz ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );

  char req[ 256 ];
  fd_cstr_printf( req, sizeof(req), NULL, "GET /%s HTTP/1.1\r\n%s\r\n", name, headers );

  static char res[ SNAP_RES_MAX ];
  ulong res_len = sizeof(res);
  curl_session( env, res, &res_len, req );

  ulong        body_len;
  char const * body = res_body( res, res_len, &body_len );
  FD_TEST( body_len==sz );
  FD_TEST( !memcmp( body, snap_file+off, sz ) );

  FD_TEST( !env->ctx->conn_cnt );
  FD_TEST( env->ctx->iobuf_free_cnt==2U*CONN_MAX );
  snapsv_env_destroy( env );
}

FD_UNIT_TEST( snap_body_full ) {
  expect_snap_body( "", 0UL, SNAP_FILE_SZ );
}

FD_UNIT_TEST( snap_body_range ) {
  expect_snap_body( "Range: bytes=100-199\r\n", 100UL, 100UL );
}

/* A range that spans several send buffers. */

FD_UNIT_TEST( snap_body_range_multi ) {
  expect_snap_body( "Range: bytes=1000-9999\r\n", 1000UL, 9000UL );
}

FD_UNIT_TEST( snap_body_suffix_range ) {
  expect_snap_body( "Range: bytes=-4200\r\n", SNAP_FILE_SZ-4200UL, 4200UL );
}

/* Deleting a snapshot mid transfer must abort the download rather than
   splice in whatever now occupies the map slot. */

FD_UNIT_TEST( snap_body_deleted_midway ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );
  fd_snapsv_t * ctx = env->ctx;

  char req[ 256 ];
  fd_cstr_printf( req, sizeof(req), NULL, "GET /%s HTTP/1.1\r\n\r\n", name );

  fake_client_t fake;
  fake_client_req( &fake, req );
  uint iter = 0U;
  for( ; iter<64U && fake.res_sz<=4096U; iter++ ) snapsv_step( env, &fake, iter );
  FD_TEST( fake.res_sz>4096U );

  snapsv_env_del_snap( env, 100UL, ULONG_MAX );
  for( uint end=iter+256U; iter<end; iter++ ) snapsv_step( env, &fake, iter );

  static char res[ SNAP_RES_MAX ];
  ulong res_len = sizeof(res);
  fake_client_res( &fake, res, &res_len );

  ulong        body_len;
  char const * body = res_body( res, res_len, &body_len );
  FD_TEST( body_len && body_len<SNAP_FILE_SZ );
  FD_TEST( !memcmp( body, snap_file, body_len ) );

  FD_TEST( !ctx->conn_cnt );
  FD_TEST( ctx->iobuf_free_cnt==2U*CONN_MAX );
  snapsv_env_destroy( env );
}

/* shoveling_conn returns the conn that is currently streaming a
   snapshot body, or NULL if there is none. */

static snapsv_conn_t *
shoveling_conn( fd_snapsv_t * ctx ) {
  for( ulong i=0UL; i<ctx->conn_max; i++ ) {
    if( ctx->conn0[ i ].state==CONN_STATE_RES_SHOVEL ) return &ctx->conn0[ i ];
  }
  return NULL;
}

/* A snapshot read that is already submitted when the snapshot is
   deleted may land after snapmk recycled the file.  Those bytes must
   not reach the client. */

FD_UNIT_TEST( snap_body_deleted_read_inflight ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );
  fd_snapsv_t * ctx = env->ctx;

  char req[ 256 ];
  fd_cstr_printf( req, sizeof(req), NULL, "GET /%s HTTP/1.1\r\n\r\n", name );

  fake_client_t fake;
  fake_client_req( &fake, req );
  uint iter = 0U;
  for( ; iter<64U && fake.res_sz<=4096U; iter++ ) snapsv_step( env, &fake, iter );
  FD_TEST( fake.res_sz>4096U );

  /* stop with a read SQE submitted but not yet executed by the fake */
  snapsv_conn_t * conn = shoveling_conn( ctx );
  FD_TEST( conn );
  int charge_busy = 0;
  for( uint end=iter+64U; iter<end; iter++ ) {
    after_credit_pre( ctx, env->stem, &charge_busy, (long)iter*STEP_NANOS );
    if( conn->disk_inflight ) break;
    fake_client_drive( &fake, ctx->ring->sq, ctx->ring->cq );
    after_credit_post( ctx, env->stem, &charge_busy, (long)iter*STEP_NANOS );
  }
  FD_TEST( conn->disk_inflight );

  /* delete the snapshot and rewrite the file underneath the in-flight
     read, the way snapmk recycles a pool slot */
  static uchar snap_file_orig[ SNAP_FILE_SZ ];
  memcpy( snap_file_orig, snap_file, SNAP_FILE_SZ );
  snapsv_env_del_snap( env, 100UL, ULONG_MAX );
  memset( snap_file, 0xa5, SNAP_FILE_SZ );

  fake_client_drive( &fake, ctx->ring->sq, ctx->ring->cq );
  after_credit_post( ctx, env->stem, &charge_busy, (long)iter*STEP_NANOS );
  for( uint end=iter+256U; iter<end; iter++ ) snapsv_step( env, &fake, iter );

  static char res[ SNAP_RES_MAX ];
  ulong res_len = sizeof(res);
  fake_client_res( &fake, res, &res_len );

  ulong        body_len;
  char const * body = res_body( res, res_len, &body_len );
  FD_TEST( body_len && body_len<SNAP_FILE_SZ );
  FD_TEST( !memcmp( body, snap_file_orig, body_len ) );

  memcpy( snap_file, snap_file_orig, SNAP_FILE_SZ );

  FD_TEST( !ctx->conn_cnt );
  FD_TEST( ctx->iobuf_free_cnt==2U*CONN_MAX );
  snapsv_env_destroy( env );
}

struct snapsv_event {
  fd_snapsv_msg_snap_t msg;
  int                  som;
  int                  eom;
};

typedef struct snapsv_event snapsv_event_t;

static ulong
snapsv_events( snapsv_env_t *   env,
               snapsv_event_t * out,
               ulong            out_max ) {
  ulong cnt = env->out_seq[ 0 ];
  FD_TEST( cnt<=out_max );
  FD_TEST( cnt<=OUT_DEPTH ); /* else the mcache wrapped and events were lost */
  for( ulong seq=0UL; seq<cnt; seq++ ) {
    fd_frag_meta_t const * mline = env->out_mcache[ 0 ] + fd_mcache_line_idx( seq, OUT_DEPTH );
    FD_TEST( mline->sig==FD_SNAPSV_MSG_SNAP );
    FD_TEST( mline->sz ==sizeof(fd_snapsv_msg_snap_t) );
    out[ seq ].msg = *(fd_snapsv_msg_snap_t const *)fd_chunk_to_laddr_const( env->ctx->out.mem, mline->chunk );
    out[ seq ].som = !!fd_frag_meta_ctl_som( mline->ctl );
    out[ seq ].eom = !!fd_frag_meta_ctl_eom( mline->ctl );
  }
  return cnt;
}

FD_UNIT_TEST( event_download ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );

  char req[ 256 ];
  fd_cstr_printf( req, sizeof(req), NULL, "GET /%s HTTP/1.1\r\nRange: bytes=1000-9999\r\n\r\n", name );
  static char res[ SNAP_RES_MAX ];
  ulong res_len = sizeof(res);
  curl_session( env, res, &res_len, req );

  snapsv_event_t event[ OUT_DEPTH ];
  ulong event_cnt = snapsv_events( env, event, OUT_DEPTH );
  FD_TEST( event_cnt>=2UL );

  FD_TEST( event[ 0 ].som && !event[ 0 ].eom );
  FD_TEST( !event[ event_cnt-1UL ].som && event[ event_cnt-1UL ].eom );

  for( ulong i=0UL; i<event_cnt; i++ ) {
    fd_snapsv_msg_snap_t const * msg = &event[ i ].msg;
    FD_TEST( msg->slot     ==100UL );
    FD_TEST( msg->base_slot==ULONG_MAX );
    FD_TEST( msg->snap_sz  ==SNAP_FILE_SZ );
    FD_TEST( msg->req_off  ==1000UL );
    FD_TEST( msg->req_sz   ==9000UL );
    FD_TEST( msg->req_cur <=msg->req_sz );
    FD_TEST( msg->key.req_seq ==0UL );
    FD_TEST( msg->key.slot_idx< CONN_MAX );
    if( i ) FD_TEST( msg->req_cur>=event[ i-1UL ].msg.req_cur );
  }

  fd_snapsv_msg_snap_t const * last = &event[ event_cnt-1UL ].msg;
  FD_TEST( last->req_cur   ==9000UL );
  FD_TEST( last->close_kind==FD_SNAPSV_CLOSE_DONE );
  FD_TEST( last->resp_ts    >0L );

  snapsv_env_destroy( env );
}

/* An aborted transfer still has to close out its row. */

FD_UNIT_TEST( event_aborted ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );

  char req[ 256 ];
  fd_cstr_printf( req, sizeof(req), NULL, "GET /%s HTTP/1.1\r\n\r\n", name );

  fake_client_t fake;
  fake_client_req( &fake, req );
  uint iter = 0U;
  for( ; iter<64U && fake.res_sz<=4096U; iter++ ) snapsv_step( env, &fake, iter );
  snapsv_env_del_snap( env, 100UL, ULONG_MAX );
  for( uint end=iter+256U; iter<end; iter++ ) snapsv_step( env, &fake, iter );

  snapsv_event_t event[ OUT_DEPTH ];
  ulong event_cnt = snapsv_events( env, event, OUT_DEPTH );
  FD_TEST( event_cnt>=2UL );

  fd_snapsv_msg_snap_t const * last = &event[ event_cnt-1UL ].msg;
  FD_TEST( event[ event_cnt-1UL ].eom );
  FD_TEST( last->req_cur<last->req_sz );
  FD_TEST( last->close_kind==FD_SNAPSV_CLOSE_ABORT );

  snapsv_env_destroy( env );
}

/* HEAD, error, and redirect responses do not open an access log row. */

FD_UNIT_TEST( event_no_body ) {
  char name[ FD_SNAP_NAME_MAX ];
  snapsv_env_t * env = snap_env( name, 1 );

  char req[ 256 ];
  fd_cstr_printf( req, sizeof(req), NULL,
      "HEAD /%s HTTP/1.1\r\n"
      "\r\n"
      "GET /nope HTTP/1.1\r\n"
      "\r\n"
      "GET /snapshot.tar.zst HTTP/1.1\r\n"
      "\r\n",
      name );
  static char res[ SNAP_RES_MAX ];
  ulong res_len = sizeof(res);
  curl_session( env, res, &res_len, req );

  FD_TEST( !env->out_seq[ 0 ] );
  snapsv_env_destroy( env );
}

static void
expect_range( char const * value,
              ulong        object_sz,
              ulong        expect0,
              ulong        expect1 ) {
  ulong range0 = ULONG_MAX;
  ulong range1 = ULONG_MAX;
  FD_TEST( !parse_range_header( value, strlen( value ), object_sz, &range0, &range1 ) );
  FD_TEST( range0==expect0 );
  FD_TEST( range1==expect1 );
}

static void
expect_range_err( char const * value,
                  ulong        object_sz,
                  int          expect_err ) {
  ulong range0, range1;
  FD_TEST( parse_range_header( value, strlen( value ), object_sz, &range0, &range1 )==expect_err );
}

FD_UNIT_TEST( range_basic ) {
  expect_range( "bytes=0-99",    1000UL, 0UL,   100UL  );
  expect_range( "bytes=10-19",   1000UL, 10UL,  20UL   );
  expect_range( "bytes=0-0",     1000UL, 0UL,   1UL    );
  expect_range( "bytes=999-999", 1000UL, 999UL, 1000UL );
}

/* An open ended or over long range is clamped to the end of the file. */

FD_UNIT_TEST( range_open_ended ) {
  expect_range( "bytes=0-",      1000UL, 0UL,   1000UL );
  expect_range( "bytes=500-",    1000UL, 500UL, 1000UL );
  expect_range( "bytes=500-9999",1000UL, 500UL, 1000UL );
  expect_range( "bytes=0-999",   1000UL, 0UL,   1000UL );
}

FD_UNIT_TEST( range_suffix ) {
  expect_range( "bytes=-100",  1000UL, 900UL, 1000UL );
  expect_range( "bytes=-1",    1000UL, 999UL, 1000UL );
  expect_range( "bytes=-1000", 1000UL, 0UL,   1000UL );
  expect_range( "bytes=-9999", 1000UL, 0UL,   1000UL );
}

FD_UNIT_TEST( range_whitespace ) {
  expect_range( " \tbytes=0-9", 1000UL, 0UL, 10UL );
  expect_range( "bytes=0-9\t ", 1000UL, 0UL, 10UL );
  expect_range( "BYTES=0-9",    1000UL, 0UL, 10UL );
}

FD_UNIT_TEST( range_malformed ) {
  expect_range_err( "",                1000UL, -1 );
  expect_range_err( "bytes=",          1000UL, -1 );
  expect_range_err( "bytes=-",         1000UL, -1 );
  expect_range_err( "bytes=0",         1000UL, -1 );
  expect_range_err( "items=0-9",       1000UL, -1 );
  expect_range_err( "bytes 0-9",       1000UL, -1 );
  expect_range_err( "bytes=0-9,20-29", 1000UL, -1 );
  expect_range_err( "bytes=x-9",       1000UL, -1 );
  expect_range_err( "bytes=0-x",       1000UL, -1 );
  expect_range_err( "bytes=-0x10",     1000UL, -1 );
}

FD_UNIT_TEST( range_overflow ) {
  expect_range_err( "bytes=99999999999999999999999-",  1000UL, -1 );
  expect_range_err( "bytes=0-99999999999999999999999", 1000UL, -1 );
  expect_range_err( "bytes=18446744073709551616-",     1000UL, -1 );
  expect_range_err( "bytes=18446744073709551615-",     1000UL, -2 );
}

/* -2 asks the caller for a 416 rather than a 400. */

FD_UNIT_TEST( range_unsatisfiable ) {
  expect_range_err( "bytes=1000-", 1000UL, -2 );
  expect_range_err( "bytes=1000-1010", 1000UL, -2 );
  expect_range_err( "bytes=20-10", 1000UL, -2 );
  expect_range_err( "bytes=-0", 1000UL, -2 );
  expect_range_err( "bytes=0-9", 0UL, -2 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 1UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 1UL ) );

  for( ulong i=0UL; i<SNAP_FILE_SZ; i+=sizeof(ulong) ) {
    FD_STORE( ulong, snap_file+i, fd_ulong_hash( i ) );
  }

  (void)rlimit_file_cnt;
  (void)populate_allowed_seccomp;
  (void)populate_allowed_fds;
  (void)privileged_init;

  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
