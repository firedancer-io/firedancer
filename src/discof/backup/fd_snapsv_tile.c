/* The snapsv tile is a HTTP file server that serves local snapshots to
   remote peers.

   This tile uses io_uring for network and file I/O.

   snapsv is fully cooperatively scheduled using io_uring waits.
   It wakes on network events, timeouts, file I/O completions, and
   futex wakes (new tango messages).

   Scheduling is event-driven (lazy).  Apart from the initial accept op,
   every other op is triggered by a completion. */

#define _GNU_SOURCE
#include "fd_snapmk_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../util/net/fd_ip6.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/futex.h>
#include "../../util/io_uring/fd_io_uring.h"
#include "../../util/io_uring/fd_io_uring_setup.h"
#include "../../util/io_uring/fd_io_uring_register.h"
#include "../../third_party/picohttpparser/picohttpparser.h"
#include "generated/fd_snapsv_tile_seccomp.h"

/* Open addressed hash map of snapshots */

struct snap_key {
  ulong slot;
  ulong base_slot; /* ULONG_MAX if full snap */
};
typedef struct snap_key snap_key_t;

struct snap_entry {
  snap_key_t key;
  uchar hash[ 32 ];
  ulong sz;
  int   fd;
  uint  locked:1;
  uint  is_zstd:1;
};
typedef struct snap_entry snap_entry_t;

static ulong
snap_key_hash( snap_key_t const * key,
               ulong              seed ) {
  /* xxHash3 adapted */
  ulong k0 = key->base_slot;
  ulong k1 = key->slot;

  ulong lo = k0 ^ (0x6782737bea4239b9UL + seed);
  ulong hi = k1 ^ (0xaf56bc3b0996523aUL - seed);

  uint128 product = (uint128)lo * (uint128)hi;
  ulong   fold    = (ulong)product ^ (ulong)( product>>64 );

  ulong acc = 16UL + fd_ulong_bswap( lo ) + hi + fold;
  acc ^= acc >> 37;
  acc *= 0x165667919E3779F9UL;
  acc ^= acc >> 32;
  return acc;
}

#define MAP_NAME            snap_map
#define MAP_ELE_T           snap_entry_t
#define MAP_KEY_T           snap_key_t
#define MAP_KEY_EQ(k0,k1)   (((k0)->slot==(k1)->slot) & ((k0)->base_slot==(k1)->base_slot))
#define MAP_KEY_HASH(k,s)   snap_key_hash( (k), (s) )
#define MAP_ELE_IS_FREE(e)  (((e)->key.slot==ULONG_MAX) & ((e)->key.base_slot==ULONG_MAX))
#define MAP_ELE_FREE(c,e)   ((e)->key=(snap_key_t){ULONG_MAX,ULONG_MAX})
#define MAP_ELE_MOVE(c,d,s) do { MAP_ELE_T * _src = (s); (*(d)) = *_src; _src->key = (snap_key_t){ULONG_MAX,ULONG_MAX}; } while(0)
#include "../../util/tmpl/fd_map_slot.c"

/* Tile state */

#define IN_LINK_MAX 1 /* cannot trivially grow */

/* 8 ought to be enough ... The SQE/CQE count per conn is limited due
   to fixed depth pipelining. */
#define SQE_PER_CONN (8UL)
#define CQE_PER_CONN (8UL)

/* io_uring fixed file indices */

#define FIXED_FD_LISTEN (0U) /* TCP listen socket */
#define FIXED_FD_CNT    (1U)

/* HTTP request head limits.  The request head is accumulated in the
   conn's iobuf, therefore it can never exceed the iobuf size. */

#define REQ_HEADER_MAX (64UL)  /* max number of request headers */

/* conn state */

#define CONN_STATE_FREE          (0U) /* conn slot is unused */
#define CONN_STATE_REQ_PEEK      (1U) /* peeking request bytes */
#define CONN_STATE_REQ_SKIP      (2U) /* consume in-flight, head still incomplete */
#define CONN_STATE_REQ_DONE      (3U) /* consume in-flight, head complete */
#define CONN_STATE_RES_WRITE_ERR (4U) /* writing response header */
#define CONN_STATE_RES_WRITE_HDR (5U) /* writing response header */
#define CONN_STATE_RES_REDIRECT  (6U) /* writing snap redirect */
#define CONN_STATE_RES_SHOVEL    (7U) /* pipelinined snap data RX & TX */

struct snapsv_conn {
  uint state;     /* CONN_STATE_{...} */
  uint iobuf_idx; /* iobuf for networking, UINT_MAX if none */
  uint rdbuf_idx; /* iobuf for disk read, UINT_MAX if none */
  uint rdbuf_len; /* completed bytes in rdbuf */

  uint sick:1;          /* force close after current request? */
  uint head:1;          /* HEAD request? */
  uint range:1;         /* range request? */
  uint incremental:1;   /* incremental snap requested? */
  uint disk_inflight:1; /* file read pending completion */
  uint net_inflight:1;  /* tcp send pending completion */
  uint closing:1;       /* close once shovel operations drain? */
  uint http_err;        /* http status code */

  struct {
    uint len;
  } req;

  struct {
    uint sent;
    uint len;
  } res;

  struct {
    snap_key_t key;
    snap_entry_t * slot;
    ulong range0; /* next file offset to read */
    ulong range1; /* exclusive response body end */
  } snap;

  long                 request_start_nanos;
  fd_kernel_timespec_t idle_timeout;

  fd_ip6_addr_t peer_ip;
  ushort        peer_port;
};

typedef struct snapsv_conn snapsv_conn_t;

struct fd_snapsv {

  /* io_uring */
  fd_io_uring_t ring[1];
  void *        ring_shmem;

  /* I/O buffers */
  uchar * iobuf0;
  uint *  iobuf_free;
  uint    iobuf_free_cnt;
  uint    iobuf_sz;

  /* TCP sockets */
  int             listen_fd;
  uint            conn0_fd_idx; /* io_uring file index */
  ulong           conn_cnt;
  ulong           conn_max;
  snapsv_conn_t * conn0;
  uint *          conn_free;
  uint            conn_free_cnt;
  long            idle_timeout_nanos;
  fd_kernel_timespec_t send_timeout;

  /* Conn accept */
  uint                    accept_inflight:1;
  struct sockaddr_storage accept_addr;
  socklen_t               accept_addr_len;

  /* snapshot hashmap */
  snap_map_t snap_map[1];
  ulong      snap_cnt_full;
  ulong      snap_cnt_incr;
  ulong      snap_max;

  /* cache: newest snaps */
  snap_entry_t * newest_full;
  snap_entry_t * newest_incr;

  /* snapshot files */
  int dir_fd;

  /* tango input links */
  uchar in_kind[ IN_LINK_MAX ];
  struct {
    void * mem;
    ulong  chunk0;
    ulong  wmark;
    ulong  mtu;

    fd_frag_meta_t const * mcache;
    ulong const *          seq_prod; /* mcache->seq[0] */
    ulong                  seq_cons; /* last consumed seq */
    uint                   depth;
    uint                   futex_armed:1;
  } in[ IN_LINK_MAX ];

};

typedef struct fd_snapsv fd_snapsv_t;

/* snapsv_udata_t represents io_uring user data. */

union snapsv_udata {
  ulong user_data;

  struct __attribute__((packed)) {
    uint  conn_idx;
    uchar op;
#define UDATA_OP_ACCEPT       ((uchar)0) /* accept new conn */
#define UDATA_OP_PEEK         ((uchar)1) /* read request bytes */
#define UDATA_OP_CONSUME_FRAG ((uchar)2) /* consume request frag */
#define UDATA_OP_CONSUME_TAIL ((uchar)3) /* consume complete request */
#define UDATA_OP_WRITE_HDR    ((uchar)4) /* write response header */
#define UDATA_OP_SHOVEL_DISK  ((uchar)5) /* read snapshot data */
#define UDATA_OP_SHOVEL_NET   ((uchar)6) /* send snapshot data */
#define UDATA_OP_FUTEX        ((uchar)7) /* wait for tango frag */
#define UDATA_OP_TIMEOUT      ((uchar)8) /* linked socket op timeout */
  };
};

typedef union snapsv_udata snapsv_udata_t;

FD_STATIC_ASSERT( sizeof(snapsv_udata_t)==sizeof(ulong), layout );

#define IN_KIND_SNAPMK 0

static ulong
scratch_align( void ) {
  return FD_SHMEM_NORMAL_PAGE_SZ;
}

FD_FN_PURE static ulong
snapsv_fd_max( fd_topo_tile_t const * tile ) {
  return FIXED_FD_CNT + tile->snapsv.snap_max + tile->snapsv.conn_max;
}

FD_FN_PURE static ulong
snapsv_map_ele_max( fd_topo_tile_t const * tile ) {
  return fd_ulong_pow2_up( tile->snapsv.snap_max );
}

FD_FN_PURE static ulong
snapsv_sq_depth( fd_topo_tile_t const * tile ) {
  return fd_ulong_pow2_up( SQE_PER_CONN*tile->snapsv.conn_max );
}

FD_FN_PURE static ulong
snapsv_cq_depth( fd_topo_tile_t const * tile ) {
  return fd_ulong_pow2_up( CQE_PER_CONN*tile->snapsv.conn_max );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong sq_depth = snapsv_sq_depth( tile );
  ulong cq_depth = snapsv_cq_depth( tile );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapsv_t),      sizeof(fd_snapsv_t) );
  l = FD_LAYOUT_APPEND( l, fd_io_uring_shmem_align(), fd_io_uring_shmem_footprint( sq_depth, cq_depth ) );
  l = FD_LAYOUT_APPEND( l, snap_map_align(),          snap_map_footprint( snapsv_map_ele_max( tile ) ) );
  l = FD_LAYOUT_APPEND( l, alignof(int),              snapsv_fd_max( tile )*sizeof(int) );
  l = FD_LAYOUT_APPEND( l, alignof(snapsv_conn_t),    tile->snapsv.conn_max*sizeof(snapsv_conn_t) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),             tile->snapsv.conn_max*sizeof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),             tile->snapsv.conn_max * 2 * sizeof(uint) );
  l = FD_LAYOUT_APPEND( l, FD_SHMEM_NORMAL_PAGE_SZ,   tile->snapsv.conn_max * (tile->snapsv.send_buffer_size_kib<<11) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* snapsv_listen creates the TCP listen socket */

static int
snapsv_listen( fd_ip6_addr_t const * listen_addr,
               ushort                listen_port,
               ulong                 conn_max ) {
  int ip4 = fd_ip6_addr_is_ip4_mapped( listen_addr->addr ) && !listen_addr->scope_id;

  int sock_fd = socket( ip4 ? AF_INET : AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==sock_fd ) ) {
    FD_LOG_ERR(( "socket(AF_INET%s,SOCK_STREAM) failed (%i-%s)", ip4 ? "" : "6", errno, fd_io_strerror( errno ) ));
  }

  /* recover quickly from restart, if there are lingering TIME_WAIT conns */
  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_REUSEADDR) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  /* load balancing across multiple snapsv tiles */
  optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sock_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_REUSEPORT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  union {
    struct sockaddr_in  ip4;
    struct sockaddr_in6 ip6;
  } addr = {0};
  ulong addr_sz;

  if( ip4 ) {
    addr.ip4 = (struct sockaddr_in){
      .sin_family      = AF_INET,
      .sin_port        = fd_ushort_bswap( listen_port ),
      .sin_addr.s_addr = fd_ip6_addr_to_ip4( listen_addr->addr )
    };
    addr_sz = sizeof(struct sockaddr_in);
  } else {
    int v6only = 0;
    if( FD_UNLIKELY( -1==setsockopt( sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(int) ) ) ) {
      FD_LOG_ERR(( "setsockopt(IPPROTO_IPV6,IPV6_V6ONLY) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    addr.ip6 = (struct sockaddr_in6){
      .sin6_family   = AF_INET6,
      .sin6_port     = fd_ushort_bswap( listen_port ),
      .sin6_scope_id = listen_addr->scope_id
    };
    memcpy( addr.ip6.sin6_addr.s6_addr, listen_addr->addr, 16UL );
    addr_sz = sizeof(struct sockaddr_in6);
  }

  char addr_cstr[ FD_IP6_ADDR_CSTR_MAX ];
  if( FD_UNLIKELY( -1==bind( sock_fd, fd_type_pun( &addr ), (uint)addr_sz ) ) ) {
    FD_LOG_ERR(( "bind(%s:%u) failed (%i-%s)",
                 fd_ip6_addr_cstr( addr_cstr, listen_addr ), listen_port,
                 errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==listen( sock_fd, (int)conn_max ) ) ) {
    FD_LOG_ERR(( "listen() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "snapshot server listening at %shttp://%s:%u%s",
                  fd_log_style_bold(), fd_ip6_addr_cstr( addr_cstr, listen_addr ), listen_port,
                  fd_log_style_normal() ));

  return sock_fd;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  ulong fd_max   = snapsv_fd_max( tile );
  ulong sq_depth = snapsv_sq_depth( tile );
  ulong cq_depth = snapsv_cq_depth( tile );
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapsv_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapsv_t),      sizeof(fd_snapsv_t) );
  void *        ring_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_io_uring_shmem_align(), fd_io_uring_shmem_footprint( sq_depth, cq_depth ) );
  void *        map_mem  = FD_SCRATCH_ALLOC_APPEND( l, snap_map_align(),          snap_map_footprint( snapsv_map_ele_max( tile ) ) );
  int *         fd_table = FD_SCRATCH_ALLOC_APPEND( l, alignof(int),              fd_max*sizeof(int) );
  /*               */(void)FD_SCRATCH_ALLOC_APPEND( l, alignof(snapsv_conn_t),    tile->snapsv.conn_max*sizeof(snapsv_conn_t) );
  /*               */(void)FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),             tile->snapsv.conn_max*sizeof(uint) );
  /*               */(void)FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),             tile->snapsv.conn_max*2UL*sizeof(uint) );
  uchar *       iobuf0   = FD_SCRATCH_ALLOC_APPEND( l, FD_SHMEM_NORMAL_PAGE_SZ,   tile->snapsv.conn_max*(tile->snapsv.send_buffer_size_kib<<11) );

  memset( ctx, 0, sizeof(fd_snapsv_t) );
  memset( fd_table, 0xff, fd_max*sizeof(int) );

  /* TCP listen socket */

  ctx->conn_max  = tile->snapsv.conn_max;
  ctx->listen_fd = snapsv_listen( &tile->snapsv.listen_addr, tile->snapsv.listen_port, tile->snapsv.conn_max );

  /* io_uring setup */

  ctx->ring_shmem = ring_mem;
  fd_io_uring_params_t params[1];
  fd_io_uring_params_init( params, (uint)sq_depth );
  params->flags |= FD_IORING_SETUP_COOP_TASKRUN | FD_IORING_SETUP_DEFER_TASKRUN;

  if( FD_UNLIKELY( !fd_io_uring_init_shmem( ctx->ring, params, ctx->ring_shmem, sq_depth, cq_depth ) ) ) {
    FD_LOG_ERR(( "fd_io_uring_init_shmem failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* registered buffer to help with DMA */

  struct iovec iovec = {
    .iov_base = iobuf0,
    .iov_len  = tile->snapsv.conn_max*(tile->snapsv.send_buffer_size_kib<<11)
  };
  if( FD_UNLIKELY( fd_io_uring_register_buffers( ctx->ring->ioring_fd, &iovec, 1UL )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register_buffers() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Build file descriptor table */
  FD_TEST( tile->snapsv.snap_max<=FD_SNAP_MAX );
  fd_table[ FIXED_FD_LISTEN ] = ctx->listen_fd;
  uint fixed_fd = FIXED_FD_CNT;
  for( ulong i=0UL; i<tile->snapsv.snap_max; i++ ) {
    fd_table[ fixed_fd++ ] = FD_SNAP_RO_FD( i );
  }
  ctx->conn0_fd_idx = fixed_fd;
  if( FD_UNLIKELY( fd_io_uring_register_files( ctx->ring->ioring_fd, fd_table, fd_max )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register_files() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  uint max_workers[2] = { tile->snapsv.io_worker_cnt, tile->snapsv.io_worker_cnt };
  if( FD_UNLIKELY( fd_io_uring_register( ctx->ring->ioring_fd, FD_IORING_REGISTER_IOWQ_MAX_WORKERS, max_workers, 2U )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register(IORING_REGISTER_IOWQ_MAX_WORKERS) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fd_io_uring_restriction_t restrictions[] = {
    { .opcode = FD_IORING_RESTRICTION_SQE_OP, .sqe_op = FD_IORING_OP_ACCEPT       },
    { .opcode = FD_IORING_RESTRICTION_SQE_OP, .sqe_op = FD_IORING_OP_RECV         },
    { .opcode = FD_IORING_RESTRICTION_SQE_OP, .sqe_op = FD_IORING_OP_SEND         },
    { .opcode = FD_IORING_RESTRICTION_SQE_OP, .sqe_op = FD_IORING_OP_READ_FIXED   },
    { .opcode = FD_IORING_RESTRICTION_SQE_OP, .sqe_op = FD_IORING_OP_FUTEX_WAIT   },
    { .opcode = FD_IORING_RESTRICTION_SQE_OP, .sqe_op = FD_IORING_OP_LINK_TIMEOUT },
    { .opcode      = FD_IORING_RESTRICTION_REGISTER_OP, /* deregister files */
      .register_op = FD_IORING_REGISTER_FILES_UPDATE },
    { .opcode    = FD_IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
      .sqe_flags = FD_IOSQE_IO_LINK },
    { .opcode    = FD_IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
      .sqe_flags = FD_IOSQE_FIXED_FILE },
  };
  if( FD_UNLIKELY( fd_io_uring_register_restrictions(
        ctx->ring->ioring_fd, restrictions,
        (uint)( sizeof(restrictions)/sizeof(restrictions[0]) ) )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register_restrictions failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fd_io_uring_enable_rings( ctx->ring->ioring_fd )<0 ) ) {
    FD_LOG_ERR(( "io_uring_enable_rings failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* snapshot map setup */

  ulong map_ele_max = snapsv_map_ele_max( tile );
  snap_entry_t * slots = snap_map_new( map_mem, map_ele_max, 0 );
  FD_TEST( slots );
  for( ulong i=0UL; i<map_ele_max; i++ ) {
    slots[ i ].key = (snap_key_t){ ULONG_MAX,ULONG_MAX };
  }
  ulong map_seed; FD_TEST( fd_rng_secure( &map_seed, sizeof(map_seed) ) );
  FD_TEST( snap_map_join( ctx->snap_map, slots, map_ele_max, map_ele_max, map_seed ) );
  ctx->snap_max = tile->snapsv.snap_max;
}

static void
prep_accept( fd_snapsv_t * ctx );

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  ulong sq_depth = snapsv_sq_depth( tile );
  ulong cq_depth = snapsv_cq_depth( tile );
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapsv_t * ctx          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapsv_t),      sizeof(fd_snapsv_t) );
  /*                   */(void)FD_SCRATCH_ALLOC_APPEND( l, fd_io_uring_shmem_align(), fd_io_uring_shmem_footprint( sq_depth, cq_depth ) );
  /*                   */(void)FD_SCRATCH_ALLOC_APPEND( l, snap_map_align(),          snap_map_footprint( snapsv_map_ele_max( tile ) ) );
  /*                   */(void)FD_SCRATCH_ALLOC_APPEND( l, alignof(int),              snapsv_fd_max( tile )*sizeof(int) );
  snapsv_conn_t * conn0      = FD_SCRATCH_ALLOC_APPEND( l, alignof(snapsv_conn_t),    tile->snapsv.conn_max*sizeof(snapsv_conn_t) );
  uint *          conn_free  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),             tile->snapsv.conn_max*sizeof(uint) );
  uint *          iobuf_free = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),             tile->snapsv.conn_max * 2 * sizeof(uint) );
  uchar *         iobuf0     = FD_SCRATCH_ALLOC_APPEND( l, FD_SHMEM_NORMAL_PAGE_SZ,   tile->snapsv.conn_max * (tile->snapsv.send_buffer_size_kib<<11) );

  FD_CHECK_ERR( tile->in_cnt<=IN_LINK_MAX, "too many input links" );
  FD_CHECK_ERR( tile->in_cnt==1, "snapsv is hardcoded to only support one input link" );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    FD_CHECK_ERR( !strcmp( link->name, "snapmk_out" ), "unexpected input link" );
    FD_CHECK_ERR( tile->in_link_poll[ i ], "expecting polled input link" );
    ctx->in_kind[ i ]   = IN_KIND_SNAPMK;
    ctx->in[ i ].mem    = fd_wksp_containing( link->dcache );
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    ulong depth = fd_mcache_depth( link->mcache );
    FD_CHECK_ERR( depth<=UINT_MAX, "input link mcache too deep" );
    ctx->in[ i ].mcache      = link->mcache;
    ctx->in[ i ].depth       = (uint)depth;
    ctx->in[ i ].seq_prod    = fd_mcache_seq_laddr_const( link->mcache );
    ctx->in[ i ].seq_cons    = ULONG_MAX;
    ctx->in[ i ].futex_armed = 0;
  }

  ctx->conn0         = conn0;
  ctx->conn_free     = conn_free;
  ctx->conn_free_cnt = (uint)tile->snapsv.conn_max;
  ctx->idle_timeout_nanos = (long)( tile->snapsv.idle_timeout_millis * ((ulong)1e6) );
  long send_timeout_nanos = (long)( tile->snapsv.send_timeout_millis * ((ulong)1e6) );
  ctx->send_timeout = (fd_kernel_timespec_t) {
    .tv_sec  = send_timeout_nanos / (long)1e9,
    .tv_nsec = send_timeout_nanos % (long)1e9
  };
  for( ulong i=0UL; i<tile->snapsv.conn_max; i++ ) {
    conn0[ i ]     = (snapsv_conn_t){ .state = CONN_STATE_FREE, .iobuf_idx = UINT_MAX, .rdbuf_idx = UINT_MAX };
    conn_free[ i ] = (uint)tile->snapsv.conn_max-1U-(uint)i;
  }

  FD_CHECK_ERR( tile->snapsv.send_buffer_size_kib, "send_buffer_size_kib is zero" );
  ulong iobuf_cnt = tile->snapsv.conn_max * 2;
  ctx->iobuf_sz       = (uint)( tile->snapsv.send_buffer_size_kib<<10 );
  ctx->iobuf0         = iobuf0;
  ctx->iobuf_free     = iobuf_free;
  ctx->iobuf_free_cnt = (uint)iobuf_cnt;
  for( ulong i=0UL; i<iobuf_cnt; i++ ) {
    iobuf_free[ i ] = (uint)iobuf_cnt-1U-(uint)i;
  }

  prep_accept( ctx );
}

/* prep_accept enqueues an io_uring conn accept SQE. */

static void
prep_accept( fd_snapsv_t * ctx ) {
  FD_CHECK_ERR( !ctx->accept_inflight, "accept already inflight" );
  FD_CHECK_ERR( ctx->conn_cnt < ctx->conn_max, "conn table full" );
  FD_CHECK_ERR( ctx->conn_free_cnt, "conn free list empty" );

  uint            conn_idx = ctx->conn_free[ --ctx->conn_free_cnt ];
  snapsv_conn_t * conn     = &ctx->conn0[ conn_idx ];
  *conn = (snapsv_conn_t){ .state = CONN_STATE_FREE, .iobuf_idx = UINT_MAX, .rdbuf_idx = UINT_MAX };
  uint fd_idx = ctx->conn0_fd_idx + conn_idx;
  ctx->accept_addr_len = sizeof(ctx->accept_addr);

  fd_io_uring_t * ring = ctx->ring;
  fd_io_uring_sqe_t * sqe = fd_io_uring_get_sqe( ring->sq );
  FD_CHECK_ERR( sqe, "io_uring submission queue full" );
  *sqe = (fd_io_uring_sqe_t) {
    .opcode     = FD_IORING_OP_ACCEPT,
    .flags      = FD_IOSQE_FIXED_FILE,
    .fd         = FIXED_FD_LISTEN,
    .off        = (ulong)&ctx->accept_addr_len,
    .addr       = (ulong)&ctx->accept_addr,
    .len        = 0,
    .file_index = fd_idx + 1U /* registered files are 1-indexed */
  };
  snapsv_udata_t udata = { .op = UDATA_OP_ACCEPT, .conn_idx = conn_idx };
  sqe->user_data = udata.user_data;
  ctx->accept_inflight = 1;
}

/* conn_iobuf returns a pointer to the current I/O buffer of a conn. */

FD_FN_PURE static uchar *
conn_iobuf( fd_snapsv_t const *   ctx,
            snapsv_conn_t const * conn ) {
  FD_CHECK_CRIT( conn->iobuf_idx!=UINT_MAX, "conn has no iobuf" );
  return ctx->iobuf0 + (ulong)conn->iobuf_idx*ctx->iobuf_sz;
}

/* iobuf_acquire lends an iobuf to a conn. */

static void
iobuf_acquire( fd_snapsv_t * ctx,
               uint *        slot ) {
  if( FD_LIKELY( *slot!=UINT_MAX ) ) return;
  /* Every conn holds at most one buffer and the pool has two per conn,
     so a conn that needs one always finds one. */
  FD_CHECK_CRIT( ctx->iobuf_free_cnt, "iobuf pool exhausted" );
  *slot = ctx->iobuf_free[ --ctx->iobuf_free_cnt ];
}

/* iobuf_release frees a conn iobuf (if any). */

static void
iobuf_release( fd_snapsv_t * ctx,
               uint *        slot ) {
  if( FD_UNLIKELY( *slot==UINT_MAX ) ) return;
  ctx->iobuf_free[ ctx->iobuf_free_cnt++ ] = *slot;
  *slot = UINT_MAX;
}

/* prep_peek enqueues a receive op to copy any newly arrived bytes into
   iobuf.  Does not advance the socket's file pointer. */

static void
prep_peek( fd_snapsv_t * ctx,
           uint          conn_idx ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( !conn->request_start_nanos ) ) {
    conn->request_start_nanos = now;
  }
  long idle_rem = fd_long_max( 1L, ctx->idle_timeout_nanos - (now - conn->request_start_nanos) );
  conn->idle_timeout = (fd_kernel_timespec_t) {
    .tv_sec  = idle_rem / (long)1e9,
    .tv_nsec = idle_rem % (long)1e9
  };
  uint            len  = ctx->iobuf_sz - conn->req.len;
  FD_CHECK_CRIT( len, "request head buffer is full" );
  iobuf_acquire( ctx, &conn->iobuf_idx );

  fd_io_uring_t * ring = ctx->ring;
  fd_io_uring_sqe_t * sqe = fd_io_uring_get_sqe( ring->sq );
  FD_CHECK_ERR( sqe, "io_uring submission queue full" );
  *sqe = (fd_io_uring_sqe_t) {
    .opcode    = FD_IORING_OP_RECV,
    .flags     = FD_IOSQE_FIXED_FILE | FD_IOSQE_IO_LINK,
    //.ioprio    = FD_IORING_RECVSEND_FIXED_BUF,
    .fd        = (int)( ctx->conn0_fd_idx + conn_idx ),
    .addr      = (ulong)( conn_iobuf( ctx, conn ) + conn->req.len ),
    .len       = len,
    //.buf_index = 0U,
    .msg_flags = MSG_PEEK
  };
  snapsv_udata_t udata = { .op = UDATA_OP_PEEK, .conn_idx = conn_idx };
  sqe->user_data = udata.user_data;

  sqe = fd_io_uring_get_sqe( ring->sq );
  FD_CHECK_ERR( sqe, "io_uring submission queue full" );
  *sqe = (fd_io_uring_sqe_t) {
    .opcode = FD_IORING_OP_LINK_TIMEOUT,
    .flags  = FD_IOSQE_FIXED_FILE, /* ignored */
    .addr   = (ulong)&conn->idle_timeout,
    .len    = 1U
  };
  udata = (snapsv_udata_t){ .op = UDATA_OP_TIMEOUT };
  sqe->user_data = udata.user_data;
}

/* prep_consume consumes previously received (via peek) iobuf bytes. */

static void
prep_consume( fd_snapsv_t * ctx,
              uint          conn_idx,
              uint          len,
              uchar         op ) {
  FD_CHECK_CRIT( len, "consuming zero bytes" );
  fd_io_uring_t * ring = ctx->ring;
  fd_io_uring_sqe_t * sqe = fd_io_uring_get_sqe( ring->sq );
  FD_CHECK_ERR( sqe, "io_uring submission queue full" );
  *sqe = (fd_io_uring_sqe_t) {
    .opcode    = FD_IORING_OP_RECV,
    .flags     = FD_IOSQE_FIXED_FILE,
    .fd        = (int)( ctx->conn0_fd_idx + conn_idx ),
    .addr      = 0UL,
    .len       = len,
    .msg_flags = MSG_TRUNC | MSG_WAITALL
  };
  snapsv_udata_t udata = { .op = op, .conn_idx = conn_idx };
  sqe->user_data = udata.user_data;
}

/* conn_close destroys a conn object.  If no accept op is in-flight,
   enqueues one. */

static void
conn_close( fd_snapsv_t * ctx,
            uint          conn_idx ) {
  FD_CHECK_CRIT( conn_idx < ctx->conn_max, "invalid conn_idx" );
  snapsv_conn_t * conn   = &ctx->conn0[ conn_idx ];
  uint            fd_idx = ctx->conn0_fd_idx + conn_idx;

  /* io_uring OP_CLOSE on a fixed file does not use FD_IOSQE_FIXED_FILE,
     therefore would break the io_uring sandbox (restrictions). */
  int unreg = -1;
  if( FD_UNLIKELY( fd_io_uring_register_files_update( ctx->ring->ioring_fd, fd_idx, &unreg, 1U )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register(IORING_REGISTER_FILES_UPDATE) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  iobuf_release( ctx, &conn->iobuf_idx );
  iobuf_release( ctx, &conn->rdbuf_idx );
  *conn = (snapsv_conn_t){ .state = CONN_STATE_FREE, .iobuf_idx = UINT_MAX, .rdbuf_idx = UINT_MAX };

  FD_CHECK_CRIT( ctx->conn_cnt, "conn count underflow" );
  ctx->conn_cnt--;
  ctx->conn_free[ ctx->conn_free_cnt++ ] = conn_idx;

  if( FD_UNLIKELY( !ctx->accept_inflight ) ) {
    prep_accept( ctx );
  }
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_snapsv_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<4+ctx->snap_max ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->ring->ioring_fd;
  out_fds[ out_cnt++ ] = ctx->listen_fd;
  for( ulong i=0UL; i<ctx->snap_max; i++ )
    out_fds[ out_cnt++ ] = FD_SNAP_RO_FD( i ); /* snapshot pool */
  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_snapsv_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_snapsv_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)ctx->ring->ioring_fd,
      (uint)FD_SNAP_RO_FD( 0 ),
      (uint)FD_SNAP_RO_FD( ctx->snap_max-1UL ) );
  return sock_filter_policy_fd_snapsv_tile_instr_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  (void)topo;
  /* stderr, logfile, boot control pipe, io_uring, listen socket, one
     spare for accept, the snapshot pool, and active connections */
  return 6UL + tile->snapsv.snap_max + tile->snapsv.conn_max;
}

/* handle_accept handles the completion of an accept op. */

static void
handle_accept( fd_snapsv_t * ctx,
               uint          conn_idx,
               int           res ) {
  ctx->accept_inflight = 0;

  if( FD_UNLIKELY( res<0 ) ) {
    FD_LOG_WARNING(( "accept() failed (%i-%s)", -res, fd_io_strerror( -res ) ));
    ctx->conn_free[ ctx->conn_free_cnt++ ] = conn_idx;
    prep_accept( ctx );
    return;
  }

  ctx->conn_cnt++;

  /* set conn addr */
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  switch( ctx->accept_addr.ss_family ) {
  case AF_INET: {
    struct sockaddr_in const * addr = fd_type_pun_const( &ctx->accept_addr );
    fd_ip6_addr_ip4_mapped( conn->peer_ip.addr, addr->sin_addr.s_addr );
    conn->peer_ip.scope_id = 0U;
    conn->peer_port = fd_ushort_bswap( addr->sin_port );
    break;
  }
  case AF_INET6: {
    struct sockaddr_in6 const * addr = fd_type_pun_const( &ctx->accept_addr );
    memcpy( conn->peer_ip.addr, addr->sin6_addr.s6_addr, 16UL );
    conn->peer_ip.scope_id = addr->sin6_scope_id;
    conn->peer_port = fd_ushort_bswap( addr->sin6_port );
    break;
  }
  default:
    FD_LOG_WARNING(( "accept() returned unknown address family %i", (int)ctx->accept_addr.ss_family ));
    memset( &conn->peer_ip, 0, sizeof(conn->peer_ip) );
    conn->peer_port = 0U;
  }

  prep_peek( ctx, conn_idx );
  if( FD_LIKELY( ctx->conn_cnt<ctx->conn_max ) ) {
    prep_accept( ctx );
  }
}

/* conn_snap_entry checks that the snapshot for the current operation is
   still valid.  The return value of this function is invalidated once
   after_credit returns. */

static snap_entry_t *
conn_snap_entry( snapsv_conn_t * conn ) {
  snap_entry_t * slot = conn->snap.slot;
  FD_CHECK_ERR( slot, "snapshot slot is NULL" );
  if( FD_UNLIKELY( ( slot->key.base_slot != conn->snap.key.base_slot ) |
                   ( slot->key.slot      != conn->snap.key.slot      ) ) ) {
    /* snapshot was deleted */
    return NULL;
  }
  return slot;
}

static int
snap_lock( snap_entry_t * entry );

/* shovel dispatches snapshot streaming I/O work.
   This forms a 2-job deep pipeline that attempts to concurrently do
   disk read and network write I/O. */

static void
shovel( fd_snapsv_t * ctx,
        uint          conn_idx ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  FD_CHECK_ERR( conn->state==CONN_STATE_RES_SHOVEL, "conn state confusion" );

  if( FD_UNLIKELY( conn->closing ) ) {
    if( !conn->disk_inflight && !conn->net_inflight ) {
      conn_close( ctx, conn_idx );
    }
    return;
  }

  if( conn->iobuf_idx!=UINT_MAX &&
      conn->res.sent==conn->res.len &&
      !conn->net_inflight ) {
    iobuf_release( ctx, &conn->iobuf_idx );
    conn->res.sent = 0U;
    conn->res.len  = 0U;
  }

  /* disk read buffer complete, rename to net send buffer */
  if( conn->iobuf_idx==UINT_MAX && conn->rdbuf_len ) {
    FD_CHECK_CRIT( conn->rdbuf_idx!=UINT_MAX, "completed read has no buffer" );
    conn->iobuf_idx = conn->rdbuf_idx;
    conn->rdbuf_idx = UINT_MAX;
    conn->res.sent  = 0U;
    conn->res.len   = conn->rdbuf_len;
    conn->rdbuf_len = 0U;
  }

  /* generate net send SQE */
  if( conn->iobuf_idx!=UINT_MAX && conn->res.sent<conn->res.len && !conn->net_inflight ) {
    fd_io_uring_sqe_t * sqe = fd_io_uring_get_sqe( ctx->ring->sq );
    FD_CHECK_ERR( sqe, "io_uring submission queue full" );
    *sqe = (fd_io_uring_sqe_t) {
      .opcode    = FD_IORING_OP_SEND,
      .flags     = FD_IOSQE_FIXED_FILE | FD_IOSQE_IO_LINK,
      //.ioprio    = FD_IORING_RECVSEND_FIXED_BUF,
      .fd        = (int)( ctx->conn0_fd_idx + conn_idx ),
      .addr      = (ulong)conn_iobuf( ctx, conn ) + conn->res.sent,
      .len       = conn->res.len - conn->res.sent,
      //.buf_index = 0U,
      .msg_flags = MSG_NOSIGNAL
    };
    snapsv_udata_t udata = { .op = UDATA_OP_SHOVEL_NET, .conn_idx = conn_idx };
    sqe->user_data = udata.user_data;
    conn->net_inflight = 1U;

    sqe = fd_io_uring_get_sqe( ctx->ring->sq );
    FD_CHECK_ERR( sqe, "io_uring submission queue full" );
    *sqe = (fd_io_uring_sqe_t) {
      .opcode = FD_IORING_OP_LINK_TIMEOUT,
      .flags  = FD_IOSQE_FIXED_FILE, /* ignored */
      .addr   = (ulong)&ctx->send_timeout,
      .len    = 1U
    };
    udata = (snapsv_udata_t){ .op = UDATA_OP_TIMEOUT };
    sqe->user_data = udata.user_data;
  }

  /* generate disk read SQE */
  if( conn->rdbuf_idx==UINT_MAX && !conn->disk_inflight && conn->snap.range0<conn->snap.range1 ) {
    snap_entry_t const * snap = conn_snap_entry( conn );
    if( FD_UNLIKELY( !snap ) ) {
      conn->closing = 1U;
      shovel( ctx, conn_idx );
      return;
    }

    iobuf_acquire( ctx, &conn->rdbuf_idx );
    ulong read_sz = fd_ulong_min( ctx->iobuf_sz, conn->snap.range1-conn->snap.range0 );
    ulong pool_idx = (ulong)( snap->fd - FD_SNAP_RO_FD( 0 ) );
    FD_CHECK_CRIT( pool_idx<ctx->snap_max, "snapshot has invalid file descriptor" );

    fd_io_uring_sqe_t * sqe = fd_io_uring_get_sqe( ctx->ring->sq );
    FD_CHECK_ERR( sqe, "io_uring submission queue full" );
    *sqe = (fd_io_uring_sqe_t) {
      .opcode    = FD_IORING_OP_READ_FIXED,
      .flags     = FD_IOSQE_FIXED_FILE,
      .fd        = (int)( FIXED_FD_CNT + pool_idx ),
      .off       = conn->snap.range0,
      .addr      = (ulong)( ctx->iobuf0 + (ulong)conn->rdbuf_idx*ctx->iobuf_sz ),
      .len       = (uint)read_sz,
      .buf_index = 0U
    };
    snapsv_udata_t udata = { .op = UDATA_OP_SHOVEL_DISK, .conn_idx = conn_idx };
    sqe->user_data = udata.user_data;
    conn->disk_inflight = 1U;
  }

  /* everything done */
  if( FD_UNLIKELY( conn->snap.range0>=conn->snap.range1 &&
                   conn->iobuf_idx==UINT_MAX &&
                   conn->rdbuf_idx==UINT_MAX &&
                   !conn->disk_inflight &&
                   !conn->net_inflight ) ) {
    if( FD_UNLIKELY( conn->sick ) ) {
      conn_close( ctx, conn_idx );
      return;
    }
    conn->state = CONN_STATE_REQ_PEEK;
    prep_peek( ctx, conn_idx );
  }
}

/* shovel_comp_disk reacts to a snapshot streaming disk read completion. */

static void
shovel_comp_disk( fd_snapsv_t * ctx,
                  uint          conn_idx,
                  int           res ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  FD_CHECK_CRIT( conn->state==CONN_STATE_RES_SHOVEL && conn->disk_inflight,
                 "unexpected shovel disk completion" );
  conn->disk_inflight = 0U;

  ulong rem = conn->snap.range1 - conn->snap.range0;
  if( FD_UNLIKELY( res<=0 || (ulong)res>fd_ulong_min( ctx->iobuf_sz, rem ) ) ) {
    if( res<0 ) FD_LOG_WARNING(( "snapshot read failed (%i-%s)", -res, fd_io_strerror( -res ) ));
    else        FD_LOG_WARNING(( "snapshot file ended early" ));
    conn->closing = 1U;
    shovel( ctx, conn_idx );
    return;
  }

  conn->snap.range0 += (ulong)res;
  conn->rdbuf_len    = (uint)res;
  shovel( ctx, conn_idx );
}

/* shovel_comp_net reacts to a snapshot streaming network write
   completion. */

static void
shovel_comp_net( fd_snapsv_t * ctx,
                 uint          conn_idx,
                 int           res ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  FD_CHECK_CRIT( conn->state==CONN_STATE_RES_SHOVEL, "unexpected shovel net completion" );
  FD_CHECK_CRIT( conn->net_inflight, "unexpected SEND completion" );
  conn->net_inflight = 0U;

  if( FD_UNLIKELY( res<=0 || (uint)res>conn->res.len-conn->res.sent ) ) {
    FD_IP6_ADDR_CSTR( addr_cstr, &conn->peer_ip );
    if( res<0 ) {
      FD_LOG_INFO(( "snapshot download peer %s:%u: snapshot data send error (%i-%s)",
                    addr_cstr, conn->peer_port, -res, fd_io_strerror( -res ) ));
    }
    conn->closing = 1U;
    shovel( ctx, conn_idx );
    return;
  }

  conn->res.sent += (uint)res;
  FD_MCNT_INC( SNAPSV, BYTES_WRITTEN, (ulong)res );
  shovel( ctx, conn_idx );
}

/* prep_write_hdr enqueues a header write op. */

static void
prep_write_hdr( fd_snapsv_t * ctx,
                uint          conn_idx ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  fd_io_uring_t * ring = ctx->ring;
  fd_io_uring_sqe_t * sqe = fd_io_uring_get_sqe( ring->sq );
  FD_CHECK_ERR( conn->res.sent < conn->res.len, "conn res state confusion" );
  FD_CHECK_ERR( sqe, "io_uring submission queue full" );
  *sqe = (fd_io_uring_sqe_t) {
    .opcode    = FD_IORING_OP_SEND,
    .flags     = FD_IOSQE_FIXED_FILE | FD_IOSQE_IO_LINK,
    //.ioprio    = FD_IORING_RECVSEND_FIXED_BUF,
    .fd        = (int)( ctx->conn0_fd_idx + conn_idx ),
    .addr      = (ulong)conn_iobuf( ctx, conn ) + conn->res.sent,
    .len       = conn->res.len - conn->res.sent,
    //.buf_index = 0U,
    .msg_flags = MSG_NOSIGNAL
  };
  snapsv_udata_t udata = { .op = UDATA_OP_WRITE_HDR, .conn_idx = conn_idx };
  sqe->user_data = udata.user_data;

  sqe = fd_io_uring_get_sqe( ring->sq );
  FD_CHECK_ERR( sqe, "io_uring submission queue full" );
  *sqe = (fd_io_uring_sqe_t) {
    .opcode = FD_IORING_OP_LINK_TIMEOUT,
    .flags  = FD_IOSQE_FIXED_FILE, /* ignored */
    .addr   = (ulong)&ctx->send_timeout,
    .len    = 1U
  };
  udata = (snapsv_udata_t){ .op = UDATA_OP_TIMEOUT };
  sqe->user_data = udata.user_data;
}

/* serve_http_err dispatches a RES_WRITE_HDR job for a generic HTTP
   error page. */

static void
serve_http_err( fd_snapsv_t * ctx,
                uint          conn_idx ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  FD_CHECK_ERR( conn->state==CONN_STATE_RES_WRITE_ERR, "state confusion" );
  iobuf_acquire( ctx, &conn->iobuf_idx );
  uchar * iobuf = conn_iobuf( ctx, conn );
  char * p = fd_cstr_init( (char *)iobuf );
  p = fd_cstr_append_cstr( p, "HTTP/1.1 ");
  switch( conn->http_err ) {
  case 400: p = fd_cstr_append_cstr( p, "400 Bad Request"           ); break;
  case 404: p = fd_cstr_append_cstr( p, "404 Not Found"             ); break;
  case 416: p = fd_cstr_append_cstr( p, "416 Range Not Satisfiable" ); break;
  default:  p = fd_cstr_append_cstr( p, "500 Internal Server Error" ); break;
  }
  p = fd_cstr_append_cstr( p, "\r\n" );
  if( conn->http_err==416 && conn->snap.slot ) {
    p = fd_cstr_append_cstr( p, "Content-Range: bytes */" );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, conn->snap.slot->sz, fd_ulong_base10_dig_cnt( conn->snap.slot->sz ) );
    p = fd_cstr_append_cstr( p, "\r\n" );
  }
  p = fd_cstr_append_cstr( p, "Content-Length: 0\r\n" );
  if( conn->sick ) {
    p = fd_cstr_append_cstr( p, "Connection: close\r\n" );
  }
  p = fd_cstr_append_cstr( p, "\r\n" );
  conn->res.sent = 0;
  conn->res.len  = (uint)( p - (char *)iobuf );
  prep_write_hdr( ctx, conn_idx );
}

/* serve_snap_res_hdr dispatches a RES_WRITE_HDR job for a snapshot GET
   or HEAD request. */

static void
serve_snap_res_hdr( fd_snapsv_t * ctx,
                    uint          conn_idx ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  FD_CHECK_ERR( conn->state==CONN_STATE_RES_WRITE_HDR, "state confusion" );

  snap_entry_t * snap = conn_snap_entry( conn );
  if( FD_UNLIKELY( !snap ) ) {
    /* rare edge case: snap was deleted by the snapmk tile just after
       the user requested it.  Don't bother returning an error, just
       abort the conn. */
    conn_close( ctx, conn_idx );
    return;
  }
  if( FD_UNLIKELY( !snap_lock( snap ) ) ) {
    conn_close( ctx, conn_idx );
    return;
  }
  /* return response header */
  FD_CHECK_ERR( conn->iobuf_idx==UINT_MAX, "conn has stale iobuf" );
  iobuf_acquire( ctx, &conn->iobuf_idx );
  uchar * iobuf = conn_iobuf( ctx, conn );
  char * p = fd_cstr_init( (char *)iobuf );
  if( conn->range ) {
    p = fd_cstr_append_cstr( p, "HTTP/1.1 206 Partial Content\r\n" );
  } else {
    p = fd_cstr_append_cstr( p, "HTTP/1.1 200 OK\r\n" );
  }
  if( snap->is_zstd ) {
    p = fd_cstr_append_cstr( p, "Content-Type: application/zstd\r\n" );
  } else {
    p = fd_cstr_append_cstr( p, "Content-Type: application/x-tar\r\n" );
  }
  p = fd_cstr_append_cstr( p, "Accept-Ranges: bytes\r\n" );
  if( conn->range ) {
    p = fd_cstr_append_cstr( p, "Content-Range: bytes " );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, conn->snap.range0, fd_ulong_base10_dig_cnt( conn->snap.range0 ) );
    p = fd_cstr_append_char( p, '-' );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, conn->snap.range1-1UL, fd_ulong_base10_dig_cnt( conn->snap.range1-1UL ) );
    p = fd_cstr_append_char( p, '/' );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, snap->sz, fd_ulong_base10_dig_cnt( snap->sz ) );
    p = fd_cstr_append_cstr( p, "\r\n" );
  }
  p = fd_cstr_append_cstr( p, "Content-Length: " );
  ulong content_len = conn->snap.range1 - conn->snap.range0;
  p = fd_cstr_append_ulong_as_text( p, 0, 0, content_len, fd_ulong_base10_dig_cnt( content_len ) );
  p = fd_cstr_append_cstr( p, "\r\n" );
  p = fd_cstr_append_cstr( p, "\r\n" );
  conn->res.sent = 0;
  conn->res.len  = (uint)( p - (char *)iobuf );
  prep_write_hdr( ctx, conn_idx );
}

/* newest_snap returns the newest snapshot of the requested type. */

static snap_entry_t *
newest_snap( fd_snapsv_t * ctx,
             int           incremental ) {

  if( FD_UNLIKELY( !( incremental ? ctx->snap_cnt_incr : ctx->snap_cnt_full ) ) ) {
    return NULL; /* no such snapshot of this type */
  }
  snap_entry_t * entry = incremental ? ctx->newest_incr : ctx->newest_full;
  if( FD_UNLIKELY( !entry ) ) {
    snap_entry_t * entry0   = snap_map_ele0( ctx->snap_map );
    ulong          ele_max  = snap_map_ele_max( ctx->snap_map );
    for( ulong i=0UL; i<ele_max; i++ ) {
      snap_entry_t * e = &entry0[ i ];
      if( snap_map_ele_is_free( e ) ) continue;
      if( (e->key.base_slot!=ULONG_MAX)!=!!incremental ) continue;
      if( entry && e->key.slot<=entry->key.slot ) continue;
      entry = e;
    }
  }
  *( incremental ? &ctx->newest_incr : &ctx->newest_full ) = entry;
  if( FD_UNLIKELY( !entry ) ) return NULL;
  return entry;
}

/* serve_redirect dispatches a RES_WRITE_HDR job for a /snapshot.tar.bz2
   redirect. */

static void
serve_redirect( fd_snapsv_t * ctx,
                uint          conn_idx ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  FD_CHECK_ERR( conn->state==CONN_STATE_RES_REDIRECT, "state confusion" );

  snap_entry_t * snap = newest_snap( ctx, conn->incremental );
  if( FD_UNLIKELY( !snap ) ) {
    conn->state    = CONN_STATE_RES_WRITE_ERR;
    conn->http_err = 404U;
    serve_http_err( ctx, conn_idx );
    return;
  }

  /* return response */
  FD_CHECK_ERR( conn->iobuf_idx==UINT_MAX, "conn has stale iobuf" );
  iobuf_acquire( ctx, &conn->iobuf_idx );
  uchar * iobuf = conn_iobuf( ctx, conn );
  char * p = fd_cstr_init( (char *)iobuf );
  p = fd_cstr_append_cstr( p, "HTTP/1.1 302 Found\r\n" );
  p = fd_cstr_append_cstr( p, "Location: /" );
  if( conn->incremental ) {
    p = fd_cstr_append_cstr( p, "incremental-snapshot-" );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, snap->key.base_slot, fd_ulong_base10_dig_cnt( snap->key.base_slot ) );
    p = fd_cstr_append_char( p, '-' );
  } else {
    p = fd_cstr_append_cstr( p, "snapshot-" );
  }
  p = fd_cstr_append_ulong_as_text( p, 0, 0, snap->key.slot, fd_ulong_base10_dig_cnt( snap->key.slot ) );
  p = fd_cstr_append_char( p, '-' );
  char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( snap->hash, NULL, hash_b58 );
  p = fd_cstr_append_cstr( p, hash_b58 );
  p = fd_cstr_append_cstr( p, snap->is_zstd ? ".tar.zst\r\n" : ".tar\r\n" );
  p = fd_cstr_append_cstr( p, "Content-Length: 0\r\n" );
  if( conn->sick ) {
    p = fd_cstr_append_cstr( p, "Connection: close\r\n" );
  }
  p = fd_cstr_append_cstr( p, "\r\n" );
  conn->res.sent = 0;
  conn->res.len  = (uint)( p - (char *)iobuf );
  conn->state = CONN_STATE_RES_WRITE_HDR; /* shared completion path */
  prep_write_hdr( ctx, conn_idx );
}

static void
prep_peek( fd_snapsv_t * ctx,
           uint          conn_idx );

/* handle_write_hdr_comp handles the completion of a header write op. */

static void
handle_write_hdr_comp( fd_snapsv_t * ctx,
                       uint          conn_idx,
                       int           res ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  if( FD_UNLIKELY( res<0 ) ) {
    if( res<0 ) {
      FD_IP6_ADDR_CSTR( addr_cstr, &conn->peer_ip );
      FD_LOG_INFO(( "snapshot download peer %s:%u: response header send error (%i-%s)",
                    addr_cstr, conn->peer_port, -res, fd_io_strerror( -res ) ));
    }
    conn_close( ctx, conn_idx );
    return;
  }
  conn->res.sent += (uint)res;
  if( FD_LIKELY( conn->res.sent < conn->res.len ) ) {
    prep_write_hdr( ctx, conn_idx );
    return;
  }
  /* wrote response body */
  iobuf_release( ctx, &conn->iobuf_idx );
  if( FD_UNLIKELY( conn->sick ) ) {
    conn_close( ctx, conn_idx );
    return;
  }
  switch( conn->state ) {
  case CONN_STATE_RES_WRITE_ERR:
    /* returned an error, handle the next request */
    conn->state = CONN_STATE_REQ_PEEK;
    prep_peek( ctx, conn_idx );
    return;
  case CONN_STATE_RES_WRITE_HDR:
    if( conn->head ) {
      conn->state = CONN_STATE_REQ_PEEK;
      prep_peek( ctx, conn_idx );
      return;
    }
    /* now serve the snapshot body */
    conn->state = CONN_STATE_RES_SHOVEL;
    shovel( ctx, conn_idx );
    return;
  default:
    FD_LOG_CRIT(( "conn %u: state confusion", conn_idx ));
  }
}

/* match_snapshot_path parses a snapshot HTTP request path. */

static snap_key_t *
match_snapshot_path( char const * path,
                     ulong        path_len,
                     snap_key_t * out,
                     uchar        out_hash[ 32 ],
                     int *        out_is_zstd ) {
  if( path_len<9 ) return NULL;

  /* ugly: copy to cstr */
  char cstr[ FD_SNAP_NAME_MAX ];
  if( FD_UNLIKELY( path_len>=FD_SNAP_NAME_MAX-1 ) ) return NULL;
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( cstr ), path, path_len ) );

  ulong full_slot, incremental_slot;
  int res = fd_ssarchive_parse_filename( cstr, &full_slot, &incremental_slot, out_hash, out_is_zstd );
  if( FD_UNLIKELY( res!=0 ) ) return NULL;
  *out = (snap_key_t) {
    .slot      = incremental_slot!=ULONG_MAX ? incremental_slot : full_slot,
    .base_slot = incremental_slot!=ULONG_MAX ? full_slot : ULONG_MAX
  };
  return out;
}

/* parse_range_header parses a 'Range: bytes=start-end' header.
   value points to the header value char[value_len].
   object_sz is the size of the file, and [*out_range0, *out_range1)
   is the requested range. */

static int
parse_range_header( char const * value,
                    ulong        value_len,
                    ulong        object_sz,
                    ulong *      out_range0,
                    ulong *      out_range1 ) {
  char const * p   = value;
  char const * end = value + value_len;

  while( p<end && (*p==' ' || *p=='\t') ) p++;
  while( end>p && (end[-1]==' ' || end[-1]=='\t') ) end--;
  if( FD_UNLIKELY( (ulong)(end-p)<7UL || strncasecmp( p, "bytes=", 6UL ) ) ) return -1;
  p += 6;

  ulong first = 0UL;
  int have_first = 0;
  while( p<end && *p>='0' && *p<='9' ) {
    uint digit = (uint)(*p-'0');
    if( FD_UNLIKELY( first>(ULONG_MAX-digit)/10UL ) ) return -1;
    first = first*10UL + digit;
    have_first = 1;
    p++;
  }
  if( FD_UNLIKELY( p==end || *p!='-' ) ) return -1;
  p++;

  ulong last = 0UL;
  int have_last = 0;
  while( p<end && *p>='0' && *p<='9' ) {
    uint digit = (uint)(*p-'0');
    if( FD_UNLIKELY( last>(ULONG_MAX-digit)/10UL ) ) return -1;
    last = last*10UL + digit;
    have_last = 1;
    p++;
  }
  if( FD_UNLIKELY( p!=end || (!have_first && !have_last) ) ) return -1;
  if( FD_UNLIKELY( !object_sz ) ) return -2;

  if( !have_first ) {
    if( FD_UNLIKELY( !last ) ) return -2;
    *out_range0 = last<object_sz ? object_sz-last : 0UL;
    *out_range1 = object_sz;
    return 0;
  }

  if( FD_UNLIKELY( first>=object_sz ) ) return -2;
  if( FD_UNLIKELY( have_last && last<first ) ) return -2;
  *out_range0 = first;
  *out_range1 = have_last && last<object_sz-1UL ? last+1UL : object_sz;
  return 0;
}

/* handle_peek handles newly received TCP data.  peek_len bytes of
   unconsumed request head sit at conn->req_len in the iobuf. */

static void
handle_peek( fd_snapsv_t * ctx,
             uint          conn_idx,
             int           res ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  if( FD_UNLIKELY( res<=0 ) ) {
    if( FD_UNLIKELY( res<0 ) ) {
      FD_IP6_ADDR_CSTR( addr_cstr, &conn->peer_ip );
      FD_LOG_INFO(( "snapshot download peer %s:%u: receive error (%i-%s)",
                    addr_cstr, conn->peer_port, -res, fd_io_strerror( -res ) ));
    }
    conn_close( ctx, conn_idx );
    return;
  }
  uint peek_len = (uint)res;

  FD_MCNT_INC( SNAPSV, BYTES_READ, (ulong)res );

  char const * method;  ulong method_len;
  char const * path;    ulong path_len;
  int minor_version;
  struct phr_header headers[ REQ_HEADER_MAX ];
  ulong header_cnt = REQ_HEADER_MAX;
  int parsed = phr_parse_request(
      (char const *)conn_iobuf( ctx, conn ),
      conn->req.len + peek_len,
      &method, &method_len,
      &path,   &path_len,
      &minor_version,
      headers, &header_cnt,
      conn->req.len /* slowloris defense */
  );

  if( FD_UNLIKELY( parsed==-2 ) ) { /* request head incomplete */
    if( FD_UNLIKELY( conn->req.len+peek_len >= ctx->iobuf_sz ) ) {
      FD_LOG_DEBUG(( "conn %u: request head exceeds %u bytes", conn_idx, ctx->iobuf_sz ));
      conn_close( ctx, conn_idx );
      return;
    }
    /* avoid copying the same data again */
    prep_consume( ctx, conn_idx, peek_len, UDATA_OP_CONSUME_FRAG );
    conn->state = CONN_STATE_REQ_SKIP;
    return;
  }

  if( FD_UNLIKELY( parsed<0 ) ) { /* malformed request head */
    FD_LOG_DEBUG(( "conn %u: malformed request", conn_idx ));
    conn_close( ctx, conn_idx );
    return;
  }

  /* valid request at this point */
  FD_CHECK_ERR( (uint)parsed > conn->req.len, "request head shrank" );
  prep_consume( ctx, conn_idx, (uint)parsed - conn->req.len, UDATA_OP_CONSUME_TAIL );
  conn->state   = CONN_STATE_REQ_DONE;
  conn->req.len = (uint)parsed - conn->req.len;

  /* must not do any work until CONSUME_TAIL completes,
     so remember what to do for when that happens */
  snap_key_t query;
  uchar      query_hash[ 32 ];
  int        query_is_zstd;
  if( method_len==4UL && !memcmp( method, "HEAD", method_len ) ) {
    conn->head = 1;
  } else if( method_len==3UL && !memcmp( method, "GET", method_len ) ) {
    conn->head = 0;
  } else {
    conn->state    = CONN_STATE_RES_WRITE_ERR;
    conn->http_err = 500;
    conn->sick     = 1;
    return;
  }

  /* strip leading slashes */
  if( FD_UNLIKELY( path_len<10    ) ) goto not_found;
  if( FD_UNLIKELY( path[ 0 ]!='/' ) ) goto not_found;
  path++; path_len--;
  /* skip superfluous leading slashes to help buggy clients */
  for( ulong i=0UL; path_len && i<15; i++ ) {
    if( FD_LIKELY( path[ 0 ]!='/' ) ) break;
    path++; path_len--;
  }

  if( path_len==16 ) {
    if( !memcmp( path, "snapshot.tar.zst", 16UL ) ||
        !memcmp( path, "snapshot.tar.bz2", 16UL ) ) {
      conn->state       = CONN_STATE_RES_REDIRECT;
      conn->incremental = 0;
      return;
    }
  } else if( path_len==28 ) {
    if( !memcmp( path, "incremental-snapshot.tar.bz2", 28UL ) ||
        !memcmp( path, "incremental-snapshot.tar.zst", 28UL ) ) {
      conn->state       = CONN_STATE_RES_REDIRECT;
      conn->incremental = 1;
      return;
    }
  }

  /* found a snapshot? */
  if( match_snapshot_path( path, path_len, &query, query_hash, &query_is_zstd ) ) {
    snap_entry_t * entry = snap_map_update( ctx->snap_map, &query );
    if( FD_UNLIKELY( !entry ) ) goto not_found;
    if( FD_UNLIKELY( 0!=memcmp( entry->hash, query_hash, 32UL ) ) ) goto not_found;
    if( FD_UNLIKELY( entry->is_zstd!=query_is_zstd ) ) goto not_found;
    conn->state       = CONN_STATE_RES_WRITE_HDR;
    conn->snap.key    = query;
    conn->snap.slot   = entry;
    conn->range       = 0U;
    conn->snap.range0 = 0UL;
    conn->snap.range1 = entry->sz;
    conn->incremental = entry->key.base_slot!=ULONG_MAX;

    char const * range     = NULL;
    ulong        range_len = 0UL;
    for( ulong i=0UL; i<header_cnt; i++ ) {
      if( headers[ i ].name_len==5UL && !strncasecmp( headers[ i ].name, "range", 5UL ) ) {
        if( !conn->head ) { /* range header only valid for GET request */
          range     = headers[ i ].value;
          range_len = headers[ i ].value_len;
        }
      }
    }
    if( range ) {
      int range_err = parse_range_header( range, range_len, entry->sz, &conn->snap.range0, &conn->snap.range1 );
      if( FD_UNLIKELY( range_err ) ) {
        conn->state    = CONN_STATE_RES_WRITE_ERR;
        conn->http_err = (uint)( range_err==-2 ? 416 : 400 );
      } else {
        conn->range = 1U;
      }
    }
    return;
  }

not_found:
  conn->state    = CONN_STATE_RES_WRITE_ERR;
  conn->http_err = 404;

  /* next step happens at handle_consume_tail_comp */
}

/* handle_consume_frag_comp handles the completion of a CONSUME_FRAG op. */

static void
handle_consume_frag_comp( fd_snapsv_t * ctx,
                          uint          conn_idx,
                          int           res ) {
  if( FD_UNLIKELY( res<=0 ) ) {
    if( FD_UNLIKELY( res<0 ) ) {
      FD_LOG_DEBUG(( "conn %u: recv() failed (%i-%s)", conn_idx, -res, fd_io_strerror( -res ) ));
    }
    conn_close( ctx, conn_idx );
    return;
  }
  uint consume_len = (uint)res;
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  FD_CHECK_ERR( conn->state==CONN_STATE_REQ_SKIP, "conn state confusion" );
  conn->req.len += consume_len;
  prep_peek( ctx, conn_idx );
}

/* handle_consume_tail_comp handles the completion of a CONSUME_TAIL op. */

static void
handle_consume_tail_comp( fd_snapsv_t * ctx,
                          uint          conn_idx,
                          int           res ) {
  snapsv_conn_t * conn = &ctx->conn0[ conn_idx ];
  if( FD_UNLIKELY( res!=(int)conn->req.len ) ) {
    conn_close( ctx, conn_idx );
    return;
  }
  conn->req.len = 0;
  conn->request_start_nanos = 0L;
  iobuf_release( ctx, &conn->iobuf_idx );
  switch( ctx->conn0[ conn_idx ].state ) {
  case CONN_STATE_RES_WRITE_ERR:
    serve_http_err( ctx, conn_idx );
    break;
  case CONN_STATE_RES_WRITE_HDR:
    serve_snap_res_hdr( ctx, conn_idx );
    break;
  case CONN_STATE_RES_REDIRECT:
    serve_redirect( ctx, conn_idx );
    break;
  default:
    FD_LOG_CRIT(( "conn %u: state confusion", conn_idx ));
  }
}

/* futex_prep asks the kernel to send a CQE for when a new
   snapmk_out frag becomes available. */

static int
futex_prep( fd_snapsv_t * ctx,
            ulong         in_idx ) {
  ulong seq_prod = fd_mcache_seq_query( ctx->in[ in_idx ].seq_prod );
  ulong seq_next = fd_seq_inc( ctx->in[ in_idx ].seq_cons, 1UL );
  fd_frag_meta_t const * mline = ctx->in[ in_idx ].mcache + fd_mcache_line_idx( seq_next, ctx->in[ in_idx ].depth );
  if( FD_UNLIKELY( fd_frag_meta_seq_query( mline )==seq_next ) ) return 0;

  if( FD_LIKELY( ctx->in[ in_idx ].futex_armed ) ) return 1;
  fd_io_uring_t * ring = ctx->ring;
  fd_io_uring_sqe_t * sqe = fd_io_uring_get_sqe( ring->sq );
  FD_CHECK_ERR( sqe, "io_uring submission queue full" );
  *sqe = (fd_io_uring_sqe_t) {
    .opcode = FD_IORING_OP_FUTEX_WAIT,
    .flags  = FD_IOSQE_FIXED_FILE, /* ignored, required for sandbox (hope no kernel ABI breakage) */
    .fd     = FUTEX2_SIZE_U32,
    .addr   = (ulong)ctx->in[ in_idx ].seq_prod,
    .off    = (ulong)(uint)seq_prod, /* value to compare against */
    .addr3  = FUTEX_BITSET_MATCH_ANY
  };
  snapsv_udata_t udata = { .op = UDATA_OP_FUTEX, .conn_idx = (uint)in_idx };
  sqe->user_data = udata.user_data;
  ctx->in[ in_idx ].futex_armed = 1;
  return 1;
}

/* futex_comp is called when a snapmk_out frag was detected.  Such
   frags are also polled by the event loop, but this is required to wake
   up fast from an io_uring_enter sleep. */

static void
futex_comp( fd_snapsv_t * ctx,
            uint          in_idx,
            int           res ) {
  FD_CHECK_CRIT( in_idx<IN_LINK_MAX, "io_uring completion has invalid in index" );
  ctx->in[ in_idx ].futex_armed = 0;
  if( FD_UNLIKELY( res<0 && res!=-EAGAIN && res!=-ECANCELED && res!=-EINTR ) ) {
    FD_LOG_ERR(( "IORING_OP_FUTEX_WAIT failed (%i-%s)", -res, fd_io_strerror( -res ) ));
  }
}

/* handle_cqe handles a single io_uring completion. */

static void
handle_cqe( fd_snapsv_t *               ctx,
            fd_io_uring_cqe_t const * cqe ) {
  snapsv_udata_t udata = { .user_data = cqe->user_data };
  switch( udata.op ) {
  case UDATA_OP_ACCEPT:
    handle_accept( ctx, udata.conn_idx, cqe->res );
    break;
  case UDATA_OP_PEEK:
    handle_peek( ctx, udata.conn_idx, cqe->res );
    break;
  case UDATA_OP_CONSUME_FRAG:
    handle_consume_frag_comp( ctx, udata.conn_idx, cqe->res );
    break;
  case UDATA_OP_CONSUME_TAIL:
    handle_consume_tail_comp( ctx, udata.conn_idx, cqe->res );
    break;
  case UDATA_OP_WRITE_HDR:
    handle_write_hdr_comp( ctx, udata.conn_idx, cqe->res );
    break;
  case UDATA_OP_SHOVEL_DISK:
    shovel_comp_disk( ctx, udata.conn_idx, cqe->res );
    break;
  case UDATA_OP_SHOVEL_NET:
    shovel_comp_net( ctx, udata.conn_idx, cqe->res );
    break;
  case UDATA_OP_FUTEX:
    futex_comp( ctx, udata.conn_idx, cqe->res );
    break;
  case UDATA_OP_TIMEOUT:
    break;
  default:
    FD_LOG_CRIT(( "io_uring completion has invalid user_data 0x%016lx", (ulong)cqe->user_data ));
  }
}

/* stem_in_update grants flow control credits to an upstream producer. */

static inline void
stem_in_update( fd_stem_tile_in_t * in );

/* after_credit performs one io_uring event-loop iteration. */

static void
after_credit( fd_snapsv_t *       ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)stem; (void)opt_poll_in;
  fd_io_uring_t * ring = ctx->ring;

  /* Reap background completions */
  uint ready = fd_io_uring_cq_ready( ring->cq );
  for( uint i=0U; i<ready; i++ ) {
    handle_cqe( ctx, fd_io_uring_cq_head( ring->cq ) );
    fd_io_uring_cq_advance( ring->cq, 1U );
    *charge_busy = 1;
  }

  /* Prepare for sleep */
  int waiting = !!futex_prep( ctx, 0UL );
  stem_in_update( &stem->in[ 0 ] );

  /* Dispatch io_uring work, poll completions, and do a bounded sleep */
  uint tail = ring->sq->sqe_tail;
  atomic_store_explicit( ring->sq->ktail, tail, memory_order_release );
  uint head = atomic_load_explicit( ring->sq->khead, memory_order_relaxed );
  ring->sq->sqe_head = head;
  uint to_submit = tail - head;
  fd_kernel_timespec_t timeout = { .tv_nsec = (long)50e6L }; /* 50ms */
  fd_io_uring_getevents_arg_t enter_arg = { .ts = (ulong)&timeout };
  int submitted = fd_io_uring_enter(
      ring->ioring_fd, to_submit, !!waiting,
      FD_IORING_ENTER_GETEVENTS | FD_IORING_ENTER_EXT_ARG,
      &enter_arg, sizeof(enter_arg)
  );
  if( FD_UNLIKELY( submitted<0 ) ) {
    if( FD_LIKELY( errno==ETIME ) ) {
      submitted = 0; /* timeout, do housekeeping */
    } else if( FD_LIKELY( errno==EINTR ) ) {
      *charge_busy = !!submitted;
      return;
    } else {
      FD_LOG_ERR(( "io_uring_enter failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
  if( FD_UNLIKELY( fd_io_uring_sq_dropped( ring->sq ) ) ) {
    FD_LOG_ERR(( "io_uring submission queue dropped entries" ));
  }
  if( FD_UNLIKELY( fd_io_uring_cq_overflow( ring->cq ) ) ) {
    FD_LOG_ERR(( "io_uring completion queue overflowed" ));
  }

  /* Reap deferred/immediate completions */
  ready = fd_io_uring_cq_ready( ring->cq );
  for( uint i=0U; i<ready; i++ ) {
    handle_cqe( ctx, fd_io_uring_cq_head( ring->cq ) );
    fd_io_uring_cq_advance( ring->cq, 1U );
    *charge_busy = 1;
  }
}

/* snap_open opens the given snapshot by pool index.  Silently ignores
   ENOENT (rare race condition where the snapshot is immediately
   deleted after being created.) */

static void
snap_open( fd_snapsv_t * ctx,
           ulong         slot,
           ulong         base_slot,
           ulong         pool_idx,
           ulong         sz,
           char const *  name ) {
  FD_CHECK_ERR( ctx->snap_cnt_full + ctx->snap_cnt_incr < ctx->snap_max, "too many snapshot files (snapmk_out desync?)" );
  FD_CHECK_CRIT( pool_idx < ctx->snap_max, "invalid snapshot pool index" );

  ulong parsed_full_slot;
  ulong parsed_incremental_slot;
  uchar hash[ 32 ];
  int   is_zstd;
  FD_CHECK_ERR( !fd_ssarchive_parse_filename( name, &parsed_full_slot, &parsed_incremental_slot, hash, &is_zstd ),
                "invalid snapshot filename" );

  snap_entry_t * entry = snap_map_insert( ctx->snap_map, &(snap_key_t){slot, base_slot} );
  FD_CHECK_ERR( !!entry, "snap_map_insert failed (snapmk_out desync?)" );

  memcpy( entry->hash, hash, sizeof(entry->hash) );
  entry->sz     = sz;
  entry->fd     = FD_SNAP_RO_FD( pool_idx );
  entry->locked = 0;
  entry->is_zstd = !!is_zstd;
  if( base_slot==ULONG_MAX ) {
    ctx->snap_cnt_full++;
    ctx->newest_full = NULL;
  } else {
    ctx->snap_cnt_incr++;
    ctx->newest_incr = NULL;
  }
}

/* snap_lock tries to acquire a read-lock to a snapshot file handle.
   Returns 1 on success, 0 on failure (currently write locked).
   Snapshots deliberately remain locked until the snapshot is about to
   be deleted to prevent F_SETLK churn. */

FD_FN_UNUSED static int
snap_lock( snap_entry_t * entry ) {
  if( entry->locked ) return 1; /* already locked */
  struct flock lock = {
    .l_type   = F_RDLCK,
    .l_whence = SEEK_SET
  };
  if( FD_UNLIKELY( fcntl( entry->fd, F_SETLK, &lock ) ) ) {
    if( errno==EAGAIN || errno==EACCES ) return 0; /* write locked */
    FD_LOG_ERR(( "fcntl(F_RDLCK, %lu, %lu) failed (%i-%s)", entry->key.slot, entry->key.base_slot, errno, fd_io_strerror( errno ) ));
  }
  entry->locked = 1;
  return 1;
}

/* snap_close releases a snapshot file handle. */

static void
snap_close( fd_snapsv_t * ctx,
            ulong         slot,
            ulong         base_slot ) {
  snap_entry_t * entry = snap_map_update( ctx->snap_map, &(snap_key_t){slot, base_slot} );
  if( FD_UNLIKELY( !entry ) ) return; /* ignore */

  if( entry->locked ) {
    struct flock lock = {
      .l_type   = F_UNLCK,
      .l_whence = SEEK_SET
    };
    if( FD_UNLIKELY( fcntl( entry->fd, F_SETLK, &lock ) ) ) {
      FD_LOG_ERR(( "fcntl(F_UNLCK, %lu, %lu) failed (%i-%s)", slot, base_slot, errno, fd_io_strerror( errno ) ));
    }
    entry->locked = 0;
  }
  entry->fd = -1;

  snap_map_remove( ctx->snap_map, entry );
  ctx->newest_full = ctx->newest_incr = NULL;
  if( base_slot==ULONG_MAX ) {
    FD_CHECK_CRIT( ctx->snap_cnt_full, "full snapshot count underflow" );
    ctx->snap_cnt_full--;
  } else {
    FD_CHECK_CRIT( ctx->snap_cnt_incr, "incremental snapshot count underflow" );
    ctx->snap_cnt_incr--;
  }
}

/* msg_snapmk is called for every snapmk_out frag. */

static void
msg_snapmk( fd_snapsv_t *           ctx,
            ulong                   msg_type, /* sig */
            fd_snapmk_msg_t const * msg,
            ulong                   msg_sz ) {
  switch( msg_type ) {
  case FD_SNAPMK_MSG_FOUND: {
    FD_CHECK_CRIT( msg_sz==sizeof(fd_snapmk_msg_found_t), "ABI mismatch" );
    snap_open( ctx, msg->found.slot, msg->found.base_slot, msg->found.pool_idx, msg->found.sz, msg->found.name );
    break;
  }
  case FD_SNAPMK_MSG_CREATED: {
    FD_CHECK_CRIT( msg_sz==sizeof(fd_snapmk_msg_created_t), "ABI mismatch" );
    snap_open( ctx, msg->created.slot, msg->created.base_slot, msg->created.pool_idx, msg->created.sz, msg->created.name );
    break;
  }
  case FD_SNAPMK_MSG_DELETED: {
    FD_CHECK_CRIT( msg_sz==sizeof(fd_snapmk_msg_deleted_t), "ABI mismatch" );
    snap_close( ctx, msg->deleted.slot, msg->deleted.base_slot );
    break;
  }
  default:
    break;
  }
}

/* returnable_frag is called for every input frag */

static int
returnable_frag( fd_snapsv_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)ctl; (void)tsorig; (void)tspub; (void)stem;
  ctx->in[ in_idx ].seq_cons = seq;
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_SNAPMK:
    FD_CHECK_CRIT( chunk >= ctx->in[ in_idx ].chunk0 &&
                   chunk <= ctx->in[ in_idx ].wmark &&
                   sz    <= ctx->in[ in_idx ].mtu,
                   "input frag is out-of-bounds" );
    fd_snapmk_msg_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    msg_snapmk( ctx, sig, msg, sz );
    return 0; /* ok */
  default:
    FD_LOG_CRIT(( "unhandled frag from in_idx=%lu", in_idx ));
  }
}

static void
metrics_write( fd_snapsv_t * ctx ) {
  FD_MGAUGE_SET( SNAPSV, SNAPSHOTS_AVAILABLE_FULL,        ctx->snap_cnt_full );
  FD_MGAUGE_SET( SNAPSV, SNAPSHOTS_AVAILABLE_INCREMENTAL, ctx->snap_cnt_incr );
  FD_MGAUGE_SET( SNAPSV, CONN_ACTIVE,                     ctx->conn_cnt      );
}

#define STEM_BURST 1UL
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapsv_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapsv_t)
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#include "../../disco/stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_snapsv = {
  .name                     = "snapsv",
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .rlimit_nproc             = 1024UL,
};
#endif
