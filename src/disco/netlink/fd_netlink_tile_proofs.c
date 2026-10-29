/* CBMC model of the netlink tile's IPv4 route table sync.

   The kernel side (RTM_GETROUTE dumps) and the net tile side (fd_fib4
   capacity rules) are modeled; the netlink tile's after_credit and
   after_frag run unmodified. */

#include "../stem/fd_stem.h"

#if !defined(CBMC)
#error "Intended to only be used from CBMC"
#endif

static void
model_stem_publish( fd_stem_context_t * stem,
                    ulong               out_idx,
                    ulong               sig,
                    ulong               chunk,
                    ulong               sz,
                    ulong               ctl,
                    ulong               tsorig,
                    ulong               tspub );

#define fd_stem_publish model_stem_publish
#include "fd_netlink_tile.c"
#undef fd_stem_publish

int   nondet_int  ( void );
ulong nondet_ulong( void );

static fd_netlink_tile_ctx_t fd_netlink_ctx;

#define ROUTE_CNT_MAX (3U)
#define STEP_CNT      (20)

/* Kernel route tables (0=local, 1=main) */

static uint kern_cnt [ 2 ];
static int  kern_peer[ 2 ][ ROUTE_CNT_MAX ];
static uint dump_tbl;

struct fake_msg {
  struct nlmsghdr nlh;
  uint            idx;
};
static struct fake_msg msgs[ ROUTE_CNT_MAX+1U ];

/* Net tile FIB model */

static ulong fib_route_cnt[ 2 ];
static ulong fib_peer_cnt [ 2 ];
static uint  fib_loaded   [ 2 ]; /* bit i set if kernel route i present */
static ulong flush_cnt;

static uchar out_buf[ 64 ];
static long  clock_now;

static ulong
tbl_idx( uint table_id ) {
  return table_id==RT_TABLE_LOCAL ? 0UL : 1UL;
}

static void
model_stem_publish( fd_stem_context_t * stem,
                    ulong               out_idx,
                    ulong               sig,
                    ulong               chunk,
                    ulong               sz,
                    ulong               ctl,
                    ulong               tsorig,
                    ulong               tspub ) {
  (void)stem; (void)out_idx; (void)sig; (void)sz; (void)ctl; (void)tsorig; (void)tspub;
  __CPROVER_assert( chunk==0UL, "chunk" );
  fd_iproute_msg_t const * msg = (fd_iproute_msg_t const *)out_buf;
  if( msg->op==FD_IPROUTE_OP_FLUSH ) {
    fib_route_cnt[0] = fib_route_cnt[1] = 0UL;
    fib_peer_cnt [0] = fib_peer_cnt [1] = 0UL;
    fib_loaded   [0] = fib_loaded   [1] = 0U;
    flush_cnt++;
    return;
  }
  __CPROVER_assert( msg->op==FD_IPROUTE_OP_UPSERT, "dump publishes upserts" );
  ulong t   = tbl_idx( msg->table_id );
  uint  idx = msg->prio;
  __CPROVER_assert( !( fib_loaded[t] & (1U<<idx) ), "no duplicate upsert" );
  if( msg->prefix==32U && msg->dst_addr ) {
    __CPROVER_assert( fib_peer_cnt[t]<fd_netlink_ctx.route_peer_max, "fd_fib4 peer insert never fails" );
    fib_peer_cnt[t]++;
  } else {
    /* fd_fib4 slot 0 is the dummy throw route */
    __CPROVER_assert( fib_route_cnt[t]+1UL<fd_netlink_ctx.route_max, "fd_fib4 insert never fails" );
    fib_route_cnt[t]++;
  }
  fib_loaded[t] |= 1U<<idx;
}

/* Kernel netlink model */

ssize_t
sendto( int fd, void const * buf, size_t len, int flags, struct sockaddr const * addr, socklen_t addr_len ) {
  (void)fd; (void)flags; (void)addr; (void)addr_len;
  struct {
    struct nlmsghdr nlh;
    struct rtmsg    rtm;
    struct rtattr   rta;
    uint            table_id;
  } const * req = buf;
  __CPROVER_assert( req->nlh.nlmsg_type==RTM_GETROUTE, "dump request" );
  dump_tbl = req->table_id;
  return (long)len;
}

fd_netlink_iter_t *
fd_netlink_iter_init( fd_netlink_iter_t * iter,
                      fd_netlink_t *      netlink,
                      uchar *             buf,
                      ulong               buf_sz ) {
  (void)netlink;
  uint n = kern_cnt[ tbl_idx( dump_tbl ) ];
  for( uint i=0U; i<=ROUTE_CNT_MAX; i++ ) {
    msgs[i].nlh = (struct nlmsghdr){ .nlmsg_type = i<n ? RTM_NEWROUTE : NLMSG_DONE };
    msgs[i].idx = i;
  }
  *iter = (fd_netlink_iter_t){ .buf=buf, .buf_sz=buf_sz, .msg0=(uchar *)&msgs[0], .msg1=(uchar *)&msgs[n+1U] };
  return iter;
}

int
fd_netlink_iter_done( fd_netlink_iter_t const * iter ) {
  return iter->err!=0 || ((struct nlmsghdr const *)iter->msg0)->nlmsg_type==NLMSG_DONE;
}

fd_netlink_iter_t *
fd_netlink_iter_next( fd_netlink_iter_t * iter,
                      fd_netlink_t *      netlink ) {
  (void)netlink;
  if( !fd_netlink_iter_done( iter ) ) iter->msg0 += sizeof(struct fake_msg);
  return iter;
}

int
fd_fib4_netlink_translate( struct nlmsghdr const * msg_hdr,
                           uint                    table_id,
                           fd_iproute_msg_t *      route ) {
  uint idx  = ((struct fake_msg const *)msg_hdr)->idx;
  int  peer = kern_peer[ tbl_idx( table_id ) ][ idx ];
  *route = (fd_iproute_msg_t){
    .dst_addr = peer ? idx+1U : (idx+1U)<<8,
    .prefix   = peer ? 32 : 24,
    .prio     = idx,
    .table_id = table_id,
    .op       = FD_IPROUTE_OP_UPSERT,
  };
  return 1;
}

/* Environment stubs */

long fd_log_wallclock( void ) { return clock_now; }
long fd_log_sleep( long dt ) { (void)dt; return 0L; }
char const * fd_log_private_0( char const * fmt, ... ) { (void)fmt; return ""; }
void fd_log_private_1( int level, long now, char const * file, int line, char const * func, char const * msg ) {
  (void)level; (void)now; (void)file; (void)line; (void)func; (void)msg;
}
void fd_log_private_2( int level, long now, char const * file, int line, char const * func, char const * msg ) {
  (void)level; (void)now; (void)file; (void)line; (void)func; (void)msg;
  __CPROVER_assert( 0, "error log used" );
}
void fd_waker_client_rearm( ulong idx ) { (void)idx; }

/* Harness */

static ulong kern_route_cnt( ulong t ) {
  ulong cnt = 0UL;
  for( uint i=0U; i<ROUTE_CNT_MAX; i++ ) cnt += (ulong)( i<kern_cnt[t] && !kern_peer[t][i] );
  return cnt;
}

static ulong kern_peer_cnt( ulong t ) {
  ulong cnt = 0UL;
  for( uint i=0U; i<ROUTE_CNT_MAX; i++ ) cnt += (ulong)( i<kern_cnt[t] && kern_peer[t][i] );
  return cnt;
}

void
route_sync( void ) {
  fd_netlink_tile_ctx_t * ctx = &fd_netlink_ctx;
  for( ulong t=0UL; t<2UL; t++ ) {
    kern_cnt[t] = (uint)nondet_ulong();
    __CPROVER_assume( kern_cnt[t]<=ROUTE_CNT_MAX );
    for( uint i=0U; i<ROUTE_CNT_MAX; i++ ) kern_peer[t][i] = nondet_int()!=0;
  }

  ctx->route_max      = nondet_ulong();
  ctx->route_peer_max = nondet_ulong();
  __CPROVER_assume( ctx->route_max>=1UL && ctx->route_max<=ROUTE_CNT_MAX+1UL );
  __CPROVER_assume( ctx->route_peer_max<=ROUTE_CNT_MAX );

  ulong waker_fseq = 0UL;
  ctx->waker_fseq     = &waker_fseq;
  ctx->out_mem        = out_buf;
  ctx->update_backoff = 1L;
  ctx->action         = FD_NET_TILE_ACTION_ROUTE4_UPDATE;

  fd_stem_context_t stem = { .sleep = 1 };

  int   fits[2];
  for( ulong t=0UL; t<2UL; t++ ) {
    fits[t] = kern_route_cnt( t )+1UL<=ctx->route_max && kern_peer_cnt( t )<=ctx->route_peer_max;
  }

  ulong sync_cnt         = 0UL;
  ulong overflow_flushes = ULONG_MAX;
  for( int step=0; step<STEP_CNT; step++ ) {
    clock_now += 2L;

    /* Net tile requests a resync after a failed insert */
    if( nondet_int() ) after_frag( ctx, 0UL, 0UL, FD_NETLINK_ROUTE4_SYNC_SIG, 0UL, 0UL, 0UL, &stem );

    int opt_poll_in = 1;
    int charge_busy = 0;
    after_credit( ctx, &stem, &opt_poll_in, &charge_busy );

    if( ctx->metrics.route_full_syncs!=sync_cnt ) {
      sync_cnt = ctx->metrics.route_full_syncs;
      for( ulong t=0UL; t<2UL; t++ ) {
        if( fits[t] ) __CPROVER_assert( fib_loaded[t]==(1U<<kern_cnt[t])-1U, "table that fits is fully loaded" );
      }
      __CPROVER_assert( ctx->route_overflow==!( fits[0] && fits[1] ), "overflow latch tracks capacity" );
      if( ctx->route_overflow && !( ctx->action & FD_NET_TILE_ACTION_ROUTE4_UPDATE ) && overflow_flushes==ULONG_MAX ) overflow_flushes = flush_cnt;
    }
  }

  __CPROVER_assert( sync_cnt>=1UL, "sync completes" );
  if( overflow_flushes!=ULONG_MAX ) {
    __CPROVER_assert( flush_cnt==overflow_flushes, "no flush after overflowed sync" );
  }
}

void
cbmc_main( void ) {
  route_sync();
}
