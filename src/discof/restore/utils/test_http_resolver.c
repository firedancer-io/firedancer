#include "fd_http_resolver.h"

#include "../../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

/* Drives the real resolver against a loopback HTTP server, so the
   peer-validity gate and the on_resolve callback are exercised, not
   just the per-leg return codes (those live in test_ssresolve). */

#define MAX_PEERS (4UL)
#define HASH_B58  "9NUeyNtZH1uoYsivVTvCHrWeqcMHvxrBCvvwHcwQG1L4"

static uchar _selector[ 1UL<<20 ] __attribute__((aligned(128UL)));
static uchar _resolver[ 1UL<<22 ] __attribute__((aligned(128UL)));

/* The resolver reports a resolved peer exactly once per cycle; record
   what it told the selector. */

struct resolve_record {
  fd_sspeer_selector_t * selector;
  int                    called;
  ulong                  full_slot;
  ulong                  incr_slot;
  int                    incr_hash_null;
};

typedef struct resolve_record resolve_record_t;

/* Mirrors snapct's on_resolve (fd_snapct_tile.c:439): the resolver
   reports, the callback is what feeds the selector. */

static void
on_resolve( void *                  ctx,
            fd_sspeer_key_t const * key,
            fd_ip4_port_t           addr,
            ulong                   full_slot,
            ulong                   incr_slot,
            uchar                   full_hash[ FD_HASH_FOOTPRINT ],
            uchar                   incr_hash[ FD_HASH_FOOTPRINT ] ) {
  resolve_record_t * rec = ctx;
  rec->called++;
  rec->full_slot      = full_slot;
  rec->incr_slot      = incr_slot;
  rec->incr_hash_null = !incr_hash;

  FD_TEST( FD_SSPEER_SCORE_INVALID!=fd_sspeer_selector_add( rec->selector, key, addr, FD_SSPEER_LATENCY_UNKNOWN,
                                                            full_slot, incr_slot, full_hash, incr_hash ) );
  fd_sspeer_selector_process_cluster_slot( rec->selector );
}

/* set_nonblock makes fd non-blocking, so the test never parks waiting
   on a peer that the resolver has not driven yet. */

static void
set_nonblock( int fd ) {
  int flags = fcntl( fd, F_GETFL, 0 );
  FD_TEST( -1!=flags );
  FD_TEST( -1!=fcntl( fd, F_SETFL, flags|O_NONBLOCK ) );
}

/* listen_loopback binds an ephemeral port on 127.0.0.1 and returns the
   listening socket, writing the bound address to addr. */

static int
listen_loopback( fd_ip4_port_t * addr ) {
  int lfd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( -1!=lfd );

  int optval = 1;
  FD_TEST( -1!=setsockopt( lfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int) ) );

  struct sockaddr_in sa = {
    .sin_family = AF_INET,
    .sin_port   = 0,
    .sin_addr   = { .s_addr = fd_uint_bswap( INADDR_LOOPBACK ) }
  };
  FD_TEST( -1!=bind( lfd, fd_type_pun_const( &sa ), sizeof(sa) ) );
  FD_TEST( -1!=listen( lfd, 8 ) );
  set_nonblock( lfd ); /* accept must never park the test */

  socklen_t sa_len = sizeof(sa);
  FD_TEST( -1!=getsockname( lfd, fd_type_pun( &sa ), &sa_len ) );

  addr->addr = sa.sin_addr.s_addr;
  addr->port = sa.sin_port;
  return lfd;
}

struct conn {
  int fd;
  int served;
};

typedef struct conn conn_t;

/* serve accepts any pending connection, reads its request, and replies
   with full_resp or incr_resp depending on the path requested.  The
   resolver opens one connection per leg, and the accept order does not
   track the leg, so the path is what selects the reply.  Connections
   are held open until teardown. */

static void
serve( int          lfd,
       conn_t *     conns,
       ulong *      conns_len,
       char const * full_resp,
       char const * incr_resp ) {
  for(;;) {
    int cfd = accept( lfd, NULL, NULL );
    if( cfd==-1 ) break;
    set_nonblock( cfd );
    FD_TEST( *conns_len<2UL*MAX_PEERS );
    conns[ (*conns_len)++ ] = (conn_t){ .fd = cfd, .served = 0 };
  }

  for( ulong i=0UL; i<*conns_len; i++ ) {
    if( conns[ i ].served ) continue;

    char req[ 4096 ];
    long n = recv( conns[ i ].fd, req, sizeof(req)-1UL, 0 );
    if( n<=0 ) continue;
    req[ n ] = '\0';
    if( !strstr( req, "\r\n\r\n" ) ) continue;

    char const * resp = strstr( req, "/incremental-snapshot.tar.bz2" ) ? incr_resp : full_resp;
    FD_TEST( (long)strlen( resp )==send( conns[ i ].fd, resp, strlen( resp ), 0 ) );
    conns[ i ].served = 1;
  }
}

/* run_resolve wires up a resolver and a selector, adds one peer, and
   pumps both sides until the peer resolves or the budget runs out. */

static void
run_resolve( char const *       full_resp,
             char const *       incr_resp,
             int                incremental_fetch,
             resolve_record_t * rec,
             fd_sspeer_t *      best_full,
             fd_sspeer_t *      best_incr ) {
  fd_memset( rec, 0, sizeof(*rec) );

  FD_TEST( fd_sspeer_selector_footprint( MAX_PEERS )<=sizeof(_selector) );
  fd_sspeer_selector_t * selector = fd_sspeer_selector_join( fd_sspeer_selector_new( _selector, MAX_PEERS, 1234UL ) );
  FD_TEST( selector );
  rec->selector = selector;

  int epoll_fd = epoll_create1( 0 );
  FD_TEST( -1!=epoll_fd );

  FD_TEST( fd_http_resolver_footprint( MAX_PEERS )<=sizeof(_resolver) );
  fd_http_resolver_t * resolver = fd_http_resolver_join( fd_http_resolver_new( _resolver, MAX_PEERS, incremental_fetch, 0, on_resolve, rec, epoll_fd ) );
  FD_TEST( resolver );

  fd_ip4_port_t addr;
  int lfd = listen_loopback( &addr );
  FD_TEST( 0==fd_http_resolver_add( resolver, addr, "localhost", 0, selector ) );

  conn_t conns[ 2UL*MAX_PEERS ];
  ulong  conns_len = 0UL;

  /* The resolve deadline is 2s, so a budget far below that keeps a
     failure here a real failure rather than a timeout. */
  for( ulong i=0UL; i<2048UL && !rec->called; i++ ) {
    fd_http_resolver_advance( resolver, fd_log_wallclock(), selector );
    serve( lfd, conns, &conns_len, full_resp, incr_resp );
  }

  fd_sspeer_selector_process_cluster_slot( selector );
  *best_full = fd_sspeer_selector_best( selector, 0, FD_SSPEER_SLOT_UNKNOWN, 0UL );
  *best_incr = fd_sspeer_selector_best( selector, 1, rec->full_slot, 0UL );

  for( ulong i=0UL; i<conns_len; i++ ) FD_TEST( 0==close( conns[ i ].fd ) );
  FD_TEST( 0==close( lfd ) );
  FD_TEST( 0==close( epoll_fd ) );
}

static char const * FULL_303 =
  "HTTP/1.1 303 See Other\r\n"
  "Location: /snapshot-100-" HASH_B58 ".tar.zst\r\n"
  "Content-Length: 0\r\n\r\n";

static char const * INCR_303 =
  "HTTP/1.1 303 See Other\r\n"
  "Location: /incremental-snapshot-100-200-" HASH_B58 ".tar.zst\r\n"
  "Content-Length: 0\r\n\r\n";

/* The case the fix is about: the server has a full but no incremental.
   The peer must still reach the selector, usable for the full and not
   for the incremental. */

static void
test_full_only_peer( void ) {
  char const * absent[] = {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 410 Gone\r\nContent-Length: 0\r\n\r\n"
  };

  for( ulong i=0UL; i<sizeof(absent)/sizeof(absent[0]); i++ ) {
    resolve_record_t rec;
    fd_sspeer_t      best_full, best_incr;
    run_resolve( FULL_303, absent[ i ], 1 /* fetch incremental */, &rec, &best_full, &best_incr );

    FD_TEST( rec.called==1 );
    FD_TEST( rec.full_slot==100UL );
    FD_TEST( rec.incr_slot==FD_SSPEER_SLOT_UNKNOWN );
    FD_TEST( rec.incr_hash_null );

    FD_TEST( best_full.addr.l );                        /* selectable for the full        */
    FD_TEST( best_full.full_slot==100UL );
    FD_TEST( !best_incr.addr.l );                       /* never for the incremental      */
  }
  FD_LOG_NOTICE(( "pass: test_full_only_peer" ));
}

/* A server with both snapshots resolves both slots. */

static void
test_full_and_incremental_peer( void ) {
  resolve_record_t rec;
  fd_sspeer_t      best_full, best_incr;
  run_resolve( FULL_303, INCR_303, 1, &rec, &best_full, &best_incr );

  FD_TEST( rec.called==1 );
  FD_TEST( rec.full_slot==100UL );
  FD_TEST( rec.incr_slot==200UL );
  FD_TEST( !rec.incr_hash_null );

  FD_TEST( best_full.addr.l );
  FD_TEST( best_incr.addr.l );
  FD_TEST( best_incr.incr_slot==200UL );

  FD_LOG_NOTICE(( "pass: test_full_and_incremental_peer" ));
}

/* A server missing the full is useless and must never be reported,
   however well the incremental leg goes. */

static void
test_full_absent_peer_rejected( void ) {
  resolve_record_t rec;
  fd_sspeer_t      best_full, best_incr;
  run_resolve( "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", INCR_303, 1, &rec, &best_full, &best_incr );

  FD_TEST( !rec.called );
  FD_TEST( !best_full.addr.l );
  FD_TEST( !best_incr.addr.l );

  FD_LOG_NOTICE(( "pass: test_full_absent_peer_rejected" ));
}

/* With incremental fetch off the incremental leg is never opened, so
   the peer resolves on the full alone. */

static void
test_no_incremental_fetch( void ) {
  resolve_record_t rec;
  fd_sspeer_t      best_full, best_incr;
  run_resolve( FULL_303, INCR_303, 0 /* no incremental fetch */, &rec, &best_full, &best_incr );

  FD_TEST( rec.called==1 );
  FD_TEST( rec.full_slot==100UL );
  FD_TEST( rec.incr_slot==FD_SSPEER_SLOT_UNKNOWN );

  FD_TEST( best_full.addr.l );
  FD_TEST( !best_incr.addr.l );

  FD_LOG_NOTICE(( "pass: test_no_incremental_fetch" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_full_only_peer();
  test_full_and_incremental_peer();
  test_full_absent_peer_rejected();
  test_no_incremental_fetch();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
