#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include "fd_adns.h"
#include "fd_lookup.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

/* Deterministic fd_adns coverage: no live nameserver.  resolv.conf
   and /etc/hosts come from memfds (same hook as test_resolv), the
   nameserver is a loopback blackhole so pending requests only ever
   expire, and expiry timing is driven through the caller-supplied
   now.  Wire-answer acceptance is covered by crafting response
   packets for fd_dns_ip4_answer directly. */

#define BLACKHOLE_RESOLVCONF "nameserver 127.255.255.254\n"
#define HOSTS                "10.0.0.1 twohost\n10.0.0.2 twohost\n"

static int
memfd_with( char const * data ) {
  int fd = memfd_create( "test_adns", 0 );
  FD_TEST( fd>=0 );
  FD_TEST( (long)strlen( data )==write( fd, data, strlen( data ) ) );
  return fd;
}

static uchar adns_mem[ 65536 ] __attribute__((aligned(64)));

static fd_adns_t *
new_adns( ulong max_reqs ) {
  FD_TEST( fd_adns_footprint( max_reqs )<=sizeof(adns_mem) );
  fd_adns_t * adns = fd_adns_join( fd_adns_new( adns_mem, max_reqs ) );
  FD_TEST( adns );
  return adns;
}

static void
test_local_completion( void ) {
  fd_adns_t * adns = new_adns( 4UL );
  fd_adns_result_t res[ 1 ];

  /* IPv4 literal completes on next advance, no I/O */
  FD_TEST( 0==fd_adns_resolve( adns, "192.168.1.7", 7UL ) );
  FD_TEST( 1==fd_adns_advance( adns, 0L, res ) );
  FD_TEST( res->req_id==7UL && !res->err && res->addr_cnt==1UL );
  FD_TEST( res->addrs[ 0 ]==FD_IP4_ADDR( 192, 168, 1, 7 ) );

  /* /etc/hosts name with two entries: multi-address completion */
  FD_TEST( 0==fd_adns_resolve( adns, "twohost", 8UL ) );
  FD_TEST( 1==fd_adns_advance( adns, 0L, res ) );
  FD_TEST( res->req_id==8UL && !res->err && res->addr_cnt==2UL );
  FD_TEST( res->addrs[ 0 ]==FD_IP4_ADDR( 10, 0, 0, 1 ) );
  FD_TEST( res->addrs[ 1 ]==FD_IP4_ADDR( 10, 0, 0, 2 ) );

  /* Unresolvable name shape fails immediately */
  FD_TEST( 0==fd_adns_resolve( adns, "", 9UL ) );
  FD_TEST( 1==fd_adns_advance( adns, 0L, res ) );
  FD_TEST( res->req_id==9UL && res->err==FD_EAI_NONAME && !res->addr_cnt );

  FD_TEST( 0==fd_adns_advance( adns, 0L, res ) );
  fd_adns_delete( fd_adns_leave( adns ) );
}

static void
test_expiry_and_requeue( void ) {
  fd_adns_t * adns = new_adns( 4UL );
  fd_adns_result_t res[ 1 ];

  /* Nameserver is a blackhole: request expires after both attempts.
     attempts=2, retry=2.5s: sends at t0 and t0+2.5s, expires at
     t0+5s. */
  long t0 = 1000L*1000L*1000L;
  FD_TEST( 0==fd_adns_resolve( adns, "peer.example.com", 1UL ) );
  FD_TEST( 0==fd_adns_advance( adns, t0, res ) );                      /* first send */
  FD_TEST( 0==fd_adns_advance( adns, t0+2600L*1000L*1000L, res ) );    /* second send */
  FD_TEST( 1==fd_adns_advance( adns, t0+5100L*1000L*1000L, res ) );    /* attempts exhausted */
  FD_TEST( res->req_id==1UL && res->err==FD_EAI_AGAIN && !res->addr_cnt );

  /* AGAIN means the caller may re-queue: slot must be free again */
  FD_TEST( 0==fd_adns_resolve( adns, "peer.example.com", 2UL ) );
  FD_TEST( 0==fd_adns_advance( adns, t0, res ) );

  fd_adns_delete( fd_adns_leave( adns ) );
}

static void
test_backpressure( void ) {
  fd_adns_t * adns = new_adns( 2UL );
  fd_adns_result_t res[ 1 ];

  FD_TEST(  0==fd_adns_resolve( adns, "a.example.com", 1UL ) );
  FD_TEST(  0==fd_adns_resolve( adns, "b.example.com", 2UL ) );
  FD_TEST( -1==fd_adns_resolve( adns, "c.example.com", 3UL ) );

  /* Draining completions frees slots */
  long t = 0L;
  ulong popped = 0UL;
  for( ulong i=0UL; i<8UL && popped<2UL; i++, t += 3L*1000L*1000L*1000L ) popped += (ulong)!!fd_adns_advance( adns, t, res );
  FD_TEST( popped==2UL );
  FD_TEST( 0==fd_adns_resolve( adns, "c.example.com", 3UL ) );

  fd_adns_delete( fd_adns_leave( adns ) );
}

/* Wire-format answer acceptance, via the same parser the adns drain
   uses.  Build a response to an A query for a 1-label name. */

static ulong
craft_answer( uchar * out,
              ushort  flags,
              ushort  ancount,
              uint    addr0,
              uint    addr1 ) {
  ulong i = 0UL;
  out[ i++ ] = 0x12; out[ i++ ] = 0x34;                       /* id */
  out[ i++ ] = (uchar)(flags>>8); out[ i++ ] = (uchar)flags;  /* flags */
  out[ i++ ] = 0; out[ i++ ] = 1;                             /* qdcount */
  out[ i++ ] = (uchar)(ancount>>8); out[ i++ ] = (uchar)ancount;
  out[ i++ ] = 0; out[ i++ ] = 0;                             /* nscount */
  out[ i++ ] = 0; out[ i++ ] = 0;                             /* arcount */
  out[ i++ ] = 4; memcpy( out+i, "peer", 4UL ); i += 4UL;     /* question */
  out[ i++ ] = 0;
  out[ i++ ] = 0; out[ i++ ] = 1;                             /* type A */
  out[ i++ ] = 0; out[ i++ ] = 1;                             /* class IN */
  uint addrs[ 2 ] = { addr0, addr1 };
  for( ushort a=0; a<ancount; a++ ) {
    out[ i++ ] = 0xc0; out[ i++ ] = 0x0c;                     /* name ptr */
    out[ i++ ] = 0; out[ i++ ] = 1;                           /* type A */
    out[ i++ ] = 0; out[ i++ ] = 1;                           /* class IN */
    out[ i++ ] = 0; out[ i++ ] = 0; out[ i++ ] = 0; out[ i++ ] = 60; /* ttl */
    out[ i++ ] = 0; out[ i++ ] = 4;                           /* rdlength */
    memcpy( out+i, &addrs[ a ], 4UL ); i += 4UL;
  }
  return i;
}

static void
test_answer_parse( void ) {
  uchar pkt[ 512 ];
  uint  addrs[ FD_ADNS_ADDR_MAX ];

  /* NOERROR with two A records */
  ulong sz = craft_answer( pkt, 0x8180, 2, FD_IP4_ADDR( 1, 2, 3, 4 ), FD_IP4_ADDR( 5, 6, 7, 8 ) );
  FD_TEST( 2==fd_dns_ip4_answer( pkt, sz, addrs, FD_ADNS_ADDR_MAX ) );
  FD_TEST( addrs[ 0 ]==FD_IP4_ADDR( 1, 2, 3, 4 ) && addrs[ 1 ]==FD_IP4_ADDR( 5, 6, 7, 8 ) );

  /* NXDOMAIN / SERVFAIL / NOERROR-no-data */
  sz = craft_answer( pkt, 0x8183, 0, 0U, 0U );
  FD_TEST( FD_EAI_NONAME==fd_dns_ip4_answer( pkt, sz, addrs, FD_ADNS_ADDR_MAX ) );
  sz = craft_answer( pkt, 0x8182, 0, 0U, 0U );
  FD_TEST( FD_EAI_AGAIN==fd_dns_ip4_answer( pkt, sz, addrs, FD_ADNS_ADDR_MAX ) );
  /* NOERROR/0 answers may validly end right after the question */
  sz = craft_answer( pkt, 0x8180, 0, 0U, 0U );
  FD_TEST( FD_EAI_NODATA==fd_dns_ip4_answer( pkt, sz, addrs, FD_ADNS_ADDR_MAX ) );
  /* ...but a packet truncated mid-question is malformed: retryable */
  FD_TEST( FD_EAI_AGAIN ==fd_dns_ip4_answer( pkt, sz-1UL, addrs, FD_ADNS_ADDR_MAX ) );
}

/* End-to-end network completion through fd_adns_advance, against a
   mock nameserver on a loopback datagram socket (fd_adns_ns_port test
   hook).  Exercises the source/id/question validation, truncation
   handling, and PENDING->DONE transition that the direct parser tests
   bypass. */

static void
test_network_completion( void ) {
  /* Mock nameserver */
  int ns_fd = socket( AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0 );
  FD_TEST( ns_fd>=0 );
  struct sockaddr_in ns_sa = { .sin_family = AF_INET, .sin_addr = { .s_addr = FD_IP4_ADDR( 127, 0, 0, 1 ) } };
  FD_TEST( !bind( ns_fd, fd_type_pun( &ns_sa ), sizeof(ns_sa) ) );
  socklen_t ns_sa_len = sizeof(ns_sa);
  FD_TEST( !getsockname( ns_fd, fd_type_pun( &ns_sa ), &ns_sa_len ) );
  fd_adns_ns_port = fd_ushort_bswap( ns_sa.sin_port );

  /* Point the client at it.  attempts:1 exercises the EDNS0 fallback
     restoring a send after the only attempt was consumed. */
  FD_TEST( 0==close( fd_etc_resolv_conf_fd ) );
  fd_etc_resolv_conf_fd = memfd_with( "nameserver 127.0.0.1\noptions attempts:1\n" );

  fd_adns_t * adns = new_adns( 4UL );
  fd_adns_result_t res[ 1 ];

  FD_TEST( 0==fd_adns_resolve( adns, "peer", 42UL ) );
  FD_TEST( 0==fd_adns_advance( adns, 0L, res ) ); /* sends the query */

  /* Receive the query at the mock server.  The wire packet is the
     bare "peer" question (22 bytes) plus the 11 byte EDNS0 OPT RR. */
  uchar query[ 512 ];
  struct sockaddr_in cli;
  socklen_t cli_len = sizeof(cli);
  long qlen = recvfrom( ns_fd, query, sizeof(query), 0, fd_type_pun( &cli ), &cli_len );
  FD_TEST( qlen==33L );
  FD_TEST( query[ 11 ]==1 && query[ (ulong)qlen-9L ]==41 ); /* arcount, OPT type */
  ulong question_sz = 10UL; /* \x04peer\x00 + type + class */

  /* Reply with a wrong id first: must NOT complete the request */
  uchar reply[ 512 ];
  ulong rsz = craft_answer( reply, 0x8180, 1, FD_IP4_ADDR( 9, 9, 9, 9 ), 0U );
  reply[ 0 ] = (uchar)(query[ 0 ]^0xFF);
  reply[ 1 ] = query[ 1 ];
  memcpy( reply+12UL, query+12UL, question_sz ); /* echo question */
  FD_TEST( rsz==(ulong)sendto( ns_fd, reply, rsz, 0, fd_type_pun( &cli ), cli_len ) );
  FD_TEST( 0==fd_adns_advance( adns, 1L, res ) );

  /* Correct id but mangled question: must NOT complete */
  reply[ 0 ] = query[ 0 ]; reply[ 1 ] = query[ 1 ];
  reply[ 13 ] ^= 0x20;
  FD_TEST( rsz==(ulong)sendto( ns_fd, reply, rsz, 0, fd_type_pun( &cli ), cli_len ) );
  FD_TEST( 0==fd_adns_advance( adns, 2L, res ) );
  reply[ 13 ] ^= 0x20;

  /* FORMERR (EDNS0-unaware server): must not complete, but must
     resend the query immediately without the OPT RR */
  reply[ 3 ] = (uchar)((reply[ 3 ]&0xF0)|1);
  FD_TEST( rsz==(ulong)sendto( ns_fd, reply, rsz, 0, fd_type_pun( &cli ), cli_len ) );
  FD_TEST( 0==fd_adns_advance( adns, 3L, res ) );
  FD_TEST( 0==fd_adns_advance( adns, 4L, res ) ); /* resend fires */
  uchar query2[ 512 ];
  long q2len = recvfrom( ns_fd, query2, sizeof(query2), 0, fd_type_pun( &cli ), &cli_len );
  FD_TEST( q2len==22L && query2[ 11 ]==0 ); /* plain query, no OPT */
  reply[ 3 ] = (uchar)(reply[ 3 ]&0xF0);

  /* Valid reply: completes with the answer address */
  FD_TEST( rsz==(ulong)sendto( ns_fd, reply, rsz, 0, fd_type_pun( &cli ), cli_len ) );
  FD_TEST( 1==fd_adns_advance( adns, 5L, res ) );
  FD_TEST( res->req_id==42UL && !res->err && res->addr_cnt==1UL );
  FD_TEST( res->addrs[ 0 ]==FD_IP4_ADDR( 9, 9, 9, 9 ) );

  fd_adns_delete( fd_adns_leave( adns ) );
  FD_TEST( 0==close( ns_fd ) );
  fd_adns_ns_port = 53;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_etc_resolv_conf_fd = memfd_with( BLACKHOLE_RESOLVCONF );
  fd_etc_hosts_fd       = memfd_with( HOSTS );

  test_local_completion();
  test_expiry_and_requeue();
  test_backpressure();
  test_answer_parse();
  test_network_completion();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
