#define _POSIX_C_SOURCE 200809L /* fmemopen */
#include "fd_fib4.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

static uchar __attribute__((aligned(FD_FIB4_ALIGN)))
fib1_mem[ 4096 ];

static uchar __attribute__((aligned(FD_FIB4_ALIGN)))
fib2_mem[ 4096 ];

#if FD_HAS_HOSTED
#include <stdio.h>

static void
test_fib_print( fd_fib4_t const * fib,
                char const *      actual ) {
  static char dump_buf[ 8192 ];
  FILE * dump = fmemopen( dump_buf, sizeof(dump_buf), "w" );
  FD_TEST( 0==fd_fib4_fprintf( fib, dump ) );
  ulong sz = (ulong)ftell( dump );
  fclose( dump );

  if( FD_UNLIKELY( 0!=strncmp( dump_buf, actual, sz ) ) ) {
    fwrite( dump_buf, 1, sz, stderr );
    fflush( stderr );
    FD_LOG_ERR(( "FAIL: fd_fib4_fprintf(fib) != expected" ));
  }
}

#else /* !FD_HAS_HOSTED */

#define test_fib_print(...)

#endif

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_ulong_is_aligned( (ulong)fib1_mem, fd_fib4_align() ) );
  FD_TEST( fd_fib4_footprint( 16 )<=sizeof(fib1_mem) );
  fd_fib4_t * fib_local = fd_fib4_join( fd_fib4_new( fib1_mem, 16 ) );
  fd_fib4_t * fib_main  = fd_fib4_join( fd_fib4_new( fib2_mem, 16 ) );
  fd_fib4_hop_t candidate[2];

  /* Ensure empty FIB returns THROW */

  FD_TEST( fd_fib4_lookup( fib_local, candidate, 0x12345678, 0 )->rtype==FD_FIB4_RTYPE_THROW );

  /* Simple production scenario

     # ip route list table local
     broadcast 192.0.2.160     dev bond0 proto kernel scope link src 192.0.2.165
     local     192.0.2.165     dev bond0 proto kernel scope host src 192.0.2.165
     broadcast 192.0.2.191     dev bond0 proto kernel scope link src 192.0.2.165
     broadcast 127.0.0.0       dev lo    proto kernel scope link src 127.0.0.1
     local     127.0.0.0/8     dev lo    proto kernel scope host src 127.0.0.1
     local     127.0.0.1       dev lo    proto kernel scope host src 127.0.0.1
     broadcast 127.255.255.255 dev lo    proto kernel scope link src 127.0.0.1

     # ip route list table main
     default        via 192.0.2.161 dev bond0 proto dhcp              src 192.0.2.165 metric 300
     192.0.2.160/27                 dev bond0 proto kernel scope link src 192.0.2.165 metric 300 */

  fd_fib4_clear( fib_local );
  FD_TEST( fd_fib4_free_cnt( fib_local )>=7 );
  *fd_fib4_append( fib_local, FD_IP4_ADDR( 192,0,2,160   ), 32, 0 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };
  *fd_fib4_append( fib_local, FD_IP4_ADDR( 192,0,2,165   ), 32, 0 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_LOCAL,     .if_idx=6, .scope=254, .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };
  *fd_fib4_append( fib_local, FD_IP4_ADDR( 192,0,2,191   ), 32, 0 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };
  *fd_fib4_append( fib_local, FD_IP4_ADDR( 127,0,0,0     ), 32, 0 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=1, .scope=253, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };
  *fd_fib4_append( fib_local, FD_IP4_ADDR( 127,0,0,0     ),  8, 0 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_LOCAL,     .if_idx=1, .scope=254, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };
  *fd_fib4_append( fib_local, FD_IP4_ADDR( 127,0,0,1     ), 32, 0 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_LOCAL,     .if_idx=1, .scope=254, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };
  *fd_fib4_append( fib_local, FD_IP4_ADDR( 127,0,255,255 ), 32, 0 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_BROADCAST, .if_idx=1, .scope=253, .ip4_src=FD_IP4_ADDR( 127,0,0,1   ) };

  test_fib_print( fib_local,
    "throw default metric 4294967295\n"
    "broadcast 192.0.2.160 dev 6 scope link src 192.0.2.165\n"
    "local 192.0.2.165 dev 6 scope host src 192.0.2.165\n"
    "broadcast 192.0.2.191 dev 6 scope link src 192.0.2.165\n"
    "broadcast 127.0.0.0 dev 1 scope link src 127.0.0.1\n"
    "local 127.0.0.0/8 dev 1 scope host src 127.0.0.1\n"
    "local 127.0.0.1 dev 1 scope host src 127.0.0.1\n"
    "broadcast 127.0.255.255 dev 1 scope link src 127.0.0.1\n" );

  fd_fib4_clear( fib_main );
  FD_TEST( fd_fib4_free_cnt( fib_main )>=2 );
  *fd_fib4_append( fib_main, FD_IP4_ADDR( 0,0,0,0     ),  0, 300 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_UNICAST, .ip4_gw=FD_IP4_ADDR( 192,0,2,161 ), .if_idx=6,             .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };
  *fd_fib4_append( fib_main, FD_IP4_ADDR( 192,0,2,161 ), 27, 300 ) = (fd_fib4_hop_t){ .rtype=FD_FIB4_RTYPE_UNICAST,                                     .if_idx=6, .scope=253, .ip4_src=FD_IP4_ADDR( 192,0,2,165 ) };

  test_fib_print( fib_main,
    "throw default metric 4294967295\n"
    "default via 192.0.2.161 dev 6 src 192.0.2.165 metric 300\n"
    "192.0.2.161/27 dev 6 scope link src 192.0.2.165 metric 300\n" );

# define QUERY(ip) fd_fib4_hop_or( fd_fib4_lookup( fib_local, candidate+0, FD_IP4_ADDR ip, 0 ), fd_fib4_lookup( fib_main, candidate+1, FD_IP4_ADDR ip, 0 ) )
  fd_fib4_hop_t const * next;

  /* $ ip route get 127.0.0.1
     local 127.0.0.1 dev lo src 127.0.0.1 */
  next = QUERY(( 127,0,0,1 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_LOCAL );
  FD_TEST( next->if_idx==1 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 127,0,0,1 ) );

  /* $ ip route get 192.0.2.160
     broadcast 192.0.2.160 dev bond0 src 192.0.2.165 */
  next = QUERY(( 192,0,2,160 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_BROADCAST );
  FD_TEST( next->if_idx==6 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 192,0,2,165 ) );

  /* $ ip route get 192.0.2.161
     192.0.2.161 dev bond0 src 192.0.2.165 */
  next = QUERY(( 192,0,2,161 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_UNICAST );
  FD_TEST( next->if_idx==6 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 192,0,2,165 ) );

  /* $ ip route get 192.0.2.191
     broadcast 192.0.2.191 dev bond0 src 192.0.2.165 */
  next = QUERY(( 192,0,2,191 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_BROADCAST );
  FD_TEST( next->if_idx==6 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 192,0,2,165 ) );

  /* $ ip route get 8.8.8.8
     8.8.8.8 via 192.0.2.161 dev bond0 src 192.0.2.165 */
  next = QUERY(( 8,8,8,8 ));
  FD_TEST( next->rtype==FD_FIB4_RTYPE_UNICAST );
  FD_TEST( next->ip4_gw==FD_IP4_ADDR( 192,0,2,161 ) );
  FD_TEST( next->if_idx==6 );
  FD_TEST( next->ip4_src==FD_IP4_ADDR( 192,0,2,165 ) );

# undef QUERY

  /* Clear again */
  fd_fib4_clear( fib_main );
  FD_TEST( fd_fib4_lookup( fib_local, candidate, 0x12345678, 0 )->rtype==FD_FIB4_RTYPE_THROW );

  fd_fib4_delete( fd_fib4_leave( fib_local ) );
  fd_fib4_delete( fd_fib4_leave( fib_main  ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
