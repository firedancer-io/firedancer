#include "fd_dns_cache_private.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_ip6.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_dns_cache_align()==FD_DNS_CACHE_ALIGN );

  FD_TEST( fd_dns_cache_footprint( 1UL,     1UL     )!=0UL );
  FD_TEST( fd_dns_cache_footprint( 0UL,     1UL     )==0UL );
  FD_TEST( fd_dns_cache_footprint( 1UL,     0UL     )==0UL );
  FD_TEST( fd_dns_cache_footprint( 0UL,     1UL<<32 )==0UL );
  FD_TEST( fd_dns_cache_footprint( 1UL<<32, 0UL     )==0UL );

  void * mem = aligned_alloc( fd_dns_cache_align(), fd_dns_cache_footprint( 4, 4 ) );
  FD_TEST( mem );

  FD_TEST( fd_dns_cache_new( NULL,           4UL, 4UL, 0UL )==NULL );
  FD_TEST( fd_dns_cache_new( (uchar *)mem+1, 4UL, 4UL, 0UL )==NULL );
  FD_TEST( fd_dns_cache_new( mem,            4UL, 4UL, 0UL )==mem  );

  fd_dns_cache_join_t ljoin[1];
  FD_TEST( fd_dns_cache_join( mem,  NULL  )==NULL  );
  FD_TEST( fd_dns_cache_join( NULL, ljoin )==NULL  );
  FD_TEST( fd_dns_cache_join( mem,  ljoin )==ljoin );

  FD_TEST( fd_dns_cache_name_pool_free( ljoin->name_pool )==4 );
  FD_TEST( fd_dns_cache_addr_pool_free( ljoin->addr_pool )==4 );

  uchar addrs[32];
  fd_ip6_addr_ip4_mapped( addrs+ 0, FD_IP4_ADDR( 127,0,0,1 ) );
  fd_ip6_addr_ip4_mapped( addrs+16, FD_IP4_ADDR( 127,0,0,2 ) );
  FD_TEST( !!fd_dns_cache_put( ljoin, "a1.example.org.", 15, 1234L, addrs, 2UL ) );
  FD_TEST( fd_dns_cache_name_pool_free( ljoin->name_pool )==3 );
  FD_TEST( fd_dns_cache_addr_pool_free( ljoin->addr_pool )==2 );

  fd_dns_cache_query_t query[1];
  fd_dns_cache_addr_t * qa;
  qa = fd_dns_cache_query_start( ljoin, query, "a1.example.org.", 15 );
  FD_TEST( !!qa );
  FD_TEST( 0==memcmp( qa->ip6, addrs+ 0, 16 ) );
  qa = fd_dns_cache_query_next( ljoin, query );
  FD_TEST( !!qa );
  FD_TEST( 0==memcmp( qa->ip6, addrs+16, 16 ) );
  qa = fd_dns_cache_query_next( ljoin, query );
  FD_TEST( !qa );

  FD_TEST( !!fd_dns_cache_put( ljoin, "bb2.example.org.", 16, 1234L, addrs+16, 1UL ) );
  FD_TEST( fd_dns_cache_name_pool_free( ljoin->name_pool )==2 );
  FD_TEST( fd_dns_cache_addr_pool_free( ljoin->addr_pool )==1 );

  fd_ip6_addr_ip4_mapped( addrs+0, FD_IP4_ADDR( 127,0,0,3 ) );
  FD_TEST( !!fd_dns_cache_put( ljoin, "a1.example.org.", 15, 1234L, addrs, 1UL ) );
  FD_TEST( fd_dns_cache_name_pool_free( ljoin->name_pool )==2 );
  FD_TEST( fd_dns_cache_addr_pool_free( ljoin->addr_pool )==2 );

  qa = fd_dns_cache_query_start( ljoin, query, "a1.example.org.", 15 );
  FD_TEST( !!qa );
  FD_TEST( fd_ip6_addr_to_ip4( qa->ip6 )==FD_IP4_ADDR( 127,0,0,3 ) );
  qa = fd_dns_cache_query_next( ljoin, query );
  FD_TEST( !qa );

  qa = fd_dns_cache_query_start( ljoin, query, "bb2.example.org.", 16 );
  FD_TEST( !!qa );
  FD_TEST( fd_ip6_addr_to_ip4( qa->ip6 )==FD_IP4_ADDR( 127,0,0,2 ) );
  qa = fd_dns_cache_query_next( ljoin, query );
  FD_TEST( !qa );

  /* FIXME test read overrun */

  fd_dns_cache_remove( ljoin, "c333.example.org.", 17 );
  FD_TEST( fd_dns_cache_name_pool_free( ljoin->name_pool )==2 );
  FD_TEST( fd_dns_cache_addr_pool_free( ljoin->addr_pool )==2 );

  fd_dns_cache_remove( ljoin, "bb2.example.org.", 16 );
  FD_TEST( fd_dns_cache_name_pool_free( ljoin->name_pool )==3 );
  FD_TEST( fd_dns_cache_addr_pool_free( ljoin->addr_pool )==3 );

  fd_dns_cache_remove( ljoin, "a1.example.org.", 15 );
  FD_TEST( fd_dns_cache_name_pool_free( ljoin->name_pool )==4 );
  FD_TEST( fd_dns_cache_addr_pool_free( ljoin->addr_pool )==4 );

  qa = fd_dns_cache_query_start( ljoin, query, "bb2.example.org.", 16 );
  FD_TEST( !qa );

  FD_TEST( fd_dns_cache_leave( NULL  )==NULL  );
  FD_TEST( fd_dns_cache_leave( ljoin )==ljoin );

  FD_TEST( fd_dns_cache_delete( NULL )==NULL );
  FD_TEST( fd_dns_cache_delete( mem  )!=NULL );
  free( mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
