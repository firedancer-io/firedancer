#include "fd_ip6.h"
#include "fd_ip4.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar ip6_addr[16];
  fd_ip6_addr_ip4_mapped( ip6_addr, FD_IP4_ADDR( 10,1,2,3 ) );
  FD_TEST( fd_memeq( ip6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x0a\x01\x02\x03", 16 ) );
  FD_TEST( fd_ip6_addr_is_ip4_mapped( ip6_addr )==1 );
  for( ulong i=0UL; i<10UL; i++ ) {
    for( ulong k=0UL; k<8UL; k++ ) {
      ip6_addr[ i ] = (uchar)( ip6_addr[ i ]^(1U<<k) );
      FD_TEST( fd_ip6_addr_is_ip4_mapped( ip6_addr )==0 );
      ip6_addr[ i ] = (uchar)( ip6_addr[ i ]^(1U<<k) );
    }
  }
  FD_TEST( fd_ip6_addr_to_ip4( ip6_addr )==FD_IP4_ADDR( 10,1,2,3 ) );

  /* fd_ip6_addr_is_unspecified */

  memset( ip6_addr, 0, 16UL );
  FD_TEST( fd_ip6_addr_is_unspecified( ip6_addr )==1 );
  for( ulong i=0UL; i<16UL; i++ ) {
    ip6_addr[ i ] = 0x01;
    FD_TEST( fd_ip6_addr_is_unspecified( ip6_addr )==0 );
    ip6_addr[ i ] = 0x00;
  }

  /* fd_ip6_addr_is_scoped */

  FD_TEST( fd_ip6_addr_is_scoped( (uchar const *)"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" )==1 ); /* link-local */
  FD_TEST( fd_ip6_addr_is_scoped( (uchar const *)"\xfe\xbf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" )==1 ); /* link-local */
  FD_TEST( fd_ip6_addr_is_scoped( (uchar const *)"\xfe\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" )==0 );
  FD_TEST( fd_ip6_addr_is_scoped( (uchar const *)"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" )==1 ); /* link-local multicast */
  FD_TEST( fd_ip6_addr_is_scoped( (uchar const *)"\xff\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" )==0 ); /* global multicast */
  FD_TEST( fd_ip6_addr_is_scoped( (uchar const *)"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" )==0 ); /* global unicast */
  FD_TEST( fd_ip6_addr_is_scoped( (uchar const *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x0a\x01\x02\x03" )==0 ); /* IPv4-mapped */

  /* fd_cstr_to_ip6_addr */

  fd_ip6_addr_t addr = { .scope_id = 123U };
  FD_TEST( fd_cstr_to_ip6_addr( "::", &addr )==1 );
  FD_TEST( fd_ip6_addr_is_unspecified( addr.addr ) ); FD_TEST( addr.scope_id==0U );

  FD_TEST( fd_cstr_to_ip6_addr( "2001:db8::1", &addr )==1 );
  FD_TEST( fd_memeq( addr.addr, "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16 ) );
  FD_TEST( addr.scope_id==0U );

  FD_TEST( fd_cstr_to_ip6_addr( "::ffff:10.1.2.3", &addr )==1 );
  FD_TEST( fd_ip6_addr_is_ip4_mapped( addr.addr ) );
  FD_TEST( fd_ip6_addr_to_ip4( addr.addr )==FD_IP4_ADDR( 10,1,2,3 ) );

  FD_TEST( fd_cstr_to_ip6_addr( "10.1.2.3",      &addr )==0 ); /* IPv4 literal */
  FD_TEST( fd_cstr_to_ip6_addr( "",              &addr )==0 );
  FD_TEST( fd_cstr_to_ip6_addr( "hello",         &addr )==0 );
  FD_TEST( fd_cstr_to_ip6_addr( "2001:db8::1%",  &addr )==0 ); /* empty zone ID */
  FD_TEST( fd_cstr_to_ip6_addr( "%1",            &addr )==0 );
  FD_TEST( fd_cstr_to_ip6_addr( "2001:db8::1%1", &addr )==0 ); /* zone ID on unscoped address */
  FD_TEST( fd_cstr_to_ip6_addr( "fe80::1%0",     &addr )==0 ); /* invalid interface index */
  FD_TEST( fd_cstr_to_ip6_addr( "fe80::1%_nope", &addr )==0 ); /* no such interface */

  FD_TEST( fd_cstr_to_ip6_addr( "fe80::1%7", &addr )==1 );
  FD_TEST( fd_memeq( addr.addr, "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16 ) );
  FD_TEST( addr.scope_id==7U );

  /* The loopback interface is index 1 on Linux */
  FD_TEST( fd_cstr_to_ip6_addr( "fe80::1%lo", &addr )==1 );
  FD_TEST( addr.scope_id==1U );

  /* fd_cstr_to_ip46_addr */

  addr.scope_id = 123U;
  FD_TEST( fd_cstr_to_ip46_addr( "10.1.2.3", &addr )==1 );
  FD_TEST( fd_ip6_addr_is_ip4_mapped( addr.addr ) );
  FD_TEST( fd_ip6_addr_to_ip4( addr.addr )==FD_IP4_ADDR( 10,1,2,3 ) );
  FD_TEST( addr.scope_id==0U );

  FD_TEST( fd_cstr_to_ip46_addr( "0.0.0.0", &addr )==1 );
  FD_TEST( fd_ip6_addr_is_ip4_mapped( addr.addr ) );
  FD_TEST( !fd_ip6_addr_is_unspecified( addr.addr ) );

  FD_TEST( fd_cstr_to_ip46_addr( "fe80::1%lo",  &addr )==1 );
  FD_TEST( addr.scope_id==1U );
  FD_TEST( fd_cstr_to_ip46_addr( "10.1.2.3%lo", &addr )==0 );

  /* fd_ip6_addr_cstr */

  char buf[ FD_IP6_ADDR_CSTR_MAX ];
  FD_TEST( fd_cstr_to_ip46_addr( "10.1.2.3", &addr )==1 );
  FD_TEST( !strcmp( fd_ip6_addr_cstr( buf, &addr ), "10.1.2.3" ) );
  addr.scope_id = 1U;
  FD_TEST( !strcmp( fd_ip6_addr_cstr( buf, &addr ), "[::ffff:10.1.2.3%1]" ) );
  FD_TEST( fd_cstr_to_ip46_addr( "fe80::1%lo", &addr )==1 );
  FD_TEST( !strcmp( fd_ip6_addr_cstr( buf, &addr ), "[fe80::1%1]" ) );

  /* Canonical text representation (RFC 5952) */

  static char const * const canonical[] = {
    "[::]",
    "[::1]",
    "[1::]",
    "[2001:db8::1]",
    "[2001:db8:0:1:1:1:1:1]",           /* single zero group is not compressed */
    "[2001:db8::1:0:0:1]",              /* leftmost longest run is compressed */
    "[2001:0:0:1::1]",
    "[1:2:3:4:5:6:7:8]",
    "[fe80::abcd:ef01]",
    "[ff02::1]",
    NULL
  };
  for( ulong i=0UL; canonical[ i ]; i++ ) {
    char const * cstr = canonical[ i ];
    char         unbracketed[ FD_IP6_ADDR_CSTR_MAX ];
    ulong        len = strlen( cstr );
    FD_TEST( len>2UL && len-2UL<sizeof(unbracketed) );
    memcpy( unbracketed, cstr+1, len-2UL );
    unbracketed[ len-2UL ] = '\0';
    FD_TEST( fd_cstr_to_ip6_addr( unbracketed, &addr )==1 );
    FD_TEST( !strcmp( fd_ip6_addr_cstr( buf, &addr ), cstr ) );
  }

  /* Uncompressed, upper case, and zero padded forms parse to the same
     address as their canonical form */

  fd_ip6_addr_t addr2;
  FD_TEST( fd_cstr_to_ip6_addr( "2001:0DB8:0000:0000:0000:0000:0000:0001", &addr  )==1 );
  FD_TEST( fd_cstr_to_ip6_addr( "2001:db8::1",                             &addr2 )==1 );
  FD_TEST( fd_memeq( addr.addr, addr2.addr, 16UL ) );
  FD_TEST( !strcmp( fd_ip6_addr_cstr( buf, &addr ), "[2001:db8::1]" ) );

  FD_TEST( fd_cstr_to_ip6_addr( "0:0:0:0:0:ffff:10.1.2.3", &addr  )==1 );
  FD_TEST( fd_cstr_to_ip6_addr( "::ffff:10.1.2.3",         &addr2 )==1 );
  FD_TEST( fd_memeq( addr.addr, addr2.addr, 16UL ) );

  /* IPv4-mapped addresses print as a dotted quad */

  FD_TEST( fd_cstr_to_ip6_addr( "::ffff:0.0.0.0", &addr )==1 );
  FD_TEST( !strcmp( fd_ip6_addr_cstr( buf, &addr ), "0.0.0.0" ) );
  FD_TEST( fd_cstr_to_ip6_addr( "::ffff:255.255.255.255", &addr )==1 );
  FD_TEST( !strcmp( fd_ip6_addr_cstr( buf, &addr ), "255.255.255.255" ) );

  /* IPv4-compatible addresses (deprecated) are not IPv4-mapped */

  FD_TEST( fd_cstr_to_ip6_addr( "::1.2.3.4", &addr )==1 );
  FD_TEST( !fd_ip6_addr_is_ip4_mapped( addr.addr ) );
  FD_TEST( !strcmp( fd_ip6_addr_cstr( buf, &addr ), "[::102:304]" ) );

  /* Valid addresses, mostly cribbed from Go's net/netip parser tests */

  static char const * const valid[] = {
    "::",
    "::1",
    "1::",
    "::ffff:192.168.140.255",
    "::ffff:c0a8:5909",
    "1:2:3:4:5:6:7:8",
    "1:2:3:4:5:6:77:88",
    "2001:db8::68",
    "2001:0db8:0000:0000:0000:0000:0000:0068",
    "0:0:0:0:0:0:0:0",
    "1:2:3:4:5:6:1.2.3.4",
    "::1.2.3.4",
    "::ffff:1.2.3.4",
    "FE80::1",                /* upper case */
    "fe80::1cc0:3e8c:119f:c2e1%1",
    NULL
  };
  for( ulong i=0UL; valid[ i ]; i++ ) {
    if( FD_UNLIKELY( fd_cstr_to_ip6_addr( valid[ i ], &addr )!=1 ) ) {
      FD_LOG_ERR(( "fd_cstr_to_ip6_addr( \"%s\" ) failed", valid[ i ] ));
    }
  }

  /* Malformed addresses from Go's net/netip parser tests */

  static char const * const invalid[] = {
    "",
    "bad",
    ":",
    "::::",
    ":1:2:3:4:5:6:7",           /* leading single colon */
    "1:2:3:4:5:6:7:",           /* trailing single colon */
    "1:",
    "1:::2",
    "1::2::3",                  /* more than one "::" */
    "::1::",
    "1:2:3:4:5:6:7",            /* too few groups */
    "1:2:3:4:5:6:7:8:9",        /* too many groups */
    "1:2:3:4:5:6:7:8::",        /* "::" covering no groups */
    "::1:2:3:4:5:6:7:8",
    "12345::",                  /* group too long */
    "::12345",
    "::-1",
    "::+1",
    "1:2:3:4:5:6:7:xyz",
    "1:2:3:4:5:6:7:8 ",         /* trailing space */
    " 1:2:3:4:5:6:7:8",         /* leading space */
    "[::1]",                    /* brackets are not part of the literal */
    "1.2.3",                    /* IPv4 literals are not IPv6 literals */
    "1.2.3.4",
    "1.2.3.4::",
    "::1.2.3",                  /* too few IPv4 octets */
    "::1.2.3.4.5",              /* too many IPv4 octets */
    "::1.2.3.400",              /* IPv4 octet out of range */
    "::1.2.3.256",
    "::1.2.3.04",               /* IPv4 octet with leading zero */
    "::1.2.3.-4",
    "::1.2 .3.4",
    "::1.2.3.4:5",              /* embedded IPv4 must be last */
    "1:2:3:4:5:6:7:1.2.3.4",    /* no room for embedded IPv4 */
    "1:2:3:4:5:6:1.2.3.4.5",
    "%1",                       /* zone ID without an address */
    "fe80::1%",                 /* empty zone ID */
    "fe80::1%%1",
    "fe80::1%4294967296",       /* interface index out of range */
    NULL
  };
  for( ulong i=0UL; invalid[ i ]; i++ ) {
    if( FD_UNLIKELY( fd_cstr_to_ip6_addr( invalid[ i ], &addr )!=0 ) ) {
      FD_LOG_ERR(( "fd_cstr_to_ip6_addr( \"%s\" ) unexpectedly succeeded", invalid[ i ] ));
    }
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

