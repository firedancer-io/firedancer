#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include "fd_resolv.h"
#include "fd_lookup.h"
#include "../../util/fd_util.h"

FD_IMPORT_BINARY( test_resolvconf, "src/waltz/resolv/test_resolvconf.txt" );

static void
test_dn_expand( void ) {
  char name[ 256 ];

  static uchar const compressed[] = {
    3, 'w', 'w', 'w',
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm',
    0,
    3, 'a', 'p', 'i',
    0xc0, 4
  };
  int ret = fd_dn_expand( compressed, compressed+sizeof(compressed),
                          compressed+17, name, (int)sizeof(name) );
  FD_TEST( 6==ret );
  FD_TEST( 0==strcmp( name, "api.example.com" ) );

  static uchar const self_loop[] = { 0xc0, 0 };
  FD_TEST( -1==fd_dn_expand( self_loop, self_loop+sizeof(self_loop),
                              self_loop, name, (int)sizeof(name) ) );

  static uchar const out_of_bounds[] = { 0xc0, 2 };
  FD_TEST( -1==fd_dn_expand( out_of_bounds, out_of_bounds+sizeof(out_of_bounds),
                              out_of_bounds, name, (int)sizeof(name) ) );

  static uchar const short_name[] = { 3, 'w', 'w', 'w', 0 };
  char short_buf[ 3 ];
  FD_TEST( -1==fd_dn_expand( short_name, short_name+sizeof(short_name),
                              short_name, short_buf, (int)sizeof(short_buf) ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_dn_expand();

  /* Test normal resolv.conf */

  fd_etc_resolv_conf_fd = memfd_create( "resolv.conf", 0 );
  FD_TEST( fd_etc_resolv_conf_fd>=0 );
  ssize_t sz = write( fd_etc_resolv_conf_fd, test_resolvconf, test_resolvconf_sz );
  FD_TEST( sz==(ssize_t)test_resolvconf_sz );
  FD_TEST( 0==lseek( fd_etc_resolv_conf_fd, 0, SEEK_SET ) );
  fd_resolvconf_t conf;
  FD_TEST( 0==fd_get_resolv_conf( &conf ) );
  FD_TEST( 0==close( fd_etc_resolv_conf_fd ) );

  /* Chop off trailing newline */

  fd_etc_resolv_conf_fd = memfd_create( "resolv.conf", 0 );
  FD_TEST( fd_etc_resolv_conf_fd>=0 );
  sz = write( fd_etc_resolv_conf_fd, test_resolvconf, test_resolvconf_sz-1UL );
  FD_TEST( sz==(ssize_t)( test_resolvconf_sz-1UL ) );
  FD_TEST( 0==lseek( fd_etc_resolv_conf_fd, 0, SEEK_SET ) );
  FD_TEST( 0==fd_get_resolv_conf( &conf ) );
  FD_TEST( 0==close( fd_etc_resolv_conf_fd ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
