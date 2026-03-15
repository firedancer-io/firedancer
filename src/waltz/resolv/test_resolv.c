#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include "fd_lookup.h"
#include "../../util/fd_util.h"

#if defined(__APPLE__)
#include <stdio.h>
#include <stdlib.h>
static int memfd_create( const char * name, unsigned int flags ) {
  (void)name; (void)flags;
  char path[] = "/tmp/fd-test-XXXXXX";
  int fd = mkstemp( path );
  if( fd != -1 ) unlink( path );
  return fd;
}
#endif

FD_IMPORT_BINARY( test_resolvconf, "src/waltz/resolv/test_resolvconf.txt" );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

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
