#define _GNU_SOURCE
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include "fd_lookup.h"
#include "../../util/fd_util.h"

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

  /* attempts:0 must not divide by zero */

  static char const resolvconf_zero[] = "nameserver 127.0.0.1\noptions attempts:0\n";
  fd_etc_resolv_conf_fd = memfd_create( "resolv.conf", 0 );
  FD_TEST( fd_etc_resolv_conf_fd>=0 );
  sz = write( fd_etc_resolv_conf_fd, resolvconf_zero, sizeof(resolvconf_zero)-1UL );
  FD_TEST( sz==(ssize_t)( sizeof(resolvconf_zero)-1UL ) );
  FD_TEST( 0==fd_get_resolv_conf( &conf ) );
  FD_TEST( conf.attempts==0U );
  uchar         query[ 1 ] = {0};
  uchar const * qp   [ 1 ] = { query };
  int           qlen [ 1 ] = { 1 };
  uchar         ans  [ 1 ][ 512 ];
  uchar *       ap   [ 1 ] = { ans[0] };
  int           alen [ 1 ];
  errno = 0;
  FD_TEST( -1==fd_res_msend_rc( 1, qp, qlen, ap, alen, sizeof(ans[0]), &conf ) );
  FD_TEST( errno==EINVAL );
  FD_TEST( 0==close( fd_etc_resolv_conf_fd ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
