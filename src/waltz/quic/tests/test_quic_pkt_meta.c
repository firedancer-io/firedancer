/* test_quic_pkt_meta.c defines unit tests for fd_quic_pkt_meta_t
   related logic. */

#include "../fd_quic_pkt_meta.h"
#include "../fd_quic_private.h"

static void
test_pkt_meta_reclaim( void ) {

}

static void
test_pkt_meta_retry( void ) {

}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_pkt_meta_reclaim();
  test_pkt_meta_retry();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
