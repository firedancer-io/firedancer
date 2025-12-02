/* fuzz_net_checks is a simple fuzzer for network header validation.

   This fuzzer tests fd_ip4_udp_hdr_strip to ensure it correctly
   validates network packets and returns pointers within bounds. */

#include "../../util/fd_util.h"
#include "fd_net_checks.h"

#include <assert.h>
#include <stdlib.h>

int
LLVMFuzzerInitialize( int *    pargc,
                      char *** pargv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( pargc, pargv );
  atexit( fd_halt );
# ifndef FD_DEBUG_MODE
  fd_log_level_core_set(3); /* crash on warning log */
# endif
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  /* Call the header strip function */
  uchar *       payload    = NULL;
  ulong         payload_sz = 0UL;
  fd_eth_hdr_t * eth       = NULL;
  fd_ip4_hdr_t * ip4       = NULL;
  fd_udp_hdr_t * udp       = NULL;

  int result = fd_ip4_udp_hdr_strip( data, data_sz,
                                     &payload, &payload_sz,
                                     &eth, &ip4, &udp );

  if( result ) {
    /* Success case: validate all pointers are within bounds */
    uchar const * data_end = data + data_sz;

    /* Ethernet header must be within bounds */
    assert( (uchar *)eth >= data );
    assert( (uchar *)eth + sizeof(fd_eth_hdr_t) <= data_end );

    /* IP4 header must be within bounds */
    assert( (uchar *)ip4 >= data );
    assert( (uchar *)ip4 + sizeof(fd_ip4_hdr_t) <= data_end );

    /* UDP header must be within bounds */
    assert( (uchar *)udp >= data );
    assert( (uchar *)udp + sizeof(fd_udp_hdr_t) <= data_end );

    /* Payload must be within bounds */
    assert( payload >= data );
    assert( payload + payload_sz <= data_end );

    /* Validate ordering: eth < ip4 < udp < payload */
    assert( (uchar *)eth < (uchar *)ip4 );
    assert( (uchar *)ip4 < (uchar *)udp );
    assert( (uchar *)udp < payload || payload_sz == 0UL );

  }

  return 0;
}
