#include "fd_failover_wire.h"
#include "../../util/fd_util.h"

static uchar frame[ FD_FAILOVER_FRAME_MAX ];
static uchar big[ 2UL*FD_FAILOVER_FRAME_MAX ];

static void
test_roundtrip( void ) {

  uchar payload[ 70 ];
  for( ulong i=0UL; i<70UL; i++ ) payload[ i ] = (uchar)i;

  ulong sz = fd_failover_wire_encode( frame, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, 70UL );
  FD_TEST( sz==FD_FAILOVER_FRAME_HDR_SZ+70UL );

  ushort        type;
  uchar const * out;
  ulong         out_sz;
  ulong         frame_sz;
  FD_TEST( fd_failover_wire_decode( frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_SUCCESS );
  FD_TEST( type==(ushort)FD_FAILOVER_MSG_DEMOTED );
  FD_TEST( out_sz==70UL );
  FD_TEST( frame_sz==sz );
  FD_TEST( fd_memeq( out, payload, 70UL ) );

  ulong sz2 = fd_failover_wire_encode( big, (ushort)FD_FAILOVER_MSG_HELLO, payload, 10UL );
  fd_memset( big+sz2, 0x77, 64UL );
  FD_TEST( fd_failover_wire_decode( big, sz2+64UL, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_SUCCESS );
  FD_TEST( frame_sz==sz2 );

  FD_LOG_NOTICE(( "pass: test_roundtrip" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_roundtrip();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
