#include "../fd_ballet.h"
#include "fd_chacha20.h"


void
test_chacha20_block( void ) {
  /* Test vector from IETF RFC 7539 Section 2.3.2
     https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.2 */

  /* Input */

  uchar const key[ 32UL ] __attribute__((aligned(32))) = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };
  uchar const idx_nonce[ 16UL ] __attribute__((aligned(16))) = {
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
  };

  /* Output */

  uchar block[ 64UL ] __attribute__((aligned((32))));
  uchar const expected[ 64UL ] = {
    0x10, 0xf1, 0xe7, 0xe4,  0xd1, 0x3b, 0x59, 0x15,
    0x50, 0x0f, 0xdd, 0x1f,  0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7,  0x33, 0xc0, 0x68, 0x03,
    0x04, 0x22, 0xaa, 0x9a,  0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46,  0x07, 0x9f, 0xaa, 0x09,
    0x14, 0xc2, 0xd7, 0x05,  0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1,  0xde, 0x16, 0x4e, 0xb9,
    0xcb, 0xd0, 0x83, 0xe8,  0xa2, 0x50, 0x3c, 0x4e,
  };

  fd_chacha20_block( block, &key, idx_nonce );

  if( FD_UNLIKELY( 0!=memcmp( block, expected, 64UL ) ) )
    FD_LOG_ERR(( "FAIL"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                 FD_LOG_HEX16_FMT_ARGS(    block    ), FD_LOG_HEX16_FMT_ARGS(    block+16 ),
                 FD_LOG_HEX16_FMT_ARGS(    block+32 ), FD_LOG_HEX16_FMT_ARGS(    block+48 ),
                 FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ),
                 FD_LOG_HEX16_FMT_ARGS( expected+32 ), FD_LOG_HEX16_FMT_ARGS( expected+48 ) ));
}

void
bench_chacha20_block( void ) {
  FD_LOG_NOTICE(( "Benchmarking fd_chacha20_block" ));

  uchar key[ 32UL ] __attribute__((aligned(32))) = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };
  uint idx_nonce[ 4UL ] __attribute__((aligned(4))) = {
    0x01, 0x09, 0x00, 0x00,
  };
  uchar block[ 64UL ] __attribute__((aligned(32)));

  /* warmup */
  for( ulong rem=1000000UL; rem; rem-- ){
    idx_nonce[0]++;
    fd_chacha20_block( block, key, idx_nonce );
  }

  /* for real */
  ulong iter = 10000000UL;
  long  dt   = -fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    idx_nonce[0]++;
    fd_chacha20_block( block, key, idx_nonce );
  }
  dt += fd_log_wallclock();
  double gbps    = ((double)(8UL*FD_CHACHA20_BLOCK_SZ*iter)) / ((double)dt);
  double ns      = (double)dt / ((double)iter * (double)FD_CHACHA20_BLOCK_SZ);
  FD_LOG_NOTICE(( "  ~%6.3f Gbps  / core", gbps ));
  FD_LOG_NOTICE(( "  ~%6.3f ns / byte",    ns   ));
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_chacha20_block();
  bench_chacha20_block();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

