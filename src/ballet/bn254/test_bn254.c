#define _DEFAULT_SOURCE
#include "fd_bn254.h"
#include "../../util/fd_util.h"

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  static const fd_bn254_point_g1_t g1 = { .v={
    45, 206, 255, 166, 152, 55, 128, 138, 79, 217, 145, 164, 25, 74, 120, 234, 234, 217,
    68, 149, 162, 44, 133, 120, 184, 205, 12, 44, 175, 98, 168, 172, 20, 24, 216, 15, 209,
    175, 106, 75, 147, 236, 90, 101, 123, 219, 245, 151, 209, 202, 218, 104, 148, 8, 32,
    254, 243, 191, 218, 122, 42, 81, 193, 84
  } };

  FD_TEST(fd_bn254_g1_check(&g1));
  
  fd_bn254_point_g1_compressed_t g1c;
  fd_bn254_g1_compress(&g1, &g1c);
  FD_TEST(memcmp(g1.v, g1c.v, sizeof(g1c)) == 0);

  fd_bn254_point_g1_t g1_2;
  fd_bn254_g1_decompress(&g1c, &g1_2);
  FD_TEST(memcmp(g1.v, g1_2.v, sizeof(g1)) == 0);
    
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
