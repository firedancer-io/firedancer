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
    
  static const fd_bn254_point_g2_t g2 = { .v={
      40, 57, 233, 205, 180, 46, 35, 111, 215, 5, 23, 93, 12, 71, 118, 225, 7, 46, 247, 147,
      47, 130, 106, 189, 184, 80, 146, 103, 141, 52, 242, 25, 0, 203, 124, 176, 110, 34, 151,
      212, 66, 180, 238, 151, 236, 189, 133, 209, 17, 137, 205, 183, 168, 196, 92, 159, 75,
      174, 81, 168, 18, 86, 176, 56, 16, 26, 210, 20, 18, 81, 122, 142, 104, 62, 251, 169,
      98, 141, 21, 253, 50, 130, 182, 15, 33, 109, 228, 31, 79, 183, 88, 147, 174, 108, 4,
      22, 14, 129, 168, 6, 80, 246, 254, 100, 218, 131, 94, 49, 247, 211, 3, 245, 22, 200,
      177, 91, 60, 144, 147, 174, 90, 17, 19, 189, 62, 147, 152, 18,
  } };

  FD_TEST(fd_bn254_g2_check(&g2));
  
  fd_bn254_point_g2_compressed_t g2c;
  fd_bn254_g2_compress(&g2, &g2c);
  FD_TEST(memcmp(g2.v, g2c.v, sizeof(g2c)) == 0);

  fd_bn254_point_g2_t g2_2;
  fd_bn254_g2_decompress(&g2c, &g2_2);
  FD_TEST(memcmp(g2.v, g2_2.v, sizeof(g2)) == 0);
    
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
