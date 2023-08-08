#include "fd_siphash13.h"
#include "../fd_ballet.h"

#define FD_SIPHASH13_TEST_CNT (64UL)

static ulong
fd_siphash13_test_vector[ FD_SIPHASH13_TEST_CNT ] = {
  0xabac0158050fc4dcUL,
  0xc9f49bf37d57ca93UL,
  0x82cb9b024dc7d44dUL,
  0x8bf80ab8e7ddf7fbUL,
  0xcf75576088d38328UL,
  0xdef9d52f49533b67UL,
  0xc50d2b50c59f22a7UL,
  0xd3927d989bb11140UL,
  0x369095118d299a8eUL,
  0x25a48eb36c063de4UL,
  0x79de85ee92ff097fUL,
  0x70c118c1f94dc352UL,
  0x78a384b157b4d9a2UL,
  0x306f760c1229ffa7UL,
  0x605aa111c0f95d34UL,
  0xd320d86d2a519956UL,
  0xcc4fdd1a7d908b66UL,
  0x9cf2689063dbd80cUL,
  0x8ffc389cb473e63eUL,
  0xf21f9de58d297d1cUL,
  0xc0dc2f46a6cce040UL,
  0xb992abfe2b45f844UL,
  0x7ffe7b9ba320872eUL,
  0x525a0e7fdae6c123UL,
  0xf464aeb267349c8cUL,
  0x45cd5928705b0979UL,
  0x3a3e35e3ca9913a5UL,
  0xa91dc74e4ade3b35UL,
  0xfb0bed02ef6cd00dUL,
  0x88d93cb44ab1e1f4UL,
  0x540f11d643c5e663UL,
  0x2370dd1f8c21d1bcUL,
  0x81157b6c16a7b60dUL,
  0x4d54b9e57a8ff9bfUL,
  0x759f12781f2a753eUL,
  0xcea1a3bebf186b91UL,
  0x2cf508d3ada26206UL,
  0xb6101c2da3c33057UL,
  0xb3f47496ae3a36a1UL,
  0x626b57547b108392UL,
  0xc1d2363299e41531UL,
  0x667cc1923f1ad944UL,
  0x65704ffec8138825UL,
  0x24f280d1c28949a6UL,
  0xc2ca1cedfaf8876bUL,
  0xc2164bfc9f042196UL,
  0xa16e9c9368b1d623UL,
  0x49fb169c8b5114fdUL,
  0x9f3143f8df074c46UL,
  0xc6fdaf2412cc86b3UL,
  0x7eaf49d10a52098fUL,
  0x1cf313559d292f9aUL,
  0xc44a30dda2f41f12UL,
  0x36fae98943a71ed0UL,
  0x318fb34c73f0bce6UL,
  0xa27abf3670a7e980UL,
  0xb4bcc0db243c6d75UL,
  0x23f8d852fdb71513UL,
  0x8f035f4da67d8a08UL,
  0xd89cd0e5b7e8f148UL,
  0xf6f4e6bcf7a644eeUL,
  0xaec59ad80f1837f2UL,
  0xc3b2f6154b6694e0UL,
  0x9d199062b7bbb3a8UL,
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong k0 = 0x0706050403020100UL;
  ulong k1 = 0x0f0e0d0c0b0a0908UL;

  uchar buf[ 64 ];
  for( ulong i=0UL; i<FD_SIPHASH13_TEST_CNT; i++ ) {
    uchar const * msg   = buf;
    ulong         msgsz = i;

    ulong hash = fd_siphash13_hash( msg, msgsz, k0, k1 );
    FD_TEST( hash == fd_siphash13_test_vector[ i ] );

    buf[ i ] = (uchar)i;
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

