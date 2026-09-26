#include "../fd_ballet.h"
#include "fd_ed25519.h"

struct verification_test {
  uchar sig[ 64 ];
  uchar pub[ 32 ];
};
typedef struct verification_test verification_test_t;

FD_IMPORT_BINARY(should_fail_bin, "src/ballet/ed25519/test_ed25519_signature_malleability_should_fail.bin");
FD_IMPORT_BINARY(should_pass_bin, "src/ballet/ed25519/test_ed25519_signature_malleability_should_pass.bin");
verification_test_t * const should_fail = ( verification_test_t * const ) should_fail_bin;
verification_test_t * const should_pass = ( verification_test_t * const ) should_pass_bin;

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_sha512_t _sha[1];
  fd_sha512_t *sha = fd_sha512_join(fd_sha512_new(_sha));
  uchar msg[] = "Zcash";

  /* Every vector also goes through the cached verify, 3 times so that
     keys get cached, and must give the uncached result */
  static uchar __attribute__((aligned(FD_ED25519_CACHE_ALIGN))) cache_mem[ 1UL<<20 ];
  FD_TEST( fd_ed25519_cache_footprint( 128UL )<=sizeof(cache_mem) );
  fd_ed25519_cache_t * cache = fd_ed25519_cache_join( fd_ed25519_cache_new( cache_mem, 128UL, 0UL ) );
  FD_TEST( cache );

  ulong should_fail_cnt = should_fail_bin_sz/sizeof(verification_test_t);
  for( ulong i=0UL; i<should_fail_cnt; i++ ) {
    int res = fd_ed25519_verify( msg, 5, should_fail[i].sig, should_fail[i].pub, sha );
    for( ulong r=0UL; r<3UL; r++ ) FD_TEST( fd_ed25519_verify_cached( msg, 5, should_fail[i].sig, should_fail[i].pub, sha, cache )==res );
    if( res == FD_ED25519_SUCCESS ) {
      FD_LOG_ERR(("FAIL: verify should have failed\n\t"
                      "index %lu\n\t"
                      "sig: " FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT "\n\t"
                      "pub: " FD_LOG_HEX16_FMT,
              i,
              FD_LOG_HEX16_FMT_ARGS(should_fail[i].sig),
              FD_LOG_HEX16_FMT_ARGS(should_fail[i].sig+32),
              FD_LOG_HEX16_FMT_ARGS(should_fail[i].pub)));
    }
  }

  ulong should_pass_cnt = should_pass_bin_sz/sizeof(verification_test_t);
  for( ulong i=0UL; i<should_pass_cnt; i++ ) {
    int res = fd_ed25519_verify( msg, 5, should_pass[i].sig, should_pass[i].pub, sha );
    for( ulong r=0UL; r<3UL; r++ ) FD_TEST( fd_ed25519_verify_cached( msg, 5, should_pass[i].sig, should_pass[i].pub, sha, cache )==res );
    if( res != FD_ED25519_SUCCESS ) {
      FD_LOG_ERR(("FAIL: verify should have passed\n\t"
                  "index %lu\n\t"
                  "sig: " FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT "\n\t"
                  "pub: " FD_LOG_HEX16_FMT,
          i,
          FD_LOG_HEX16_FMT_ARGS(should_pass[i].sig),
          FD_LOG_HEX16_FMT_ARGS(should_pass[i].sig+32),
          FD_LOG_HEX16_FMT_ARGS(should_pass[i].pub)));
    }
  }

  FD_LOG_NOTICE(( "cache hit %lu miss %lu insert %lu", fd_ed25519_cache_hit_cnt( cache ), fd_ed25519_cache_miss_cnt( cache ), fd_ed25519_cache_insert_cnt( cache ) ));
  fd_ed25519_cache_delete( fd_ed25519_cache_leave( cache ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
