#include "../fd_ballet.h"

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

  ulong should_fail_cnt = should_fail_bin_sz/sizeof(verification_test_t);
  for( ulong i=0UL; i<should_fail_cnt; i++ ) {
    if( fd_ed25519_verify( msg, 5, should_fail[i].sig, should_fail[i].pub, sha ) == FD_ED25519_SUCCESS ) {
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
    if( fd_ed25519_verify( msg, 5, should_pass[i].sig, should_pass[i].pub, sha ) != FD_ED25519_SUCCESS ) {
      FD_LOG_ERR(("FAIL: verify should have passed\n\t"
                  "index %lu\n\t"
                  "sig: " FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT "\n\t"
                  "pub: " FD_LOG_HEX16_FMT,
          i,
          FD_LOG_HEX16_FMT_ARGS(should_fail[i].sig),
          FD_LOG_HEX16_FMT_ARGS(should_fail[i].sig+32),
          FD_LOG_HEX16_FMT_ARGS(should_fail[i].pub)));
    }
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
