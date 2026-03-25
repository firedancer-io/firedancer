/* Tests are run through `make run-test-vectors` and are available at:
   https://github.com/firedancer-io/test-vectors/tree/main/instr/fixtures/zk_sdk

   This unit test just runs an instance of pubkey_validity. */
#include "fd_zksdk_private.h"
#include "../hex/fd_hex.h"

#include "instructions/test_fd_zksdk_pubkey_validity.h"

// turn on/off benches
#define BENCH 0

#if BENCH
static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}
#endif

FD_FN_UNUSED static void
test_pubkey_validity( FD_FN_UNUSED fd_rng_t * rng ) {
  char * hex = tx_pubkey_validity;
  ulong hex_sz = strlen(tx_pubkey_validity);
  ulong offset = instr_offset_pubkey_validity;
  ulong context_sz = fd_zksdk_context_sz[FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY];

  // load test data
  uchar tx[ 1232 ];
  fd_hex_decode( tx, hex, hex_sz/2 );
  uchar * context = tx+offset+1;
  uchar * proof   = context+context_sz;

  // valid
  FD_TEST( fd_zksdk_instr_verify_proof_pubkey_validity( context, proof )==FD_ZKSDK_VERIFY_PROOF_SUCCESS );

  // invalid proof
  proof[1 + context_sz] ^= 0xff;
  FD_TEST( fd_zksdk_instr_verify_proof_pubkey_validity( context, proof )==FD_ZKSDK_VERIFY_PROOF_ERROR );
  proof[1 + context_sz] ^= 0xff;

  FD_LOG_NOTICE(( "test_pubkey_validity... ok" ));
  /* Benchmarks */
#if BENCH
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( proof ); FD_COMPILER_FORGET( context );
    fd_zksdk_instr_verify_proof_pubkey_validity( context, proof );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_zksdk_instr_verify_proof_pubkey_validity", iter, dt );
#endif
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_pubkey_validity( rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
