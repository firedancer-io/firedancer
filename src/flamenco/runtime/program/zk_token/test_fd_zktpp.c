// tests
// https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof-tests/tests/process_transaction.rs
// benches
// https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/benches/verify_proofs.rs
#include <stdio.h>
#include "fd_zktpp_private.h"
#include "../../../fd_flamenco.h"
#include "../../../../ballet/hex/fd_hex.h"

#include "instructions/test_fd_zktpp_ciphertext_commitment_equality.h"

// turn on/off benches
#define BENCH 1

uchar *
load_test_tx(char * hex[], ulong hex_sz, ulong * tx_len) {
  ulong hex_len = 0;
  for ( ulong i=0; i<hex_sz/sizeof(char *); i++ ) {
    hex_len += strlen(hex[i]);
    // printf("adding %d, total %d\n", strlen(hex[i]), hex_len);
  }
  *tx_len = hex_len / 2;
  uchar * tx = malloc(hex_len / 2);

  hex_len = 0;
  for ( ulong i=0; i<hex_sz/sizeof(char *); i++ ) {
    ulong cur_len = strlen(hex[i]);
    fd_hex_decode( &tx[hex_len/2], hex[i], cur_len );
    hex_len += cur_len;
  }
  return tx;
}

void
create_test_ctx(fd_exec_instr_ctx_t * ctx, fd_instr_info_t * instr, uchar * tx, ulong tx_len, ulong instr_off) {
  // This is just minimally setting the instr data so we can test zkp verification
  // TODO: properly load tx
  ctx->instr = instr;
  instr->data = &tx[instr_off];
  instr->data_sz = (ushort)(tx_len - instr_off); //TODO: this only works if the instruction is the last one
}

static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

static void
test_ciphertext_commitment_equality( FD_FN_UNUSED fd_rng_t * rng ) {
  fd_exec_instr_ctx_t _ctx[1]; fd_exec_instr_ctx_t * ctx = _ctx;
  fd_instr_info_t instr[1];
  char ** hex = tx_ciphertext_commitment_equality;
  ulong hex_sz = sizeof(tx_ciphertext_commitment_equality);
  ulong tx_len = 0;

  // load test data
  uchar * tx = load_test_tx(hex, hex_sz, &tx_len);
  create_test_ctx(ctx, instr, tx, tx_len, instr_offset_ciphertext_commitment_equality);

  void const * context = tx + context_offset_ciphertext_commitment_equality;
  void const * proof = tx + proof_offset_ciphertext_commitment_equality;

  // valid
  FD_TEST( fd_zktpp_instr_verify_proof_ciphertext_commitment_equality( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  // invalid proof
  tx[1 + proof_offset_ciphertext_commitment_equality] ^= 0xff;
  FD_TEST( fd_zktpp_instr_verify_proof_ciphertext_commitment_equality( context, proof )==FD_EXECUTOR_INSTR_ERR_GENERIC_ERR );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  tx[1 + proof_offset_ciphertext_commitment_equality] ^= 0xff;

  // invalid data
  instr->data_sz -= 10;
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  instr->data_sz += 10;

  /* Benchmarks */
#if BENCH
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( proof ); FD_COMPILER_FORGET( context );
    fd_zktpp_instr_verify_proof_ciphertext_commitment_equality( context, proof );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_zktpp_instr_verify_proof_ciphertext_commitment_equality", iter, dt );
#endif
  free(tx);
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  // fd_flamenco_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  // test_withdraw( rng );
  // test_zero_balance( rng );
  // test_ciphertext_ciphertext_equality( rng );
  // test_transfer_without_fee( rng );
  // test_transfer_with_fee( rng );
  // test_pubkey_validity( rng );
  // test_range_proof_u64( rng );
  // test_batched_range_proof_u64( rng );
  // test_batched_range_proof_u128( rng );
  // test_batched_range_proof_u256( rng );
  test_ciphertext_commitment_equality( rng );
  // test_grouped_ciphertext_validity( rng );
  // test_batched_grouped_ciphertext_validity( rng );
  // test_fee_sigma( rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  // fd_flamenco_halt();
  fd_halt();
  return 0;
}
