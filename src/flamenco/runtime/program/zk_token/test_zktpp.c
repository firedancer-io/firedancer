// tests
// https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof-tests/tests/process_transaction.rs
// benches
// https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/benches/verify_proofs.rs
#include <stdio.h>
#include "fd_zktpp_private.h"
#include "../../../fd_flamenco.h"
#include "../../../../ballet/hex/fd_hex.h"

#include "instructions/test_fd_zktpp_close_context_state.h"
#include "instructions/test_fd_zktpp_batched_grouped_ciphertext_validity.h"
#include "instructions/test_fd_zktpp_batched_range_proof_u128.h"
// #include "instructions/test_fd_zktpp_batched_range_proof_u256.h"
// #include "instructions/test_fd_zktpp_batched_range_proof_u64.h"
// #include "instructions/test_fd_zktpp_ciphertext_ciphertext_equality.h"
#include "instructions/test_fd_zktpp_ciphertext_commitment_equality.h"
// #include "instructions/test_fd_zktpp_fee_sigma.h"
// #include "instructions/test_fd_zktpp_grouped_ciphertext_validity.h"
#include "instructions/test_fd_zktpp_pubkey_validity.h"
// #include "instructions/test_fd_zktpp_range_proof_u64.h"
// #include "instructions/test_fd_zktpp_transfer_with_fee.h"
// #include "instructions/test_fd_zktpp_transfer_without_fee.h"
#include "instructions/test_fd_zktpp_withdraw.h"
// #include "instructions/test_fd_zktpp_zero_balance.h"

// turn on/off benches
#define BENCH 0

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

void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

static void
test_close_context_state( FD_FN_UNUSED fd_rng_t * rng ) {
  char ** hex = tx_close_context_state;
  ulong hex_sz = sizeof(tx_close_context_state);
  ulong offset = instr_offset_close_context_state;

  fd_exec_instr_ctx_t _ctx[1]; fd_exec_instr_ctx_t * ctx = _ctx;
  fd_instr_info_t instr[1];
  ulong tx_len = 0;

  // load test data
  uchar * tx = load_test_tx(hex, hex_sz, &tx_len);
  create_test_ctx(ctx, instr, tx, tx_len, offset);

#if 0
  // valid
  FD_TEST( fd_zktpp_instr_verify_proof_close_context_state( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_SUCCESS );
#endif
  free(tx);
}

static void
test_withdraw( FD_FN_UNUSED fd_rng_t * rng ) {
  char ** hex = tx_withdraw;
  ulong hex_sz = sizeof(tx_withdraw);
  ulong offset = instr_offset_withdraw;
  ulong context_sz = fd_zktpp_context_sz[FD_ZKTPP_INSTR_VERIFY_WITHDRAW];

  fd_exec_instr_ctx_t _ctx[1]; fd_exec_instr_ctx_t * ctx = _ctx;
  fd_instr_info_t instr[1];
  ulong tx_len = 0;
  ulong proof_offset = offset + 1 + context_sz;

  // load test data
  uchar * tx = load_test_tx(hex, hex_sz, &tx_len);
  create_test_ctx(ctx, instr, tx, tx_len, offset);

  FD_FN_UNUSED void const * context = tx + offset + 1;
  FD_FN_UNUSED void const * proof = tx + proof_offset;

  //TODO

  // valid
  // FD_TEST( fd_zktpp_instr_verify_proof_withdraw( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  // FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  // invalid proof
  // tx[1 + proof_offset] ^= 0xff;
  // FD_TEST( fd_zktpp_instr_verify_proof_withdraw( context, proof )==FD_EXECUTOR_INSTR_ERR_GENERIC_ERR );
  // FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  // tx[1 + proof_offset] ^= 0xff;

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
    fd_zktpp_instr_verify_proof_withdraw( context, proof );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_zktpp_instr_verify_proof_withdraw", iter, dt );
#endif
  free(tx);
}

static void
test_pubkey_validity( FD_FN_UNUSED fd_rng_t * rng ) {
  char ** hex = tx_pubkey_validity;
  ulong hex_sz = sizeof(tx_pubkey_validity);
  ulong offset = instr_offset_pubkey_validity;
  ulong context_sz = fd_zktpp_context_sz[FD_ZKTPP_INSTR_VERIFY_PUBKEY_VALIDITY];

  fd_exec_instr_ctx_t _ctx[1]; fd_exec_instr_ctx_t * ctx = _ctx;
  fd_instr_info_t instr[1];
  ulong tx_len = 0;
  ulong proof_offset = offset + 1 + context_sz;

  // load test data
  uchar * tx = load_test_tx(hex, hex_sz, &tx_len);
  create_test_ctx(ctx, instr, tx, tx_len, offset);

  void const * context = tx + offset + 1;
  void const * proof = tx + proof_offset;

  // valid
  FD_TEST( fd_zktpp_instr_verify_proof_pubkey_validity( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  // invalid proof
  tx[1 + proof_offset] ^= 0xff;
  FD_TEST( fd_zktpp_instr_verify_proof_pubkey_validity( context, proof )==FD_EXECUTOR_INSTR_ERR_GENERIC_ERR );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  tx[1 + proof_offset] ^= 0xff;

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
    fd_zktpp_instr_verify_proof_pubkey_validity( context, proof );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_zktpp_instr_verify_proof_pubkey_validity", iter, dt );
#endif
  free(tx);
}

static void
test_batched_range_proof_u128( FD_FN_UNUSED fd_rng_t * rng ) {
  char ** hex = tx_batched_range_proof_u128;
  ulong hex_sz = sizeof(tx_batched_range_proof_u128);
  ulong offset = instr_offset_batched_range_proof_u128;
  ulong context_sz = fd_zktpp_context_sz[FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128];

  fd_exec_instr_ctx_t _ctx[1]; fd_exec_instr_ctx_t * ctx = _ctx;
  fd_instr_info_t instr[1];
  ulong tx_len = 0;
  ulong proof_offset = offset + 1 + context_sz;

  // load test data
  uchar * tx = load_test_tx(hex, hex_sz, &tx_len);
  create_test_ctx(ctx, instr, tx, tx_len, offset);

  void const * context = tx + offset + 1;
  void const * proof = tx + proof_offset;

  // valid
  FD_TEST( fd_zktpp_instr_verify_proof_batched_range_proof_u128( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  // invalid proof
  tx[1 + proof_offset] ^= 0xff;
  FD_TEST( fd_zktpp_instr_verify_proof_batched_range_proof_u128( context, proof )==FD_EXECUTOR_INSTR_ERR_GENERIC_ERR );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  tx[1 + proof_offset] ^= 0xff;

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
    fd_zktpp_instr_verify_proof_batched_range_proof_u128( context, proof );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_zktpp_instr_verify_proof_batched_range_proof_u128", iter, dt );
#endif
  free(tx);
}

static void
test_ciphertext_commitment_equality( FD_FN_UNUSED fd_rng_t * rng ) {
  char ** hex = tx_ciphertext_commitment_equality;
  ulong hex_sz = sizeof(tx_ciphertext_commitment_equality);
  ulong offset = instr_offset_ciphertext_commitment_equality;
  ulong context_sz = fd_zktpp_context_sz[FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY];

  fd_exec_instr_ctx_t _ctx[1]; fd_exec_instr_ctx_t * ctx = _ctx;
  fd_instr_info_t instr[1];
  ulong tx_len = 0;
  ulong proof_offset = offset + 1 + context_sz;

  // load test data
  uchar * tx = load_test_tx(hex, hex_sz, &tx_len);
  create_test_ctx(ctx, instr, tx, tx_len, offset);

  void const * context = tx + offset + 1;
  void const * proof = tx + offset + 1 + context_sz;

  // valid
  FD_TEST( fd_zktpp_instr_verify_proof_ciphertext_commitment_equality( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  // invalid proof
  tx[1 + proof_offset] ^= 0xff;
  FD_TEST( fd_zktpp_instr_verify_proof_ciphertext_commitment_equality( context, proof )==FD_EXECUTOR_INSTR_ERR_GENERIC_ERR );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  tx[1 + proof_offset] ^= 0xff;

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

static void
test_batched_grouped_ciphertext_validity( FD_FN_UNUSED fd_rng_t * rng ) {
  char ** hex = tx_batched_grouped_ciphertext_validity;
  ulong hex_sz = sizeof(tx_batched_grouped_ciphertext_validity);
  ulong offset = instr_offset_batched_grouped_ciphertext_validity;
  ulong context_sz = fd_zktpp_context_sz[FD_ZKTPP_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY];

  fd_exec_instr_ctx_t _ctx[1]; fd_exec_instr_ctx_t * ctx = _ctx;
  fd_instr_info_t instr[1];
  ulong tx_len = 0;
  ulong proof_offset = offset + 1 + context_sz;

  // load test data
  uchar * tx = load_test_tx(hex, hex_sz, &tx_len);
  create_test_ctx(ctx, instr, tx, tx_len, offset);

  void const * context = tx + offset + 1;
  void const * proof = tx + proof_offset;

  // valid
  FD_TEST( fd_zktpp_instr_verify_proof_batched_grouped_ciphertext_validity( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  // invalid proof
  tx[1 + proof_offset] ^= 0xff;
  FD_TEST( fd_zktpp_instr_verify_proof_batched_grouped_ciphertext_validity( context, proof )==FD_EXECUTOR_INSTR_ERR_GENERIC_ERR );
  FD_TEST( fd_zktpp_process_verify_proof( *ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  tx[1 + proof_offset] ^= 0xff;

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
    fd_zktpp_instr_verify_proof_batched_grouped_ciphertext_validity( context, proof );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_zktpp_instr_verify_proof_batched_grouped_ciphertext_validity", iter, dt );
#endif
  free(tx);
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  // fd_flamenco_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_close_context_state( rng );

  test_withdraw( rng );
  // test_zero_balance( rng );
  // test_ciphertext_ciphertext_equality( rng );
  // test_transfer_without_fee( rng );
  // test_transfer_with_fee( rng );
  test_pubkey_validity( rng );
  // test_range_proof_u64( rng );
  // test_batched_range_proof_u64( rng );
  test_batched_range_proof_u128( rng );
  // test_batched_range_proof_u256( rng );
  test_ciphertext_commitment_equality( rng );
  // test_grouped_ciphertext_validity( rng );
  test_batched_grouped_ciphertext_validity( rng );
  // test_fee_sigma( rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  // fd_flamenco_halt();
  fd_halt();
  return 0;
}
