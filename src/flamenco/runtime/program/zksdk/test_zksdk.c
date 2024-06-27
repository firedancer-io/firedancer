/* Tests are run through `make run-test-vectors` and are available at:
   https://github.com/firedancer-io/test-vectors/tree/main/instr/fixtures/zk_sdk
 
   This unit test just runs an instance of pubkey_validity. */
#include "fd_zksdk_private.h"
#include "../../../../ballet/hex/fd_hex.h"

#include "instructions/test_fd_zksdk_pubkey_validity.h"

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
    fd_hex_decode( &tx[hex_len/2], hex[i], cur_len/2 );
    hex_len += cur_len;
  }
  return tx;
}

void
create_test_ctx( fd_exec_instr_ctx_t * ctx,
                 fd_exec_txn_ctx_t *   txn_ctx,
                 fd_instr_info_t *     instr,
                 uchar * tx,
                 ulong   tx_len,
                 ulong   instr_off,
                 ulong   compute_meter ) {
  // This is just minimally setting the instr data so we can test zkp verification
  // TODO: properly load tx
  ctx->txn_ctx = txn_ctx;
  txn_ctx->compute_meter = compute_meter;
  ctx->instr = instr;
  instr->data = &tx[instr_off];
  instr->data_sz = (ushort)(tx_len - instr_off); //TODO: this only works if the instruction is the last one
  instr->acct_cnt = 0; // TODO: hack to avoid filling proof context account (it requires to create the account first)
}

void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

FD_FN_UNUSED static void
test_pubkey_validity( FD_FN_UNUSED fd_rng_t * rng ) {
  char ** hex = tx_pubkey_validity;
  ulong hex_sz = sizeof(tx_pubkey_validity);
  ulong offset = instr_offset_pubkey_validity;
  ulong context_sz = fd_zksdk_context_sz[FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY];
  ulong cu = FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS;

  fd_exec_instr_ctx_t ctx;
  fd_exec_txn_ctx_t txn_ctx[1];
  fd_instr_info_t instr[1];
  ulong tx_len = 0;
  ulong proof_offset = offset + 1 + context_sz;

  // load test data
  uchar * tx = load_test_tx( hex, hex_sz, &tx_len );
  create_test_ctx( &ctx, txn_ctx, instr, tx, tx_len, offset, cu );

  void const * context = tx + offset + 1;
  void const * proof = tx + proof_offset;

  // valid
  FD_TEST( fd_zksdk_instr_verify_proof_pubkey_validity( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_zksdk_process_verify_proof( ctx )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_executor_zk_elgamal_proof_program_execute( ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  // invalid proof
  tx[1 + proof_offset] ^= 0xff;
  FD_TEST( fd_zksdk_instr_verify_proof_pubkey_validity( context, proof )==FD_ZKSDK_VERIFY_PROOF_ERROR );
  FD_TEST( fd_zksdk_process_verify_proof( ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  tx[1 + proof_offset] ^= 0xff;

  // invalid data
  instr->data_sz = (ushort)(instr->data_sz - 10);
  FD_TEST( fd_zksdk_process_verify_proof( ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  instr->data_sz = (ushort)(instr->data_sz + 10);

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
  free(tx);
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  // fd_flamenco_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_pubkey_validity( rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  // fd_flamenco_halt();
  fd_halt();
  return 0;
}
