/* Tests are run through `make run-test-vectors` and are available at:
   https://github.com/firedancer-io/test-vectors/tree/main/instr/fixtures/zk_sdk

   This unit test just runs an instance of pubkey_validity. */
#include "fd_zksdk_private.h"
#include "../../../../ballet/hex/fd_hex.h"
#include "../../fd_bank.h"
#include "../../fd_runtime.h"
#include "../../../log_collector/fd_log_collector.h"

#include "instructions/test_fd_zksdk_pubkey_validity.h"

#include <stdlib.h> // ARM64: malloc(3), free(3)

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
                 fd_runtime_t *        runtime,
                 fd_txn_out_t *        txn_out,
                 fd_instr_info_t *     instr,
                 uchar *               tx,
                 ulong                 tx_len,
                 ulong                 instr_off,
                 ulong                 compute_meter ) {
  // This is just minimally setting the instr data so we can test zkp verification
  // TODO: properly load tx
  ctx->txn_out = txn_out;
  ctx->txn_out->details.compute_budget.compute_meter = compute_meter;
  ctx->instr = instr;
  ctx->runtime = runtime;
  instr->data_sz = (ushort)(tx_len - instr_off); //TODO: this only works if the instruction is the last one
  instr->acct_cnt = 0; // TODO: hack to avoid filling proof context account (it requires to create the account first)
  memcpy( instr->data, &tx[instr_off], instr->data_sz );
  fd_log_collector_init( ctx->runtime->log.log_collector, 1 );
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
test_pubkey_validity( FD_FN_UNUSED fd_rng_t * rng, fd_runtime_t * runtime ) {
  char ** hex = tx_pubkey_validity;
  ulong hex_sz = sizeof(tx_pubkey_validity);
  ulong offset = instr_offset_pubkey_validity;
  ulong context_sz = fd_zksdk_context_sz[FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY];
  ulong cu = FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS;

  fd_exec_instr_ctx_t ctx;
  fd_txn_out_t txn_out[1];
  fd_instr_info_t instr[1];
  fd_log_collector_t log_collector[1];
  fd_bank_t bank[1];
  ulong tx_len = 0;
  ctx.bank = bank;
  runtime->log.log_collector = log_collector;

  fd_bank_slot_set( bank, 0UL );
  fd_features_t * features = fd_bank_features_modify( bank );
  fd_features_enable_all( features );

  // load test data
  uchar * tx = load_test_tx( hex, hex_sz, &tx_len );
  create_test_ctx( &ctx, runtime, txn_out, instr, tx, tx_len, offset, cu );

  void const * context = instr->data+1;
  void const * proof   = instr->data+1+context_sz;

  // valid
  FD_TEST( fd_zksdk_instr_verify_proof_pubkey_validity( context, proof )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_zksdk_process_verify_proof( &ctx )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_executor_zk_elgamal_proof_program_execute( &ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  // invalid proof
  instr->data[1 + context_sz] ^= 0xff;
  FD_TEST( fd_zksdk_instr_verify_proof_pubkey_validity( context, proof )==FD_ZKSDK_VERIFY_PROOF_ERROR );
  FD_TEST( fd_zksdk_process_verify_proof( &ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  instr->data[1 + context_sz] ^= 0xff;

  // invalid data
  instr->data_sz = (ushort)(instr->data_sz - 10);
  FD_TEST( fd_zksdk_process_verify_proof( &ctx )==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
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

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 5UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  FD_TEST( runtime );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_pubkey_validity( rng, runtime );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
