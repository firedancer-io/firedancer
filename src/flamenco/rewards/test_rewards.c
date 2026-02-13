#include "fd_rewards.h"
#include "../mini/fd_svm_mini.h"
#include "../runtime/fd_bank.h"
#include "../capture/fd_capture_ctx.h"
#include "../solcap/fd_solcap_writer.h"
#include "../solcap/fd_pkt_buf.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_svm_mini_limits_t svm_limits = {
    .max_vote_accounts = 4,
    .max_fork_nodes    = 3,
    .max_live_slots    = 1
  };
  fd_svm_mini_t * svm = fd_svm_mini_create( &svm_limits, "test", 0UL );
  fd_svm_view_t * view = fd_svm_mini_join_root( svm );

  fd_capture_ctx_t capture_ctx = {0};

  /* solcap logging */

  ulong          solcap_depth   = 64UL;
  void *         solcap_buf_mem = aligned_alloc( fd_pkt_buf_align(), fd_pkt_buf_footprint( solcap_depth, FD_SOLCAP_MTU ) );
  fd_pkt_buf_t * solcap_buf     = fd_pkt_buf_new( solcap_buf_mem, solcap_depth, FD_SOLCAP_MTU );
  FD_TEST( solcap_buf );
  capture_ctx.solcap = fd_pkt_buf_writer( solcap_buf );

  fd_hash_t const * parent_blockhash = fd_blockhashes_peek_last_hash( fd_bank_block_hash_queue_query( view->bank ) );
  FD_TEST( parent_blockhash );
  ulong parent_epoch = fd_bank_epoch_get( view->bank )-1UL;
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( svm->banks );
  fd_begin_partitioned_rewards(
      view->bank,
      view->accdb,
      &view->xid,
      view->runtime_stack,
      &capture_ctx,
      stake_delegations,
      parent_blockhash,
      parent_epoch );

  /* Clean up */

  fd_svm_mini_destroy( svm );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
