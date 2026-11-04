/* Tests the per-runtime sysvar cache: it must follow the bank the
   runtime executes, reload only when that bank changes, and never serve
   one fork's sysvars to another. */

#include "tests/fd_svm_mini.h"
#include "fd_runtime.h"
#include "fd_system_ids.h"
#include "sysvar/fd_sysvar.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_clock.h"

/* Gives bank a Clock sysvar whose epoch_start_timestamp is tag, and
   deletes its LastRestartSlot sysvar if drop_restart. */

static void
test_tag_bank( fd_svm_mini_t * mini,
               ulong           bank_idx,
               long            tag,
               int             drop_restart ) {
  fd_bank_t *  bank  = fd_svm_mini_bank( mini, bank_idx );
  fd_accdb_t * accdb = mini->runtime->accdb;

  fd_sol_sysvar_clock_t clock[1];
  FD_TEST( fd_sysvar_clock_read( accdb, bank->accdb_fork_id, clock ) );
  clock->epoch_start_timestamp = tag;
  fd_sysvar_account_update( bank, accdb, NULL, &fd_sysvar_clock_id, clock, sizeof(fd_sol_sysvar_clock_t) );

  if( drop_restart ) {
    fd_acc_t acc = fd_accdb_write_one( accdb, bank->accdb_fork_id, fd_sysvar_last_restart_slot_id.uc );
    acc.lamports = 0UL;
    acc.data_len = 0UL;
    acc.commit   = 1;
    fd_accdb_unwrite_one( accdb, &acc );
  }
}

static long
test_cached_tag( fd_runtime_t * runtime ) {
  fd_sol_sysvar_clock_t clock[1];
  FD_TEST( fd_sysvar_cache_clock_read( runtime->sysvar_cache, clock ) );
  return clock->epoch_start_timestamp;
}

static void
test_bank_switch( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  /* Two sibling forks with distinct sysvars.  B lacks LastRestartSlot. */
  ulong a_idx = fd_svm_mini_attach_child( mini, root_idx, params->root_slot+1UL );
  ulong b_idx = fd_svm_mini_attach_child( mini, root_idx, params->root_slot+2UL );
  test_tag_bank( mini, a_idx, 111L, 0 );
  test_tag_bank( mini, b_idx, 222L, 1 );

  fd_runtime_t * runtime = mini->runtime;
  fd_bank_t *    a       = fd_svm_mini_bank( mini, a_idx );
  fd_bank_t *    b       = fd_svm_mini_bank( mini, b_idx );
  ulong          switch0 = runtime->metrics.bank_switch_cnt;

  /* A -> A -> B -> A: reload only on change */
  fd_runtime_sysvar_cache_refresh( runtime, a );
  FD_TEST( test_cached_tag( runtime )==111L );
  FD_TEST( fd_sysvar_cache_last_restart_slot_is_valid( runtime->sysvar_cache ) );
  fd_runtime_sysvar_cache_refresh( runtime, a );
  FD_TEST( runtime->metrics.bank_switch_cnt==switch0+1UL );

  fd_runtime_sysvar_cache_refresh( runtime, b );
  FD_TEST( test_cached_tag( runtime )==222L );
  FD_TEST( !fd_sysvar_cache_last_restart_slot_is_valid( runtime->sysvar_cache ) );
  FD_TEST( runtime->metrics.bank_switch_cnt==switch0+2UL );

  fd_runtime_sysvar_cache_refresh( runtime, a );
  FD_TEST( test_cached_tag( runtime )==111L );
  FD_TEST( fd_sysvar_cache_last_restart_slot_is_valid( runtime->sysvar_cache ) );
  FD_TEST( runtime->metrics.bank_switch_cnt==switch0+3UL );

  /* Leave B cached, then root A, which prunes B.  The next bank reuses
     B's pool slot under a new bank_seq and must not be mistaken for B. */
  fd_runtime_sysvar_cache_refresh( runtime, b );
  FD_TEST( test_cached_tag( runtime )==222L );
  ulong b_seq = b->bank_seq;
  fd_svm_mini_freeze      ( mini, a_idx );
  fd_svm_mini_advance_root( mini, a_idx );
  ulong c_idx = fd_svm_mini_attach_child( mini, a_idx, params->root_slot+3UL );
  FD_TEST( c_idx==b_idx );
  test_tag_bank( mini, c_idx, 333L, 0 );
  fd_bank_t * c = fd_svm_mini_bank( mini, c_idx );
  FD_TEST( c->bank_seq!=b_seq );

  fd_runtime_sysvar_cache_refresh( runtime, c );
  FD_TEST( test_cached_tag( runtime )==333L );
  FD_TEST( fd_sysvar_cache_last_restart_slot_is_valid( runtime->sysvar_cache ) );
  FD_TEST( runtime->metrics.bank_switch_cnt==switch0+5UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_bank_switch( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
