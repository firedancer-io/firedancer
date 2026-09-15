/* Reproducer for https://github.com/firedancer-io/firedancer/issues/11517

   query_towers reads back the vote account of every entry in the t-2
   top votes set whose cached is_valid flag is set, and asserts that the
   account read back from accdb really is an initialized, correctly
   sized, vote-program owned account:

     FD_TEST( accs[ j ].lamports && fd_vsv_is_correct_size_owner_and_init( ... ) );

   is_valid is only ever computed by fd_vote_stakes_refresh, which runs
   at genesis, at an epoch boundary, and once at boot after a snapshot
   has been loaded.  This test pins down when the assert can fire:

   1. test_snapshot_reincarnated_vote_account: a "weird" snapshot whose
      t-2 top votes set names a vote account that, in the accounts of
      the same snapshot, is a reincarnated non-vote account (lamports>0,
      system-program owned).  The boot refresh clears is_valid for that
      entry, so query_towers skips it and no abort happens.  The report
      as filed (a bad entry coming straight out of a snapshot) is
      therefore not reachable.

   2. test_stale_is_valid_mid_epoch: the account is a valid vote account
      when the refresh computes is_valid, and is closed (and optionally
      funded again as a plain system account) later in the same epoch.
      is_valid is not recomputed until the next epoch boundary, so
      query_towers reads back the closed/reincarnated account and
      aborts.  Both the closed (lamports==0) and reincarnated
      (lamports>0, wrong owner) variants are covered.

      This is reachable on chain: the vote program allows a full
      withdraw (which deinitializes the account) as long as the vote
      account earned no credits in the last two epochs, while the t-2
      top votes set only requires that the account had stake two epochs
      ago.  A vote account that has been delinquent for two epochs but
      still carries delegated stake can therefore be closed mid-epoch.

   The mid-epoch cases assert the current (aborting) behavior, so they
   are a reproducer, not a regression test: if the abort is replaced
   with a skip (as fd_refresh_vote_accounts does), update them.

   The test needs a large workspace for accdb, e.g.

     unit-test/test_tower_query_towers --page-sz gigantic --page-cnt 6 */

#define _GNU_SOURCE

#include "fd_tower_tile.c"

#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/accdb/fd_accdb_shmem.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../../flamenco/stakes/fd_vote_stakes.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define SENTINEL ((fd_accdb_fork_id_t){ .val = USHORT_MAX })

#define VOTE_ACCOUNT_LAMPORTS (1000000000UL)
#define VOTER_STAKE           (1000000000UL)
#define TEST_EPOCH            (1UL)

struct test_env {
  fd_wksp_t *  wksp;
  ulong        tag;
  fd_banks_t * banks;
  fd_bank_t *  bank;
  fd_accdb_t * accdb;
  void *       accdb_shmem;
  void *       accdb_join;
  int          accdb_fd;

  fd_tower_tile_t * ctx;
};
typedef struct test_env test_env_t;

static fd_pubkey_t vote_key( ulong i ) { return (fd_pubkey_t){ .ul[0] = 0x100UL + i }; }

/* Accounts ***************************************************************/

static void
put_vote_account( test_env_t *        env,
                  fd_pubkey_t const * vote_account,
                  fd_pubkey_t const * node_pubkey ) {
  uchar vote_state_data[ FD_VOTE_STATE_V4_SZ ] = {0};

  fd_vote_state_versioned_t versioned[1];
  FD_TEST( fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v4 ) );

  fd_vote_state_v4_t * vs = &versioned->v4;
  vs->node_pubkey                      = *node_pubkey;
  vs->authorized_withdrawer            = *node_pubkey;
  vs->inflation_rewards_collector      = *vote_account;
  vs->block_revenue_collector          = *node_pubkey;
  vs->inflation_rewards_commission_bps = 100;

  fd_vote_authorized_voter_t * voter = fd_vote_authorized_voters_pool_ele_acquire( vs->authorized_voters.pool );
  fd_memset( voter, 0, sizeof(fd_vote_authorized_voter_t) );
  voter->epoch  = 0UL;
  voter->pubkey = *node_pubkey;
  voter->prio   = node_pubkey->uc[0];
  fd_vote_authorized_voters_treap_ele_insert( vs->authorized_voters.treap, voter, vs->authorized_voters.pool );

  FD_TEST( !fd_vote_state_versioned_serialize( versioned, vote_state_data, sizeof(vote_state_data) ) );

  fd_acc_t acc = fd_accdb_write_one( env->accdb, env->bank->accdb_fork_id, vote_account->uc );
  acc.lamports   = VOTE_ACCOUNT_LAMPORTS;
  acc.executable = 0;
  fd_memcpy( acc.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) );
  acc.data_len   = sizeof(vote_state_data);
  fd_memcpy( acc.data, vote_state_data, sizeof(vote_state_data) );
  acc.commit     = 1;
  fd_accdb_unwrite_one( env->accdb, &acc );
}

/* put_reincarnated_account models a vote account that was closed (full
   withdraw) and whose address was then funded again as a plain
   system-owned account.  lamports>0, but the owner is wrong. */

static void
put_reincarnated_account( test_env_t *        env,
                          fd_pubkey_t const * pubkey ) {
  fd_acc_t acc = fd_accdb_write_one( env->accdb, env->bank->accdb_fork_id, pubkey->uc );
  acc.lamports   = VOTE_ACCOUNT_LAMPORTS;
  acc.executable = 0;
  fd_memcpy( acc.owner, fd_solana_system_program_id.key, sizeof(fd_pubkey_t) );
  acc.data_len   = 0UL;
  acc.commit     = 1;
  fd_accdb_unwrite_one( env->accdb, &acc );
}

/* put_closed_account models a vote account that was closed by a full
   withdraw and never funded again. */

static void
put_closed_account( test_env_t *        env,
                    fd_pubkey_t const * pubkey ) {
  fd_acc_t acc = fd_accdb_write_one( env->accdb, env->bank->accdb_fork_id, pubkey->uc );
  acc.lamports   = 0UL;
  acc.executable = 0;
  fd_memset( acc.owner, 0, sizeof(fd_pubkey_t) );
  acc.data_len   = 0UL;
  acc.commit     = 1;
  fd_accdb_unwrite_one( env->accdb, &acc );
}

/* Environment ************************************************************/

static void
drain_background( fd_accdb_t * accdb ) {
  int charge_busy = 0;
  fd_accdb_background( accdb, &charge_busy );
}

static test_env_t *
test_env_create( test_env_t * env,
                 fd_wksp_t *  wksp ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  ulong const max_total_banks = 8UL;
  ulong const max_fork_width  = 4UL;

  ulong const accdb_max_accounts       = 1024UL;
  ulong const accdb_max_live_slots     = 16UL;
  ulong const accdb_writes_per_slot    = 256UL;
  ulong const accdb_partition_cnt      = 8UL;
  ulong const accdb_partition_sz       = 1UL<<26UL;  /* 64 MiB */
  ulong const accdb_cache_footprint    = 4UL<<30UL;  /* 4 GiB (cache minimum) */
  ulong const accdb_cache_min_reserved = fd_accdb_cache_min_reserved( 0 );
  ulong const accdb_joiner_cnt         = 1UL;

  ulong accdb_shmem_sz = fd_accdb_shmem_footprint( accdb_max_accounts, accdb_max_live_slots,
                                                   accdb_writes_per_slot, accdb_partition_cnt,
                                                   accdb_cache_footprint, accdb_cache_min_reserved,
                                                   accdb_joiner_cnt, 0UL );
  ulong accdb_join_sz = fd_accdb_footprint( accdb_max_live_slots );

  env->accdb_shmem = fd_wksp_alloc_laddr( wksp, fd_accdb_shmem_align(), accdb_shmem_sz, env->tag );
  FD_TEST( env->accdb_shmem );
  env->accdb_join = fd_wksp_alloc_laddr( wksp, fd_accdb_align(), accdb_join_sz, env->tag );
  FD_TEST( env->accdb_join );

  env->accdb_fd = memfd_create( "tower_test", 0 );
  if( FD_UNLIKELY( env->accdb_fd<0 ) ) FD_LOG_ERR(( "memfd_create failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( env->accdb_shmem, accdb_max_accounts, accdb_max_live_slots,
                          accdb_writes_per_slot, accdb_partition_cnt, accdb_partition_sz,
                          accdb_cache_footprint, accdb_cache_min_reserved, 0, 42UL, accdb_joiner_cnt, 0UL ) );
  FD_TEST( shmem );
  env->accdb = fd_accdb_join( fd_accdb_new( env->accdb_join, shmem, env->accdb_fd, 0UL, NULL ) );
  FD_TEST( env->accdb );

  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width, 2048UL, 32768UL, 2048UL ), env->tag );
  FD_TEST( banks_mem );
  env->banks = fd_banks_join( fd_banks_new( banks_mem, max_total_banks, max_fork_width, 2048UL, 32768UL, 2048UL, 0, 8888UL ) );
  FD_TEST( env->banks );

  env->bank = fd_banks_init_bank( env->banks );
  FD_TEST( env->bank );
  env->bank->f.slot  = 1UL;
  env->bank->f.epoch = TEST_EPOCH;

  env->bank->accdb_fork_id = fd_accdb_attach_child( env->accdb, SENTINEL );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( env->bank );
  fd_vote_stakes_reset( vote_stakes );
  env->bank->vote_stakes_fork_id = fd_vote_stakes_init( vote_stakes, env->bank->f.epoch );

  /* Tower tile context.  Only the parts query_towers touches are set
     up.  The vote accounts below carry no votes, so the ghost and
     lockout paths in count_vote_acc are not exercised. */

  fd_tower_tile_t * ctx = fd_wksp_alloc_laddr( wksp, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t), env->tag );
  FD_TEST( ctx );
  fd_memset( ctx, 0, sizeof(fd_tower_tile_t) );

  void * tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( 16UL, 16UL ), env->tag );
  FD_TEST( tower_mem );
  ctx->tower = fd_tower_join( fd_tower_new( tower_mem, 16UL, 16UL, 0UL ) );
  FD_TEST( ctx->tower );

  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( 16UL, 16UL ), env->tag );
  FD_TEST( ghost_mem );
  ctx->ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 16UL, 16UL, 0UL ) );
  FD_TEST( ctx->ghost );
  fd_hash_t block_id = { .ul = { 0x77UL } };
  FD_TEST( fd_ghost_init( ctx->ghost, ULONG_MAX, 0UL, &block_id ) );

  /* Our own vote account does not exist in accdb, so the tower
     reconcile path at the end of query_towers is skipped. */
  fd_memset( ctx->vote_account, 0xEE, sizeof(fd_pubkey_t) );

  ctx->banks = env->banks;
  ctx->accdb = env->accdb;
  env->ctx   = ctx;

  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  fd_wksp_free_laddr( env->banks );
  fd_wksp_free_laddr( env->accdb_join );
  fd_wksp_free_laddr( env->accdb_shmem );
  if( FD_LIKELY( env->accdb_fd>=0 ) ) close( env->accdb_fd );
  fd_memset( env, 0, sizeof(test_env_t) );
}

/* snapshot_load inserts voter_cnt entries into the t-2 top votes set,
   the same way fd_ssload_manifest does when booting from a snapshot,
   and then refreshes them against accdb like the replay tile does once
   the snapshot has finished loading. */

static void
snapshot_load( test_env_t * env,
               ulong        voter_cnt ) {
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( env->bank );
  ulong              fork_id     = env->bank->vote_stakes_fork_id;

  uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = {0};
  for( ulong i=0UL; i<voter_cnt; i++ ) {
    fd_pubkey_t v = vote_key( i );
    fd_vote_stakes_snap_insert_t_2( vote_stakes, fork_id, &v, &v, VOTER_STAKE, 100, bls );
  }

  fd_vote_stakes_refresh( vote_stakes, fork_id, env->accdb, env->bank->accdb_fork_id );
}

/* new_slot appends a child bank (and a child accdb fork) to the current
   bank, modelling replay of the next slot within the same epoch. */

static void
new_slot( test_env_t * env ) {
  fd_bank_t * parent = env->bank;
  FD_TEST( parent->state==FD_BANK_STATE_FROZEN );

  ulong       child_idx = fd_banks_new_bank( env->banks, parent->idx, 0L, 0 )->idx;
  fd_bank_t * child     = fd_banks_clone_from_parent( env->banks, child_idx );
  FD_TEST( child );

  child->f.slot        = parent->f.slot + 1UL;
  child->f.parent_slot = parent->f.slot;
  child->f.epoch       = parent->f.epoch;
  child->accdb_fork_id = fd_accdb_attach_child( env->accdb, parent->accdb_fork_id );

  env->bank = child;
}

static ulong
run_query_towers( test_env_t * env ) {
  fd_replay_slot_completed_t slot_completed;
  fd_memset( &slot_completed, 0, sizeof(slot_completed) );
  slot_completed.slot     = env->bank->f.slot;
  slot_completed.epoch    = env->bank->f.epoch;
  slot_completed.bank_idx = env->bank->idx;

  int    found_our_vote_acct = 0;
  ulong  our_vote_acct_bal   = 0UL;
  ushort our_vote_acct_com   = 0;

  fd_ghost_blk_t * ghost_blk = fd_ghost_root( env->ctx->ghost );
  return query_towers( env->ctx, &slot_completed, ghost_blk,
                       &found_our_vote_acct, &our_vote_acct_bal, &our_vote_acct_com );
}

/* Tests ******************************************************************/

/* Boot from a snapshot whose t-2 top votes set names voter 1, but whose
   accounts have voter 1 as a reincarnated system-owned account.  The
   boot refresh marks the entry invalid, so query_towers skips it. */

static void
test_snapshot_reincarnated_vote_account( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "testing snapshot with reincarnated vote account" ));

  static test_env_t env[1];
  test_env_create( env, wksp );

  fd_pubkey_t good = vote_key( 0UL );
  fd_pubkey_t bad  = vote_key( 1UL );
  put_vote_account       ( env, &good, &good );
  put_reincarnated_account( env, &bad );
  drain_background( env->accdb );

  snapshot_load( env, 2UL );

  ulong total_stake = run_query_towers( env );

  /* Total stake counts every t-2 entry, valid or not, but only the
     valid vote account is read back and counted as a voter. */
  FD_TEST( total_stake==2UL*VOTER_STAKE );
  FD_TEST( env->ctx->vtr_cnt==1UL );
  FD_TEST( !memcmp( &env->ctx->vote_accs[ 0 ], &good, sizeof(fd_pubkey_t) ) );

  test_env_destroy( env );
  FD_LOG_NOTICE(( "... pass (no abort: the snapshot path refreshes is_valid)" ));
}

/* Close and reincarnate a vote account in the middle of an epoch, after
   the refresh that computed is_valid.  is_valid is only recomputed at
   the next epoch boundary, so query_towers reads back a non-vote
   account and aborts.  Run in a child process as the abort is fatal. */

static void
test_stale_is_valid_mid_epoch( fd_wksp_t * wksp,
                               int         reincarnate ) {
  FD_LOG_NOTICE(( "testing stale is_valid after mid-epoch %s", reincarnate ? "reincarnation" : "close" ));

  /* The child logs the failed assert to stderr before aborting; capture
     it so the test can tell this abort apart from any other one. */

  int pipefd[2];
  FD_TEST( !pipe( pipefd ) );

  pid_t pid = fork();
  FD_TEST( pid>=0 );

  if( !pid ) {
    close( pipefd[ 0 ] );
    FD_TEST( dup2( pipefd[ 1 ], STDERR_FILENO )>=0 );
    close( pipefd[ 1 ] );

    static test_env_t env[1];
    test_env_create( env, wksp );

    fd_pubkey_t voter = vote_key( 0UL );
    put_vote_account( env, &voter, &voter );
    drain_background( env->accdb );

    /* is_valid is computed while the account is still a valid vote
       account. */
    snapshot_load( env, 1UL );

    /* Later in the same epoch the vote account is closed and its
       address is funded again as a plain system account.  Nothing
       recomputes is_valid until the next epoch boundary. */
    new_slot( env );
    if( reincarnate ) put_reincarnated_account( env, &voter );
    else              put_closed_account      ( env, &voter );
    drain_background( env->accdb );

    run_query_towers( env );

    _exit( 0 );
  }

  close( pipefd[ 1 ] );

  static char err[ 65536 ];
  ulong err_len = 0UL;
  for(;;) {
    long n = read( pipefd[ 0 ], err+err_len, sizeof(err)-1UL-err_len );
    if( n<0L && errno==EINTR ) continue;
    if( n<=0L ) break;
    err_len += (ulong)n;
    if( err_len>=sizeof(err)-1UL ) break;
  }
  err[ err_len ] = '\0';
  close( pipefd[ 0 ] );

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );

  int aborted = ( WIFEXITED( status ) && WEXITSTATUS( status )==1 ) ||
                ( WIFSIGNALED( status ) && WTERMSIG( status )==SIGABRT );
  if( FD_UNLIKELY( !aborted ) ) {
    FD_LOG_ERR(( "expected query_towers to abort on a stale is_valid entry, but the child exited with status %i", status ));
  }
  if( FD_UNLIKELY( !strstr( err, "FAIL: accs[ j ].lamports" ) ) ) {
    FD_LOG_ERR(( "child aborted, but not on the expected assert.  stderr was:\n%s", err ));
  }

  FD_LOG_NOTICE(( "... pass (abort reproduced in query_towers)" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 6UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong        page_sz  = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_snapshot_reincarnated_vote_account( wksp );
  test_stale_is_valid_mid_epoch( wksp, 1 /* reincarnate */ );
  test_stale_is_valid_mid_epoch( wksp, 0 /* close       */ );

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
