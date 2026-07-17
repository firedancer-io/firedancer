#include "fd_top_votes_v2.h"
#include "../../util/fd_util.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static fd_pubkey_t
test_pubkey( ulong id ) {
  fd_pubkey_t key = {0};
  memcpy( key.uc, &id, sizeof(id) );
  return key;
}

static void
assert_t_1_present( fd_top_votes_v2_t const * top_votes,
                    ulong                     child_idx,
                    fd_pubkey_t const *        pubkey,
                    fd_pubkey_t const *        node_account,
                    ulong                     stake,
                    ushort                    commission ) {
  fd_pubkey_t node_account_out;
  ulong       stake_out;
  ushort      commission_out;
  FD_TEST( fd_top_votes_v2_query_t_1( top_votes,
                                      child_idx,
                                      pubkey,
                                      &node_account_out,
                                      &stake_out,
                                      &commission_out ) );
  FD_TEST( !memcmp( &node_account_out, node_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_out==stake );
  FD_TEST( commission_out==commission );
}

static void
assert_t_1_absent( fd_top_votes_v2_t const * top_votes,
                   ulong                     child_idx,
                   fd_pubkey_t const *        pubkey ) {
  FD_TEST( !fd_top_votes_v2_query_t_1( top_votes, child_idx, pubkey, NULL, NULL, NULL ) );
}

typedef void (*invalid_lifecycle_fn_t)( fd_top_votes_v2_t * top_votes );

static void
reopen_completed_empty_group( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_insert_init( top_votes, 0UL );
  fd_top_votes_v2_insert_fini( top_votes );
  fd_top_votes_v2_insert_init( top_votes, 0UL );
}

static void
share_fresh_group( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_new_child( top_votes, 0UL, 1UL );
}

static void
rotate_fresh_group( fd_top_votes_v2_t * top_votes ) {
  fd_top_votes_v2_new_epoch_child( top_votes, 0UL, 1UL );
}

static void
assert_lifecycle_rejected( fd_top_votes_v2_t *  top_votes,
                           invalid_lifecycle_fn_t action ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_enable_unclean_exit();
    fd_log_level_logfile_set( 5 );
    fd_log_level_stderr_set( 5 );
    action( top_votes );
    _exit( 0 );
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  FD_TEST( WEXITSTATUS( status )==1 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong const max_fork_width = 3UL;
  ulong const max_live_banks = 4UL;
  ulong const align          = fd_top_votes_v2_align();
  ulong const footprint      = fd_top_votes_v2_footprint( max_fork_width, max_live_banks );

  FD_TEST( align );
  FD_TEST( footprint );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );
  FD_TEST( !fd_top_votes_v2_footprint( 0UL,           max_live_banks ) );
  FD_TEST( !fd_top_votes_v2_footprint( max_fork_width, 0UL            ) );
  FD_TEST( !fd_top_votes_v2_new( NULL, max_fork_width, max_live_banks, 1234UL ) );

  void * mem = aligned_alloc( align, footprint );
  FD_TEST( mem );
  fd_top_votes_v2_t * top_votes = fd_top_votes_v2_join(
      fd_top_votes_v2_new( mem, max_fork_width, max_live_banks, 1234UL ) );
  FD_TEST( top_votes );

  assert_lifecycle_rejected( top_votes, reopen_completed_empty_group );
  assert_lifecycle_rejected( top_votes, share_fresh_group );
  assert_lifecycle_rejected( top_votes, rotate_fresh_group );

  fd_pubkey_t vote_a = test_pubkey( 1UL );
  fd_pubkey_t node_a = test_pubkey( 101UL );
  fd_pubkey_t vote_b = test_pubkey( 2UL );
  fd_pubkey_t node_b = test_pubkey( 102UL );

  fd_top_votes_v2_insert_init( top_votes, 0UL );
  fd_top_votes_v2_insert( top_votes, &vote_a, &node_a, 10UL, 1U );
  fd_top_votes_v2_insert( top_votes, &vote_b, &node_b, 20UL, 2U );
  fd_top_votes_v2_insert_fini( top_votes );

  assert_t_1_present( top_votes, 0UL, &vote_a, &node_a, 10UL, 1U );
  assert_t_1_present( top_votes, 0UL, &vote_b, &node_b, 20UL, 2U );
  assert_t_1_absent(  top_votes, 0UL, &node_a );

  fd_top_votes_v2_new_child( top_votes, 0UL, 1UL );
  assert_t_1_present( top_votes, 1UL, &vote_a, &node_a, 10UL, 1U );

  /* All persisted references are offsets, so copying the complete object
     to a different address must preserve a valid join. */

  void * relocated = aligned_alloc( align, footprint );
  FD_TEST( relocated );
  memcpy( relocated, mem, footprint );
  FD_TEST( fd_top_votes_v2_join( relocated ) );
  FD_TEST( !fd_top_votes_v2_join( (uchar *)relocated+1UL ) );

  free( relocated );
  free( mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
