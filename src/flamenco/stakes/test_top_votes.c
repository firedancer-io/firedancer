#include "fd_top_votes.h"
#include "../runtime/fd_runtime_const.h"

static void
assert_vote_present( fd_top_votes_t *    top_votes,
                     fd_pubkey_t const * vote_pubkey,
                     fd_pubkey_t const * expected_node,
                     ulong               expected_stake ) {
  fd_pubkey_t node_out = {0};
  ulong       stake_out = 0UL;
  ulong       slot_out = 0UL;
  long        timestamp_out = 0L;
  FD_TEST( fd_top_votes_query( top_votes, vote_pubkey, &node_out, &stake_out, &slot_out, &timestamp_out ) );
  FD_TEST( !memcmp( &node_out, expected_node, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_out==expected_stake );
  FD_TEST( slot_out==expected_stake );
  FD_TEST( timestamp_out==(long)expected_stake );
}

static void
assert_vote_absent( fd_top_votes_t *    top_votes,
                    fd_pubkey_t const * vote_pubkey ) {
  FD_TEST( !fd_top_votes_query( top_votes, vote_pubkey, NULL, NULL, NULL, NULL ) );
}

int
main( int argc, char * argv[] ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_pubkey_t vote_A = { .ul = { 101UL } };
  fd_pubkey_t vote_B = { .ul = { 102UL } };
  fd_pubkey_t vote_C = { .ul = { 103UL } };
  fd_pubkey_t vote_D = { .ul = { 104UL } };
  fd_pubkey_t vote_E = { .ul = { 105UL } };
  fd_pubkey_t vote_F = { .ul = { 106UL } };
  fd_pubkey_t vote_G = { .ul = { 107UL } };
  fd_pubkey_t vote_H = { .ul = { 108UL } };
  fd_pubkey_t vote_I = { .ul = { 109UL } };
  fd_pubkey_t vote_J = { .ul = { 110UL } };
  fd_pubkey_t vote_K = { .ul = { 111UL } };
  fd_pubkey_t vote_L = { .ul = { 112UL } };
  fd_pubkey_t vote_M = { .ul = { 113UL } };

  fd_pubkey_t node_A = { .ul = { 201UL } };
  fd_pubkey_t node_B = { .ul = { 202UL } };
  fd_pubkey_t node_C = { .ul = { 203UL } };
  fd_pubkey_t node_D = { .ul = { 204UL } };
  fd_pubkey_t node_E = { .ul = { 205UL } };
  fd_pubkey_t node_F = { .ul = { 206UL } };
  fd_pubkey_t node_G = { .ul = { 207UL } };
  fd_pubkey_t node_H = { .ul = { 208UL } };
  fd_pubkey_t node_I = { .ul = { 209UL } };
  fd_pubkey_t node_J = { .ul = { 210UL } };
  fd_pubkey_t node_K = { .ul = { 211UL } };
  fd_pubkey_t node_L = { .ul = { 212UL } };
  fd_pubkey_t node_M = { .ul = { 213UL } };

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  ushort const vote_accounts_max = 4UL;
  ulong  const footprint         = fd_top_votes_footprint( vote_accounts_max );

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_top_votes_align(), footprint, wksp_tag );
  FD_TEST( mem );

  FD_TEST( fd_top_votes_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) <= FD_TOP_VOTES_MAX_FOOTPRINT );

  FD_TEST( !fd_top_votes_new( NULL, vote_accounts_max, 0UL ) );
  fd_top_votes_t * top_votes = fd_top_votes_join( fd_top_votes_new( mem, vote_accounts_max, 1234UL ) );
  FD_TEST( top_votes );

  fd_top_votes_init( top_votes );

  /* Basic insertion and query */
  fd_top_votes_insert( top_votes, &vote_A, &node_A, 10UL, 10UL, 10L );
  fd_top_votes_insert( top_votes, &vote_B, &node_B, 20UL, 20UL, 20L );
  fd_top_votes_insert( top_votes, &vote_C, &node_C, 30UL, 30UL, 30L );
  fd_top_votes_insert( top_votes, &vote_D, &node_D, 40UL, 40UL, 40L );
  assert_vote_present( top_votes, &vote_A, &node_A, 10UL );
  assert_vote_present( top_votes, &vote_B, &node_B, 20UL );
  assert_vote_present( top_votes, &vote_C, &node_C, 30UL );
  assert_vote_present( top_votes, &vote_D, &node_D, 40UL );
  assert_vote_absent( top_votes, &vote_E );
  FD_TEST( fd_top_votes_query( top_votes, &vote_A, NULL, NULL, NULL, NULL ) );

  /* Iterator returns all valid top vote entries. */
  ulong iter_stake_sum = 0UL;
  ulong iter_cnt       = 0UL;
  uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) top_votes_iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];
  for( fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes, top_votes_iter_mem, 0 );
       !fd_top_votes_iter_done( top_votes, iter );
       fd_top_votes_iter_next( top_votes, iter, 0 ) ) {
    fd_pubkey_t iter_pubkey;
    ulong       iter_stake;
    fd_top_votes_iter_ele( top_votes, iter, &iter_pubkey, NULL, &iter_stake, NULL, NULL );
    iter_stake_sum += iter_stake;
    iter_cnt++;
    FD_TEST( fd_top_votes_query( top_votes, &iter_pubkey, NULL, NULL, NULL, NULL ) );
  }
  FD_TEST( iter_cnt==4UL );
  FD_TEST( iter_stake_sum==(10UL+20UL+30UL+40UL) );

  /* When full, lower-than-min stakes are ignored. */
  fd_top_votes_insert( top_votes, &vote_E, &node_E, 5UL, 5UL, 5L );
  assert_vote_absent( top_votes, &vote_E );
  assert_vote_present( top_votes, &vote_A, &node_A, 10UL );

  /* When full and no min tie exists, only the minimum stake is evicted. */
  fd_top_votes_insert( top_votes, &vote_E, &node_E, 50UL, 50UL, 50L );
  assert_vote_absent( top_votes, &vote_A );
  assert_vote_present( top_votes, &vote_B, &node_B, 20UL );
  assert_vote_present( top_votes, &vote_C, &node_C, 30UL );
  assert_vote_present( top_votes, &vote_D, &node_D, 40UL );
  assert_vote_present( top_votes, &vote_E, &node_E, 50UL );

  /* Tied minimum entries are all evicted when a higher stake arrives. */
  fd_top_votes_init( top_votes );
  fd_top_votes_insert( top_votes, &vote_A, &node_A, 10UL, 10UL, 10L );
  fd_top_votes_insert( top_votes, &vote_B, &node_B, 10UL, 10UL, 10L );
  fd_top_votes_insert( top_votes, &vote_C, &node_C, 20UL, 20UL, 20L );
  fd_top_votes_insert( top_votes, &vote_D, &node_D, 30UL, 30UL, 30L );
  fd_top_votes_insert( top_votes, &vote_E, &node_E, 40UL, 40UL, 40L );
  assert_vote_absent( top_votes, &vote_A );
  assert_vote_absent( top_votes, &vote_B );
  assert_vote_present( top_votes, &vote_C, &node_C, 20UL );
  assert_vote_present( top_votes, &vote_D, &node_D, 30UL );
  assert_vote_present( top_votes, &vote_E, &node_E, 40UL );

  /* If a candidate stake ties the minimum when full, all min entries are removed,
     no new entry is inserted, and that stake is permanently watermarked. */
  fd_top_votes_init( top_votes );
  fd_top_votes_insert( top_votes, &vote_A, &node_A, 10UL, 10UL, 10L );
  fd_top_votes_insert( top_votes, &vote_B, &node_B, 10UL, 10UL, 10L );
  fd_top_votes_insert( top_votes, &vote_C, &node_C, 20UL, 20UL, 20L );
  fd_top_votes_insert( top_votes, &vote_D, &node_D, 30UL, 30UL, 30L );
  fd_top_votes_insert( top_votes, &vote_E, &node_E, 10UL, 10UL, 10L );
  assert_vote_absent( top_votes, &vote_A );
  assert_vote_absent( top_votes, &vote_B );
  assert_vote_absent( top_votes, &vote_E );
  assert_vote_present( top_votes, &vote_C, &node_C, 20UL );
  assert_vote_present( top_votes, &vote_D, &node_D, 30UL );

  /* Watermark behavior: <= watermark is ignored, > watermark is allowed. */
  fd_top_votes_insert( top_votes, &vote_F, &node_F, 10UL, 10UL, 10L );
  fd_top_votes_insert( top_votes, &vote_G, &node_G, 9UL, 9UL, 9L );
  assert_vote_absent( top_votes, &vote_F );
  assert_vote_absent( top_votes, &vote_G );

  fd_top_votes_insert( top_votes, &vote_H, &node_H, 11UL, 11UL, 11L );
  assert_vote_present( top_votes, &vote_H, &node_H, 11UL );

  /* Iterator should skip invalid entries. */
  fd_top_votes_invalidate( top_votes, &vote_H );
  FD_TEST( !fd_top_votes_query( top_votes, &vote_H, NULL, NULL, NULL, NULL ) );
  FD_TEST( fd_top_votes_query( top_votes, &vote_C, NULL, NULL, NULL, NULL ) );
  FD_TEST( fd_top_votes_query( top_votes, &vote_D, NULL, NULL, NULL, NULL ) );
  ulong valid_iter_cnt = 0UL;
  for( fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes, top_votes_iter_mem, 0 );
       !fd_top_votes_iter_done( top_votes, iter );
       fd_top_votes_iter_next( top_votes, iter, 0 ) ) {
    fd_pubkey_t iter_pubkey;
    fd_top_votes_iter_ele( top_votes, iter, &iter_pubkey, NULL, NULL, NULL, NULL );
    FD_TEST( memcmp( &iter_pubkey, &vote_H, sizeof(fd_pubkey_t) ) );
    valid_iter_cnt++;
  }
  FD_TEST( valid_iter_cnt==2UL );

  /* Watermark should advance if another "tie with current min when full" occurs. */
  fd_top_votes_insert( top_votes, &vote_I, &node_I, 25UL, 25UL, 25L ); /* now full */
  fd_top_votes_insert( top_votes, &vote_J, &node_J, 11UL, 11UL, 11L ); /* ties current min */
  assert_vote_absent( top_votes, &vote_H );
  assert_vote_absent( top_votes, &vote_J );
  assert_vote_present( top_votes, &vote_C, &node_C, 20UL );
  assert_vote_present( top_votes, &vote_D, &node_D, 30UL );
  assert_vote_present( top_votes, &vote_I, &node_I, 25UL );

  fd_top_votes_insert( top_votes, &vote_K, &node_K, 11UL, 11UL, 11L );
  assert_vote_absent( top_votes, &vote_K );

  fd_top_votes_insert( top_votes, &vote_L, &node_L, 12UL, 12UL, 12L );
  assert_vote_present( top_votes, &vote_L, &node_L, 12UL );

  /* init should reset both membership and watermark. */
  fd_top_votes_init( top_votes );
  assert_vote_absent( top_votes, &vote_C );
  fd_top_votes_insert( top_votes, &vote_M, &node_M, 11UL, 11UL, 11L );
  assert_vote_present( top_votes, &vote_M, &node_M, 11UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
