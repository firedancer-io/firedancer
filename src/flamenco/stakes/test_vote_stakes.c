#include "fd_vote_stakes.h"
#include "fd_vote_stakes_private.h"

int main( int argc, char * argv[] ) {
  (void)argc;
  (void)argv;
  FD_LOG_NOTICE(( "pass" ));

  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_pubkey_t pubkey_A = {.ul = {10}}; (void)pubkey_A;
  fd_pubkey_t pubkey_B = {.ul = {11}}; (void)pubkey_B;
  fd_pubkey_t pubkey_C = {.ul = {12}}; (void)pubkey_C;
  fd_pubkey_t pubkey_D = {.ul = {13}}; (void)pubkey_D;
  fd_pubkey_t pubkey_E = {.ul = {14}}; (void)pubkey_E;
  fd_pubkey_t pubkey_F = {.ul = {15}}; (void)pubkey_F;

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  ulong footprint = fd_vote_stakes_footprint( 16UL, 4, 128UL );

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_vote_stakes_align(), footprint, wksp_tag );
  FD_TEST( mem );

  fd_vote_stakes_t * vote_stakes = fd_vote_stakes_join( fd_vote_stakes_new( mem, 16UL, 16, 128UL, 0UL ) );
  FD_TEST( vote_stakes );
  ushort root_idx = vote_stakes->root_idx; (void)root_idx;

  index_ele_t * index_pool = get_index_pool( vote_stakes );

  fd_vote_stakes_insert_root( vote_stakes, &pubkey_A, 100UL, 200UL );
  fd_vote_stakes_insert_root( vote_stakes, &pubkey_B, 101UL, 200UL );
  fd_vote_stakes_insert_root( vote_stakes, &pubkey_C, 102UL, 200UL );
  fd_vote_stakes_insert_root( vote_stakes, &pubkey_D, 103UL, 200UL );
  fd_vote_stakes_insert_root( vote_stakes, &pubkey_E, 104UL, 200UL );

  FD_TEST( 5U==index_pool_used( index_pool ) );

  ulong stake_t_1;
  ulong stake_t_2;
  fd_vote_stakes_query_stake( vote_stakes, root_idx, &pubkey_A, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 100UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, root_idx, &pubkey_B, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 101UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, root_idx, &pubkey_C, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 102UL ); FD_TEST( stake_t_2 == 200UL );

  ushort idx_1 = fd_vote_stakes_new_child( vote_stakes );
  fd_vote_stakes_insert( vote_stakes, idx_1, &pubkey_A, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_1, &pubkey_B, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_1, &pubkey_C, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_1, &pubkey_D, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_1, &pubkey_E, 301UL, 200UL );
  FD_TEST( 10U==index_pool_used( index_pool ) );

  fd_vote_stakes_query_stake( vote_stakes, idx_1, &pubkey_A, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_1, &pubkey_B, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_1, &pubkey_C, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_1, &pubkey_D, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_1, &pubkey_E, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );

  ushort idx_2 = fd_vote_stakes_new_child( vote_stakes );
  fd_vote_stakes_insert( vote_stakes, idx_2, &pubkey_A, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_2, &pubkey_B, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_2, &pubkey_C, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_2, &pubkey_D, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_2, &pubkey_E, 302UL, 200UL );
  FD_TEST( 11U==index_pool_used( index_pool ) );

  fd_vote_stakes_query_stake( vote_stakes, idx_2, &pubkey_A, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_2, &pubkey_B, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_2, &pubkey_C, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_2, &pubkey_D, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_2, &pubkey_E, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 302UL ); FD_TEST( stake_t_2 == 200UL );

  ushort idx_3 = fd_vote_stakes_new_child( vote_stakes );
  fd_vote_stakes_insert( vote_stakes, idx_3, &pubkey_A, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_3, &pubkey_B, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_3, &pubkey_C, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_3, &pubkey_D, 301UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_3, &pubkey_E, 302UL, 200UL );
  fd_vote_stakes_insert( vote_stakes, idx_3, &pubkey_F, 302UL, 200UL );
  FD_TEST( 12U==index_pool_used( index_pool ) );

  fd_vote_stakes_query_stake( vote_stakes, idx_3, &pubkey_A, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_3, &pubkey_B, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_3, &pubkey_C, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_3, &pubkey_D, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_3, &pubkey_E, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 302UL ); FD_TEST( stake_t_2 == 200UL );
  fd_vote_stakes_query_stake( vote_stakes, idx_3, &pubkey_F, &stake_t_1, &stake_t_2 );
  FD_TEST( stake_t_1 == 302UL ); FD_TEST( stake_t_2 == 200UL );

  fd_vote_stakes_advance_root( vote_stakes, root_idx );
  FD_TEST( 12U==index_pool_used( index_pool ) );

  fd_vote_stakes_advance_root( vote_stakes, idx_1 );
  FD_TEST( 5U==index_pool_used( index_pool ) );

  FD_LOG_NOTICE(( "pass" ));
}
