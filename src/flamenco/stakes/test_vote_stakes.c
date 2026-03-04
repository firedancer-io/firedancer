#include "fd_vote_stakes.h"
#include "fd_vote_stakes_private.h"

int main( int argc, char * argv[] ) {
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

  fd_pubkey_t node_account_t_1 = {.ul = {16}};
  fd_pubkey_t node_account_t_2 = {.ul = {17}};
  fd_pubkey_t node_account_t_1_fork_1 = {.ul = {18}};
  fd_pubkey_t node_account_t_1_fork_2 = {.ul = {19}};
  fd_pubkey_t node_account_t_1_fork_3 = {.ul = {20}};

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  ulong footprint = fd_vote_stakes_footprint( 64UL, 64UL, 16UL );

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_vote_stakes_align(), footprint, wksp_tag );
  FD_TEST( mem );

  fd_vote_stakes_t * vote_stakes = fd_vote_stakes_join( fd_vote_stakes_new( mem, 64UL, 64UL, 16UL, 0UL ) );
  FD_TEST( vote_stakes );
  ushort root_idx = fd_vote_stakes_get_root_idx( vote_stakes );

  index_ele_t * index_pool = get_index_pool( vote_stakes );

  fd_vote_stakes_root_insert_key( vote_stakes, &pubkey_A, &node_account_t_1, 100UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &pubkey_A, &node_account_t_2, 200UL, 0UL );
  fd_vote_stakes_root_insert_key( vote_stakes, &pubkey_B, &node_account_t_1, 101UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &pubkey_B, &node_account_t_2, 200UL, 0UL );
  fd_vote_stakes_root_insert_key( vote_stakes, &pubkey_C, &node_account_t_1, 102UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &pubkey_C, &node_account_t_2, 200UL, 0UL );
  fd_vote_stakes_root_insert_key( vote_stakes, &pubkey_D, &node_account_t_1, 103UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &pubkey_D, &node_account_t_2, 200UL, 0UL );
  fd_vote_stakes_root_insert_key( vote_stakes, &pubkey_E, &node_account_t_1, 104UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &pubkey_E, &node_account_t_2, 200UL, 0UL );

  FD_TEST( 5U==index_pool_used( index_pool ) );
  FD_TEST( 5U==fd_vote_stakes_ele_cnt( vote_stakes, root_idx ) );

  ulong stake_t_1;
  ulong stake_t_2;
  fd_pubkey_t node_account_t_1_out;
  fd_pubkey_t node_account_t_2_out;
  FD_TEST( fd_vote_stakes_query( vote_stakes, root_idx, &pubkey_A, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 100UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, root_idx, &pubkey_B, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 101UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, root_idx, &pubkey_C, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 102UL ); FD_TEST( stake_t_2 == 200UL );

  /* root_purge_key should remove the key from root */
  fd_vote_stakes_root_purge_key( vote_stakes, &pubkey_D );
  FD_TEST( !fd_vote_stakes_query( vote_stakes, root_idx, &pubkey_D, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( 4U==fd_vote_stakes_ele_cnt( vote_stakes, root_idx ) );
  FD_TEST( 4U==index_pool_used( index_pool ) );

  /* Reinsert D so subsequent fork-count assertions stay stable */
  fd_vote_stakes_root_insert_key( vote_stakes, &pubkey_D, &node_account_t_1, 103UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &pubkey_D, &node_account_t_2, 200UL, 0UL );
  FD_TEST( 5U==index_pool_used( index_pool ) );

  ushort idx_1 = fd_vote_stakes_new_child( vote_stakes );
  fd_vote_stakes_insert_key( vote_stakes, idx_1, &pubkey_A, &node_account_t_1_fork_1, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_1, &pubkey_A, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_1, &pubkey_B, &node_account_t_1_fork_1, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_1, &pubkey_B, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_1, &pubkey_C, &node_account_t_1_fork_1, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_1, &pubkey_C, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_1, &pubkey_D, &node_account_t_1_fork_1, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_1, &pubkey_D, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_1, &pubkey_E, &node_account_t_1_fork_1, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_1, &pubkey_E, 301UL );
  fd_vote_stakes_insert_fini( vote_stakes, idx_1 );
  FD_TEST( 10U==index_pool_used( index_pool ) );
  FD_TEST( 5U==fd_vote_stakes_ele_cnt( vote_stakes, idx_1 ) );

  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_1, &pubkey_A, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_1, &pubkey_B, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_1, &pubkey_C, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_1, &pubkey_D, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_1, &pubkey_E, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );

  ushort idx_2 = fd_vote_stakes_new_child( vote_stakes );
  fd_vote_stakes_insert_key( vote_stakes, idx_2, &pubkey_A, &node_account_t_1_fork_2, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_2, &pubkey_A, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_2, &pubkey_B, &node_account_t_1_fork_2, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_2, &pubkey_B, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_2, &pubkey_C, &node_account_t_1_fork_2, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_2, &pubkey_C, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_2, &pubkey_D, &node_account_t_1_fork_2, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_2, &pubkey_D, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_2, &pubkey_E, &node_account_t_1_fork_2, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_2, &pubkey_E, 302UL );
  fd_vote_stakes_insert_fini( vote_stakes, idx_2 );
  FD_TEST( 15U==index_pool_used( index_pool ) );
  FD_TEST( 5U==fd_vote_stakes_ele_cnt( vote_stakes, idx_2 ) );

  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_2, &pubkey_A, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_2, &pubkey_B, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_2, &pubkey_C, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_2, &pubkey_D, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_2, &pubkey_E, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 302UL ); FD_TEST( stake_t_2 == 200UL );

  ushort idx_3 = fd_vote_stakes_new_child( vote_stakes );
  fd_vote_stakes_insert_key( vote_stakes, idx_3, &pubkey_A, &node_account_t_1_fork_3, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_3, &pubkey_A, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_3, &pubkey_B, &node_account_t_1_fork_3, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_3, &pubkey_B, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_3, &pubkey_C, &node_account_t_1_fork_3, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_3, &pubkey_C, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_3, &pubkey_D, &node_account_t_1_fork_3, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_3, &pubkey_D, 301UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_3, &pubkey_E, &node_account_t_1_fork_3, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_3, &pubkey_E, 302UL );
  fd_vote_stakes_insert_key( vote_stakes, idx_3, &pubkey_F, &node_account_t_1_fork_3, &node_account_t_2, 200UL, 0UL ); fd_vote_stakes_insert_update( vote_stakes, idx_3, &pubkey_F, 302UL );
  fd_vote_stakes_insert_fini( vote_stakes, idx_3 );
  FD_TEST( 21U==index_pool_used( index_pool ) );
  FD_TEST( 6U==fd_vote_stakes_ele_cnt( vote_stakes, idx_3 ) );

  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_3, &pubkey_A, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_3, &pubkey_B, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_3, &pubkey_C, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_3, &pubkey_D, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 301UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_3, &pubkey_E, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 302UL ); FD_TEST( stake_t_2 == 200UL );
  FD_TEST( fd_vote_stakes_query( vote_stakes, idx_3, &pubkey_F, &stake_t_1, &stake_t_2, &node_account_t_1_out, &node_account_t_2_out ) );
  FD_TEST( stake_t_1 == 302UL ); FD_TEST( stake_t_2 == 200UL );

  /* basic iterator smoke test */
  {
    uint seen = 0U;
    uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_fork_iter_init( vote_stakes, idx_3, iter_mem );
         !fd_vote_stakes_fork_iter_done( vote_stakes, idx_3, iter );
         fd_vote_stakes_fork_iter_next( vote_stakes, idx_3, iter ) ) {
      fd_pubkey_t iter_pubkey;
      fd_vote_stakes_fork_iter_ele( vote_stakes, idx_3, iter, &iter_pubkey, NULL, NULL, NULL, NULL );
      seen++;
    }
    FD_TEST( seen==6U );
  }

  fd_vote_stakes_advance_root( vote_stakes, root_idx );
  FD_TEST( 21U==index_pool_used( index_pool ) );

  fd_vote_stakes_advance_root( vote_stakes, idx_1 );
  FD_TEST( 5U==index_pool_used( index_pool ) );
  FD_TEST( fd_vote_stakes_get_root_idx( vote_stakes )==idx_1 );

  fd_vote_stakes_reset( vote_stakes );
  FD_TEST( 0U==index_pool_used( index_pool ) );
  FD_TEST( 0U==fd_vote_stakes_ele_cnt( vote_stakes, fd_vote_stakes_get_root_idx( vote_stakes ) ) );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
