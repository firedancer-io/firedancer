#include "fd_vote_timestamps.h"
#include "fd_vote_timestamps_private.h"

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_pubkey_t pubkey_A = {.ul = {0}};
  fd_pubkey_t pubkey_B = {.ul = {1}};
  fd_pubkey_t pubkey_C = {.ul = {2}};
  fd_pubkey_t pubkey_D = {.ul = {3}};
  fd_pubkey_t pubkey_E = {.ul = {4}};
  fd_pubkey_t pubkey_F = {.ul = {5}}; (void)pubkey_F;
  fd_pubkey_t pubkey_G = {.ul = {6}}; (void)pubkey_G;
  fd_pubkey_t pubkey_H = {.ul = {7}}; (void)pubkey_H;

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  ulong footprint = fd_vote_timestamps_footprint( 16UL, 4, 128UL );
  FD_LOG_NOTICE(( "footprint: %lu", footprint ));

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_vote_timestamps_align(), footprint, wksp_tag );
  FD_TEST( mem );


  fd_vote_timestamps_t * vote_timestamps = fd_vote_timestamps_join( fd_vote_timestamps_new( mem, 16UL, 4, 128UL, 0UL ) );
  FD_TEST( vote_timestamps );

  fork_ele_t * fork_pool = fd_vote_timestamps_get_fork_pool( vote_timestamps );

  ushort root_idx = fd_vote_timestamps_init( vote_timestamps, 0UL, 0 );
  FD_TEST( root_idx==0 );

  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_A, 10, 100UL );
  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_B, 10, 200UL );
  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_C, 10, 300UL );
  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_D, 10, 400UL );
  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_E, 10, 500UL );

  FD_TEST( 5U==index_pool_used(fd_vote_timestamps_get_index_pool( vote_timestamps ) ) );
  fork_ele_t * root = fork_pool_ele( fork_pool, vote_timestamps->root_idx );
  FD_TEST( root->deltas_cnt==0 );
  FD_TEST( root->snapshot_idx!=UCHAR_MAX );
  FD_TEST( root->parent_idx==USHORT_MAX );
  FD_TEST( root->child_idx==USHORT_MAX );
  FD_TEST( root->sibling_idx==USHORT_MAX );

  ushort child_idx = fd_vote_timestamps_attach_child( vote_timestamps, root_idx, 1UL, 0 );
  fd_vote_timestamps_insert( vote_timestamps, child_idx, pubkey_A, 11, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx, pubkey_B, 11, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx, pubkey_C, 11, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx, pubkey_D, 11, 0UL );
  FD_TEST( 5U==index_pool_used(fd_vote_timestamps_get_index_pool( vote_timestamps ) ) );
  fork_ele_t * child_fork = fork_pool_ele( fork_pool, child_idx );
  FD_TEST( child_fork->deltas_cnt==4 );
  FD_TEST( root->child_idx==child_idx );
  FD_TEST( child_fork->parent_idx==root_idx );
  FD_TEST( child_fork->child_idx==USHORT_MAX );
  FD_TEST( child_fork->sibling_idx==USHORT_MAX );
  FD_TEST( root->snapshot_idx!=UCHAR_MAX );
  fd_vote_timestamps_get_timestamp( vote_timestamps, child_idx );
  snapshot_ele_t * snapshot = fd_vote_timestamps_get_snapshot( vote_timestamps, child_fork->snapshot_idx );
  snapshot_map_t * snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_timestamps, child_fork->snapshot_idx );

  ulong t_10_cnt = 0UL;
  ulong t_11_cnt = 0UL;
  for( snapshot_map_iter_t iter = snapshot_map_iter_init( snapshot_map, snapshot );
       !snapshot_map_iter_done( iter, snapshot_map, snapshot );
       iter = snapshot_map_iter_next( iter, snapshot_map, snapshot ) ) {
    snapshot_ele_t * ele = snapshot_map_iter_ele( iter, snapshot_map, snapshot );
    if( ele->timestamp==10 )      t_10_cnt++;
    else if( ele->timestamp==11 ) t_11_cnt++;
    else FD_TEST( 0 );
  }
  FD_TEST( t_10_cnt==1 );
  FD_TEST( t_11_cnt==4 );


  ushort child_idx2 = fd_vote_timestamps_attach_child( vote_timestamps, child_idx, 2UL, 0 );
  fd_vote_timestamps_insert( vote_timestamps, child_idx2, pubkey_F, 11, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx2, pubkey_A, 15, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx2, pubkey_B, 15, 0UL );
  FD_TEST( 6U==index_pool_used(fd_vote_timestamps_get_index_pool( vote_timestamps ) ) );
  fd_vote_timestamps_get_timestamp( vote_timestamps, child_idx2 );
  fork_ele_t * child_fork2 = fork_pool_ele( fork_pool, child_idx2 );
  FD_TEST( child_fork->child_idx==child_idx2 );
  FD_TEST( child_fork2->parent_idx==child_idx );
  FD_TEST( child_fork2->child_idx==USHORT_MAX );
  FD_TEST( child_fork2->sibling_idx==USHORT_MAX );
  FD_TEST( child_fork2->deltas_cnt==3 );
  FD_TEST( root->snapshot_idx!=UCHAR_MAX );
  snapshot = fd_vote_timestamps_get_snapshot( vote_timestamps, child_fork2->snapshot_idx );
  snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_timestamps, child_fork2->snapshot_idx );
  t_10_cnt = 0UL;
  t_11_cnt = 0UL;
  ulong t_15_cnt = 0UL;
  for( snapshot_map_iter_t iter = snapshot_map_iter_init( snapshot_map, snapshot );
       !snapshot_map_iter_done( iter, snapshot_map, snapshot );
       iter = snapshot_map_iter_next( iter, snapshot_map, snapshot ) ) {
    snapshot_ele_t * ele = snapshot_map_iter_ele( iter, snapshot_map, snapshot );
    if( ele->timestamp==10 )      t_10_cnt++;
    else if( ele->timestamp==11 ) t_11_cnt++;
    else if( ele->timestamp==15 ) t_15_cnt++;
    else FD_TEST( 0 );
  }
  FD_TEST( t_10_cnt==1 );
  FD_TEST( t_11_cnt==3 );
  FD_TEST( t_15_cnt==2 );

  ushort child_idx3 = fd_vote_timestamps_attach_child( vote_timestamps, child_idx, 3UL, 0 );
  fd_vote_timestamps_insert( vote_timestamps, child_idx3, pubkey_F, 11, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx3, pubkey_A, 15, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx3, pubkey_B, 15, 0UL );
  FD_TEST( 6U==index_pool_used(fd_vote_timestamps_get_index_pool( vote_timestamps ) ) );
  fd_vote_timestamps_get_timestamp( vote_timestamps, child_idx3 );
  fork_ele_t * child_fork3 = fork_pool_ele( fork_pool, child_idx3 );
  FD_TEST( child_fork->child_idx==child_idx2 );
  FD_TEST( child_fork2->sibling_idx==child_idx3 );
  FD_TEST( child_fork3->parent_idx==child_idx );
  FD_TEST( child_fork3->child_idx==USHORT_MAX );
  FD_TEST( child_fork3->sibling_idx==USHORT_MAX );
  FD_TEST( child_fork3->deltas_cnt==3 );
  FD_TEST( root->snapshot_idx!=UCHAR_MAX );
  snapshot = fd_vote_timestamps_get_snapshot( vote_timestamps, child_fork3->snapshot_idx );
  snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_timestamps, child_fork3->snapshot_idx );
  t_10_cnt = 0UL;
  t_11_cnt = 0UL;
  t_15_cnt = 0UL;
  for( snapshot_map_iter_t iter = snapshot_map_iter_init( snapshot_map, snapshot );
       !snapshot_map_iter_done( iter, snapshot_map, snapshot );
       iter = snapshot_map_iter_next( iter, snapshot_map, snapshot ) ) {
    snapshot_ele_t * ele = snapshot_map_iter_ele( iter, snapshot_map, snapshot );
    if( ele->timestamp==10 )      t_10_cnt++;
    else if( ele->timestamp==11 ) t_11_cnt++;
    else if( ele->timestamp==15 ) t_15_cnt++;
    else FD_TEST( 0 );
  }
  FD_TEST( t_10_cnt==1 );
  FD_TEST( t_11_cnt==3 );
  FD_TEST( t_15_cnt==2 );

  /* Make sure the eviction policy is working.  At this point we expect
     LRU eviction to kick in excluding the root and the best option.
     In this case the best option is child_idx_2, so we expect child_idx
     to have its snapshot evicted. */
  ushort child_idx4 = fd_vote_timestamps_attach_child( vote_timestamps, child_idx2, 4UL, 0 );
  fd_vote_timestamps_insert( vote_timestamps, child_idx4, pubkey_C, 16, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx4, pubkey_A, 15, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx4, pubkey_B, 15, 0UL );
  fd_vote_timestamps_get_timestamp( vote_timestamps, child_idx4 );
  fork_ele_t * child_fork4 = fork_pool_ele( fork_pool, child_idx4 );
  FD_TEST( child_fork4->parent_idx==child_idx2 );
  FD_TEST( child_fork4->snapshot_idx!=UCHAR_MAX );
  FD_TEST( child_fork->snapshot_idx==UCHAR_MAX );
  FD_TEST( child_fork4->deltas_cnt==3 );
  FD_TEST( root->snapshot_idx!=UCHAR_MAX );
  t_10_cnt = 0UL;
  t_11_cnt = 0UL;
  t_15_cnt = 0UL;
  ulong t_16_cnt = 0UL;
  snapshot = fd_vote_timestamps_get_snapshot( vote_timestamps, child_fork4->snapshot_idx );
  snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_timestamps, child_fork4->snapshot_idx );
  for( snapshot_map_iter_t iter = snapshot_map_iter_init( snapshot_map, snapshot );
       !snapshot_map_iter_done( iter, snapshot_map, snapshot );
       iter = snapshot_map_iter_next( iter, snapshot_map, snapshot ) ) {
    snapshot_ele_t * ele = snapshot_map_iter_ele( iter, snapshot_map, snapshot );
    if( ele->timestamp==10 ) t_10_cnt++;
    else if( ele->timestamp==11 ) t_11_cnt++;
    else if( ele->timestamp==15 ) t_15_cnt++;
    else if( ele->timestamp==16 ) t_16_cnt++;
    else FD_TEST( 0 );
  }
  FD_TEST( t_10_cnt==1 );
  FD_TEST( t_11_cnt==2 );
  FD_TEST( t_15_cnt==2 );
  FD_TEST( t_16_cnt==1 );

  /* Now try to make a child off of child_idx and see if the skipped
     delta gets applied correctly.  We also should expect to see
     child_idx2's snapshot to be evicted.  Make sure that the root's
     snapshot idx does not get evicted. */

  ushort child_idx5 = fd_vote_timestamps_attach_child( vote_timestamps, child_idx, 5UL, 0 );
  fd_vote_timestamps_insert( vote_timestamps, child_idx5, pubkey_A, 20, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx5, pubkey_B, 20, 0UL );
  fd_vote_timestamps_insert( vote_timestamps, child_idx5, pubkey_C, 20, 0UL );
  fd_vote_timestamps_get_timestamp( vote_timestamps, child_idx5 );

  fork_ele_t * child_fork5 = fork_pool_ele( fork_pool, child_idx5 );
  FD_TEST( child_fork2->snapshot_idx==UCHAR_MAX );
  FD_TEST( root->snapshot_idx!=UCHAR_MAX );
  FD_TEST( child_fork5->snapshot_idx!=UCHAR_MAX );

  ulong t_20_cnt = 0UL;
  t_11_cnt = 0UL;
  t_10_cnt = 0UL;
  snapshot = fd_vote_timestamps_get_snapshot( vote_timestamps, child_fork5->snapshot_idx );
  snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_timestamps, child_fork5->snapshot_idx );
  for( snapshot_map_iter_t iter = snapshot_map_iter_init( snapshot_map, snapshot );
       !snapshot_map_iter_done( iter, snapshot_map, snapshot );
       iter = snapshot_map_iter_next( iter, snapshot_map, snapshot ) ) {
    snapshot_ele_t * ele = snapshot_map_iter_ele( iter, snapshot_map, snapshot );
    if( ele->timestamp==20 ) t_20_cnt++;
    else if( ele->timestamp==11 ) t_11_cnt++;
    else if( ele->timestamp==10 ) t_10_cnt++;
    else FD_TEST( 0 );
  }
  FD_TEST( t_20_cnt==3 );
  FD_TEST( t_11_cnt==1 );
  FD_TEST( t_10_cnt==1 );

  ushort child_idx6 = fd_vote_timestamps_attach_child( vote_timestamps, child_idx2, 6UL, 0 );
  fd_vote_timestamps_get_timestamp( vote_timestamps, child_idx6 );
  FD_TEST( child_fork3->snapshot_idx==UCHAR_MAX );
  FD_TEST( root->snapshot_idx!=UCHAR_MAX );

  /* Advance the root to a node that does not have a snapshot: in this
     case move to child_idx.  This node also has no siblings so only
     the old root will get pruned. */
  fd_vote_timestamps_advance_root( vote_timestamps, child_idx );
  /* TODO: Asserts here.  Make sure that the values in the snapshot are
     what we expect them to be.  Also validate the fork structure at
     this point. */
  fork_ele_t * new_root = fork_pool_ele( fork_pool, vote_timestamps->root_idx );
  FD_TEST( new_root->deltas_cnt==0 );
  FD_TEST( new_root->snapshot_idx!=UCHAR_MAX );
  snapshot = fd_vote_timestamps_get_snapshot( vote_timestamps, new_root->snapshot_idx );
  snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_timestamps, new_root->snapshot_idx );
  ulong ts_10_cnt = 0UL;
  ulong ts_11_cnt = 0UL;
  for( snapshot_map_iter_t iter = snapshot_map_iter_init( snapshot_map, snapshot );
       !snapshot_map_iter_done( iter, snapshot_map, snapshot );
       iter = snapshot_map_iter_next( iter, snapshot_map, snapshot ) ) {
    snapshot_ele_t * ele = snapshot_map_iter_ele( iter, snapshot_map, snapshot );
    FD_TEST( ele->timestamp==10 || ele->timestamp==11 );
    if( ele->timestamp==10 ) ts_10_cnt++;
    else ts_11_cnt++;
  }
  FD_TEST( ts_10_cnt==1 );
  FD_TEST( ts_11_cnt==4 );

  /* Now try advancing the root to the child_idx5 which has a snapshot.
     Also now every other element in the tree will be pruned. */
  fd_vote_timestamps_advance_root( vote_timestamps, child_idx5 );
  new_root = fork_pool_ele( fork_pool, vote_timestamps->root_idx );
  FD_TEST( new_root->deltas_cnt==0 );
  FD_TEST( new_root->snapshot_idx!=UCHAR_MAX );
  FD_TEST( fork_pool_used( fork_pool )==1 );

  snapshot_key_ele_t * snapshot_keys_pool = fd_vote_timestamps_get_snapshot_keys_pool( vote_timestamps );
  FD_TEST( snapshot_key_pool_used( snapshot_keys_pool )==1 );
  /* Make sure pubkey_F is pruned from the index. */
  FD_TEST( 5U==index_pool_used(fd_vote_timestamps_get_index_pool( vote_timestamps ) ) );
  snapshot = fd_vote_timestamps_get_snapshot( vote_timestamps, new_root->snapshot_idx );
  snapshot_map = fd_vote_timestamps_get_snapshot_map( vote_timestamps, new_root->snapshot_idx );

  t_20_cnt = 0UL;
  t_11_cnt = 0UL;
  t_10_cnt = 0UL;
  for( snapshot_map_iter_t iter = snapshot_map_iter_init( snapshot_map, snapshot );
       !snapshot_map_iter_done( iter, snapshot_map, snapshot );
       iter = snapshot_map_iter_next( iter, snapshot_map, snapshot ) ) {
    snapshot_ele_t * ele = snapshot_map_iter_ele( iter, snapshot_map, snapshot );
    if( ele->timestamp==20 ) t_20_cnt++;
    else if( ele->timestamp==11 ) t_11_cnt++;
    else if( ele->timestamp==10 ) t_10_cnt++;
    else FD_TEST( 0 );
  }
  FD_TEST( t_20_cnt==3 );
  FD_TEST( t_11_cnt==1 );
  FD_TEST( t_10_cnt==1 );


  /* TODO: The index currently leaks elements.  */

  FD_LOG_NOTICE(( "pass" ));
}
