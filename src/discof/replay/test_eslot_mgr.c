#include "fd_eslot_mgr.h"
#include "../../flamenco/runtime/fd_runtime_const.h"

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
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

  ulong const max_eslots = 1000UL;

  void * eslot_mgr_mem = fd_wksp_alloc_laddr( wksp, fd_eslot_mgr_align(), fd_eslot_mgr_footprint( max_eslots ), wksp_tag );
  FD_TEST( eslot_mgr_mem );

  FD_TEST( !fd_eslot_mgr_new( NULL, max_eslots, 999UL ) );

  FD_TEST( !fd_eslot_mgr_join( eslot_mgr_mem ) );
  eslot_mgr_mem = fd_eslot_mgr_new( eslot_mgr_mem, max_eslots, 999UL );
  FD_TEST( eslot_mgr_mem );

  FD_TEST( !fd_eslot_mgr_join( NULL ) );

  fd_eslot_mgr_t * eslot_mgr = fd_eslot_mgr_join( eslot_mgr_mem );
  FD_TEST( eslot_mgr );

  fd_eslot_ele_t * ele = fd_eslot_mgr_ele_insert_initial( eslot_mgr, 0UL );
  FD_TEST( ele );
  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 0UL, 0UL ) );
  FD_TEST( ele );

  fd_hash_t merkle_zero    = { .ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };
  fd_hash_t merkle_one     = { .ul[0] = 1UL };               /* slot 1   */
  fd_hash_t merkle_two     = { .ul[0] = 2UL };               /* slot 1   */
  fd_hash_t merkle_three   = { .ul[0] = 3UL };               /* slot 1   */
  fd_hash_t merkle_four    = { .ul[0] = 4UL };               /* slot 2   */
  fd_hash_t merkle_four_e  = { .ul[0] = 4UL, .ul[1] = 1UL }; /* slot 2'  */
  fd_hash_t merkle_five    = { .ul[0] = 5UL };               /* slot 2   */
  fd_hash_t merkle_six     = { .ul[0] = 6UL };               /* slot 3   */
  fd_hash_t merkle_seven   = { .ul[0] = 7UL };               /* slot 4   */
  fd_hash_t merkle_eight   = { .ul[0] = 8UL };               /* slot 5   */
  fd_hash_t merkle_nine    = { .ul[0] = 9UL };               /* slot 5   */
  fd_hash_t merkle_nine_e  = { .ul[0] = 9UL, .ul[1] = 1UL }; /* slot 5'  */
  fd_hash_t merkle_nine_ee = { .ul[0] = 9UL, .ul[1] = 2UL }; /* slot 5'' */

  /* Slot transition. */
  fd_eslot_ele_t * inserted_ele = NULL;

  int is_equiv;
  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 1UL, &merkle_one, &merkle_zero, 0UL, &is_equiv );
  FD_TEST( inserted_ele );
  FD_TEST( !is_equiv );
  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 1UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_one );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 1UL, &merkle_two, &merkle_one, 1UL, &is_equiv );
  FD_TEST( !is_equiv );
  FD_TEST( inserted_ele );
  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 1UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_two );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 1UL, &merkle_three, &merkle_two, 2UL, &is_equiv );
  FD_TEST( inserted_ele );
  FD_TEST( !is_equiv );
  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 1UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_three );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  /* Slot transition. */

  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 2UL, &merkle_four, &merkle_three, 0UL, &is_equiv );
  FD_TEST( inserted_ele );
  FD_TEST( !is_equiv );
  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 2UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_four );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  fd_eslot_mgr_ele_insert_fec( eslot_mgr, 2UL, &merkle_five, &merkle_four, 1UL, &is_equiv );
  FD_TEST( !is_equiv );
  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 2UL, 0UL ) );
  FD_TEST( ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_five );
  FD_TEST( ele );

  /* Equivocate at the start of slot 2 */

  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 2UL, &merkle_four_e, &merkle_three, 0UL, &is_equiv );
  FD_TEST( (ulong)inserted_ele->eslot.slot==2UL );
  FD_TEST( (ulong)inserted_ele->eslot.prime==1UL );
  FD_TEST( is_equiv );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 2UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( (ulong)ele->eslot.slot==2UL );
  FD_TEST( (ulong)ele->eslot.prime==0UL );
  FD_TEST( ele!=inserted_ele );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 2UL, 1UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_four_e );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  /* Now build a leader block off of 2' (2, 1). */

  inserted_ele = fd_eslot_mgr_ele_insert_leader( eslot_mgr, 3UL, fd_eslot( 2UL, 1UL ) );
  FD_TEST( inserted_ele );
  FD_TEST( inserted_ele->eslot.slot==3UL );
  FD_TEST( inserted_ele->eslot.prime==0UL );
  FD_TEST( inserted_ele->is_leader );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 3UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele == inserted_ele );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, inserted_ele->parent_eslot );
  FD_TEST( ele );
  FD_TEST( ele->eslot.slot==2UL );
  FD_TEST( ele->eslot.prime==1UL );

  fd_eslot_mgr_rekey_merkle_root( eslot_mgr, inserted_ele, &merkle_six );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 3UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_six );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  /* Build a leader block off of a leader block. */

  inserted_ele = fd_eslot_mgr_ele_insert_leader( eslot_mgr, 4UL, fd_eslot( 3UL, 0UL ) );
  FD_TEST( inserted_ele );
  FD_TEST( inserted_ele->eslot.slot==4UL );
  FD_TEST( inserted_ele->eslot.prime==0UL );
  FD_TEST( inserted_ele->is_leader );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 4UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, inserted_ele->parent_eslot );
  FD_TEST( ele );
  FD_TEST( ele->eslot.slot==3UL );
  FD_TEST( ele->eslot.prime==0UL );

  fd_eslot_mgr_rekey_merkle_root( eslot_mgr, inserted_ele, &merkle_seven );

  /* Build a non-leader block off of a leader block. */

  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 5UL, &merkle_eight, &merkle_seven, 0UL, &is_equiv );
  FD_TEST( inserted_ele );
  FD_TEST( !is_equiv );
  FD_TEST( inserted_ele->eslot.slot==5UL );
  FD_TEST( inserted_ele->eslot.prime==0UL );
  FD_TEST( !inserted_ele->is_leader );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_eight );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );

  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 5UL, &merkle_nine, &merkle_eight, 1UL, &is_equiv );
  FD_TEST( inserted_ele );
  FD_TEST( !is_equiv );
  FD_TEST( inserted_ele->eslot.slot==5UL );
  FD_TEST( inserted_ele->eslot.prime==0UL );
  FD_TEST( !inserted_ele->is_leader );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 0UL ) );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_nine );
  FD_TEST( ele );
  FD_TEST( ele==inserted_ele );
  ele = fd_eslot_mgr_ele_query_merkle_root( eslot_mgr, &merkle_eight );
  FD_TEST( !ele );

  /* Equivocate mid block. */

  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 5UL, &merkle_nine_e, &merkle_eight, 0UL, &is_equiv );
  FD_TEST( inserted_ele );
  FD_TEST( is_equiv );
  FD_TEST( inserted_ele->eslot.slot==5UL );
  FD_TEST( inserted_ele->eslot.prime==1UL );
  FD_TEST( !inserted_ele->is_leader );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 0UL ) );
  FD_TEST( ele!=inserted_ele );

  inserted_ele = fd_eslot_mgr_ele_insert_fec( eslot_mgr, 5UL, &merkle_nine_ee, &merkle_eight, 0UL, &is_equiv );
  FD_TEST( inserted_ele );
  FD_TEST( is_equiv );
  FD_TEST( inserted_ele->eslot.slot==5UL );
  FD_TEST( inserted_ele->eslot.prime==2UL );
  FD_TEST( !inserted_ele->is_leader );

  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 0UL ) );
  FD_TEST( ele!=inserted_ele );
  ele = fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 1UL ) );
  FD_TEST( ele!=inserted_ele );

  /* Publish a new merkle root. */

  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 0UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 1UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 2UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 2UL, 1UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 3UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 4UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 1UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 2UL ) ) );

  fd_eslot_mgr_publish( eslot_mgr, 0UL, 4UL );

  FD_TEST( !fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 0UL, 0UL ) ) );
  FD_TEST( !fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 1UL, 0UL ) ) );
  FD_TEST( !fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 2UL, 0UL ) ) );
  FD_TEST( !fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 2UL, 1UL ) ) );
  FD_TEST( !fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 3UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 4UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 0UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 1UL ) ) );
  FD_TEST( fd_eslot_mgr_ele_query_eslot( eslot_mgr, fd_eslot( 5UL, 2UL ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
