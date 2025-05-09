#include "fd_fec_repair.h"

void
test_regular_fec( fd_wksp_t * wksp ){
  ulong fec_max = 32;

  void * mem = fd_wksp_alloc_laddr( wksp, fd_fec_repair_align(), fd_fec_repair_footprint( fec_max, 1 ), 1UL );
  FD_TEST( mem );
  fd_fec_repair_t * fec_repair = fd_fec_repair_join( fd_fec_repair_new( mem, fec_max, 1, 0UL ) );

  mem = fd_wksp_alloc_laddr( wksp, fd_fec_chainer_align(), fd_fec_chainer_footprint( fec_max ), 1UL );
  FD_TEST( mem );
  fd_fec_chainer_t * fec_chainer = fd_fec_chainer_join( fd_fec_chainer_new( mem, fec_max, 0UL ) );
  FD_TEST( fec_chainer );
  FD_TEST( fec_repair );

  /*
  Inserting data shreds only:
    slot, fec_set_idx, shred_idx
    ( 1, 5, 5 )
    ( 1, 0, 4 )
    (1, 0, 3 )
    (1, 0, 2 )
    (1, 0, 1 )
    (1, 0, 0 ) => should signal completion
  */
  fd_fec_repair_insert( fec_repair, 1, 5, 5, 0, 0, 0 );
  ulong key5 = ( 1UL << 32 ) | ( 5UL );
  ulong key0 = ( 1UL << 32 ) | ( 0UL );
  FD_TEST( fd_fec_intra_map_ele_query( fec_repair->intra_map, &key5, NULL, fec_repair->intra_pool ) );
  FD_TEST( !check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 5 ) );

  fd_fec_repair_insert( fec_repair, 1, 0, 4, 0, 0, 0 );
  FD_TEST( fd_fec_intra_map_ele_query( fec_repair->intra_map, &key0, NULL, fec_repair->intra_pool ) );
  FD_TEST( !check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );

  fd_fec_repair_insert( fec_repair, 1, 0, 3, 0, 0, 0 );
  FD_TEST( !check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );
  fd_fec_repair_insert( fec_repair, 1, 0, 2, 0, 0, 0 );
  FD_TEST( !check_set_blind_fec_completed( fec_repair,fec_chainer,  1, 0 ) );
  fd_fec_repair_insert( fec_repair, 1, 0, 1, 0, 0, 0 );
  FD_TEST( !check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );
  fd_fec_repair_insert( fec_repair, 1, 0, 0, 0, 0, 0 );
  FD_TEST( check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );

  fd_wksp_free_laddr( fd_fec_repair_delete( fd_fec_repair_leave( fec_repair ) ) );
}

void
test_completing_fec( fd_wksp_t * wksp ) {
    ulong fec_max = 32;

    void * mem = fd_wksp_alloc_laddr( wksp, fd_fec_repair_align(), fd_fec_repair_footprint( fec_max, 1 ), 1UL );
    FD_TEST( mem );
    fd_fec_repair_t * fec_repair = fd_fec_repair_join( fd_fec_repair_new( mem, fec_max, 1, 0UL ) );

    mem = fd_wksp_alloc_laddr( wksp, fd_fec_chainer_align(), fd_fec_chainer_footprint( fec_max ), 1UL );
    FD_TEST( mem );
    fd_fec_chainer_t * fec_chainer = fd_fec_chainer_join( fd_fec_chainer_new( mem, fec_max, 0UL ) );
    FD_TEST( fec_chainer );

    FD_TEST( fec_repair );

    /* inserting data shreds only:
        slot, fec_set_idx, shred_idx, completes
        ( 1, 0, 2 )
        (1, 0, 4 ) completes
        (1, 0, 3 )
        (1, 0, 1 )
        (1, 0, 0 ) => should signal completion
    */

    ulong key0 = ( 1UL << 32 ) | ( 0UL );
    fd_fec_repair_insert( fec_repair, 1, 0, 2, 0, 0, 0 );
    FD_TEST( !check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );
    fd_fec_repair_insert( fec_repair, 1, 0, 4, 1, 0, 0 );
    FD_LOG_WARNING(("completes idx: %u", fd_fec_intra_map_ele_query( fec_repair->intra_map, &key0, NULL, fec_repair->intra_pool )->completes_idx ));
    FD_TEST( !check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );
    FD_LOG_WARNING(("completes idx: %u", fd_fec_intra_map_ele_query( fec_repair->intra_map, &key0, NULL, fec_repair->intra_pool )->completes_idx ));

    fd_fec_repair_insert( fec_repair, 1, 0, 3, 0, 0, 0 );
    FD_TEST( !check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );
    fd_fec_repair_insert( fec_repair, 1, 0, 1, 0, 0, 0 );
    FD_TEST( !check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );
    fd_fec_repair_insert( fec_repair, 1, 0, 0, 0, 0, 0 );
    FD_TEST( check_set_blind_fec_completed( fec_repair, fec_chainer, 1, 0 ) );

    fd_wksp_free_laddr( fd_fec_repair_delete( fd_fec_repair_leave( fec_repair ) ) );

}

void
test_fec_insert( fd_wksp_t * wksp ){
  ulong fec_max = 32;

  void * mem = fd_wksp_alloc_laddr( wksp, fd_fec_repair_align(), fd_fec_repair_footprint( fec_max, 1 ), 1UL );
  FD_TEST( mem );
  fd_fec_repair_t * fec_repair = fd_fec_repair_join( fd_fec_repair_new( mem, fec_max, 1,  0UL ) );
  FD_TEST( fec_repair );

  fd_fec_repair_insert( fec_repair, 1, 48, 48, 0, 0, 0 );
  fd_fec_repair_insert( fec_repair, 1, 48, 54, 1, 0, 0 );

  fd_fec_repair_insert( fec_repair, 1, 48, 7, 0, 1, 0 );
  fd_fec_repair_insert( fec_repair, 1, 48,  49, 0, 0, 0 );
  fd_fec_repair_insert( fec_repair, 1, 48, 50, 0, 0, 0 );

  ulong key = ( 1UL << 32 ) | ( 48UL );
  fd_fec_intra_t * fec = fd_fec_intra_map_ele_query( fec_repair->intra_map, &key, NULL, fec_repair->intra_pool );
  FD_TEST( fec );
  FD_TEST( fec->recv_cnt == 5 );
  FD_TEST( fec->data_cnt == 7 );
  FD_TEST( fec->completes_idx == 6 );
  FD_TEST( fec->buffered_idx == 2 );

  FD_TEST( fd_fec_intra_pool_used( fec_repair->intra_pool ) == 1 );
  fd_wksp_free_laddr( fd_fec_repair_delete( fd_fec_repair_leave( fec_repair ) ) );
}


int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );


  test_regular_fec( wksp );
  test_completing_fec( wksp );
  test_fec_insert( wksp );

  fd_halt();
  return 0;
}
