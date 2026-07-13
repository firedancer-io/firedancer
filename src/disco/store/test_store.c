#define _GNU_SOURCE
#include "fd_store.h"
#include "fd_store.c"

#define TEST_PAYLOAD_PATH "/tmp/test_store_fec_payload.db"

/* Helper: acquire a pool element, set its key, and insert it into the
   map.  Returns the inserted element. */

static fd_store_fec_t *
insert( fd_store_t * store, fd_store_map_t * map, fd_hash_t const * mr ) {
  fd_store_fec_t * fec = fd_store_fec_acquire( store );
  FD_TEST( fec );
  fec->key     = *mr;
  fec->data_sz = 0UL;
  FD_TEST( !fd_store_insert( map, fec ) );
  return fec;
}

static fd_store_fec_t *
insert_payload( fd_store_t * store,
                fd_store_map_t * map,
                int disk_fd,
                fd_hash_t const * mr,
                uchar byte,
                ulong sz ) {
  fd_store_fec_t * fec = insert( store, map, mr );
  uchar * data = fd_store_fec_data_acquire( store, disk_fd, fec );
  FD_TEST( data );
  fd_memset( data, byte, sz );
  fec->data_sz = sz;
  fec->shred_offs[0] = (uint)sz;
  fd_store_fec_data_publish( store, fec );
  return fec;
}

void
test_api( fd_wksp_t * wksp ) {
  ulong  fec_max     = 8;
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, 0UL ), 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, 31840UL, 0UL, 0UL, 0UL, TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( store );

  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( store, map ) );

  fd_store_pool_t pool = pool_ljoin( store );
  FD_TEST( pool.ele );
  FD_TEST( pool.ele_max == fec_max );
  FD_TEST( pool.pool );

  fd_hash_t mr0 = { { 0 } };
  fd_hash_t mr1 = { { 1 } };
  fd_hash_t mr2 = { { 2 } };
  fd_hash_t mr3 = { { 3 } };
  fd_hash_t mr4 = { { 4 } };
  fd_hash_t mr5 = { { 5 } };
  fd_hash_t mr6 = { { 6 } };
  insert( store, map, &mr0 );
  insert( store, map, &mr1 );
  insert( store, map, &mr2 );
  insert( store, map, &mr4 );
  insert( store, map, &mr3 );
  insert( store, map, &mr5 );
  insert( store, map, &mr6 );

  fd_store_fec_t const * fec0 = fd_store_query( map, &mr0 );
  fd_store_fec_t const * fec1 = fd_store_query( map, &mr1 );
  fd_store_fec_t const * fec2 = fd_store_query( map, &mr2 );
  fd_store_fec_t const * fec3 = fd_store_query( map, &mr3 );
  fd_store_fec_t const * fec4 = fd_store_query( map, &mr4 );
  fd_store_fec_t const * fec5 = fd_store_query( map, &mr5 );
  fd_store_fec_t const * fec6 = fd_store_query( map, &mr6 );
  FD_TEST( fec0 );
  FD_TEST( fec1 );
  FD_TEST( fec2 );
  FD_TEST( fec3 );
  FD_TEST( fec4 );
  FD_TEST( fec5 );
  FD_TEST( fec6 );

  /* Remove returns the element; a subsequent query must miss and a
     second remove must return NULL. */
  fd_store_fec_t * rem = fd_store_remove( map, &mr1 );
  FD_TEST( rem==fec1 );
  fd_store_fec_release( store, rem );
  FD_TEST( !fd_store_query( map, &mr1 ) );
  FD_TEST( !fd_store_remove( map, &mr1 ) ); /* missing remove */

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_query_miss( fd_wksp_t * wksp ) {
  ulong  fec_max     = 16;
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, 0UL ), 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, 31840UL, 0UL, 0UL, 0UL, TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( store );

  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( store, map ) );

  fd_hash_t mr0 = { .ul = { 0xdeadbeefUL } };
  FD_TEST( !fd_store_query( map, &mr0 ) );

  for( ulong i=0UL; i<fec_max; i++ ) {
    fd_hash_t mr = { .ul = { i, 0xaUL } };
    insert( store, map, &mr );
    FD_TEST( fd_store_query( map, &mr ) );
  }

  fd_hash_t missing = { .ul = { fec_max, 0xaUL } };
  FD_TEST( !fd_store_query( map, &missing ) );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_fec_data_max( fd_wksp_t * wksp ) {
  ulong fec_max = 8;

  /* With shred_cache_bytes==0, the RAM cache can hold all live FECs, so
     the footprint scales with the aligned payload slot size.  With a
     bounded cache, footprint scales with the cache budget instead. */
  ulong fp_fixed = fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, 0UL );
  ulong fp_var   = fd_store_footprint( fec_max, 63985UL, 0UL, 0UL, 0UL );
  ulong fp_cap   = fd_store_footprint( fec_max, 63985UL, 0UL, 2UL*fd_store_payload_slot_sz( 63985UL ), 0UL );
  FD_TEST( fp_fixed );
  FD_TEST( fp_var );
  FD_TEST( fp_var > fp_fixed );
  FD_TEST( fp_cap < fp_var );

  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), fp_var, 1UL );
  fd_store_t * st    = fd_store_join( fd_store_new( mem, fec_max, 63985UL, 0UL, 0UL, 0UL, TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( st );
  FD_TEST( st->fec_data_max == 63985UL );

  FD_TEST( st->payload_slot_sz >= 63985UL );
  FD_TEST( fd_ulong_is_aligned( st->payload_slot_sz, FD_STORE_PAYLOAD_PAGE_SZ ) );

  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( st, map ) );

  fd_hash_t mr0 = { { 0 } };
  fd_hash_t mr1 = { { 1 } };
  fd_store_fec_t * fec0 = insert( st, map, &mr0 );
  fd_store_fec_t * fec1 = insert( st, map, &mr1 );
  FD_TEST( fec0 );
  FD_TEST( fec1 );

  uchar * data0 = fd_store_fec_data_acquire( st, -1, fec0 );
  uchar * data1 = fd_store_fec_data_acquire( st, -1, fec1 );
  FD_TEST( data0 );
  FD_TEST( data1 );

  FD_TEST( fec0->data_off != fec1->data_off );
  ulong off_span = fec1->data_off > fec0->data_off
                 ? fec1->data_off - fec0->data_off
                 : fec0->data_off - fec1->data_off;
  FD_TEST( off_span >= 63985UL );

  fd_memset( data0, 0xAA, 63985UL );
  fd_memset( data1, 0xBB, 63985UL );
  fec0->data_sz = 63985UL;
  fec1->data_sz = 63985UL;
  fd_store_fec_data_publish( st, fec0 );
  fd_store_fec_data_publish( st, fec1 );

  FD_TEST( data0[ 63984UL ] == 0xAA );
  FD_TEST( data1[ 63984UL ] == 0xBB );

  uchar scratch[ FD_STORE_FEC_DATA_SCRATCH_SZ ];
  fd_store_fec_data_view_t view[1];
  FD_TEST( !fd_store_fec_data_view( st, -1, fec0, scratch, view ) );
  FD_TEST( view->data[ 63984UL ] == 0xAA );
  fd_store_fec_data_view_release( st, view );
  fd_store_fec_data_consumed( st, fec0 );
  FD_TEST( fec0->data_state==FD_STORE_FEC_DATA_CONSUMED );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( st ) ) );

  mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fp_fixed, 1UL );
  st  = fd_store_join( fd_store_new( mem, fec_max, 31840UL, 0UL, 0UL, 0UL, TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( st );
  FD_TEST( st->fec_data_max == 31840UL );

  FD_TEST( fd_store_map_ljoin( st, map ) );

  fec0 = insert( st, map, &mr0 );
  fec1 = insert( st, map, &mr1 );

  data0 = fd_store_fec_data_acquire( st, -1, fec0 );
  data1 = fd_store_fec_data_acquire( st, -1, fec1 );
  FD_TEST( data0 );
  FD_TEST( data1 );

  off_span = fec1->data_off > fec0->data_off
           ? fec1->data_off - fec0->data_off
           : fec0->data_off - fec1->data_off;
  FD_TEST( off_span >= 31840UL );

  fd_memset( data0, 0xCC, 31840UL );
  fd_memset( data1, 0xDD, 31840UL );
  fec0->data_sz = 31840UL;
  fec1->data_sz = 31840UL;
  fd_store_fec_data_publish( st, fec0 );
  fd_store_fec_data_publish( st, fec1 );

  FD_TEST( data0[ 31839UL ] == 0xCC );
  FD_TEST( data1[ 31839UL ] == 0xDD );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( st ) ) );
}

void
test_fec_sets_arena( fd_wksp_t * wksp ) {
  ulong fec_max     = 4UL;
  ulong fec_set_cnt = 5UL;

  ulong fp_without = fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, 0UL );
  ulong fp_with    = fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, fec_set_cnt );
  FD_TEST( fp_with > fp_without );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fp_with, 1UL );
  fd_store_t * st = fd_store_join( fd_store_new( mem, fec_max, 31840UL, 0UL, 0UL, fec_set_cnt, TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( st );
  FD_TEST( st->fec_set_cnt==fec_set_cnt );

  fd_fec_set_t * fec_sets = fd_store_fec_sets( st );
  FD_TEST( fec_sets );
  FD_TEST( fd_ulong_is_aligned( (ulong)fec_sets, alignof(fd_fec_set_t) ) );

  fec_sets[ 0 ].data_shred_rcvd = 0x12345678U;
  fec_sets[ 4 ].parity_shred_rcvd = 0x87654321U;
  FD_TEST( fec_sets[ 0 ].data_shred_rcvd==0x12345678U );
  FD_TEST( fec_sets[ 4 ].parity_shred_rcvd==0x87654321U );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( st ) ) );
}

void
test_spill( fd_wksp_t * wksp ) {
  ulong fec_max      = 3UL;
  ulong fec_data_max = 64UL;
  ulong cache_bytes  = 2UL * fd_store_payload_slot_sz( fec_data_max );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max, fec_data_max, 0UL, cache_bytes, 0UL ), 1UL );
  fd_store_t * st = fd_store_join( fd_store_new( mem, fec_max, fec_data_max, 0UL, cache_bytes, 0UL, TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( st );
  FD_TEST( st->cache_slot_cnt==2UL );
  FD_TEST( st->cache_free_cnt==2UL );
  FD_TEST( st->fec_spill_cnt==0UL );

  int fd = open( TEST_PAYLOAD_PATH, O_RDWR, (mode_t)0600 );
  FD_TEST( fd>=0 );

  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( st, map ) );

  fd_hash_t mr0 = { { 0 } };
  fd_hash_t mr1 = { { 1 } };
  fd_hash_t mr2 = { { 2 } };
  fd_store_fec_t * fec0 = insert_payload( st, map, fd, &mr0, 0xA0, fec_data_max );
  fd_store_fec_t * fec1 = insert_payload( st, map, fd, &mr1, 0xB0, fec_data_max );
  fd_store_fec_t * fec2 = insert_payload( st, map, fd, &mr2, 0xC0, fec_data_max );
  FD_TEST( st->cache_slot_cnt-st->cache_free_cnt==2UL );
  FD_TEST( st->fec_spill_cnt==1UL );

  FD_TEST( fec0->data_state==FD_STORE_FEC_DATA_DISK );
  FD_TEST( fec1->data_state==FD_STORE_FEC_DATA_RAM_READY );
  FD_TEST( fec2->data_state==FD_STORE_FEC_DATA_RAM_READY );

  uchar scratch[ FD_STORE_FEC_DATA_SCRATCH_SZ ];
  fd_store_fec_data_view_t view[1];
  FD_TEST( !fd_store_fec_data_view( st, fd, fec0, scratch, view ) );
  FD_TEST( view->data[0]==0xA0 );
  FD_TEST( view->data[fec_data_max-1UL]==0xA0 );
  fd_store_fec_data_view_release( st, view );

  FD_TEST( !fd_store_fec_data_view( st, fd, fec2, scratch, view ) );
  FD_TEST( view->data[0]==0xC0 );
  fd_store_fec_data_view_release( st, view );

  close( fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( st ) ) );
}

/* Concurrent insert test: multiple tiles insert distinct keys into the
   shared map with no external locking.  Verifies fd_map_chain_para's
   per-chain locking correctly serializes concurrent inserts. */

static ulong        tile_go;
static ulong        num_insert = 64;
static fd_store_t * g_store;

static int
shred_tile_insert( int argc, char ** argv ) {
  (void)argc; (void)argv;

  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( g_store, map ) );

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  ulong tile_idx = fd_tile_idx();
  for( ulong i = 1; i < num_insert; i++ ) {
    fd_hash_t mr = { .ul = { (i << 16) | tile_idx } };
    fd_store_fec_t * fec = fd_store_fec_acquire( g_store );
    FD_TEST( fec );
    fec->key     = mr;
    fec->data_sz = 0UL;
    FD_TEST( !fd_store_insert( map, fec ) );
  }
  return 0;
}

void
test_concurrent( fd_wksp_t * wksp ) {
  ulong  tile_cnt = fd_tile_cnt();
  ulong  fec_max  = tile_cnt * num_insert + 16UL;
  void * mem      = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, 0UL ), 1UL );
  g_store         = fd_store_join( fd_store_new( mem, fec_max, 31840UL, 0UL, 0UL, 0UL, TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( g_store );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tile_go ) = 0;
  FD_COMPILER_MFENCE();

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {
    fd_tile_exec_new( tile_idx, shred_tile_insert, 0, NULL );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tile_go ) = 1;
  FD_COMPILER_MFENCE();

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {
    fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );
  }

  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( g_store, map ) );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {
    for( ulong i = 1; i < num_insert; i++ ) {
      fd_hash_t mr = { .ul = { (i << 16) | tile_idx } };
      FD_TEST( fd_store_query( map, &mr ) );
    }
  }

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( g_store ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"              );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                     );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_api         ( wksp );
  test_query_miss  ( wksp );
  test_fec_data_max( wksp );
  test_fec_sets_arena( wksp );
  test_spill       ( wksp );
  test_concurrent  ( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
