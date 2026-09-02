#define _GNU_SOURCE
#include "fd_store.h"
#include <errno.h>
#include <fcntl.h>
#include "fd_store.c"

#include <sys/stat.h>

#define TEST_PAYLOAD_PATH "/tmp/test_store_fec_payload.db"

/* Helper: insert a new key and return its pool element. */

static fd_store_fec_t *
insert( fd_store_t * store, fd_store_map_t * map, fd_hash_t const * mr ) {
  fd_store_fec_t * fec;
  FD_TEST( !fd_store_insert( store, map, mr, &fec ) && fec );
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
  FD_TEST( sz<=USHORT_MAX );
  fec->data_sz = (uint)sz;
  fec->shred_sz[0] = (ushort)sz;
  fd_store_fec_data_publish( store, fec );
  return fec;
}

static int
store_file_open( fd_store_t * store,
                 int          flags ) {
  FD_TEST( !fd_store_file_init( store ) );
  return fd_store_file_open( store, flags );
}

void
test_api( fd_wksp_t * wksp ) {
  FD_TEST( sizeof(fd_store_fec_t)==128UL );

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
  fd_hash_t mr7 = { { 7 } };
  fd_hash_t mr8 = { { 8 } };
  insert( store, map, &mr0 );
  insert( store, map, &mr1 );
  insert( store, map, &mr2 );
  insert( store, map, &mr4 );
  insert( store, map, &mr3 );
  insert( store, map, &mr5 );
  insert( store, map, &mr6 );
  insert( store, map, &mr7 );

  fd_store_fec_t * duplicate;
  FD_TEST( fd_store_insert( store, map, &mr0, &duplicate )==FD_MAP_ERR_KEY );
  FD_TEST( !duplicate );

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

  /* A subsequent query must miss and a second remove is a no-op. */
  FD_TEST( fd_store_remove( store, map, &mr1 ) );
  FD_TEST( !fd_store_query( map, &mr1 ) );
  FD_TEST( !fd_store_remove( store, map, &mr1 ) );
  FD_TEST( insert( store, map, &mr8 ) );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_db_path( fd_wksp_t * wksp ) {
  FD_STATIC_ASSERT( sizeof(((fd_store_t *)0)->db_path)==PATH_MAX, db_path_contract );

  char  db_path[ PATH_MAX ];
  ulong path_len;
  FD_TEST( fd_cstr_printf_check( db_path, PATH_MAX, &path_len, "/tmp/" ) );
  while( path_len<300UL ) {
    db_path[ path_len++ ] = '.';
    db_path[ path_len++ ] = '/';
  }
  ulong suffix_len;
  FD_TEST( fd_cstr_printf_check( db_path+path_len, PATH_MAX-path_len, &suffix_len, "test_store_long_path.db" ) );
  path_len += suffix_len;
  FD_TEST( path_len>256UL && path_len<PATH_MAX );

  ulong fp = fd_store_footprint( 2UL, 31840UL, 0UL, 0UL, 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fp, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 2UL, 31840UL, 0UL, 0UL, 0UL, db_path, 0UL ) );
  FD_TEST( store );
  FD_TEST( !strcmp( store->db_path, db_path ) );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
  FD_TEST( !unlink( db_path ) || errno==ENOENT );

  char too_long[ PATH_MAX ];
  fd_memset( too_long, 'x', sizeof(too_long) );
  mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fp, 1UL );
  FD_TEST( !fd_store_new( mem, 2UL, 31840UL, 0UL, 0UL, 0UL, too_long, 0UL ) );
  fd_wksp_free_laddr( mem );
}

void
test_file_open( fd_wksp_t * wksp ) {
  FD_TEST( !unlink( TEST_PAYLOAD_PATH ) || errno==ENOENT );

  ulong footprint = fd_store_footprint( 2UL, 31840UL, 1UL, 0UL, 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 2UL, 31840UL, 1UL, 0UL, 0UL,
                                                    TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 16UL;
  FD_TEST( access( TEST_PAYLOAD_PATH, F_OK ) && errno==ENOENT );

  FD_TEST( !fd_store_file_init( store ) );
  int fd = fd_store_file_open( store, O_RDWR );
  FD_TEST( fd>=0 );
  struct stat st[1];
  FD_TEST( !fstat( fd, st ) );
  FD_TEST( (ulong)st->st_size==store->wire_off + store->disk_max_shreds*sizeof(fd_shredb_entry_t) );

  uchar value = 0xa5U;
  FD_TEST( pwrite( fd, &value, 1UL, 0 )==1L );
  close( fd );

  fd = fd_store_file_open( store, O_RDONLY );
  FD_TEST( fd>=0 );
  uchar observed = 0U;
  FD_TEST( pread( fd, &observed, 1UL, 0 )==1L );
  FD_TEST( observed==value );
  close( fd );

  errno = 0;
  FD_TEST( fd_store_file_open( store, O_RDWR | O_TRUNC )<0 && errno==EINVAL );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_pread_all( void ) {
  int fd = open( TEST_PAYLOAD_PATH, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600 );
  FD_TEST( fd>=0 );

  uchar src[ 32 ];
  uchar dst[ 33 ];
  for( ulong i=0UL; i<sizeof(src); i++ ) src[ i ] = (uchar)i;
  FD_TEST( !store_pwrite_all( fd, src, sizeof(src), 0 ) );
  FD_TEST( !store_pread_all ( fd, dst, sizeof(src), 0 ) );
  FD_TEST( !memcmp( src, dst, sizeof(src) ) );

  close( fd );
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

  FD_TEST( fd_shredb_max_slots( 1UL )==fd_shredb_max_shreds( 1UL )/FD_FEC_SHRED_CNT );
  FD_TEST( fd_store_footprint( fec_max, 31840UL, FD_SHREDB_MAX_SIZE_GIB,     0UL, 0UL )>0UL );
  FD_TEST( fd_store_footprint( fec_max, 31840UL, FD_SHREDB_MAX_SIZE_GIB+1UL, 0UL, 0UL )==0UL );
  FD_TEST( fd_store_footprint( fec_max, 31840UL, 50UL, 0UL, 0UL )<(4UL<<30) );
  FD_TEST( !fd_store_payload_slot_sz( ULONG_MAX ) );
  FD_TEST( !fd_store_footprint( fec_max, ULONG_MAX, 0UL, 1UL, 0UL ) );
  FD_TEST( !fd_store_footprint( fec_max, (ulong)UINT_MAX+1UL, 0UL, 1UL, 0UL ) );
  FD_TEST( !fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, ULONG_MAX ) );

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

  fd_store_fec_data_view_t view[1];
  FD_TEST( !fd_store_fec_data_view( st, -1, fec0, view ) );
  FD_TEST( view->fec==fec0 );
  FD_TEST( !view->flags );
  FD_TEST( view->data[ 63984UL ] == 0xAA );
  fd_store_fec_data_view_release( st, view );

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
  FD_TEST( st->spill_slot_cnt==0UL );
  FD_TEST( st->spill_free_cnt==0UL );
  FD_TEST( st->fec_spill_cnt==0UL );

  int fd = store_file_open( st, O_RDWR );
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
  FD_TEST( st->spill_slot_cnt==1UL );
  FD_TEST( st->spill_free_cnt==0UL );

  struct stat spill_stat0[1];
  FD_TEST( !fstat( fd, spill_stat0 ) );

  FD_TEST( fec0->data_state==FD_STORE_FEC_DATA_DISK );
  FD_TEST( fec1->data_state==FD_STORE_FEC_DATA_RAM_READY );
  FD_TEST( fec2->data_state==FD_STORE_FEC_DATA_RAM_READY );

  fd_store_fec_data_view_t view[1];
  FD_TEST( !fd_store_fec_data_view( st, fd, fec0, view ) );
  FD_TEST( view->fec==fec0 );
  FD_TEST( view->flags==FD_STORE_FEC_DATA_VIEW_SPILL );
  FD_TEST( view->data[0]==0xA0 );
  FD_TEST( view->data[fec_data_max-1UL]==0xA0 );
  fd_store_fec_data_view_t second_view[1];
  FD_TEST( fd_store_fec_data_view( st, fd, fec0, second_view )==-1 );
  FD_TEST( !second_view->data && !second_view->fec && !second_view->flags );
  fd_store_fec_data_view_release( st, view );
  FD_TEST( fec0->data_state==FD_STORE_FEC_DATA_DISK );

  FD_TEST( !fd_store_fec_data_view( st, fd, fec2, view ) );
  FD_TEST( view->fec==fec2 );
  FD_TEST( !view->flags );
  FD_TEST( view->data[0]==0xC0 );
  fd_store_fec_data_view_release( st, view );

  /* Recycle fec0's spill slot for the payload that was already read. */
  ulong reused_off = fec0->data_off;
  FD_TEST( fd_store_remove( st, map, &mr0 ) );
  FD_TEST( st->spill_slot_cnt==1UL );
  FD_TEST( st->spill_reclaim_cnt==1UL );
  FD_TEST( !st->spill_free_cnt );

  fd_hash_t mr3 = { { 3 } };
  fd_store_fec_t * fec3 = insert_payload( st, map, fd, &mr3, 0xD0, fec_data_max );
  FD_TEST( fec3->data_state==FD_STORE_FEC_DATA_RAM_READY );
  FD_TEST( fec2->data_state==FD_STORE_FEC_DATA_DISK );
  FD_TEST( fec2->data_off==reused_off );
  FD_TEST( st->spill_slot_cnt==1UL );
  FD_TEST( !st->spill_reclaim_cnt );
  FD_TEST( st->spill_free_cnt==0UL );
  FD_TEST( !fd_store_fec_data_view( st, fd, fec2, view ) );
  FD_TEST( view->data[0]==0xC0 );
  fd_store_fec_data_view_release( st, view );
  struct stat spill_stat1[1];
  FD_TEST( !fstat( fd, spill_stat1 ) );
  FD_TEST( spill_stat1->st_blocks==spill_stat0->st_blocks );

  FD_TEST( fd_store_remove( st, map, &mr2 ) );
  FD_TEST( st->spill_reclaim_cnt==1UL );
  FD_TEST( fd_store_disk_maintain( st, fd ) );
  struct stat reclaimed_stat[1];
  FD_TEST( !fstat( fd, reclaimed_stat ) );
  FD_TEST( reclaimed_stat->st_blocks<spill_stat0->st_blocks );
  FD_TEST( st->spill_free_cnt==1UL );

  close( fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( st ) ) );
}

void
test_pinned_spill( fd_wksp_t * wksp ) {
  ulong fec_max      = 4UL;
  ulong fec_data_max = 64UL;
  ulong cache_bytes  = 2UL * fd_store_payload_slot_sz( fec_data_max );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( fec_max, fec_data_max, 0UL, cache_bytes, 0UL ), 1UL );
  fd_store_t * st = fd_store_join( fd_store_new( mem, fec_max, fec_data_max, 0UL, cache_bytes, 0UL, TEST_PAYLOAD_PATH, 0UL ) );
  FD_TEST( st );
  int fd = store_file_open( st, O_RDWR );
  FD_TEST( fd>=0 );

  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( st, map ) );
  fd_hash_t mr0 = { { 0 } };
  fd_hash_t mr1 = { { 1 } };
  fd_hash_t mr2 = { { 2 } };
  fd_hash_t mr3 = { { 3 } };
  fd_store_fec_t * fec0 = insert_payload( st, map, fd, &mr0, 0xA0, fec_data_max );
  fd_store_fec_t * fec1 = insert_payload( st, map, fd, &mr1, 0xB0, fec_data_max );

  fd_store_fec_data_view_t view[1];
  FD_TEST( !fd_store_fec_data_view( st, fd, fec0, view ) );
  FD_TEST( st->cache_pinned_cnt==1UL );
  FD_TEST( view->data[0]==0xA0 );

  fd_store_fec_t * fec2 = insert_payload( st, map, fd, &mr2, 0xC0, fec_data_max );
  FD_TEST( fec0->data_state==FD_STORE_FEC_DATA_RAM_READY );
  FD_TEST( fec1->data_state==FD_STORE_FEC_DATA_DISK );
  FD_TEST( fec2->data_state==FD_STORE_FEC_DATA_RAM_READY );
  FD_TEST( view->data[0]==0xA0 );

  fd_store_fec_data_view_release( st, view );
  FD_TEST( !st->cache_pinned_cnt );

  fd_store_fec_t * fec3 = insert_payload( st, map, fd, &mr3, 0xD0, fec_data_max );
  FD_TEST( fec0->data_state==FD_STORE_FEC_DATA_DISK );
  FD_TEST( fec2->data_state==FD_STORE_FEC_DATA_RAM_READY );
  FD_TEST( fec3->data_state==FD_STORE_FEC_DATA_RAM_READY );
  FD_TEST( st->fec_spill_cnt==2UL );
  FD_TEST( st->fec_spill_bytes==2UL*fec_data_max );

  close( fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( st ) ) );
}

static fd_store_t * disk_concurrent_store;
static int          disk_concurrent_fd;
static uchar        disk_concurrent_shred[ FD_TILE_MAX ][ FD_SHRED_MAX_SZ ];
static int          disk_concurrent_result[ FD_TILE_MAX ];
static atomic_ulong disk_concurrent_go;

static fd_shred_t *
disk_make_shred( uchar buf[ FD_SHRED_MAX_SZ ],
                 ulong slot,
                 uint  idx,
                 uchar marker ) {
  fd_memset( buf, 0, FD_SHRED_MAX_SZ );
  fd_shred_t * shred = fd_type_pun( buf );
  shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  shred->slot      = slot;
  shred->idx       = idx;
  shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+1UL);
  buf[ FD_SHRED_DATA_HEADER_SZ ] = marker;
  return shred;
}

static int
disk_tile_insert_concurrent( int argc FD_PARAM_UNUSED,
                             char ** argv FD_PARAM_UNUSED ) {
  ulong tile_idx = fd_tile_idx();
  while( !atomic_load_explicit( &disk_concurrent_go, memory_order_acquire ) ) FD_SPIN_PAUSE();
  disk_concurrent_result[ tile_idx ] = fd_store_disk_insert(
      disk_concurrent_store, disk_concurrent_fd,
      (fd_shred_t const *)fd_type_pun_const( disk_concurrent_shred[ tile_idx ] ) );
  return 0;
}

void
test_disk_query_highest( fd_wksp_t * wksp ) {
  ulong fec_max      = 8UL;
  ulong fec_data_max = 31840UL;
  ulong footprint    = fd_store_footprint( fec_max, fec_data_max, 1UL, 0UL, 0UL );
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, fec_data_max, 1UL, 0UL, 0UL,
                                                    TEST_PAYLOAD_PATH, 42UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 64UL;

  int disk_fd = store_file_open( store, O_RDWR );
  FD_TEST( disk_fd>=0 );

  struct stat file_stat[1];
  FD_TEST( !fstat( disk_fd, file_stat ) );
  FD_TEST( (ulong)file_stat->st_size==store->wire_off + store->disk_max_shreds*sizeof(fd_shredb_entry_t) );
  FD_TEST( (ulong)file_stat->st_blocks*512UL>=store->disk_max_shreds*sizeof(fd_shredb_entry_t) );
  FD_TEST( (ulong)file_stat->st_blocks*512UL<(ulong)file_stat->st_size );

  uchar buf[ FD_SHRED_MAX_SZ ];
  fd_memset( buf, 0, sizeof(buf) );
  fd_shred_t * shred = (fd_shred_t *)fd_type_pun( buf );
  shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  shred->slot      = 42UL;
  shred->idx       = 3U;
  shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;

  FD_TEST( fd_store_disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );

  uchar out[ FD_SHRED_MAX_SZ ];
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, 42UL, 3U, out )>0 );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, 42UL, 4U, out )==FD_STORE_DISK_QUERY_MISS );

  fd_store_disk_stats_t stats[1];
  FD_TEST( !fd_store_disk_stats_query( store, stats ) );
  FD_TEST( stats->shred_cnt==1UL );
  FD_TEST( stats->current_bytes==sizeof(fd_shredb_entry_t) );
  FD_TEST( stats->allocated_bytes==store->disk_max_shreds*sizeof(fd_shredb_entry_t) );
  FD_TEST( stats->insert_cnt==1UL );
  FD_TEST( stats->write_bytes==sizeof(fd_shredb_entry_t) );

  fd_shredb_entry_t raw_entry[1];
  FD_TEST( pread( disk_fd, raw_entry, sizeof(fd_shredb_entry_t), (off_t)store->wire_off )==(long)sizeof(fd_shredb_entry_t) );
  ulong first_shred_sz = fd_shred_sz( shred );
  FD_TEST( first_shred_sz<FD_SHRED_MAX_SZ );
  FD_TEST( !raw_entry->shred[ first_shred_sz ] );
  ulong first_tag = raw_entry->tag;

  fd_memset( buf, 0, sizeof(buf) );
  shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  shred->slot      = 43UL;
  shred->idx       = 3U;
  shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;
  shred->data.flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;

  FD_TEST( fd_store_disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );
  /* An unrelated metadata update does not invalidate this binding. */
  FD_TEST( pread( disk_fd, raw_entry, sizeof(fd_shredb_entry_t), (off_t)store->wire_off )==(long)sizeof(fd_shredb_entry_t) );
  FD_TEST( raw_entry->tag==first_tag );

  FD_TEST( fd_store_disk_query_highest( store, disk_fd, 43UL, 4U, out )>0 );
  fd_shred_t const * result = (fd_shred_t const *)fd_type_pun_const( out );
  FD_TEST( result->slot==43UL );
  FD_TEST( result->idx==3U );
  FD_TEST( result->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_many_wraps( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL,
                                                    TEST_PAYLOAD_PATH, 42UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 16UL;
  atomic_store_explicit( &store->disk_reservation_head, (1UL<<32)-80UL, memory_order_relaxed );

  int disk_fd = store_file_open( store, O_RDWR );
  FD_TEST( disk_fd>=0 );

  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];
  for( ulong i=0UL; i<160UL; i++ ) {
    fd_memset( buf, 0, sizeof(buf) );
    fd_shred_t * shred = fd_type_pun( buf );
    shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
    shred->slot      = i/4UL;
    shred->idx       = (uint)(i%4UL);
    shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+1UL);
    buf[ FD_SHRED_DATA_HEADER_SZ ] = (uchar)i;
    FD_TEST( fd_store_disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );
  }
  FD_TEST( atomic_load_explicit( &store->disk_cnt, memory_order_relaxed )==16UL );
  for( ulong i=144UL; i<160UL; i++ ) {
    int sz = fd_store_disk_query( store, disk_fd, i/4UL, (uint)(i%4UL), out );
    FD_TEST( sz>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==(uchar)i );
  }
  FD_TEST( fd_store_disk_query( store, disk_fd, 35UL, 3U, out )==FD_STORE_DISK_QUERY_MISS );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_concurrent_writes( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL,
                                                    TEST_PAYLOAD_PATH, 42UL ) );
  FD_TEST( store );
  store->disk_max_shreds = fd_ulong_max( 16UL, 2UL*fd_tile_cnt() );
  int disk_fd = store_file_open( store, O_RDWR );
  FD_TEST( disk_fd>=0 );

  ulong tile_cnt = fd_tile_cnt();
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    fd_memset( disk_concurrent_shred[ tile_idx ], 0, FD_SHRED_MAX_SZ );
    fd_shred_t * shred = fd_type_pun( disk_concurrent_shred[ tile_idx ] );
    shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
    shred->slot      = 100UL + tile_idx;
    shred->idx       = 0U;
    shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;
    disk_concurrent_result[ tile_idx ] = FD_STORE_DISK_INSERT_ERR;
  }

  disk_concurrent_store = store;
  disk_concurrent_fd    = disk_fd;
  atomic_store_explicit( &disk_concurrent_go, 0UL, memory_order_relaxed );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    fd_tile_exec_new( tile_idx, disk_tile_insert_concurrent, 0, NULL );
  atomic_store_explicit( &disk_concurrent_go, 1UL, memory_order_release );
  FD_TEST( !disk_tile_insert_concurrent( 0, NULL ) );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );

  uchar out[ FD_SHRED_MAX_SZ ];
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    FD_TEST( disk_concurrent_result[ tile_idx ]==FD_STORE_DISK_INSERT_SUCCESS );
    FD_TEST( fd_store_disk_query( store, disk_fd, 100UL+tile_idx, 0U, out )>0 );
  }
  FD_TEST( atomic_load_explicit( &store->disk_cnt, memory_order_relaxed )==tile_cnt );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_slot_hint( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL,
                                                    TEST_PAYLOAD_PATH, 42UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 4UL;

  int disk_fd = store_file_open( store, O_RDWR );
  FD_TEST( disk_fd>=0 );

  ulong const stride = store->disk_max_slots;
  ulong const slot_a = 17UL;
  ulong const slot_b = slot_a + stride;
  ulong const slot_c = slot_b + stride;
  FD_TEST( stride>8UL && !(slot_c>>48) );
  FD_TEST( slot_a%stride==slot_b%stride && slot_b%stride==slot_c%stride );

  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];

  /* A lower-index colliding slot cannot lower or steal the bucket
     watermark.  Its exact shred remains independently readable. */
  FD_TEST( fd_store_disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_a, 10U, 0xa1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_b, 5U, 0xb1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_b, 5U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xb1U );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_b, 0U, out )==FD_STORE_DISK_QUERY_BUSY );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_a, 0U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xa1U );

  /* A higher index may claim the bucket, but that only makes the old
     owner conservative-BUSY; it does not affect exact reads. */
  FD_TEST( fd_store_disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_c, 11U, 0xc1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_c, 0U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xc1U );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_a, 0U, out )==FD_STORE_DISK_QUERY_BUSY );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_a, 10U, out )>0 );

  /* Advance the four-cell ring until slot_c:11 is evicted.  The hint is
     intentionally never lowered or removed, so a missing hinted exact
     key must return SCAN_LIMIT rather than a false lower result. */
  for( ulong i=0UL; i<4UL; i++ )
    FD_TEST( fd_store_disk_insert( store, disk_fd,
                                   disk_make_shred( buf, slot_a+1UL+i, 0U, (uchar)(0xd0U+i) ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_c, 11U, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_c, 0U, out )==FD_STORE_DISK_QUERY_SCAN_LIMIT );

  FD_TEST( fd_store_disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_c, 3U, 0xc2U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_c, 3U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xc2U );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_c, 0U, out )==FD_STORE_DISK_QUERY_SCAN_LIMIT );
  FD_TEST( fd_store_disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_c, FD_SHRED_BLK_MAX, 0xc3U ) )==FD_STORE_DISK_INSERT_ERR );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_lazy_highest( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL,
                                                    TEST_PAYLOAD_PATH, 42UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 2UL;

  int disk_fd = store_file_open( store, O_RDWR );
  FD_TEST( disk_fd>=0 );
  uchar buf[ FD_SHRED_MAX_SZ ];
  uint idxs[3] = { 30000U, 0U, 0U };
  ulong slots[3] = { 7UL, 7UL, 8UL };
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( buf, 0, sizeof(buf) );
    fd_shred_t * shred = fd_type_pun( buf );
    shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
    shred->slot      = slots[i];
    shred->idx       = idxs[i];
    shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;
    FD_TEST( fd_store_disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );
  }

  uchar out[ FD_SHRED_MAX_SZ ];
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, 7UL, 0U, out )==FD_STORE_DISK_QUERY_SCAN_LIMIT );
  FD_TEST( fd_store_disk_query( store, disk_fd, 7UL, 0U, out )>0 );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_collision_eviction( fd_wksp_t * wksp ) {
  ulong const seed = 42UL;
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL,
                                                    TEST_PAYLOAD_PATH, seed ) );
  FD_TEST( store );
  store->disk_max_shreds = 2UL;

  int disk_fd = store_file_open( store, O_RDWR );
  FD_TEST( disk_fd>=0 );

  /* Keep the physical maps large but force the ring to wrap after two
     entries.  The keys deliberately land in the same hash chain, which
     exercises removal by stable ring index during eviction. */
  ulong keys[ 3 ];
  ulong key_cnt = 0UL;
  for( ulong upper=1UL; key_cnt<3UL; upper++ ) {
    ulong key = fd_ulong_hash_inverse( (upper<<32) | 0xdeadbeefUL ) ^ seed;
    if( fd_shredb_key_shred_idx( key )>=FD_SHRED_BLK_MAX ) continue;
    keys[ key_cnt++ ] = key;
  }
  FD_TEST( keys[ 0 ]!=keys[ 1 ] );
  FD_TEST( (uint)fd_ulong_hash( keys[ 0 ] ^ seed )==(uint)fd_ulong_hash( keys[ 1 ] ^ seed ) );

  uchar payloads[ 3 ] = { 1U, 2U, 3U };
  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( buf, 0, sizeof(buf) );
    fd_shred_t * shred = (fd_shred_t *)fd_type_pun( buf );
    shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
    shred->slot      = fd_shredb_key_slot( keys[ i ] );
    shred->idx       = fd_shredb_key_shred_idx( keys[ i ] );
    shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+1UL);
    buf[ FD_SHRED_DATA_HEADER_SZ ] = payloads[ i ];

    FD_TEST( fd_store_disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );
  }

  FD_TEST( fd_store_disk_query( store, disk_fd, fd_shredb_key_slot( keys[ 0 ] ), fd_shredb_key_shred_idx( keys[ 0 ] ), out )==FD_STORE_DISK_QUERY_MISS );
  for( ulong i=1UL; i<3UL; i++ ) {
    FD_TEST( fd_store_disk_query( store, disk_fd, fd_shredb_key_slot( keys[ i ] ), fd_shredb_key_shred_idx( keys[ i ] ), out )>0 );
    FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==payloads[ i ] );
  }

  /* A malformed in-memory header must not make the fixed-size disk
     entry copy past either its source or destination buffer. */
  fd_memset( buf, 0, sizeof(buf) );
  fd_shred_t * oversized = (fd_shred_t *)fd_type_pun( buf );
  oversized->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  oversized->slot      = 9UL;
  oversized->idx       = 0U;
  oversized->data.size = USHRT_MAX;
  FD_TEST( fd_store_disk_insert( store, disk_fd, oversized )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, 9UL, 0U, out )==(int)FD_SHRED_MAX_SZ );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

/* Concurrent insert test: multiple tiles insert distinct keys into the
   shared map with no external locking.  Verifies fd_map_chain_para's
   per-chain locking correctly serializes concurrent inserts. */

static ulong        tile_go;
static ulong        num_insert = 64;
static fd_store_t * g_store;
static atomic_ulong unique_insert_success_cnt;

static int
shred_tile_insert( int argc, char ** argv ) {
  (void)argc; (void)argv;

  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( g_store, map ) );

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  ulong tile_idx = fd_tile_idx();
  for( ulong i = 1; i < num_insert; i++ ) {
    fd_hash_t mr = { .ul = { (i << 16) | tile_idx } };
    fd_store_fec_t * fec;
    FD_TEST( !fd_store_insert( g_store, map, &mr, &fec ) && fec );
  }
  return 0;
}

static int
shred_tile_insert_same( int argc FD_PARAM_UNUSED,
                        char ** argv FD_PARAM_UNUSED ) {
  fd_store_map_t map[1];
  FD_TEST( fd_store_map_ljoin( g_store, map ) );
  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  fd_hash_t mr = { .ul = { 0xdeadbeefUL } };
  fd_store_fec_t * fec;
  int err = fd_store_insert( g_store, map, &mr, &fec );
  if( FD_LIKELY( !err ) ) atomic_fetch_add_explicit( &unique_insert_success_cnt, 1UL, memory_order_relaxed );
  else FD_TEST( err==FD_MAP_ERR_KEY && !fec );
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

  /* Exactly one tile may insert this key. */
  FD_VOLATILE( tile_go ) = 0UL;
  atomic_store_explicit( &unique_insert_success_cnt, 0UL, memory_order_relaxed );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    fd_tile_exec_new( tile_idx, shred_tile_insert_same, 0, NULL );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( tile_go ) = 1UL;
  FD_COMPILER_MFENCE();
  FD_TEST( !shred_tile_insert_same( 0, NULL ) );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );
  FD_TEST( atomic_load_explicit( &unique_insert_success_cnt, memory_order_relaxed )==1UL );
  fd_hash_t unique_mr = { .ul = { 0xdeadbeefUL } };
  FD_TEST( fd_store_query( map, &unique_mr ) );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( g_store ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  int require_multitile = fd_env_strip_cmdline_contains( &argc, &argv, "--require-multitile" );
  if( FD_UNLIKELY( require_multitile && fd_tile_cnt()<2UL ) )
    FD_LOG_ERR(( "--require-multitile needs at least two tile CPUs" ));

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"              );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                     );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_api         ( wksp );
  test_db_path     ( wksp );
  test_file_open   ( wksp );
  test_pread_all   ();
  test_query_miss  ( wksp );
  test_fec_data_max( wksp );
  test_fec_sets_arena( wksp );
  test_spill       ( wksp );
  test_pinned_spill( wksp );
  test_disk_query_highest( wksp );
  test_disk_collision_eviction( wksp );
  test_disk_many_wraps( wksp );
  test_disk_concurrent_writes( wksp );
  test_disk_slot_hint( wksp );
  test_disk_lazy_highest( wksp );
  test_concurrent  ( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
