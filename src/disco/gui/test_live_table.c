#include "../fd_disco.h"

uchar scratch[ 256 ] __attribute__((aligned(256UL)));

#define TEST_LIVE_TABLE_ROW_CNT          (10000UL)
#define TEST_LIVE_TABLE_MAX_SORT_KEY_CNT (    2UL)
struct test_live_table_row {
  struct {
    ulong parent;
    ulong left;
    ulong right;
  } treaps[ TEST_LIVE_TABLE_MAX_SORT_KEY_CNT ];
  ulong prio;
  ulong sort_keys;
  struct {
    ulong prev;
    ulong next;
  } dlist;

  fd_pubkey_t key;
  uint ipv4;
  ulong counter;
};
typedef struct test_live_table_row test_live_table_row_t;

static int live_table_col_pubkey_lt ( void const * a, void const * b ) { return memcmp( (fd_pubkey_t *)a, (fd_pubkey_t *)b, 32UL ) < 0; }
static int live_table_col_ipv4_lt   ( void const * a, void const * b ) { return *(uint *)a < *(uint *)b;                                }
static int live_table_col_counter_lt( void const * a, void const * b ) { return *(ulong *)a < *(ulong *)b;                              }

#define LIVE_TABLE_NAME test_live_table
#define LIVE_TABLE_COLUMN_CNT (3UL)
#define LIVE_TABLE_SORT_KEYS sort_keys
#define LIVE_TABLE_DLIST dlist
#define LIVE_TABLE_MAX_SORT_KEY_CNT TEST_LIVE_TABLE_MAX_SORT_KEY_CNT
#define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( LIVE_TABLE_COL_ENTRY("Pubkey", key, live_table_col_pubkey_lt), LIVE_TABLE_COL_ENTRY("IP Address", ipv4, live_table_col_ipv4_lt), LIVE_TABLE_COL_ENTRY("Some Metric", counter, live_table_col_counter_lt) )
#define LIVE_TABLE_ROW_T test_live_table_row_t
#include "fd_gui_live_table_tmpl.c"

#define TEST_LIVE_TABLE32_MAX_SORT_KEY_CNT (2UL)
struct test_live_table32_row {
  struct {
    uint parent;
    uint left;
    uint right;
  } treaps[ TEST_LIVE_TABLE32_MAX_SORT_KEY_CNT ];
  uint prio;
  ulong sort_keys;
  struct {
    ulong prev;
    ulong next;
  } dlist;

  uint value;
};
typedef struct test_live_table32_row test_live_table32_row_t;

static int
live_table32_col_value_lt( void const * a,
                           void const * b ) {
  return *(uint *)a < *(uint *)b;
}

#define LIVE_TABLE_NAME test_live_table32
#define LIVE_TABLE_COLUMN_CNT (1UL)
#define LIVE_TABLE_IDX_T uint
#define LIVE_TABLE_SORT_KEYS sort_keys
#define LIVE_TABLE_DLIST dlist
#define LIVE_TABLE_MAX_SORT_KEY_CNT TEST_LIVE_TABLE32_MAX_SORT_KEY_CNT
#define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( LIVE_TABLE_COL_ENTRY("Value", value, live_table32_col_value_lt) )
#define LIVE_TABLE_ROW_T test_live_table32_row_t
#include "fd_gui_live_table_tmpl.c"
#ifdef LIVE_TABLE_IDX_T
#undef LIVE_TABLE_IDX_T
#endif

/* A table with more sort key slots than one bitmap word, to exercise
   slot allocation, iteration and eviction across words. */

#define TEST_LIVE_TABLE_WIDE_MAX_SORT_KEY_CNT (130UL)
struct test_live_table_wide_row {
  struct {
    uint parent;
    uint left;
    uint right;
  } treaps[ TEST_LIVE_TABLE_WIDE_MAX_SORT_KEY_CNT ];
  uint  prio;
  ulong sort_keys;
  struct {
    ulong prev;
    ulong next;
  } dlist;

  ulong a;
  ulong b;
  ulong c;
};
typedef struct test_live_table_wide_row test_live_table_wide_row_t;

static int
live_table_wide_col_lt( void const * a,
                        void const * b ) {
  return *(ulong *)a < *(ulong *)b;
}

#define LIVE_TABLE_NAME test_live_table_wide
#define LIVE_TABLE_COLUMN_CNT (3UL)
#define LIVE_TABLE_IDX_T uint
#define LIVE_TABLE_SORT_KEYS sort_keys
#define LIVE_TABLE_DLIST dlist
#define LIVE_TABLE_MAX_SORT_KEY_CNT TEST_LIVE_TABLE_WIDE_MAX_SORT_KEY_CNT
#define LIVE_TABLE_COLUMNS LIVE_TABLE_COL_ARRAY( LIVE_TABLE_COL_ENTRY("A", a, live_table_wide_col_lt), LIVE_TABLE_COL_ENTRY("B", b, live_table_wide_col_lt), LIVE_TABLE_COL_ENTRY("C", c, live_table_wide_col_lt) )
#define LIVE_TABLE_ROW_T test_live_table_wide_row_t
#include "fd_gui_live_table_tmpl.c"
#ifdef LIVE_TABLE_IDX_T
#undef LIVE_TABLE_IDX_T
#endif

/* wide_key_i returns the i-th of 72 distinct sort keys over three
   columns: the 48 keys ordering all three columns (6 orders x 8 sign
   patterns) then the 24 ordering two (6 orders x 4 sign patterns, the
   third column unsorted). */

#define WIDE_KEY_CNT (72UL)

static test_live_table_wide_sort_key_t
wide_key_i( ulong i ) {
  static ulong const perm[ 6 ][ 3 ] = { {0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0} };
  test_live_table_wide_sort_key_t key;
  ulong p, signs, active;
  if( i<48UL ) { p = i/8UL;         signs = i%8UL;         active = 3UL; }
  else         { p = (i-48UL)/4UL;  signs = (i-48UL)%4UL;  active = 2UL; }
  for( ulong c=0UL; c<3UL; c++ ) {
    key.col[ c ] = perm[ p ][ c ];
    key.dir[ c ] = c<active ? (((signs>>c)&1UL) ? -1 : 1) : 0;
  }
  return key;
}

static void
test_wide( void ) {
#define WIDE_ROW_CNT (64UL)
  static test_live_table_wide_row_t pool[ WIDE_ROW_CNT ];
  static uchar mem[ 32768 ] __attribute__((aligned(256UL)));
  FD_TEST( sizeof(mem)>=test_live_table_wide_footprint( WIDE_ROW_CNT ) );
  test_live_table_wide_t * table = test_live_table_wide_join( test_live_table_wide_new( mem, WIDE_ROW_CNT ) );
  FD_TEST( table );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 7U, 0UL ) );
  for( ulong i=0UL; i<WIDE_ROW_CNT; i++ ) {
    pool[ i ].a = fd_rng_ulong_roll( rng, 4UL );
    pool[ i ].b = fd_rng_ulong_roll( rng, 4UL );
    pool[ i ].c = i;
  }
  test_live_table_wide_seed( pool, WIDE_ROW_CNT, 45UL );
  for( ulong i=0UL; i<WIDE_ROW_CNT/2UL; i++ ) test_live_table_wide_idx_insert( table, i, pool );

  /* activate 72 distinct keys, across both bitmap words, with row
     churn in between; every active treap stays consistent */
  for( ulong k=0UL; k<WIDE_KEY_CNT; k++ ) {
    test_live_table_wide_sort_key_t key = wide_key_i( k );
    ulong cnt = 0UL;
    for( test_live_table_wide_fwd_iter_t it = test_live_table_wide_fwd_iter_init( table, &key, pool ); !test_live_table_wide_fwd_iter_done( it ); it = test_live_table_wide_fwd_iter_next( it, pool ) ) cnt++;
    FD_TEST( cnt==test_live_table_wide_ele_cnt( table ) );
    FD_TEST( test_live_table_wide_active_sort_key_cnt( table )==k+1UL );
    ulong r = fd_rng_ulong_roll( rng, WIDE_ROW_CNT );
    if( r<WIDE_ROW_CNT/2UL ) { test_live_table_wide_idx_remove( table, r, pool ); pool[ r ].a = fd_rng_ulong_roll( rng, 4UL ); test_live_table_wide_idx_insert( table, r, pool ); }
    else if( k&1UL )         { test_live_table_wide_idx_insert( table, r, pool ); test_live_table_wide_idx_remove( table, r, pool ); }
    FD_TEST( !test_live_table_wide_verify( table, pool ) );
  }
  FD_TEST( test_live_table_wide_active_sort_key_cnt( table )==WIDE_KEY_CNT );

  /* remove keys from both words, then re-add into the freed slots */
  for( ulong k=0UL; k<WIDE_KEY_CNT; k+=3UL ) { test_live_table_wide_sort_key_t key = wide_key_i( k ); test_live_table_wide_sort_key_remove( table, &key ); }
  FD_TEST( test_live_table_wide_active_sort_key_cnt( table )==WIDE_KEY_CNT-24UL );
  for( ulong k=0UL; k<WIDE_KEY_CNT; k+=3UL ) {
    test_live_table_wide_sort_key_t key = wide_key_i( k );
    ulong cnt = 0UL;
    for( test_live_table_wide_fwd_iter_t it = test_live_table_wide_fwd_iter_init( table, &key, pool ); !test_live_table_wide_fwd_iter_done( it ); it = test_live_table_wide_fwd_iter_next( it, pool ) ) cnt++;
    FD_TEST( cnt==test_live_table_wide_ele_cnt( table ) );
  }
  FD_TEST( test_live_table_wide_active_sort_key_cnt( table )==WIDE_KEY_CNT );
  FD_TEST( !test_live_table_wide_verify( table, pool ) );

  /* every row ends up in every active treap: the ordered walk of each
     key is a permutation consistent with lt */
  for( ulong k=0UL; k<WIDE_KEY_CNT; k++ ) {
    test_live_table_wide_sort_key_t key = wide_key_i( k );
    test_live_table_wide_row_t const * prev = NULL;
    ulong cnt = 0UL;
    for( test_live_table_wide_fwd_iter_t it = test_live_table_wide_fwd_iter_init( table, &key, pool ); !test_live_table_wide_fwd_iter_done( it ); it = test_live_table_wide_fwd_iter_next( it, pool ) ) {
      test_live_table_wide_row_t const * cur = test_live_table_wide_fwd_iter_ele_const( it, pool );
      if( prev ) FD_TEST( !test_live_table_wide_lt( &key, cur, prev ) );
      prev = cur;
      cnt++;
    }
    FD_TEST( cnt==test_live_table_wide_ele_cnt( table ) );
  }

  FD_TEST( test_live_table_wide_delete( test_live_table_wide_leave( table ) ) );
  fd_rng_delete( fd_rng_leave( rng ) );
#undef WIDE_ROW_CNT
#undef WIDE_KEY_CNT
}

static inline int
test_live_table_key( test_live_table_t * table, test_live_table_sort_key_t const * key,  test_live_table_row_t * pool, ulong const * expected, ulong const expected_sz ) {
  for( test_live_table_fwd_iter_t iter = test_live_table_fwd_iter_init( table, key, pool ), i = 0; !test_live_table_fwd_iter_done( iter ); iter = test_live_table_fwd_iter_next( iter, pool ), i++ ) {
    if( i>=expected_sz ) {
      FD_LOG_WARNING(( "i=%lu < expected_sz=%lu", i, expected_sz ));
      return 0;
    }
    if( test_live_table_fwd_iter_idx( iter )!=expected[ i ] ) {
      FD_LOG_WARNING(( "expected=%lu actual=%lu", expected[ i ], test_live_table_fwd_iter_idx( iter ) ));
      return 0;
    }
  }
  return 1;
}

int
main( int argc, char ** argv ) {
  (void)argc; (void)argv;

  FD_TEST( test_live_table32_idx_null()==(ulong)UINT_MAX );

  uchar scratch32[ 256 ] __attribute__((aligned(256UL)));
  FD_TEST( sizeof(scratch32)==test_live_table32_footprint( 3UL ) );
  test_live_table32_t * table32 = test_live_table32_join( test_live_table32_new( scratch32, 3UL ) );
  test_live_table32_row_t pool32[] = {
    { .value = 2U },
    { .value = 0U },
    { .value = 1U },
  };
  test_live_table32_sort_key_t key32 = { .col = { 0UL }, .dir = { 1 } };
  test_live_table32_seed( pool32, 3UL, 42UL );
  for( ulong i=0UL; i<3UL; i++ ) test_live_table32_idx_insert( table32, i, pool32 );
  ulong expected32[] = { 1UL, 2UL, 0UL };
  ulong i = 0UL;
  for( test_live_table32_fwd_iter_t iter = test_live_table32_fwd_iter_init( table32, &key32, pool32 );
       !test_live_table32_fwd_iter_done( iter );
       iter = test_live_table32_fwd_iter_next( iter, pool32 ) ) {
    FD_TEST( i<3UL );
    FD_TEST( test_live_table32_fwd_iter_idx( iter )==expected32[ i++ ] );
  }
  FD_TEST( i==3UL );
  FD_TEST( !test_live_table32_verify( table32, pool32 ) );
  FD_TEST( test_live_table32_delete( test_live_table32_leave( table32 ) ) );

  if( sizeof(scratch)!=test_live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) ) {
    FD_LOG_ERR(("scratch_sz=%lu != test_live_table_footprint( %lu )=%lu", sizeof(scratch), TEST_LIVE_TABLE_ROW_CNT, test_live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) ));
  }

  test_live_table_t * table = test_live_table_join( test_live_table_new( scratch, TEST_LIVE_TABLE_ROW_CNT ) );

  FD_TEST( !strcmp( test_live_table_col_idx_to_name( table, 2 ), "Some Metric" ) );
  FD_TEST( !strcmp( test_live_table_col_idx_to_name( table, 0 ), "Pubkey" )      );
  FD_TEST( !strcmp( test_live_table_col_idx_to_name( table, 1 ), "IP Address" )  );
  FD_TEST( test_live_table_col_idx_to_name( table, ULONG_MAX )==NULL             );

  FD_TEST( test_live_table_col_name_to_idx( table, "Some Metric" )==2 );
  FD_TEST( test_live_table_col_name_to_idx( table, "Pubkey" )==0 );
  FD_TEST( test_live_table_col_name_to_idx( table, "IP Address" )==1 );
  FD_TEST( test_live_table_col_name_to_idx( table, "NOT PRESENT" )==ULONG_MAX);

  test_live_table_row_t pool[] = {
    { .key = { .uc = { 0UL } }, .ipv4 = 1, .counter = 8 },
    { .key = { .uc = { 1UL } }, .ipv4 = 0, .counter = 7 },
    { .key = { .uc = { 2UL } }, .ipv4 = 2, .counter = 6 },
    { .key = { .uc = { 3UL } }, .ipv4 = 4, .counter = 5 },
  };

  test_live_table_sort_key_t keys[] = {
    { .col = { 0, 1, 2 }, .dir =  {  0,  1,  0 } },
    { .col = { 0, 1, 2 }, .dir =  {  0, -1,  0 } },
    { .col = { 0, 1, 2 }, .dir =  { -1, -1,  0 } },
    { .col = { 0, 1, 2 }, .dir =  {  0,  1,  0 } }, /* identical to keys[ 0 ]  */
    { .col = { 0, 2, 1 }, .dir =  {  0,  0,  1 } }  /* isomorphic to keys[ 0 ] */
  };

  test_live_table_seed( pool, 4UL, 42UL );
  FD_TEST( test_live_table_ele_cnt( table )==0UL );
  test_live_table_idx_insert( table, 0UL, pool );
  test_live_table_idx_insert( table, 1UL, pool );
  test_live_table_idx_insert( table, 2UL, pool );
  FD_TEST( test_live_table_ele_max( table )==TEST_LIVE_TABLE_ROW_CNT );
  FD_TEST( test_live_table_ele_cnt( table )==3UL );

  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 0, 2 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key0 */
  FD_TEST( test_live_table_key( table, &keys[ 3 ], pool, (ulong[]){ 1, 0, 2 }, 3UL ) );

  /* test insert equivalent keys. key0==key3==key4 */
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key0 */
  FD_TEST( test_live_table_key( table, &keys[ 4 ], pool, (ulong[]){ 1, 0, 2 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key0 */
  test_live_table_sort_key_remove( table, &keys[ 2 ] ); /* removing nonexisting key is NOP */
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL );
  test_live_table_sort_key_remove( table, &keys[ 4 ] );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==0UL );

  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 0, 2 }, 3UL ) );
  FD_TEST( test_live_table_key( table, &keys[ 1 ], pool, (ulong[]){ 2, 0, 1 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key0 + key1 */

  /* insert new row */
  test_live_table_idx_insert( table, 3UL, pool );
  FD_TEST( test_live_table_ele_cnt( table )==4UL );

  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 0, 2, 3 }, 4UL ) );
  FD_TEST( test_live_table_key( table, &keys[ 1 ], pool, (ulong[]){ 3, 2, 0, 1 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key0 + key1 */

  /* update existing row */
  test_live_table_idx_remove( table, 0UL, pool );
  pool[ 0 ] = (test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 3 };
  test_live_table_idx_insert( table, 0UL, pool );

  FD_TEST( test_live_table_key( table, &keys[ 1 ], pool, (ulong[]){ 3, 0, 2, 1 }, 4UL ) );
  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 2, 0, 3 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key0 + key1 */

  /* evict keys[ 0 ] */
  test_live_table_sort_key_remove( table, &keys[ 0 ] );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key1 */
  FD_TEST( test_live_table_key( table, &keys[ 2 ], pool, (ulong[]){ 3, 2, 1, 0 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key1 + key2 */

  /* evict keys[ 1 ] */
  test_live_table_sort_key_remove( table, &keys[ 1 ] );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key2 */
  FD_TEST( test_live_table_key( table, &keys[ 0 ], pool, (ulong[]){ 1, 2, 0, 3 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key2 + key0 */

  /* evict keys[ 2 ] */
  test_live_table_sort_key_remove( table, &keys[ 2 ] );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==1UL ); /* key0 */
  FD_TEST( test_live_table_key( table, &keys[ 1 ], pool, (ulong[]){ 3, 0, 2, 1 }, 4UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( table )==2UL ); /* key0 + key1 */

  FD_TEST( !test_live_table_verify( table, pool ) );

  /* test lt */
  FD_TEST( 0==test_live_table_lt( &(test_live_table_sort_key_t){ .col = { 0, 1, 2 }, .dir =  {  0, 0, 0 } }, &(test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 0, .counter = 0 }, &(test_live_table_row_t){ .key = { .uc = { 1UL } }, .ipv4 = 1, .counter = 1 } ) );
  FD_TEST( 0==test_live_table_lt( &(test_live_table_sort_key_t){ .col = { 0, 1, 2 }, .dir =  {  0, 0, 0 } }, &(test_live_table_row_t){ .key = { .uc = { 1UL } }, .ipv4 = 1, .counter = 1 }, &(test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 0, .counter = 0 } ) );
  FD_TEST( 1==test_live_table_lt( &(test_live_table_sort_key_t){ .col = { 0, 1, 2 }, .dir =  {  0, 1, 0 } }, &(test_live_table_row_t){ .key = { .uc = { 1UL } }, .ipv4 = 0, .counter = 1 }, &(test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 1, .counter = 0 } ) );
  FD_TEST( 0==test_live_table_lt( &(test_live_table_sort_key_t){ .col = { 0, 1, 2 }, .dir =  {  0, 1, 0 } }, &(test_live_table_row_t){ .key = { .uc = { 0UL } }, .ipv4 = 1, .counter = 0 }, &(test_live_table_row_t){ .key = { .uc = { 1UL } }, .ipv4 = 0, .counter = 1 } ) );

  FD_TEST( test_live_table_delete( test_live_table_leave( table ) ) );

  uchar reg_scratch[ 256 ] __attribute__((aligned(256UL)));
  FD_TEST( sizeof(reg_scratch)==test_live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) );

  test_live_table_t * reg_table = test_live_table_join( test_live_table_new( reg_scratch, TEST_LIVE_TABLE_ROW_CNT ) );

  test_live_table_row_t reg_pool[] = {
    { .key = { .uc = { 0UL } }, .ipv4 = 0U, .counter = 0UL },
    { .key = { .uc = { 0UL } }, .ipv4 = 0U, .counter = 1UL },
    { .key = { .uc = { 1UL } }, .ipv4 = 0U, .counter = 0UL },
  };

  test_live_table_seed( reg_pool, 3UL, 43UL );
  test_live_table_idx_insert( reg_table, 0UL, reg_pool );
  test_live_table_idx_insert( reg_table, 1UL, reg_pool );
  test_live_table_idx_insert( reg_table, 2UL, reg_pool );

  test_live_table_sort_key_t key_with_tie_break = { .col = { 0, 1, 2 }, .dir = { 1, 1, -1 } };
  test_live_table_sort_key_t key_without_tie_break = { .col = { 0, 1, 2 }, .dir = { 1, 1,  0 } };

  FD_TEST( test_live_table_key( reg_table, &key_with_tie_break,    reg_pool, (ulong[]){ 1UL, 0UL, 2UL }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( reg_table )==1UL );
  FD_TEST( test_live_table_key( reg_table, &key_without_tie_break, reg_pool, (ulong[]){ 0UL, 1UL, 2UL }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( reg_table )==2UL );

  FD_TEST( test_live_table_delete( test_live_table_leave( reg_table ) ) );

  /* Test fwd_iter_init eviction */
  uchar evict_scratch[ 256 ] __attribute__((aligned(256UL)));
  FD_TEST( sizeof(evict_scratch)==test_live_table_footprint( TEST_LIVE_TABLE_ROW_CNT ) );

  test_live_table_t * evict_table = test_live_table_join( test_live_table_new( evict_scratch, TEST_LIVE_TABLE_ROW_CNT ) );

  test_live_table_row_t evict_pool[] = {
    { .key = { .uc = { 0UL } }, .ipv4 = 2, .counter = 30 },
    { .key = { .uc = { 1UL } }, .ipv4 = 0, .counter = 20 },
    { .key = { .uc = { 2UL } }, .ipv4 = 1, .counter = 10 },
  };

  test_live_table_seed( evict_pool, 3UL, 44UL );
  test_live_table_idx_insert( evict_table, 0UL, evict_pool );
  test_live_table_idx_insert( evict_table, 1UL, evict_pool );
  test_live_table_idx_insert( evict_table, 2UL, evict_pool );

  /* Three distinct sort keys — only 2 cache slots available. */
  test_live_table_sort_key_t evict_key0 = { .col = { 0, 1, 2 }, .dir = {  1, 0, 0 } }; /* asc pubkey   */
  test_live_table_sort_key_t evict_key1 = { .col = { 1, 0, 2 }, .dir = {  1, 0, 0 } }; /* asc ipv4     */
  test_live_table_sort_key_t evict_key2 = { .col = { 2, 0, 1 }, .dir = { -1, 0, 0 } }; /* desc counter */

  /* Fill both cache slots. */
  FD_TEST( test_live_table_key( evict_table, &evict_key0, evict_pool, (ulong[]){ 0, 1, 2 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( evict_table )==1UL );
  FD_TEST( test_live_table_key( evict_table, &evict_key1, evict_pool, (ulong[]){ 1, 2, 0 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( evict_table )==2UL );

  /* 3rd key triggers auto-eviction inside fwd_iter_init. */
  FD_TEST( test_live_table_key( evict_table, &evict_key2, evict_pool, (ulong[]){ 0, 1, 2 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( evict_table )==2UL ); /* still 2 — one evicted, one created */

  /* The evicted key should be transparently rebuilt on re-query. */
  FD_TEST( test_live_table_key( evict_table, &evict_key0, evict_pool, (ulong[]){ 0, 1, 2 }, 3UL ) );
  FD_TEST( test_live_table_active_sort_key_cnt( evict_table )==2UL );

  /* Cycle through all three keys repeatedly to stress the eviction
     path — each call evicts and rebuilds. */
  for( ulong round=0UL; round<4UL; round++ ) {
    FD_TEST( test_live_table_key( evict_table, &evict_key0, evict_pool, (ulong[]){ 0, 1, 2 }, 3UL ) );
    FD_TEST( test_live_table_key( evict_table, &evict_key1, evict_pool, (ulong[]){ 1, 2, 0 }, 3UL ) );
    FD_TEST( test_live_table_key( evict_table, &evict_key2, evict_pool, (ulong[]){ 0, 1, 2 }, 3UL ) );
    FD_TEST( test_live_table_active_sort_key_cnt( evict_table )==2UL );
  }

  FD_TEST( !test_live_table_verify( evict_table, evict_pool ) );
  FD_TEST( test_live_table_delete( test_live_table_leave( evict_table ) ) );

  test_wide();

  FD_LOG_INFO(( "PASSED" ));
  return 0;
}
