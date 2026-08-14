#include "../../util/fd_util.h"
#include "fd_gui_store.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* DBs for the test. */
#define DB_ENT8  (0UL)  /* entity, 8-byte key  (key + payload)          */
#define DB_ENT16 (1UL)  /* entity, 16-byte key ((slot,bank_seq)+payload) */
#define DB_ENTBIG (2UL) /* entity, 8-byte key, 256-byte value           */
#define DB_TS    (3UL)  /* time-series, 8-byte val                      */
#define DB_CNT   (4UL)

struct ent8_val  { ulong key;                  ulong payload; };
struct ent16_val { ulong slot; ulong bank_seq; ulong payload; };
typedef struct ent8_val  ent8_val_t;
typedef struct ent16_val ent16_val_t;

struct ts_val { long ts; ulong seq; };
typedef struct ts_val ts_val_t;

static ulong
ent_key_hash( void const * key ) {
  return fd_ulong_hash( ((ulong const *)key)[ 0 ] );
}

static int
ent8_key_cmp( void const * a, void const * b ) {
  ulong ka = ((ulong const *)a)[ 0 ];
  ulong kb = ((ulong const *)b)[ 0 ];
  if( ka<kb ) return -1;
  if( ka>kb ) return  1;
  return 0;
}

static int
ent16_key_cmp( void const * a, void const * b ) {
  ulong const * ka = a;
  ulong const * kb = b;
  if( ka[ 0 ]<kb[ 0 ] ) return -1;
  if( ka[ 0 ]>kb[ 0 ] ) return  1;
  if( ka[ 1 ]==ULONG_MAX || kb[ 1 ]==ULONG_MAX ) return 0;
  if( ka[ 1 ]<kb[ 1 ] ) return -1;
  if( ka[ 1 ]>kb[ 1 ] ) return  1;
  return 0;
}

static fd_gui_store_desc_t const descs[] = {
  { .name="ent8",  .kind=FD_GUI_STORE_KIND_KV, .key_off=0UL, .key_sz=8UL,  .key_hash=ent_key_hash, .key_cmp=ent8_key_cmp,  .val_sz=sizeof(ent8_val_t),  .val_align=8UL, .max_records=1UL<<20 },
  { .name="ent16", .kind=FD_GUI_STORE_KIND_KV, .key_off=0UL, .key_sz=16UL, .key_hash=ent_key_hash, .key_cmp=ent16_key_cmp, .val_sz=sizeof(ent16_val_t), .val_align=8UL, .max_records=1UL<<20 },
  { .name="entbig",.kind=FD_GUI_STORE_KIND_KV, .key_off=0UL, .key_sz=8UL,  .key_hash=ent_key_hash, .key_cmp=ent8_key_cmp,  .val_sz=256UL,              .val_align=8UL, .max_records=1UL<<20 },
  { .name="ts",    .kind=FD_GUI_STORE_KIND_TS,                                                                             .val_sz=sizeof(ts_val_t),   .val_align=8UL, .ts_off=0UL, .granularity=1UL },
};

static char *
mk_path( char * buf, ulong buf_sz ) {
  fd_cstr_printf_check( buf, buf_sz, NULL, "/tmp/fd_gui_store_test.%i", (int)getpid() );
  return buf;
}

/* test helpers: allocate the store's workspace region with the C heap (the
   gui tile uses its tile workspace; the unit test just needs aligned
   memory) and wrap new/join + delete/free. */
static fd_gui_store_t *
db_open( char const * path, ulong size ) {
  ulong fp = fd_gui_store_footprint( size, DB_CNT, descs );
  FD_TEST( fp );
  void * mem = aligned_alloc( fd_gui_store_align(), fd_ulong_align_up( fp, fd_gui_store_align() ) );
  FD_TEST( mem );
  fd_gui_store_t * db = fd_gui_store_join( fd_gui_store_new( mem, path, size, DB_CNT, descs ) );
  FD_TEST( db );
  return db;
}
static void
db_close( fd_gui_store_t * db ) {
  void * mem = fd_gui_store_delete( fd_gui_store_leave( db ) );
  free( mem );
}

/* cleanup removes the store's backing file so the test leaves nothing on
   disk.  The store is a single mmap'd file at `path` (no lock file, no
   directory). */
static void
cleanup( char const * path ) {
  if( FD_UNLIKELY( unlink( path ) && errno!=ENOENT ) ) FD_LOG_WARNING(( "failed to clean up %s", path ));
}

/* ent8_put upserts an ENT8 record (key + payload).  The store seeds the key
   into the value on insert; we (re)write it explicitly too and fill the
   payload through the returned pointer.  Returns the fd_gui_store_kv_get_or_create
   status. */
static int
ent8_put( fd_gui_store_t * db, ulong key, ulong payload ) {
  void * dst = NULL;
  int rc = fd_gui_store_kv_get_or_create( db, DB_ENT8, &key, &dst );
  if( FD_LIKELY( rc==FD_GUI_STORE_SUCCESS ) ) {
    ent8_val_t * v = dst;
    v->key = key; v->payload = payload;
  }
  return rc;
}

/* ent16_put upserts an ENT16 record ((slot,bank_seq) + payload). */
static int
ent16_put( fd_gui_store_t * db, ulong slot, ulong bank_seq, ulong payload ) {
  ulong key[ 2 ] = { slot, bank_seq };
  void * dst = NULL;
  int rc = fd_gui_store_kv_get_or_create( db, DB_ENT16, key, &dst );
  if( FD_LIKELY( rc==FD_GUI_STORE_SUCCESS ) ) {
    ent16_val_t * v = dst;
    v->slot = slot; v->bank_seq = bank_seq; v->payload = payload;
  }
  return rc;
}

/* entbig_put upserts an ENTBIG record: 8-byte key followed by a 248-byte
   payload filled with `fill`. */
static int
entbig_put( fd_gui_store_t * db, ulong key, uchar fill ) {
  void * dst = NULL;
  int rc = fd_gui_store_kv_get_or_create( db, DB_ENTBIG, &key, &dst );
  if( FD_LIKELY( rc==FD_GUI_STORE_SUCCESS ) ) {
    uchar * b = dst;
    memcpy( b, &key, sizeof(ulong) );
    memset( b+sizeof(ulong), (int)fill, 256UL-sizeof(ulong) );
  }
  return rc;
}

/* ---- entity DB tests -------------------------------------------------- */

static void
test_entity_open_wipe( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );

  fd_gui_store_t * db = db_open( path, 256UL<<20 );
  FD_TEST( fd_gui_store_cnt( db )==DB_CNT );

  ulong k = 7UL;
  FD_TEST( ent8_put( db, k, 42UL )==FD_GUI_STORE_SUCCESS );

  ent8_val_t const * got = fd_gui_store_kv_get( db, DB_ENT8, &k );
  FD_TEST( got && got->key==7UL && got->payload==42UL );
  db_close( db );

  /* reopen: the store is wiped on open (see fd_gui_store_new) */
  db = db_open( path, 256UL<<20 );
  FD_TEST( fd_gui_store_kv_get( db, DB_ENT8, &k )==NULL );
  db_close( db );

  cleanup( path );
  FD_LOG_NOTICE(( "test_entity_open_wipe: ok" ));
}

static void
test_entity_upsert_get( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  fd_gui_store_t * db = db_open( path, 256UL<<20 );

  /* upsert several times; a later upsert of the same key modifies in
     place (last writer wins) */
  for( ulong pass=0UL; pass<2UL; pass++ ) {
    for( ulong i=0UL; i<8UL; i++ ) {
      FD_TEST( ent8_put( db, i, pass*100UL + i )==FD_GUI_STORE_SUCCESS );
    }
  }
  for( ulong i=0UL; i<8UL; i++ ) {
    ent8_val_t const * got = fd_gui_store_kv_get( db, DB_ENT8, &i );
    FD_TEST( got && got->key==i && got->payload==100UL+i );
  }

  /* missing key */
  ulong k99 = 99UL;
  FD_TEST( fd_gui_store_kv_get( db, DB_ENT8, &k99 )==NULL );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_entity_upsert_get: ok" ));
}

static void
test_entity_get_any( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  fd_gui_store_t * db = db_open( path, 256UL<<20 );

  /* two-ulong keys (slot, bank_seq); insert (5,2),(5,7),(9,0) */
  FD_TEST( ent16_put( db, 5UL, 2UL, 1000UL )==FD_GUI_STORE_SUCCESS );
  FD_TEST( ent16_put( db, 5UL, 7UL, 1001UL )==FD_GUI_STORE_SUCCESS );
  FD_TEST( ent16_put( db, 9UL, 0UL, 1002UL )==FD_GUI_STORE_SUCCESS );

  /* get_any for slot 5 (wildcard bank_seq) -> lowest bank_seq (5,2) -> payload 1000 */
  ulong key5[2] = { 5UL, ULONG_MAX };
  ent16_val_t const * got = fd_gui_store_kv_get_any( db, DB_ENT16, key5 );
  FD_TEST( got && got->slot==5UL && got->bank_seq==2UL && got->payload==1000UL );

  /* slot with no match */
  ulong key7[2] = { 7UL, ULONG_MAX };
  FD_TEST( fd_gui_store_kv_get_any( db, DB_ENT16, key7 )==NULL );

  /* exact get must disambiguate the two slot-5 records (same bucket,
     different bank_seq) by matching the full (slot,bank_seq) key. */
  ulong k52[2] = { 5UL, 2UL };
  ulong k57[2] = { 5UL, 7UL };
  ent16_val_t const * g52 = fd_gui_store_kv_get( db, DB_ENT16, k52 );
  ent16_val_t const * g57 = fd_gui_store_kv_get( db, DB_ENT16, k57 );
  FD_TEST( g52 && g52->payload==1000UL );
  FD_TEST( g57 && g57->payload==1001UL );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_entity_get_any: ok" ));
}

static void
test_entity_iter( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  fd_gui_store_t * db = db_open( path, 256UL<<20 );

  /* Three forks of slot 5 (out of bank_seq order on insert) plus a slot 9. */
  FD_TEST( ent16_put( db, 5UL, 7UL, 2000UL )==FD_GUI_STORE_SUCCESS );
  FD_TEST( ent16_put( db, 5UL, 2UL, 2001UL )==FD_GUI_STORE_SUCCESS );
  FD_TEST( ent16_put( db, 5UL, 4UL, 2002UL )==FD_GUI_STORE_SUCCESS );
  FD_TEST( ent16_put( db, 9UL, 0UL, 2003UL )==FD_GUI_STORE_SUCCESS );

  /* Iterate slot 5 (wildcard bank_seq) -> ascending bank_seq: (5,2)=2001,
     (5,4)=2002, (5,7)=2000. */
  ulong key5[2] = { 5UL, ULONG_MAX };
  fd_gui_store_kv_iter_t it[ 1 ];
  fd_gui_store_kv_iter_begin( db, it, DB_ENT16, key5 );

  ulong exp_seq[3] = { 2UL, 4UL, 7UL };
  ulong exp_val[3] = { 2001UL, 2002UL, 2000UL };
  ulong n = 0UL;
  for( ; !fd_gui_store_kv_iter_done( it ); fd_gui_store_kv_iter_next( it ) ) {
    FD_TEST( n<3UL );
    ent16_val_t const * rec = it->rec;
    FD_TEST( it->key_sz==2UL*sizeof(ulong) && it->val_sz==sizeof(ent16_val_t) );
    FD_TEST( rec->slot==5UL && rec->bank_seq==exp_seq[n] );
    FD_TEST( rec->payload==exp_val[n] );
    n++;
  }
  FD_TEST( n==3UL );

  /* iter_begin == get_any for the first element. */
  fd_gui_store_kv_iter_begin( db, it, DB_ENT16, key5 );
  FD_TEST( !fd_gui_store_kv_iter_done( it ) );
  FD_TEST( ((ent16_val_t const *)it->rec)->payload==2001UL );

  /* slot with no records -> done immediately. */
  ulong key7[2] = { 7UL, ULONG_MAX };
  fd_gui_store_kv_iter_begin( db, it, DB_ENT16, key7 );
  FD_TEST( fd_gui_store_kv_iter_done( it ) );
  FD_TEST( !fd_gui_store_kv_iter_next( it ) );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_entity_iter: ok" ));
}

static void
test_entity_evict( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  fd_gui_store_t * db = db_open( path, 256UL<<20 );

  /* (slot, bank_seq) keys for slots 0..9, bank_seq 0 */
  for( ulong i=0UL; i<10UL; i++ ) {
    FD_TEST( ent16_put( db, i, 0UL, i )==FD_GUI_STORE_SUCCESS );
  }

  /* evict every key < (7, 0): removes slots 0..6 */
  ulong hi[2] = { 7UL, 0UL };
  ulong budget = 100UL; int drained = 0;
  FD_TEST( fd_gui_store_kv_evict( db, DB_ENT16, hi, &budget, &drained )==FD_GUI_STORE_SUCCESS );
  FD_TEST( drained==1 && budget==93UL ); /* 7 reclaimed */

  /* survivors: slots 7,8,9 */
  for( ulong i=0UL; i<10UL; i++ ) {
    ulong k[2] = { i, 0UL };
    ent16_val_t const * got = fd_gui_store_kv_get( db, DB_ENT16, k );
    if( i<7UL ) FD_TEST( got==NULL );
    else        FD_TEST( got && got->payload==i );
  }

  /* bounded budget: evicting the remaining with budget 1 stops early */
  ulong hiall[2] = { 100UL, 0UL };
  budget = 1UL; drained = 1;
  FD_TEST( fd_gui_store_kv_evict( db, DB_ENT16, hiall, &budget, &drained )==FD_GUI_STORE_SUCCESS );
  FD_TEST( drained==0 && budget==0UL );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_entity_evict: ok" ));
}

/* ---- time-series DB tests --------------------------------------------- */

static void
test_ts_append_scan( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  fd_gui_store_t * db = db_open( path, 256UL<<20 );

  /* append 3 records to window 1, 2 to window 2, 1 to window 5 */
  ulong seq = 0UL;
  for( ulong w=1UL; w<=5UL; w++ ) {
    ulong n = (w==1UL) ? 3UL : (w==2UL) ? 2UL : (w==5UL) ? 1UL : 0UL;
    for( ulong i=0UL; i<n; i++ ) {
      ts_val_t v = { .ts = (long)w, .seq = seq++ };
      FD_TEST( fd_gui_store_ts_append( db, DB_TS, &v )==FD_GUI_STORE_SUCCESS );
    }
  }

  /* full scan [0, ULONG_MAX]: 6 records, window-nondecreasing, insertion
     order within a window */
  fd_gui_store_ts_iter_t it[ 1 ];
  fd_gui_store_ts_scan_begin( db, it, DB_TS, 0UL, ULONG_MAX, NULL, NULL );
  ulong cnt = 0UL; ulong prev_window = 0UL; ulong expect_val = 0UL;
  while( !fd_gui_store_ts_scan_done( it ) ) {
    FD_TEST( it->window>=prev_window ); prev_window = it->window;
    FD_TEST( ((ts_val_t const *)it->rec)->seq==expect_val ); expect_val++;
    cnt++;
    fd_gui_store_ts_scan_next( it );
  }
  fd_gui_store_ts_scan_end( it );
  FD_TEST( cnt==6UL );

  /* windowed scan [2,2]: only the 2 records in window 2 (values 3,4) */
  fd_gui_store_ts_scan_begin( db, it, DB_TS, 2UL, 2UL, NULL, NULL );
  cnt = 0UL;
  while( !fd_gui_store_ts_scan_done( it ) ) {
    FD_TEST( it->window==2UL );
    cnt++;
    fd_gui_store_ts_scan_next( it );
  }
  fd_gui_store_ts_scan_end( it );
  FD_TEST( cnt==2UL );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_ts_append_scan: ok" ));
}

/* keep only even record values */
static int
even_filter( void const * rec, void * ctx ) {
  (void)ctx;
  return ( ((ts_val_t const *)rec)->seq % 2UL )==0UL;
}

static void
test_ts_filter_and_evict( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  fd_gui_store_t * db = db_open( path, 256UL<<20 );

  /* values 0..9 across windows 0..9 (one each) */
  for( ulong i=0UL; i<10UL; i++ ) {
    ts_val_t v = { .ts = (long)i, .seq = i };
    FD_TEST( fd_gui_store_ts_append( db, DB_TS, &v )==FD_GUI_STORE_SUCCESS );
  }

  /* filtered scan: only even values -> 0,2,4,6,8 */
  fd_gui_store_ts_iter_t it[ 1 ];
  fd_gui_store_ts_scan_begin( db, it, DB_TS, 0UL, ULONG_MAX, even_filter, NULL );
  ulong cnt = 0UL;
  while( !fd_gui_store_ts_scan_done( it ) ) {
    FD_TEST( ( ((ts_val_t const *)it->rec)->seq % 2UL )==0UL );
    cnt++;
    fd_gui_store_ts_scan_next( it );
  }
  fd_gui_store_ts_scan_end( it );
  FD_TEST( cnt==5UL );

  /* evict windows < 5 with a generous budget: drains 5 records */
  ulong budget = 100UL; int drained = 0;
  FD_TEST( fd_gui_store_ts_evict( db, DB_TS, 5UL, &budget, &drained )==FD_GUI_STORE_SUCCESS );
  FD_TEST( drained==1 && budget==95UL );

  /* survivors: windows 5..9 (5 records) */
  fd_gui_store_ts_scan_begin( db, it, DB_TS, 0UL, ULONG_MAX, NULL, NULL );
  cnt = 0UL;
  while( !fd_gui_store_ts_scan_done( it ) ) { FD_TEST( it->window>=5UL ); cnt++; fd_gui_store_ts_scan_next( it ); }
  fd_gui_store_ts_scan_end( it );
  FD_TEST( cnt==5UL );

  /* bounded-budget evict of the rest: budget 2 stops early (not drained) */
  budget = 2UL; drained = 1;
  FD_TEST( fd_gui_store_ts_evict( db, DB_TS, ULONG_MAX, &budget, &drained )==FD_GUI_STORE_SUCCESS );
  FD_TEST( drained==0 && budget==0UL );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_ts_filter_and_evict: ok" ));
}

static void
test_map_full( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  /* A single-region store: 256-byte entity inserts eventually overflow the
     one available region, and the upsert must surface the distinct
     FD_GUI_STORE_MAP_FULL code (Layer 1 does NOT evict).  One 36 MiB region
     holds ~135K of these records. */
  fd_gui_store_t * db = db_open( path, (36UL<<20) + (1UL<<20) ); /* ~1 region + overhead */

  int saw_map_full = 0;
  for( ulong i=0UL; i<1000000UL && !saw_map_full; i++ ) {
    int rc = entbig_put( db, i, (uchar)i );
    if( rc==FD_GUI_STORE_MAP_FULL ) { saw_map_full = 1; break; }
    FD_TEST( rc==FD_GUI_STORE_SUCCESS );
  }
  FD_TEST( saw_map_full );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_map_full: ok" ));
}

static void
test_space_accounting( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  ulong size = 128UL<<20; /* 128 MiB (>= a few 36 MiB regions) */
  fd_gui_store_t * db = db_open( path, size );

  FD_TEST( fd_gui_store_size( db )==size );

  ulong used0 = fd_gui_store_used_bytes( db );
  FD_TEST( used0>0UL && used0<=size );
  FD_TEST( fd_gui_store_live_bytes( db )==0UL ); /* nothing live yet */

  for( ulong i=0UL; i<2000UL; i++ ) {
    FD_TEST( entbig_put( db, i, (uchar)i )==FD_GUI_STORE_SUCCESS );
  }

  ulong used1 = fd_gui_store_used_bytes( db );
  FD_TEST( used1>used0 && used1<=size );
  /* committed = superblock + live + fragmentation */
  FD_TEST( fd_gui_store_live_bytes( db )>0UL );
  FD_TEST( fd_gui_store_used_bytes( db )>=fd_gui_store_live_bytes( db ) );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_space_accounting: ok" ));
}

/* test_region_grow_reclaim drives the region allocator across several
   regions: a 256 MiB store fits several 36 MiB regions, and 256-byte ENTBIG
   records (one region holds ~135K of them) force multiple region claims as we
   insert.  Eviction then advances the watermark past whole regions, which
   must release them back to the pool (used_bytes shrinks) and let later
   inserts re-claim the freed space without exceeding the ceiling. */
static void
test_region_grow_reclaim( void ) {
  char path[ 128 ]; mk_path( path, sizeof(path) );
  ulong size = 256UL<<20; /* 256 MiB -> several 36 MiB regions */
  fd_gui_store_t * db = db_open( path, size );

  ulong open_used = fd_gui_store_used_bytes( db );

  /* Insert enough 256-byte records to claim more than one region.  One 36
     MiB region holds region_sz/stride ~= 135K records; insert 400K to force
     at least three region claims. */
  ulong const N = 400000UL;
  for( ulong i=0UL; i<N; i++ ) {
    FD_TEST( entbig_put( db, i, (uchar)i )==FD_GUI_STORE_SUCCESS );
  }

  ulong grown_used = fd_gui_store_used_bytes( db );
  FD_TEST( grown_used>open_used );          /* claimed regions */
  FD_TEST( grown_used<=size );              /* never exceeds ceiling */
  FD_TEST( grown_used-open_used >= (36UL<<20) ); /* at least one region */

  /* All inserted records still readable. */
  for( ulong i=0UL; i<N; i+=4096UL ) {
    uchar const * out = fd_gui_store_kv_get( db, DB_ENTBIG, &i );
    FD_TEST( out );
    FD_TEST( out[ sizeof(ulong) ]==(uchar)i ); /* first payload byte */
  }

  /* Evict the oldest ~2/3 (keys < 2N/3 in numeric order).  Generous budget so
     it drains. */
  ulong hi = ( 2UL*N )/3UL;
  ulong budget = N; int drained = 0;
  FD_TEST( fd_gui_store_kv_evict( db, DB_ENTBIG, &hi, &budget, &drained )==FD_GUI_STORE_SUCCESS );
  FD_TEST( drained==1 );

  ulong evicted_used = fd_gui_store_used_bytes( db );
  FD_TEST( evicted_used<grown_used );       /* regions returned to the pool */

  /* Evicted keys are gone, survivors remain. */
  ulong probe_lo = 10UL;
  FD_TEST( fd_gui_store_kv_get( db, DB_ENTBIG, &probe_lo )==NULL );
  ulong probe_hi = N-1UL;
  FD_TEST( fd_gui_store_kv_get( db, DB_ENTBIG, &probe_hi )!=NULL );

  /* Re-insert: the freed regions are reusable, so this succeeds and stays
     under the ceiling. */
  for( ulong i=N; i<N+50000UL; i++ ) {
    FD_TEST( entbig_put( db, i, (uchar)i )==FD_GUI_STORE_SUCCESS );
  }
  FD_TEST( fd_gui_store_used_bytes( db )<=size );

  db_close( db );
  cleanup( path );
  FD_LOG_NOTICE(( "test_region_grow_reclaim: ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_entity_open_wipe();
  test_entity_upsert_get();
  test_entity_get_any();
  test_entity_iter();
  test_entity_evict();
  test_ts_append_scan();
  test_ts_filter_and_evict();
  test_map_full();
  test_space_accounting();
  test_region_grow_reclaim();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
