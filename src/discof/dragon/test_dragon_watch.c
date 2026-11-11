/* test_dragon_watch checks the watch index against a model that keeps,
   for every address of a small universe, the sets that hold it. */

#include "fd_dragon_watch.h"
#include "../../util/fd_util.h"

#define KEY_MAX  (96UL)
#define UNIVERSE (128UL)

static uchar mem[ 65536 ] __attribute__((aligned(FD_DRAGON_WATCH_ALIGN)));

static uchar model_key [ UNIVERSE ][ 32 ];
static ulong model_mask[ UNIVERSE ];

static void
model_init( void ) {
  for( ulong i=0UL; i<UNIVERSE; i++ ) {
    for( ulong j=0UL; j<4UL; j++ ) FD_STORE( ulong, model_key[ i ]+8UL*j, fd_ulong_hash( i*4UL+j ) );
    model_mask[ i ] = 0UL;
  }
}

static ulong
model_key_cnt( void ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<UNIVERSE; i++ ) cnt += !!model_mask[ i ];
  return cnt;
}

static ulong
model_set_key_cnt( ulong set ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<UNIVERSE; i++ ) cnt += ( model_mask[ i ]>>set )&1UL;
  return cnt;
}

static void
model_set_clear( ulong set ) {
  for( ulong i=0UL; i<UNIVERSE; i++ ) model_mask[ i ] &= ~( 1UL<<set );
}

static void
check_all( fd_dragon_watch_t * watch ) {
  FD_TEST( !fd_dragon_watch_verify( watch ) );
  for( ulong i=0UL; i<UNIVERSE; i++ ) FD_TEST( fd_dragon_watch_query( watch, model_key[ i ] )==model_mask[ i ] );
  ulong open = fd_dragon_watch_set_mask( watch );
  for( ulong set=0UL; set<FD_DRAGON_WATCH_SET_MAX; set++ ) {
    if( !( ( open>>set )&1UL ) ) continue;
    FD_TEST( fd_dragon_watch_set_key_cnt( watch, set )==model_set_key_cnt( set ) );
  }
  FD_TEST( fd_dragon_watch_key_cnt( watch )>=model_key_cnt() );
  if( !fd_dragon_watch_sweep_pending( watch ) ) FD_TEST( fd_dragon_watch_key_cnt( watch )==model_key_cnt() );
}

static fd_dragon_watch_t *
watch_new( ulong key_max,
           ulong seed ) {
  FD_TEST( fd_dragon_watch_footprint( key_max ) && fd_dragon_watch_footprint( key_max )<=sizeof(mem) );
  fd_dragon_watch_t * watch = fd_dragon_watch_join( fd_dragon_watch_new( mem, key_max, seed ) );
  FD_TEST( watch );
  FD_TEST( fd_dragon_watch_key_max( watch )==key_max );
  FD_TEST( !fd_dragon_watch_key_cnt( watch ) );
  FD_TEST( !fd_dragon_watch_set_mask( watch ) );
  model_init();
  return watch;
}

static void
test_construct( void ) {
  FD_TEST( fd_dragon_watch_align()==FD_DRAGON_WATCH_ALIGN );
  FD_TEST( !fd_dragon_watch_footprint( 0UL ) );
  FD_TEST( !fd_dragon_watch_footprint( FD_DRAGON_WATCH_KEY_MAX+1UL ) );
  FD_TEST(  fd_dragon_watch_footprint( FD_DRAGON_WATCH_KEY_MAX ) );
  FD_TEST( fd_ulong_is_aligned( fd_dragon_watch_footprint( 1UL ), FD_DRAGON_WATCH_ALIGN ) );

  /* 56 bytes per address plus the chain heads */
  ulong fp = fd_dragon_watch_footprint( 1UL<<20 );
  FD_TEST( fp>=56UL<<20 && fp<=65UL<<20 );

  FD_TEST( !fd_dragon_watch_new( NULL,  KEY_MAX, 0UL ) );
  FD_TEST( !fd_dragon_watch_new( mem+1, KEY_MAX, 0UL ) );
  FD_TEST( !fd_dragon_watch_new( mem,   0UL,     0UL ) );
  FD_TEST( !fd_dragon_watch_join( NULL ) );

  FD_TEST( fd_dragon_watch_new( mem, KEY_MAX, 0UL )==mem );
  fd_dragon_watch_t * watch = fd_dragon_watch_join( mem );
  FD_TEST( watch );
  FD_TEST( !fd_dragon_watch_verify( watch ) );
  FD_TEST( fd_dragon_watch_leave( watch )==mem );
  FD_TEST( fd_dragon_watch_delete( mem )==mem );
  FD_TEST( !fd_dragon_watch_join( mem ) );
  FD_TEST( !fd_dragon_watch_delete( mem ) );
  FD_LOG_NOTICE(( "test_construct: ok" ));
}

static void
test_basic( void ) {
  fd_dragon_watch_t * watch = watch_new( KEY_MAX, 1UL );
  uchar const * a = model_key[ 0 ];
  uchar const * b = model_key[ 1 ];

  FD_TEST( !fd_dragon_watch_query( watch, a ) );
  fd_dragon_watch_set_open( watch, 3UL );
  FD_TEST( fd_dragon_watch_set_mask( watch )==1UL<<3 );
  FD_TEST( !fd_dragon_watch_query( watch, a ) );

  FD_TEST( fd_dragon_watch_add( watch, 3UL, a )==1 );
  FD_TEST( fd_dragon_watch_add( watch, 3UL, a )==0 );
  FD_TEST( fd_dragon_watch_query( watch, a )==1UL<<3 );
  FD_TEST( !fd_dragon_watch_query( watch, b ) );
  FD_TEST( fd_dragon_watch_key_cnt( watch )==1UL );
  FD_TEST( fd_dragon_watch_set_key_cnt( watch, 3UL )==1UL );

  /* An address two sets hold is stored once */
  fd_dragon_watch_set_open( watch, 63UL );
  FD_TEST( fd_dragon_watch_add( watch, 63UL, a )==1 );
  FD_TEST( fd_dragon_watch_add( watch, 63UL, b )==1 );
  FD_TEST( fd_dragon_watch_query( watch, a )==( (1UL<<3)|(1UL<<63) ) );
  FD_TEST( fd_dragon_watch_query( watch, b )==1UL<<63 );
  FD_TEST( fd_dragon_watch_key_cnt( watch )==2UL );

  FD_TEST( fd_dragon_watch_remove( watch, 3UL, b )==0 );
  FD_TEST( fd_dragon_watch_remove( watch, 3UL, a )==1 );
  FD_TEST( fd_dragon_watch_remove( watch, 3UL, a )==0 );
  FD_TEST( fd_dragon_watch_query( watch, a )==1UL<<63 );
  FD_TEST( fd_dragon_watch_key_cnt( watch )==2UL );
  FD_TEST( fd_dragon_watch_remove( watch, 63UL, a )==1 );
  FD_TEST( !fd_dragon_watch_query( watch, a ) );
  FD_TEST( fd_dragon_watch_key_cnt( watch )==1UL );
  FD_TEST( !fd_dragon_watch_sweep_pending( watch ) );
  FD_TEST( !fd_dragon_watch_verify( watch ) );
  FD_LOG_NOTICE(( "test_basic: ok" ));
}

/* A full index refuses an add and keeps what it has. */

static void
test_full( void ) {
  fd_dragon_watch_t * watch = watch_new( 4UL, 2UL );
  fd_dragon_watch_set_open( watch, 0UL );
  fd_dragon_watch_set_open( watch, 1UL );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( fd_dragon_watch_add( watch, 0UL, model_key[ i ] )==1 );
  FD_TEST( fd_dragon_watch_add( watch, 0UL, model_key[ 4 ] )==-1 );
  FD_TEST( fd_dragon_watch_add( watch, 1UL, model_key[ 4 ] )==-1 );
  FD_TEST( !fd_dragon_watch_sweep_pending( watch ) );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( fd_dragon_watch_query( watch, model_key[ i ] )==1UL );
  FD_TEST( !fd_dragon_watch_query( watch, model_key[ 4 ] ) );

  /* A stored address takes another set without new storage */
  FD_TEST( fd_dragon_watch_add( watch, 1UL, model_key[ 0 ] )==1 );
  FD_TEST( fd_dragon_watch_add( watch, 0UL, model_key[ 0 ] )==0 );

  FD_TEST( fd_dragon_watch_remove( watch, 0UL, model_key[ 1 ] )==1 );
  FD_TEST( fd_dragon_watch_add( watch, 1UL, model_key[ 4 ] )==1 );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 4 ] )==2UL );
  FD_TEST( !fd_dragon_watch_verify( watch ) );
  FD_LOG_NOTICE(( "test_full: ok" ));
}

/* A clear takes effect at once; the storage comes back with the
   sweep. */

static void
test_clear( void ) {
  fd_dragon_watch_t * watch = watch_new( 4UL, 3UL );
  fd_dragon_watch_set_open( watch, 5UL );
  fd_dragon_watch_set_clear( watch, 5UL );
  FD_TEST( !fd_dragon_watch_sweep_pending( watch ) );
  FD_TEST( fd_dragon_watch_remove( watch, 5UL, model_key[ 0 ] )==0 );

  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( fd_dragon_watch_add( watch, 5UL, model_key[ i ] )==1 );
  fd_dragon_watch_set_clear( watch, 5UL );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( !fd_dragon_watch_query( watch, model_key[ i ] ) );
  FD_TEST( !fd_dragon_watch_set_key_cnt( watch, 5UL ) );
  FD_TEST( fd_dragon_watch_set_mask( watch )==1UL<<5 );
  FD_TEST( fd_dragon_watch_key_cnt( watch )==4UL );
  FD_TEST( fd_dragon_watch_sweep_pending( watch ) );
  FD_TEST( !fd_dragon_watch_verify( watch ) );

  /* A cleared address is added again in place; a new one waits */
  FD_TEST( fd_dragon_watch_add( watch, 5UL, model_key[ 0 ] )==1 );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 0 ] )==1UL<<5 );
  FD_TEST( fd_dragon_watch_add( watch, 5UL, model_key[ 9 ] )==-1 );
  FD_TEST( fd_dragon_watch_sweep_pending( watch ) );

  FD_TEST( fd_dragon_watch_sweep( watch, 1UL )==1 );
  FD_TEST( fd_dragon_watch_sweep( watch, 0UL )==1 );
  FD_TEST( fd_dragon_watch_sweep( watch, 3UL )==0 );
  FD_TEST( fd_dragon_watch_key_cnt( watch )==1UL );
  FD_TEST( fd_dragon_watch_add( watch, 5UL, model_key[ 9 ] )==1 );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 0 ] )==1UL<<5 );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 9 ] )==1UL<<5 );
  FD_TEST( !fd_dragon_watch_verify( watch ) );

  /* A closed set leaves nothing behind for the set that reuses its
     number */
  fd_dragon_watch_set_close( watch, 5UL );
  FD_TEST( !fd_dragon_watch_set_mask( watch ) );
  FD_TEST( !fd_dragon_watch_query( watch, model_key[ 0 ] ) );
  fd_dragon_watch_set_open( watch, 5UL );
  FD_TEST( !fd_dragon_watch_query( watch, model_key[ 0 ] ) );
  FD_TEST( !fd_dragon_watch_set_key_cnt( watch, 5UL ) );
  FD_TEST( fd_dragon_watch_sweep( watch, 4UL )==0 );
  FD_TEST( !fd_dragon_watch_key_cnt( watch ) );
  FD_TEST( !fd_dragon_watch_verify( watch ) );
  FD_LOG_NOTICE(( "test_clear: ok" ));
}

/* With every bit in use or retired, the first add of a set waits for
   the sweep. */

static void
test_bits( void ) {
  fd_dragon_watch_t * watch = watch_new( KEY_MAX, 4UL );
  for( ulong set=0UL; set<FD_DRAGON_WATCH_SET_MAX; set++ ) {
    fd_dragon_watch_set_open( watch, set );
    FD_TEST( fd_dragon_watch_add( watch, set, model_key[ set ] )==1 );
    FD_TEST( fd_dragon_watch_add( watch, set, model_key[ 100 ] )==1 );
  }
  FD_TEST( fd_dragon_watch_set_mask( watch )==ULONG_MAX );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 100 ] )==ULONG_MAX );
  FD_TEST( fd_dragon_watch_key_cnt( watch )==65UL );

  /* A clear with all 64 sets in use */
  fd_dragon_watch_set_clear( watch, 0UL );
  FD_TEST( fd_dragon_watch_set_mask( watch )==ULONG_MAX );
  FD_TEST( !fd_dragon_watch_query( watch, model_key[ 0 ] ) );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 100 ] )==~1UL );
  FD_TEST( !fd_dragon_watch_set_key_cnt( watch, 0UL ) );
  FD_TEST( fd_dragon_watch_sweep_pending( watch ) );
  FD_TEST( fd_dragon_watch_add( watch, 0UL, model_key[ 7 ] )==-1 );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 7 ] )==1UL<<7 );
  FD_TEST( !fd_dragon_watch_verify( watch ) );

  /* A close and a reopen in the same state */
  fd_dragon_watch_set_close( watch, 1UL );
  fd_dragon_watch_set_open ( watch, 1UL );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 100 ] )==~3UL );
  FD_TEST( !fd_dragon_watch_query( watch, model_key[ 1 ] ) );
  FD_TEST( fd_dragon_watch_add( watch, 1UL, model_key[ 1 ] )==-1 );
  FD_TEST( !fd_dragon_watch_verify( watch ) );

  FD_TEST( fd_dragon_watch_sweep( watch, KEY_MAX )==0 );
  FD_TEST( fd_dragon_watch_key_cnt( watch )==63UL );
  FD_TEST( fd_dragon_watch_add( watch, 0UL, model_key[ 7 ] )==1 );
  FD_TEST( fd_dragon_watch_add( watch, 1UL, model_key[ 1 ] )==1 );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 7 ] )==( 1UL|(1UL<<7) ) );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 1 ] )==2UL );
  FD_TEST( fd_dragon_watch_query( watch, model_key[ 100 ] )==~3UL );
  FD_TEST( !fd_dragon_watch_verify( watch ) );

  /* A set that holds nothing clears and closes without retiring */
  fd_dragon_watch_set_close( watch, 2UL );
  FD_TEST( fd_dragon_watch_sweep( watch, KEY_MAX )==0 );
  fd_dragon_watch_set_open ( watch, 2UL );
  fd_dragon_watch_set_clear( watch, 2UL );
  fd_dragon_watch_set_close( watch, 2UL );
  FD_TEST( !fd_dragon_watch_sweep_pending( watch ) );
  FD_LOG_NOTICE(( "test_bits: ok" ));
}

static void
test_random( fd_rng_t * rng ) {
  fd_dragon_watch_t * watch = watch_new( KEY_MAX, fd_rng_ulong( rng ) );

  ulong add_full = 0UL;
  ulong bit_full = 0UL;
  for( ulong iter=0UL; iter<2000000UL; iter++ ) {
    uint  r    = fd_rng_uint( rng );
    ulong op   = r & 15UL;
    /* Low set numbers dominate so that sets share addresses */
    ulong set  = ( (r>>4) & 1UL ) ? ( (r>>5) & 63UL ) : ( (r>>5) & 3UL );
    ulong k    = (r>>11) % UNIVERSE;
    ulong open = fd_dragon_watch_set_mask( watch );
    int   is_open = (int)( ( open>>set )&1UL );

    if( op<7UL ) {
      if( !is_open ) continue;
      int have = (int)( ( model_mask[ k ]>>set )&1UL );
      int rc   = fd_dragon_watch_add( watch, set, model_key[ k ] );
      if( rc==-1 ) {
        FD_TEST( !have );
        if( fd_dragon_watch_key_cnt( watch )==KEY_MAX ) add_full++;
        else                                            bit_full++;
        if( fd_dragon_watch_sweep_pending( watch ) ) {
          FD_TEST( !fd_dragon_watch_sweep( watch, KEY_MAX ) );
          rc = fd_dragon_watch_add( watch, set, model_key[ k ] );
        }
        if( rc==-1 ) {
          FD_TEST( model_key_cnt()==KEY_MAX && !model_mask[ k ] );
          continue;
        }
      }
      FD_TEST( rc==!have );
      model_mask[ k ] |= 1UL<<set;
    } else if( op<11UL ) {
      if( !is_open ) continue;
      int have = (int)( ( model_mask[ k ]>>set )&1UL );
      FD_TEST( fd_dragon_watch_remove( watch, set, model_key[ k ] )==have );
      model_mask[ k ] &= ~( 1UL<<set );
    } else if( op==11UL ) {
      FD_TEST( fd_dragon_watch_query( watch, model_key[ k ] )==model_mask[ k ] );
    } else if( op==12UL ) {
      fd_dragon_watch_sweep( watch, (r>>20) & 31UL );
    } else if( op==13UL ) {
      if( is_open ) continue;
      fd_dragon_watch_set_open( watch, set );
    } else if( op==14UL ) {
      if( !is_open || ( (r>>20) & 7UL ) ) continue;
      fd_dragon_watch_set_clear( watch, set );
      model_set_clear( set );
    } else {
      if( !is_open || ( (r>>20) & 7UL ) ) continue;
      fd_dragon_watch_set_close( watch, set );
      model_set_clear( set );
    }

    if( !( iter & 1023UL ) ) check_all( watch );
  }
  check_all( watch );
  FD_TEST( add_full );
  FD_LOG_NOTICE(( "test_random: ok (%lu adds on a full index, %lu waits for a bit)", add_full, bit_full ));
}

/* A bit retired by a clear is free after key_max visits. */

static void
test_sweep_bound( fd_rng_t * rng ) {
  fd_dragon_watch_t * watch = watch_new( KEY_MAX, fd_rng_ulong( rng ) );
  fd_dragon_watch_set_open( watch, 0UL );
  fd_dragon_watch_set_open( watch, 1UL );
  for( ulong round=0UL; round<1000UL; round++ ) {
    for( ulong i=0UL; i<KEY_MAX; i++ ) {
      ulong k = fd_rng_ulong_roll( rng, UNIVERSE );
      if( fd_dragon_watch_add( watch, fd_rng_ulong_roll( rng, 2UL ), model_key[ k ] )==-1 ) break;
    }
    fd_dragon_watch_sweep( watch, fd_rng_ulong_roll( rng, KEY_MAX ) );
    fd_dragon_watch_set_clear( watch, 0UL );
    fd_dragon_watch_set_clear( watch, 1UL );
    ulong visit = fd_rng_ulong_roll( rng, KEY_MAX+1UL );
    fd_dragon_watch_sweep( watch, visit );
    FD_TEST( !fd_dragon_watch_sweep( watch, KEY_MAX-visit ) );
    FD_TEST( !fd_dragon_watch_key_cnt( watch ) );
  }
  FD_TEST( !fd_dragon_watch_verify( watch ) );
  FD_LOG_NOTICE(( "test_sweep_bound: ok" ));
}

/* The cost of the lookup an account write pays, on an index far
   larger than the cache. */

#define BENCH_KEY_MAX (1UL<<20)

static uchar bench_mem[ 64UL<<20 ] __attribute__((aligned(FD_DRAGON_WATCH_ALIGN)));

static void
bench_key( uchar * key,
           ulong   i ) {
  for( ulong j=0UL; j<4UL; j++ ) FD_STORE( ulong, key+8UL*j, fd_ulong_hash( i*4UL+j ) );
}

static void
test_bench( void ) {
  FD_TEST( fd_dragon_watch_footprint( BENCH_KEY_MAX )<=sizeof(bench_mem) );
  fd_dragon_watch_t * watch = fd_dragon_watch_join( fd_dragon_watch_new( bench_mem, BENCH_KEY_MAX, 1234UL ) );
  FD_TEST( watch );
  fd_dragon_watch_set_open( watch, 0UL );

  uchar key[ 32 ];
  long  dt = -fd_log_wallclock();
  for( ulong i=0UL; i<BENCH_KEY_MAX; i++ ) {
    bench_key( key, i );
    FD_TEST( fd_dragon_watch_add( watch, 0UL, key )==1 );
  }
  dt += fd_log_wallclock();
  FD_TEST( fd_dragon_watch_key_cnt( watch )==BENCH_KEY_MAX );
  bench_key( key, BENCH_KEY_MAX );
  FD_TEST( fd_dragon_watch_add( watch, 0UL, key )==-1 );
  FD_LOG_NOTICE(( "add:        %6.1f ns/key (%lu keys)", (double)dt/(double)BENCH_KEY_MAX, BENCH_KEY_MAX ));

  ulong iter = 2000000UL;
  ulong hit  = 0UL;
  dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    bench_key( key, fd_ulong_hash( i ) & (BENCH_KEY_MAX-1UL) );
    hit += fd_dragon_watch_query( watch, key );
  }
  dt += fd_log_wallclock();
  FD_TEST( hit==iter );
  FD_LOG_NOTICE(( "query hit:  %6.1f ns", (double)dt/(double)iter ));

  hit = 0UL;
  dt  = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    bench_key( key, BENCH_KEY_MAX + i );
    hit += fd_dragon_watch_query( watch, key );
  }
  dt += fd_log_wallclock();
  FD_TEST( !hit );
  FD_LOG_NOTICE(( "query miss: %6.1f ns", (double)dt/(double)iter ));

  fd_dragon_watch_set_clear( watch, 0UL );
  dt = -fd_log_wallclock();
  FD_TEST( !fd_dragon_watch_sweep( watch, BENCH_KEY_MAX ) );
  dt += fd_log_wallclock();
  FD_TEST( !fd_dragon_watch_key_cnt( watch ) );
  FD_LOG_NOTICE(( "sweep:      %6.1f ns/key", (double)dt/(double)BENCH_KEY_MAX ));

  FD_TEST( !fd_dragon_watch_verify( watch ) );
  FD_LOG_NOTICE(( "test_bench: ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_construct();
  test_basic();
  test_full();
  test_clear();
  test_bits();
  test_random( rng );
  test_sweep_bound( rng );
  test_bench();

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
