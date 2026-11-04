#include "fd_leaders.c"
#include <sys/wait.h>
#include <unistd.h>

#define REF_PUB_MAX   (64UL)
#define REF_SCHED_MAX (512UL)

static fd_validator_location_t const CITY[ 8 ] = {
  {  4051542,   618526,  4870645 }, {  3977778,        0,  4969055 },
  {  1333729, -4654333,  4138065 }, { -3955214,  3355452,  3699409 },
  { -4646017,  2553114, -3534483 }, {  4017263, -4252595, -2532673 },
  { -1523141,  6191788,   149262 }, {  1074501, -4842760,  3995767 }
};

static fd_validator_location_t
city_loc( ulong i ) {
  fd_validator_location_t loc = CITY[ i%8UL ];
  loc.x += (int)( 7UL*( (i/8UL)%41UL ) );
  return loc;
}

static void
ref_shuffle( fd_chacha_rng_t * rng,
             uint *            a,
             ulong             n ) {
  if( n<2UL ) return;
  for( ulong i=n-1UL; i>=1UL; i-- ) {
    ulong j = fd_chacha_rng_ulong_roll( rng, i+1UL );
    uint  t = a[ i ]; a[ i ] = a[ j ]; a[ j ] = t;
  }
}

static ulong
ref_radius( fd_vote_stake_weight_t const * stakes,
            ulong                          pub_cnt,
            ulong                          v,
            ulong                          total ) {
  static ulong d[ REF_PUB_MAX ];
  static ulong w[ REF_PUB_MAX ];
  ulong n = 0UL;
  for( ulong u=0UL; u<pub_cnt; u++ ) {
    d[ n ] = fd_validator_location_dist2( &stakes[ v ].location, &stakes[ u ].location );
    w[ n ] = stakes[ u ].stake;
    n++;
  }
  for( ulong i=1UL; i<n; i++ ) {
    for( ulong k=i; k>0UL && d[ k-1UL ]>d[ k ]; k-- ) {
      ulong td = d[ k ]; d[ k ] = d[ k-1UL ]; d[ k-1UL ] = td;
      ulong tw = w[ k ]; w[ k ] = w[ k-1UL ]; w[ k-1UL ] = tw;
    }
  }
  uint128 acc = 0;
  for( ulong i=0UL; i<n; i++ ) {
    acc += w[ i ];
    if( acc*10UL>=(uint128)total ) return d[ i ];
  }
  FD_LOG_ERR(( "unreachable" ));
}

static void
ref_reorder( uint *                         sched,
             ulong                          sched_cnt,
             fd_vote_stake_weight_t const * stakes,
             ulong                          pub_cnt,
             ulong                          epoch ) {
  static ulong r       [ REF_PUB_MAX ];
  static uint  anchor  [ REF_PUB_MAX ];
  static uint  cnt     [ REF_PUB_MAX ];
  static uint  mem     [ REF_PUB_MAX ][ FD_EPOCH_LEADERS_GEO_RUN_LENGTH ];
  static uint  near_idx[ REF_PUB_MAX ];
  static uint  order   [ REF_PUB_MAX ];
  static uint  out     [ REF_SCHED_MAX ];

  ulong total = 0UL;
  for( ulong i=0UL; i<pub_cnt; i++ ) total += stakes[ i ].stake;
  for( ulong v=0UL; v<pub_cnt; v++ ) r[ v ] = ref_radius( stakes, pub_cnt, v, total );

  uchar tag[] = "geo-aware-leader-schedule";
  uchar buf[ 25UL+8UL ];
  memcpy( buf, tag, 25UL );
  for( ulong b=0UL; b<8UL; b++ ) buf[ 25UL+b ] = (uchar)( epoch>>(8UL*b) );
  uchar key[ 32 ];
  fd_sha256_hash( buf, sizeof(buf), key );
  fd_chacha_rng_t _rng[1];
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_MOD ) );
  fd_chacha_rng_init( rng, key, FD_CHACHA_RNG_ALGO_CHACHA20 );

  ulong open = 0UL;
  ulong n    = 0UL;
  for( ulong i=0UL; i<sched_cnt; i++ ) {
    uint  l        = sched[ i ];
    ulong near_cnt = 0UL;
    for( ulong b=0UL; b<open; b++ ) {
      uint a = anchor[ b ];
      if( fd_validator_location_dist2( &stakes[ l ].location, &stakes[ a ].location )<=fd_ulong_max( r[ a ], r[ l ] ) ) near_idx[ near_cnt++ ] = (uint)b;
    }
    ulong b;
    if( !near_cnt ) { b = open++; anchor[ b ] = l; cnt[ b ] = 0U; }
    else            b = near_idx[ fd_chacha_rng_ulong_roll( rng, near_cnt ) ];
    mem[ b ][ cnt[ b ]++ ] = l;
    if( cnt[ b ]==FD_EPOCH_LEADERS_GEO_RUN_LENGTH ) {
      ref_shuffle( rng, mem[ b ], cnt[ b ] );
      for( ulong m=0UL; m<cnt[ b ]; m++ ) out[ n++ ] = mem[ b ][ m ];
      for( ulong k=b; k+1UL<open; k++ ) {
        anchor[ k ] = anchor[ k+1UL ];
        cnt   [ k ] = cnt   [ k+1UL ];
        memcpy( mem[ k ], mem[ k+1UL ], sizeof(mem[ k ]) );
      }
      open--;
    }
  }
  for( ulong b=0UL; b<open; b++ ) order[ b ] = (uint)b;
  ref_shuffle( rng, order, open );
  for( ulong k=0UL; k<open; k++ ) {
    uint b = order[ k ];
    ref_shuffle( rng, mem[ b ], cnt[ b ] );
    for( ulong m=0UL; m<cnt[ b ]; m++ ) out[ n++ ] = mem[ b ][ m ];
  }
  fd_chacha_rng_delete( fd_chacha_rng_leave( rng ) );
  FD_TEST( n==sched_cnt );
  memcpy( sched, out, sched_cnt*sizeof(uint) );
}

static fd_pubkey_t scratch[ REF_PUB_MAX ];

static void
test_city_locations_valid( void ) {
  for( ulong i=0UL; i<2048UL; i++ ) {
    fd_validator_location_t loc = city_loc( i );
    FD_TEST( fd_validator_location_is_valid( &loc ) );
  }
}

static void
test_radius( fd_rng_t * rng ) {
  fd_geo_neighbor_t neighbor[ 3 ] = { { 0UL, 5UL }, { 100UL, 5UL }, { 900UL, 90UL } };
  FD_TEST( compute_smallest_radius( neighbor, 3UL, 100UL )==100UL );

  static fd_geo_neighbor_t p[ 200 ];
  static fd_geo_neighbor_t s[ 200 ];
  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    ulong   n     = 1UL+fd_rng_ulong_roll( rng, 200UL );
    ulong   dmax  = 1UL+fd_rng_ulong_roll( rng, iter&1UL ? 4UL : 1000000UL );
    ulong   total = 0UL;
    for( ulong i=0UL; i<n; i++ ) {
      p[ i ].dist2 = i ? fd_rng_ulong_roll( rng, dmax ) : 0UL;
      p[ i ].stake = 1UL+fd_rng_ulong_roll( rng, iter&2UL ? 3UL : 1000000UL );
      total       += p[ i ].stake;
    }
    memcpy( s, p, n*sizeof(fd_geo_neighbor_t) );
    sort_geo_neighbor_inplace( s, n );
    uint128 acc = 0;
    ulong   ref = ULONG_MAX;
    for( ulong i=0UL; i<n; i++ ) { acc += s[ i ].stake; if( acc*10UL>=(uint128)total ) { ref = s[ i ].dist2; break; } }
    FD_TEST( compute_smallest_radius( p, n, total )==ref );
  }
}

static void
test_radius_fallback( void ) {
  static fd_geo_neighbor_t p   [ 64 ];
  static ulong             slot[ 64 ];
  ulong const n        = 64UL;
  ulong       slot_cnt = n;
  ulong       rank     = 1UL;
  for( ulong i=0UL; i<n; i++ ) slot[ i ] = i;
  while( slot_cnt>2UL ) {
    ulong mid = slot_cnt/2UL;
    p[ slot[ 0   ] ].dist2 = rank++;
    p[ slot[ mid ] ].dist2 = rank++;
    memmove( slot+mid, slot+mid+1UL, (slot_cnt-mid-1UL)*sizeof(ulong) );
    memmove( slot,     slot+1UL,     (slot_cnt-2UL)*sizeof(ulong)     );
    slot_cnt -= 2UL;
  }
  for( ulong i=0UL; i<slot_cnt; i++ ) p[ slot[ i ] ].dist2 = rank++;
  for( ulong i=0UL; i<n; i++ ) p[ i ].stake = p[ i ].dist2==n ? 1000000UL : 1UL;
  ulong total = 0UL;
  for( ulong i=0UL; i<n; i++ ) total += p[ i ].stake;
  FD_TEST( compute_smallest_radius( p, n, total )==n );
}

static void
test_differential( fd_rng_t * rng ) {
  static fd_vote_stake_weight_t stakes[ REF_PUB_MAX ];
  static uint                   a     [ REF_SCHED_MAX ];
  static uint                   b     [ REF_SCHED_MAX ];
  for( ulong iter=0UL; iter<3000UL; iter++ ) {
    ulong pub_cnt   = 1UL+fd_rng_ulong_roll( rng, REF_PUB_MAX );
    ulong sched_cnt = 1UL+fd_rng_ulong_roll( rng, REF_SCHED_MAX );
    ulong cities    = 1UL+fd_rng_ulong_roll( rng, 8UL );
    memset( stakes, 0, sizeof(stakes) );
    for( ulong i=0UL; i<pub_cnt; i++ ) {
      stakes[ i ].stake    = 1UL+fd_rng_ulong_roll( rng, iter&1UL ? 1000UL : 1000000000UL );
      stakes[ i ].location = city_loc( fd_rng_ulong_roll( rng, cities )+8UL*fd_rng_ulong_roll( rng, 3UL ) );
    }
    for( ulong i=0UL; i<sched_cnt; i++ ) a[ i ] = (uint)fd_rng_ulong_roll( rng, pub_cnt );
    memcpy( b, a, sched_cnt*sizeof(uint) );
    ulong epoch = fd_rng_ulong( rng );
    geo_aware_reorder( a, sched_cnt, stakes, pub_cnt, epoch, scratch );
    ref_reorder( b, sched_cnt, stakes, pub_cnt, epoch );
    FD_TEST( !memcmp( a, b, sched_cnt*sizeof(uint) ) );
  }
}

static int
reorder_exit_status( fd_vote_stake_weight_t const * stakes,
                     ulong                          pub_cnt ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_level_logfile_set( 6 );
    fd_log_level_stderr_set( 6 );
    uint s[ 4 ] = { 0U, 1U, 0U, 1U };
    geo_aware_reorder( s, 4UL, stakes, pub_cnt, 1UL, scratch );
    _exit( 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  return WEXITSTATUS( status );
}

static void
test_unlocated_err( void ) {
  static fd_vote_stake_weight_t stakes[ 3 ];
  memset( stakes, 0, sizeof(stakes) );
  for( ulong i=0UL; i<3UL; i++ ) { stakes[ i ].stake = 10UL; stakes[ i ].location = city_loc( i ); }
  FD_TEST( reorder_exit_status( stakes, 3UL )==0 );
  stakes[ 1 ].location = (fd_validator_location_t){ 6000000, 0, 0 };
  FD_TEST( reorder_exit_status( stakes, 3UL )==1 );
  stakes[ 1 ].location = city_loc( 1UL );
  stakes[ 2 ].location = (fd_validator_location_t){ 6000000, 0, 0 };
  FD_TEST( reorder_exit_status( stakes, 3UL )==1 );
}

FD_IMPORT_BINARY( e454_stakes, "src/flamenco/leaders/fixtures/epoch-stakes-454.bin" );

#define SLOT_CNT  (432000UL)
#define PUB_MAX   (2048UL)

static uchar base_buf[ FD_EPOCH_LEADERS_FOOTPRINT( PUB_MAX, SLOT_CNT ) ] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));
static uchar geo_buf [ FD_EPOCH_LEADERS_FOOTPRINT( PUB_MAX, SLOT_CNT ) ] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));
static fd_vote_stake_weight_t lstakes[ PUB_MAX ];

static fd_epoch_leaders_t *
lsched( uchar * buf,
        ulong   epoch,
        ulong   slot_cnt,
        ulong   pub_cnt,
        int     geo ) {
  fd_epoch_leaders_t * leaders = fd_epoch_leaders_join( fd_epoch_leaders_new( buf, epoch, 0UL, slot_cnt, pub_cnt, lstakes, geo ) );
  FD_TEST( leaders );
  return leaders;
}

static void
fill_stakes( ulong pub_cnt ) {
  FD_TEST( pub_cnt<=PUB_MAX && pub_cnt<=e454_stakes_sz/sizeof(fd_stake_weight_t) );
  fd_stake_weight_t const * e454 = (fd_stake_weight_t const *)e454_stakes;
  memset( lstakes, 0, sizeof(lstakes) );
  for( ulong i=0UL; i<pub_cnt; i++ ) {
    lstakes[ i ].stake    = e454[ i ].stake;
    lstakes[ i ].id_key   = e454[ i ].key;
    lstakes[ i ].vote_key = e454[ i ].key;
    lstakes[ i ].location = city_loc( i );
  }
}

static void
check_permutation( fd_epoch_leaders_t const * base,
                   fd_epoch_leaders_t const * geo ) {
  static uint cnt[ PUB_MAX ];
  FD_TEST( base->sched_cnt==geo->sched_cnt && base->pub_cnt==geo->pub_cnt );
  memset( cnt, 0, sizeof(cnt) );
  for( ulong i=0UL; i<base->sched_cnt; i++ ) cnt[ base->sched[ i ] ]++;
  for( ulong i=0UL; i<geo->sched_cnt;  i++ ) { FD_TEST( cnt[ geo->sched[ i ] ] ); cnt[ geo->sched[ i ] ]--; }
  for( ulong i=0UL; i<base->pub_cnt;   i++ ) FD_TEST( !cnt[ i ] );
  for( ulong i=0UL; i<geo->sched_cnt;  i++ ) FD_TEST( !memcmp( geo->vote_addr+i, &lstakes[ geo->sched[ i ] ].vote_key, 32UL ) );
}

static void
test_single_location( void ) {
  ulong const R = FD_EPOCH_LEADERS_GEO_RUN_LENGTH;
  fill_stakes( 500UL );
  for( ulong i=0UL; i<500UL; i++ ) lstakes[ i ].location = CITY[ 0 ];
  fd_epoch_leaders_t * base = lsched( base_buf, 9UL, SLOT_CNT, 500UL, 0 );
  fd_epoch_leaders_t * geo  = lsched( geo_buf,  9UL, SLOT_CNT, 500UL, 1 );
  check_permutation( base, geo );
  int differ = 0;
  for( ulong i=0UL; i<base->sched_cnt; i+=R ) {
    ulong n = fd_ulong_min( R, base->sched_cnt-i );
    uint  b[ FD_EPOCH_LEADERS_GEO_RUN_LENGTH ];
    memcpy( b, base->sched+i, n*sizeof(uint) );
    for( ulong j=0UL; j<n; j++ ) {
      ulong k;
      for( k=0UL; k<n; k++ ) if( b[ k ]==geo->sched[ i+j ] ) break;
      FD_TEST( k<n );
      b[ k ] = UINT_MAX;
    }
    differ |= !!memcmp( base->sched+i, geo->sched+i, n*sizeof(uint) );
  }
  FD_TEST( differ );
}

static void
test_two_clusters( void ) {
  ulong const R = FD_EPOCH_LEADERS_GEO_RUN_LENGTH;
  fill_stakes( 200UL );
  for( ulong i=0UL; i<200UL; i++ ) lstakes[ i ].location = (i&1UL) ? CITY[ 3 ] : CITY[ 0 ];
  fd_epoch_leaders_t * base = lsched( base_buf, 11UL, SLOT_CNT, 200UL, 0 );
  fd_epoch_leaders_t * geo  = lsched( geo_buf,  11UL, SLOT_CNT, 200UL, 1 );
  check_permutation( base, geo );
  ulong full = (geo->sched_cnt-2UL*(R-1UL))/R;
  for( ulong k=0UL; k<full; k++ ) {
    uint c = geo->sched[ k*R ]&1U;
    for( ulong j=1UL; j<R; j++ ) FD_TEST( (geo->sched[ k*R+j ]&1U)==c );
  }
}

static void
test_determinism( void ) {
  fill_stakes( 300UL );
  fd_epoch_leaders_t * a = lsched( base_buf, 13UL, SLOT_CNT, 300UL, 1 );
  fd_epoch_leaders_t * b = lsched( geo_buf,  13UL, SLOT_CNT, 300UL, 1 );
  FD_TEST( !memcmp( a->sched, b->sched, a->sched_cnt*sizeof(uint) ) );
  b = lsched( geo_buf, 14UL, SLOT_CNT, 300UL, 1 );
  FD_TEST(  memcmp( a->sched, b->sched, a->sched_cnt*sizeof(uint) ) );

  for( ulong slot_cnt=1UL; slot_cnt<=64UL; slot_cnt++ ) {
    for( ulong pub_cnt=1UL; pub_cnt<=5UL; pub_cnt++ ) {
      fd_epoch_leaders_t * base = lsched( base_buf, slot_cnt, slot_cnt, pub_cnt, 0 );
      fd_epoch_leaders_t * geo  = lsched( geo_buf,  slot_cnt, slot_cnt, pub_cnt, 1 );
      check_permutation( base, geo );
    }
  }
}

static void
test_golden( void ) {
  static uchar const golden[ 32 ] = {
    0x7d, 0xe3, 0x0e, 0x78, 0x66, 0x7f, 0x8b, 0x79,
    0x5b, 0xcc, 0x0f, 0x5c, 0x0b, 0x34, 0x9c, 0x33,
    0x28, 0x21, 0x56, 0x31, 0x05, 0x8b, 0x2c, 0xd7,
    0x6a, 0x1e, 0x5f, 0xf6, 0xe3, 0x12, 0xb3, 0x51
  };
  fill_stakes( 300UL );
  fd_epoch_leaders_t * base = lsched( base_buf, 13UL, SLOT_CNT, 300UL, 0 );
  fd_epoch_leaders_t * geo  = lsched( geo_buf,  13UL, SLOT_CNT, 300UL, 1 );
  uchar hash[ 32 ];
  fd_sha256_hash( geo->sched, geo->sched_cnt*sizeof(uint), hash );
  FD_LOG_NOTICE(( "geo golden " FD_LOG_HEX16_FMT " " FD_LOG_HEX16_FMT, FD_LOG_HEX16_FMT_ARGS( hash ), FD_LOG_HEX16_FMT_ARGS( hash+16 ) ));
  FD_TEST( memcmp( base->sched, geo->sched, geo->sched_cnt*sizeof(uint) ) );
  FD_TEST( !memcmp( hash, golden, 32UL ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 675U, 0UL ) );

  test_city_locations_valid();
  test_radius( rng );
  test_radius_fallback();
  test_differential( rng );
  test_unlocated_err();
  test_single_location();
  test_two_clusters();
  test_determinism();
  test_golden();

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
