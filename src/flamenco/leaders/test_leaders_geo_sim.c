#include "fd_leaders.h"
#include <math.h>

FD_IMPORT_BINARY( e454_stakes, "src/flamenco/leaders/fixtures/epoch-stakes-454.bin" );

#define SLOT_CNT (432000UL)
#define PUB_MAX  (2048UL)
#define PI       (3.14159265358979323846)

static uchar base_buf[ FD_EPOCH_LEADERS_FOOTPRINT( PUB_MAX, SLOT_CNT ) ] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));
static uchar geo_buf [ FD_EPOCH_LEADERS_FOOTPRINT( PUB_MAX, SLOT_CNT ) ] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));
static fd_vote_stake_weight_t stakes[ PUB_MAX ];

static fd_validator_location_t
from_latlon( double lat,
             double lon ) {
  double a   = 6378137.0;
  double e2  = 6.69437999014e-3;
  double phi = lat*PI/180.0;
  double lam = lon*PI/180.0;
  double n   = a/sqrt( 1.0-e2*sin( phi )*sin( phi ) );
  return (fd_validator_location_t){ .x = (int)lround( n*cos( phi )*cos( lam ) ),
                                    .y = (int)lround( n*cos( phi )*sin( lam ) ),
                                    .z = (int)lround( n*(1.0-e2)*sin( phi ) ) };
}

struct city { double lat, lon; uint weight; };

static struct city const cities[] = {
  { 50.11,    8.68, 22 }, { 52.37,   4.90, 12 }, { 51.51,  -0.13, 7 }, { 53.35,  -6.26, 2 },
  { 48.86,    2.35,  2 }, { 52.23,  21.01,  2 }, { 47.38,   8.54, 2 }, { 59.33,  18.07, 1 },
  { 54.69,   25.28,  2 }, { 39.04, -77.49,  9 }, { 40.71, -74.01, 6 }, { 41.88, -87.63, 3 },
  { 32.78,  -96.80,  2 }, { 34.05,-118.24,  4 }, { 40.76,-111.89, 2 }, { 43.65, -79.38, 2 },
  {-23.55,  -46.63,  1 }, { 35.68, 139.69,  9 }, {  1.35, 103.82, 4 }, { 22.32, 114.17, 1 },
  { 37.57,  126.98,  1 }
};
#define CITY_CNT (sizeof(cities)/sizeof(cities[0]))

static double
handover_ms( fd_validator_location_t const * u,
             fd_validator_location_t const * v ) {
  double chord = sqrt( (double)fd_validator_location_dist2( u, v ) );
  double km    = 2.0*6371.0*asin( fmin( 1.0, chord/(2.0*6371000.0) ) );
  return km/150.0;
}

static void
report( char const *               label,
        fd_epoch_leaders_t const * l,
        ulong                      adv0 ) {
  double sum     = 0.0;
  double sum_hon = 0.0;
  ulong  hon_cnt = 0UL;
  ulong  run     = 0UL;
  ulong  run_max = 0UL;
  for( ulong i=0UL; i<l->sched_cnt; i++ ) {
    uint cur = l->sched[ i ];
    if( i ) {
      uint   prev = l->sched[ i-1UL ];
      double ms   = handover_ms( &stakes[ prev ].location, &stakes[ cur ].location );
      sum += ms;
      if( prev<adv0 && cur<adv0 ) { sum_hon += ms; hon_cnt++; }
    }
    run     = cur>=adv0 ? run+1UL : 0UL;
    run_max = fd_ulong_max( run_max, run );
  }
  FD_LOG_NOTICE(( "%-5s mean handover %5.1f ms (honest %5.1f ms) adversary max run %lu",
                  label, sum/(double)(l->sched_cnt-1UL), sum_hon/(double)hon_cnt, run_max ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1234U, 0UL ) );

  ulong const hon_cnt = 2000UL;
  ulong const adv_cnt = 10UL;
  fd_stake_weight_t const * e454 = (fd_stake_weight_t const *)e454_stakes;
  FD_TEST( hon_cnt<=e454_stakes_sz/sizeof(fd_stake_weight_t) );
  uint weight_sum = 0U;
  for( ulong c=0UL; c<CITY_CNT; c++ ) weight_sum += cities[ c ].weight;
  ulong total = 0UL;
  for( ulong i=0UL; i<hon_cnt; i++ ) {
    stakes[ i ].stake    = e454[ i ].stake;
    stakes[ i ].id_key   = e454[ i ].key;
    stakes[ i ].vote_key = e454[ i ].key;
    uint  pick = fd_rng_uint_roll( rng, weight_sum );
    ulong c    = 0UL;
    while( pick>=cities[ c ].weight ) pick -= cities[ c++ ].weight;
    stakes[ i ].location = from_latlon( cities[ c ].lat+0.4*fd_rng_double_c( rng )-0.2, cities[ c ].lon+0.4*fd_rng_double_c( rng )-0.2 );
    total += stakes[ i ].stake;
  }
  for( ulong i=hon_cnt; i<hon_cnt+adv_cnt; i++ ) {
    stakes[ i ].stake = total/19UL/adv_cnt;
    memset( stakes[ i ].vote_key.uc, (int)i, 32UL );
    stakes[ i ].id_key   = stakes[ i ].vote_key;
    stakes[ i ].location = from_latlon( -33.87, 151.21 );
  }
  ulong pub_cnt = hon_cnt+adv_cnt;

  for( ulong epoch=1038UL; epoch<1041UL; epoch++ ) {
    long t0 = fd_log_wallclock();
    fd_epoch_leaders_t * base = fd_epoch_leaders_join( fd_epoch_leaders_new( base_buf, epoch, 0UL, SLOT_CNT, pub_cnt, stakes, 0 ) );
    long t1 = fd_log_wallclock();
    fd_epoch_leaders_t * geo  = fd_epoch_leaders_join( fd_epoch_leaders_new( geo_buf,  epoch, 0UL, SLOT_CNT, pub_cnt, stakes, 1 ) );
    long t2 = fd_log_wallclock();
    FD_LOG_NOTICE(( "epoch %lu: base %.1f ms, geo %.1f ms", epoch, (double)(t1-t0)/1e6, (double)(t2-t1)/1e6 ));
    report( "base", base, hon_cnt );
    report( "geo",  geo,  hon_cnt );
  }

  for( ulong i=0UL; i<hon_cnt; i++ ) {
    stakes[ i ].stake    = 1000000000UL;
    stakes[ i ].location = from_latlon( 180.0*fd_rng_double_c( rng )-90.0, 360.0*fd_rng_double_c( rng )-180.0 );
  }
  long t0 = fd_log_wallclock();
  fd_epoch_leaders_new( geo_buf, 7UL, 0UL, SLOT_CNT, hon_cnt, stakes, 1 );
  long t1 = fd_log_wallclock();
  FD_LOG_NOTICE(( "uniform worst case: geo %.1f ms", (double)(t1-t0)/1e6 ));

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
