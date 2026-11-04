#include "fd_leaders.c"
#include <assert.h>
#include <stdlib.h>

static fd_validator_location_t const CITY[ 8 ] = {
  {  4051542,   618526,  4870645 }, {  3977778,        0,  4969055 },
  {  1333729, -4654333,  4138065 }, { -3955214,  3355452,  3699409 },
  { -4646017,  2553114, -3534483 }, {  4017263, -4252595, -2532673 },
  { -1523141,  6191788,   149262 }, {  1074501, -4842760,  3995767 }
};

#define PUB_MAX   (64UL)
#define SCHED_MAX (1024UL)

static fd_pubkey_t scratch[ PUB_MAX ];

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  fd_log_level_stderr_set( 4 );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( size<10UL ) return 0;
  ulong pub_cnt   = 1UL+( (ulong)data[ 0 ]%PUB_MAX );
  ulong epoch     = FD_LOAD( ulong, data+1UL );
  data += 9UL; size -= 9UL;
  if( size<pub_cnt*3UL ) return 0;

  static fd_vote_stake_weight_t stakes[ PUB_MAX ];
  memset( stakes, 0, sizeof(stakes) );
  for( ulong i=0UL; i<pub_cnt; i++ ) {
    stakes[ i ].stake    = 1UL+( (ulong)FD_LOAD( ushort, data+3UL*i )<<24 );
    stakes[ i ].location = CITY[ data[ 3UL*i+2UL ]&7U ];
    stakes[ i ].location.x += (int)( data[ 3UL*i+2UL ]>>3 );
  }
  data += pub_cnt*3UL; size -= pub_cnt*3UL;

  ulong sched_cnt = fd_ulong_min( size, SCHED_MAX );
  if( !sched_cnt ) return 0;
  static uint sched[ SCHED_MAX ];
  static uint cnt  [ PUB_MAX ];
  memset( cnt, 0, sizeof(cnt) );
  for( ulong i=0UL; i<sched_cnt; i++ ) { sched[ i ] = (uint)( data[ i ]%pub_cnt ); cnt[ sched[ i ] ]++; }

  geo_aware_reorder( sched, sched_cnt, stakes, pub_cnt, epoch, scratch );

  for( ulong i=0UL; i<sched_cnt; i++ ) { assert( sched[ i ]<pub_cnt ); assert( cnt[ sched[ i ] ] ); cnt[ sched[ i ] ]--; }
  for( ulong i=0UL; i<pub_cnt;   i++ ) assert( !cnt[ i ] );
  return 0;
}
