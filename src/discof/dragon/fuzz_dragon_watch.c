/* fuzz_dragon_watch.c drives the watch index with a sequence of
   operations read from the input and compares every answer with a
   naive model: for each address of a small universe, the sets that
   hold it.  The index is small, so that inputs reach a full index,
   and sets cover all 64 numbers, so that they run out of bits.

   The first byte seeds the address hash.  Every following pair of
   bytes is one operation: the low 3 bits of the first byte pick it,
   the rest pick the set, and the second byte picks the address or the
   number of slots to sweep. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_dragon_watch.h"
#include "../../util/fd_util.h"

#define KEY_MAX  (24UL)
#define UNIVERSE (40UL)

static uchar g_mem[ 16384 ] __attribute__((aligned(FD_DRAGON_WATCH_ALIGN)));
static uchar g_key[ UNIVERSE ][ 32 ];

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  (void)atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */

  for( ulong i=0UL; i<UNIVERSE; i++ ) {
    for( ulong j=0UL; j<4UL; j++ ) FD_STORE( ulong, g_key[ i ]+8UL*j, fd_ulong_hash( i*4UL+j ) );
  }
  /* Two addresses that differ in their last byte only */
  fd_memcpy( g_key[ 1 ], g_key[ 0 ], 32UL );
  g_key[ 1 ][ 31 ] ^= (uchar)1;
  return 0;
}

static ulong
model_key_cnt( ulong const * model ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<UNIVERSE; i++ ) cnt += !!model[ i ];
  return cnt;
}

static void
model_set_clear( ulong * model,
                 ulong   set ) {
  for( ulong i=0UL; i<UNIVERSE; i++ ) model[ i ] &= ~( 1UL<<set );
}

static void
fuzz_check( fd_dragon_watch_t const * watch,
            ulong const *             model,
            ulong                     open ) {
  assert( !fd_dragon_watch_verify( watch ) );
  assert( fd_dragon_watch_set_mask( watch )==open );
  for( ulong i=0UL; i<UNIVERSE; i++ ) assert( fd_dragon_watch_query( watch, g_key[ i ] )==model[ i ] );
  for( ulong set=0UL; set<FD_DRAGON_WATCH_SET_MAX; set++ ) {
    if( !( ( open>>set )&1UL ) ) continue;
    ulong cnt = 0UL;
    for( ulong i=0UL; i<UNIVERSE; i++ ) cnt += ( model[ i ]>>set )&1UL;
    assert( fd_dragon_watch_set_key_cnt( watch, set )==cnt );
  }
  ulong key_cnt = fd_dragon_watch_key_cnt( watch );
  assert( key_cnt<=KEY_MAX );
  assert( key_cnt>=model_key_cnt( model ) );
  if( !fd_dragon_watch_sweep_pending( watch ) ) assert( key_cnt==model_key_cnt( model ) );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( size<1UL ) return -1;
  ulong seed = data[ 0 ];
  data += 1UL; size -= 1UL;

  assert( fd_dragon_watch_footprint( KEY_MAX )<=sizeof(g_mem) );
  fd_dragon_watch_t * watch = fd_dragon_watch_join( fd_dragon_watch_new( g_mem, KEY_MAX, seed ) );
  assert( watch );

  ulong model[ UNIVERSE ] = {0};
  ulong open = 0UL;

  for( ulong off=0UL; off+2UL<=size; off+=2UL ) {
    ulong op      = data[ off ] & 7UL;
    ulong set     = (ulong)data[ off ]>>3;       /* in [0,32) */
    ulong arg     = data[ off+1UL ];
    if( arg & 0x80UL ) set += 32UL;              /* in [0,64) */
    ulong k       = ( arg & 0x7fUL ) % UNIVERSE;
    int   is_open = (int)( ( open>>set )&1UL );

    switch( op ) {
    case 0UL:
      if( is_open ) break;
      fd_dragon_watch_set_open( watch, set );
      open |= 1UL<<set;
      break;
    case 1UL:
      if( !is_open ) break;
      fd_dragon_watch_set_close( watch, set );
      open &= ~( 1UL<<set );
      model_set_clear( model, set );
      break;
    case 2UL:
      if( !is_open ) break;
      fd_dragon_watch_set_clear( watch, set );
      model_set_clear( model, set );
      break;
    case 3UL:
    case 4UL: {
      if( !is_open ) break;
      int have = (int)( ( model[ k ]>>set )&1UL );
      int rc   = fd_dragon_watch_add( watch, set, g_key[ k ] );
      if( rc==-1 ) {
        assert( !have );
        if( fd_dragon_watch_sweep_pending( watch ) ) {
          /* Whatever a sweep can free is free after key_max visits */
          assert( !fd_dragon_watch_sweep( watch, KEY_MAX ) );
          rc = fd_dragon_watch_add( watch, set, g_key[ k ] );
        }
        if( rc==-1 ) {
          /* The index is full of addresses that sets hold */
          assert( model_key_cnt( model )==KEY_MAX && !model[ k ] );
          break;
        }
      }
      assert( rc==!have );
      model[ k ] |= 1UL<<set;
      break;
    }
    case 5UL: {
      if( !is_open ) break;
      int have = (int)( ( model[ k ]>>set )&1UL );
      assert( fd_dragon_watch_remove( watch, set, g_key[ k ] )==have );
      model[ k ] &= ~( 1UL<<set );
      break;
    }
    case 6UL: {
      int pending = fd_dragon_watch_sweep( watch, arg & 31UL );
      assert( pending==fd_dragon_watch_sweep_pending( watch ) );
      break;
    }
    default:
      fuzz_check( watch, model, open );
      break;
    }

    assert( fd_dragon_watch_query( watch, g_key[ k ] )==model[ k ] );
  }

  fuzz_check( watch, model, open );
  assert( fd_dragon_watch_delete( fd_dragon_watch_leave( watch ) )==g_mem );
  return 0;
}
