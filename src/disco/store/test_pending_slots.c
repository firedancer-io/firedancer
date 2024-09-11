#include "fd_pending_slots.h"
#include "../../util/fd_util.h"
#include "../../flamenco/fd_flamenco.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

void
random_shuffle( ulong* array, uint len) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong i=0; i<len; i++ ) {
      ulong idx_to_swap  = fd_rng_ulong_roll( rng, len );
      ulong tmp          = array[i];
      array[i]           = array[idx_to_swap];
      array[idx_to_swap] = tmp;
    }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_NOTICE(( "New fd_pending_slots_t" ));
  ulong seed = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed", "",  0UL );
  uchar __attribute__((aligned((alignof( fd_pending_slots_t ))))) buf[ fd_pending_slots_footprint() ];
  fd_pending_slots_t * pending_slots = fd_pending_slots_join( fd_pending_slots_new( (void *)buf, (uint)seed ) );

  FD_LOG_NOTICE(( "Insert %lu elements into pending_slots", FD_BLOCK_MAX ));
  ulong slots[FD_BLOCK_MAX];
  for( ulong i=0; i<FD_BLOCK_MAX; i++ ) slots[i] = i;
  random_shuffle( slots, FD_BLOCK_MAX );

  long now = fd_log_wallclock();
  for( ulong i=0; i<FD_BLOCK_MAX; i++ ) {
    long when = now + (long)slots[i];
    fd_pending_slots_add( pending_slots, slots[i], when );
  }

  FD_LOG_NOTICE(( "Iterate pending_slots and check the insertion" ));
  ulong iterated = 0;
  fd_pending_slots_treap_fwd_iter_t iter;
  for( iter=fd_pending_slots_treap_fwd_iter_init( pending_slots->treap, pending_slots->pool );
       !fd_pending_slots_treap_fwd_iter_done( iter );
       iter=fd_pending_slots_treap_fwd_iter_next( iter, pending_slots->pool ) ) {
    iterated += 1;
    fd_pending_slots_treap_ele_t * ele = fd_pending_slots_treap_fwd_iter_ele( iter, pending_slots->pool );
    FD_TEST( ele->slot==iterated-1 );
    FD_TEST( ele->time==now+(long)ele->slot );
  }
  FD_TEST( iterated==FD_BLOCK_MAX );

  FD_LOG_NOTICE(( "Remove %lu slots by calling set_lo_wmark()", FD_BLOCK_MAX/2 ));
  ulong lo_wmark = FD_BLOCK_MAX / 2 - 1;
  fd_pending_slots_set_lo_wmark( pending_slots, lo_wmark );

  FD_LOG_NOTICE(( "Iterate pending_slots and check the remove by set_lo_wmark()" ));
  iterated = 0;
  for( iter=fd_pending_slots_treap_fwd_iter_init( pending_slots->treap, pending_slots->pool );
       !fd_pending_slots_treap_fwd_iter_done( iter );
       iter=fd_pending_slots_treap_fwd_iter_next( iter, pending_slots->pool ) ) {
    iterated += 1;
    fd_pending_slots_treap_ele_t * ele = fd_pending_slots_treap_fwd_iter_ele( iter, pending_slots->pool );
    FD_TEST( ele->slot>lo_wmark );
  }
  FD_TEST( iterated==FD_BLOCK_MAX/2 );

  FD_LOG_NOTICE(( "Insert with existing slot#, but different timestamp" ));
  for( ulong i=lo_wmark+1; i<FD_BLOCK_MAX; i++ ) {
    long when = now + (long)i - (long)lo_wmark;
    fd_pending_slots_add( pending_slots, i, when );
  }

  FD_LOG_NOTICE(( "Iterate pending_slots and check the insertion with existing slot#" ));
  iterated = 0;
  for( iter=fd_pending_slots_treap_fwd_iter_init( pending_slots->treap, pending_slots->pool );
       !fd_pending_slots_treap_fwd_iter_done( iter );
       iter=fd_pending_slots_treap_fwd_iter_next( iter, pending_slots->pool ) ) {
    iterated += 1;
    fd_pending_slots_treap_ele_t * ele = fd_pending_slots_treap_fwd_iter_ele( iter, pending_slots->pool );
    FD_TEST( ele->time==now+(long)ele->slot-(long)lo_wmark );
  }
  FD_TEST( iterated==FD_BLOCK_MAX/2 );

  FD_LOG_NOTICE(( "Insert %lu new elements to pending_slots", FD_BLOCK_MAX/2 ));
  for( ulong i=0; i<FD_BLOCK_MAX/2; i++ ) {
    ulong slot = FD_BLOCK_MAX + i;
    fd_pending_slots_add( pending_slots, slot, now + (long)slot - (long)lo_wmark );
  }

  FD_LOG_NOTICE(( "Remove elements in the middle of the treap during iteration" ));
  iterated = 0;
  for( iter=fd_pending_slots_treap_fwd_iter_init( pending_slots->treap, pending_slots->pool );
       !fd_pending_slots_treap_fwd_iter_done( iter ); ) {
    iterated += 1;
    fd_pending_slots_treap_ele_t * ele = fd_pending_slots_treap_fwd_iter_ele( iter, pending_slots->pool );
    iter = fd_pending_slots_treap_fwd_iter_next( iter, pending_slots->pool );
    if( iterated & 1 ) {
      fd_pending_slots_treap_ele_remove( pending_slots->treap, ele, pending_slots->pool );
      fd_pending_slots_pool_ele_release( pending_slots->pool, ele );
    }
  }
  FD_TEST( iterated==FD_BLOCK_MAX );

  FD_LOG_NOTICE(( "Iterate pending_slots and check the removal during iteration" ));
  iterated = 0;
  for( iter=fd_pending_slots_treap_fwd_iter_init( pending_slots->treap, pending_slots->pool );
       !fd_pending_slots_treap_fwd_iter_done( iter );
       iter=fd_pending_slots_treap_fwd_iter_next( iter, pending_slots->pool ) ) {
    iterated += 1;
    fd_pending_slots_treap_ele_t * ele = fd_pending_slots_treap_fwd_iter_ele( iter, pending_slots->pool );
    FD_TEST( ele->slot==lo_wmark+iterated*2 );
    FD_TEST( ele->time==now+(long)ele->slot-(long)lo_wmark );
  }
  FD_TEST( iterated==FD_BLOCK_MAX/2 );

  FD_LOG_WARNING(( "Insert %lu+1 new element which should trigger an error saying that the treap/pool is full", FD_BLOCK_MAX/2 ));
  for( ulong i=0; i<FD_BLOCK_MAX/2+1; i++ ) {
    fd_pending_slots_add( pending_slots, FD_BLOCK_MAX * 2 + i, 0 );
  }

  return 0;
}
