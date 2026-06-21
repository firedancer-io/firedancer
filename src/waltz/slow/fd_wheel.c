#include "fd_wheel.h"
#include "../../util/log/fd_log.h"

fd_wheel_t *
fd_wheel_new( fd_wheel_t *       wheel,
              fd_wheel_timer_t * pool,
              long               now ) {
  for( ulong i=0UL; i<FD_WHEEL_LEVEL_CNT; i++ ) {
    for( ulong j=0UL; j<FD_WHEEL_BUCKET_CNT; j++ ) {
      wheel->map[ i ][ j ] = UINT_MAX;
    }
  }
  wheel->pool = pool;
  wheel->base = (long)fd_ulong_align_dn( (ulong)now, (ulong)FD_WHEEL_BUCKET( 0 ) );
  return wheel;
}

void *
fd_wheel_delete( fd_wheel_t * wheel ) {
  wheel->pool = NULL;
  wheel->base = LONG_MAX;
  return wheel;
}

static uint
wheel_level( long ts ) {
  ts &= FD_WHEEL_RANGE( FD_WHEEL_LEVEL_CNT-1 )-1;
  if( ts < FD_WHEEL_RANGE( 0 ) ) return 0U;
  if( ts < FD_WHEEL_RANGE( 1 ) ) return 1U;
  if( ts < FD_WHEEL_RANGE( 2 ) ) return 2U;
  if( ts < FD_WHEEL_RANGE( 3 ) ) return 3U;
  return 4U;
}

void
fd_wheel_insert( fd_wheel_t *       wheel,
                 fd_wheel_timer_t * timer ) {
  fd_wheel_timer_t * pool = wheel->pool;
  uint               idx  = (uint)( timer-pool );

  /* Clamp deadline to fall in wheel range */

  if( FD_UNLIKELY( timer->deadline < wheel->base ) ) {
    timer->deadline = wheel->base;
  }
  long delta = timer->deadline - wheel->base;
  if( FD_UNLIKELY( delta >= FD_WHEEL_RANGE( FD_WHEEL_LEVEL_CNT-1 ) ) ) {
    delta = FD_WHEEL_RANGE( FD_WHEEL_LEVEL_CNT-1 )-1;
    timer->deadline = wheel->base + delta;
  }

  /* Insert timer at [level][slot] */

  uint level = wheel_level( delta );
  uint slot  = FD_WHEEL_SLOT( level, timer->deadline );
  FD_DCHECK_CRIT( level<FD_WHEEL_LEVEL_CNT, "unreachable" );

  timer->level = level & 0x3;
  timer->prev  = UINT_MAX;
  timer->next  = wheel->map[ level ][ slot ];
  if( timer->next!=UINT_MAX ) {
    pool[ timer->next ].prev = idx;
  }
  wheel->map[ level ][ slot ] = idx;
}

fd_wheel_timer_t *
fd_wheel_remove( fd_wheel_t *       wheel,
                 fd_wheel_timer_t * timer ) {
  fd_wheel_timer_t * pool = wheel->pool;

  uint level = timer->level;
  uint slot  = FD_WHEEL_SLOT( level, timer->deadline );
  FD_CHECK_CRIT( level < FD_WHEEL_LEVEL_CNT, "corruption detected" );

  if( timer->prev!=UINT_MAX ) {
    pool[ timer->prev ].next = timer->next;
    FD_CHECK_CRIT( pool[ timer->prev ].level==level, "corruption detected" );
  } else {
    wheel->map[ level ][ slot ] = timer->next;
  }
  if( timer->next!=UINT_MAX ) {
    pool[ timer->next ].prev = timer->prev;
    FD_CHECK_CRIT( pool[ timer->next ].level==level, "corruption detected" );
  }

  timer->prev = UINT_MAX;
  timer->next = UINT_MAX;
  return timer;
}
