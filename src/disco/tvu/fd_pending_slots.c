#include "fd_pending_slots.h"

void *
fd_pending_slots_new( void * mem, ulong lo_wmark ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_pending_slots_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_pending_slots_footprint();

  fd_memset( mem, 0, footprint );
  ulong laddr = (ulong)mem;
  fd_pending_slots_t * pending_slots = (void *)laddr;
  pending_slots->lo_wmark = lo_wmark;
  pending_slots->start = 0;
  pending_slots->end = 0;
  pending_slots->lock = 0;

  laddr += sizeof( fd_pending_slots_t );
  pending_slots->pending = (void *)laddr;
  
  laddr += sizeof(long) * FD_PENDING_MAX;

  FD_TEST( laddr == (ulong)mem + footprint );

  return mem;
}

/* TODO only safe for local joins */
fd_pending_slots_t *
fd_pending_slots_join( void * pending_slots ) {
  if( FD_UNLIKELY( !pending_slots ) ) {
    FD_LOG_WARNING( ( "NULL pending_slots" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pending_slots, fd_pending_slots_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned pending_slots" ) );
    return NULL;
  }

  fd_pending_slots_t * pending_slots_ = (fd_pending_slots_t *)pending_slots;

  return pending_slots_;
}

void *
fd_pending_slots_leave( fd_pending_slots_t const * pending_slots ) {
  if( FD_UNLIKELY( !pending_slots ) ) {
    FD_LOG_WARNING( ( "NULL pending_slots" ) );
    return NULL;
  }

  return (void *)pending_slots;
}

void *
fd_pending_slots_delete( void * pending_slots ) {
  if( FD_UNLIKELY( !pending_slots ) ) {
    FD_LOG_WARNING( ( "NULL pending_slots" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pending_slots, fd_pending_slots_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned pending_slots" ) );
    return NULL;
  }

  return pending_slots;
}

static void
fd_pending_slots_lock( fd_pending_slots_t * pending_slots ) {
  for(;;) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( &pending_slots->lock, 0UL, 1UL) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
}

static void
fd_pending_slots_unlock( fd_pending_slots_t * pending_slots ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( pending_slots->lock ) = 0UL;
}


ulong
fd_pending_slots_iter_init( fd_pending_slots_t * pending_slots ) {
  return pending_slots->start;
}

ulong
fd_pending_slots_iter_next( fd_pending_slots_t * pending_slots,
                            long now,
                            ulong i ) {
  fd_pending_slots_lock( pending_slots );
  ulong end = pending_slots->end;
  for( i = fd_ulong_max(i, pending_slots->start); 1; ++i ) {
    if( i >= end ) {
      /* End sentinel */
      i = ULONG_MAX;
      break;
    }
    long * ele = &pending_slots->pending[ i & FD_PENDING_MASK ];
    if( i <= pending_slots->lo_wmark || *ele == 0 ) {
      /* Empty or useless slot */
      if( pending_slots->start == i )
        pending_slots->start = i+1U; /* Pop it */
    } else if( *ele <= now ) {
      /* Do this slot */
      long when = *ele;
      *ele = 0;
      if( pending_slots->start == i )
        pending_slots->start = i+1U; /* Pop it */
      FD_LOG_DEBUG(( "preparing slot %lu when=%ld now=%ld latency=%ld",
                     i, when, now, now - when ));
      break;
    }
  }
  fd_pending_slots_unlock( pending_slots );
  return i;
}

void
fd_pending_slots_add( fd_pending_slots_t * pending_slots,
                      ulong slot,
                      long when ) {
  fd_pending_slots_lock( pending_slots );
  
  long * pending = pending_slots->pending;
  if( pending_slots->start == pending_slots->end ) {
    /* Queue is empty */
    pending_slots->start = slot;
    pending_slots->end = slot+1U;
    pending[slot & FD_PENDING_MASK] = when;
    
  } else if ( slot < pending_slots->start ) {
    /* Grow down */
    if( (long)(pending_slots->end - slot) > (long)FD_PENDING_MAX )
      FD_LOG_ERR(( "pending queue overrun: start=%lu, end=%lu, new slot=%lu", pending_slots->start, pending_slots->end, slot ));
    pending[slot & FD_PENDING_MASK] = when;
    for( ulong i = slot+1; i < pending_slots->start; i++ ) {
      /* Zero fill */
      pending[i & FD_PENDING_MASK] = 0;
    }
    pending_slots->start = slot;

  } else if ( slot >= pending_slots->end ) {
    /* Grow up */
    if( (long)(slot - pending_slots->start) > (long)FD_PENDING_MAX )
      FD_LOG_ERR(( "pending queue overrun: start=%lu, end=%lu, new slot=%lu", pending_slots->start, pending_slots->end, slot ));
    pending[slot & FD_PENDING_MASK] = when;
    for( ulong i = pending_slots->end; i < slot; i++ ) {
      /* Zero fill */
      pending[i & FD_PENDING_MASK] = 0;
    }
    pending_slots->end = slot+1U;

  } else {
    /* Update in place */
    long * p = &pending[slot & FD_PENDING_MASK];
    if( 0 == *p || *p > when )
      *p = when;
  }

  fd_pending_slots_unlock( pending_slots );
}
