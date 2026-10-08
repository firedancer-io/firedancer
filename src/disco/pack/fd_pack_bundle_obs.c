#include "fd_pack_bundle_obs.h"

#define IDX_NULL (ULONG_MAX)

struct fd_pack_bobs {
  ulong ele_max;
  ulong pack_idx_max;
  ulong used;

  ulong blocked[ FD_PACK_BOBS_REASON_CNT ];
  long  last_time;
  int   last_reason;

  ulong sched_head; /* oldest SCHEDULED */
  ulong sched_tail;

  ulong                free_cnt;
  ulong *              free;     /* stack of free element indices, ele_max */
  uint  *              by_pack;  /* pack_idx -> element index+1, 0 if none, pack_idx_max */
  fd_pack_bobs_ele_t * ele;      /* ele_max */
};

FD_FN_CONST ulong
fd_pack_bobs_align( void ) {
  return 64UL;
}

FD_FN_CONST ulong
fd_pack_bobs_footprint( ulong ele_max,
                        ulong pack_idx_max ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, 64UL,                        sizeof(fd_pack_bobs_t)                 );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),              ele_max*sizeof(ulong)                  );
  l = FD_LAYOUT_APPEND( l, alignof(uint),               pack_idx_max*sizeof(uint)              );
  l = FD_LAYOUT_APPEND( l, alignof(fd_pack_bobs_ele_t), ele_max*sizeof(fd_pack_bobs_ele_t)     );
  return FD_LAYOUT_FINI( l, fd_pack_bobs_align() );
}

void *
fd_pack_bobs_new( void * mem,
                  ulong  ele_max,
                  ulong  pack_idx_max ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( !ele_max || ele_max>UINT_MAX-1UL || pack_idx_max>UINT_MAX ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_bobs_t *     bobs = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                        sizeof(fd_pack_bobs_t)             );
  ulong *              free = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),              ele_max*sizeof(ulong)              );
  uint  *              byp  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),               pack_idx_max*sizeof(uint)          );
  fd_pack_bobs_ele_t * ele  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pack_bobs_ele_t), ele_max*sizeof(fd_pack_bobs_ele_t) );
  FD_SCRATCH_ALLOC_FINI( l, fd_pack_bobs_align() );

  memset( bobs, 0, sizeof(fd_pack_bobs_t) );
  bobs->ele_max      = ele_max;
  bobs->pack_idx_max = pack_idx_max;
  bobs->last_reason  = FD_PACK_BOBS_REASON_NONE;
  bobs->sched_head   = IDX_NULL;
  bobs->sched_tail   = IDX_NULL;
  bobs->free_cnt     = ele_max;
  memset( byp, 0, pack_idx_max*sizeof(uint) );
  memset( ele, 0, ele_max*sizeof(fd_pack_bobs_ele_t) );
  for( ulong i=0UL; i<ele_max; i++ ) free[ i ] = ele_max-1UL-i; /* pop 0 first */
  return mem;
}

fd_pack_bobs_t *
fd_pack_bobs_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_bobs_t * bobs = FD_SCRATCH_ALLOC_APPEND( l, 64UL, sizeof(fd_pack_bobs_t) );
  ulong ele_max      = bobs->ele_max;
  ulong pack_idx_max = bobs->pack_idx_max;
  bobs->free    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),              ele_max*sizeof(ulong)              );
  bobs->by_pack = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),               pack_idx_max*sizeof(uint)          );
  bobs->ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pack_bobs_ele_t), ele_max*sizeof(fd_pack_bobs_ele_t) );
  FD_SCRATCH_ALLOC_FINI( l, fd_pack_bobs_align() );
  return bobs;
}

void
fd_pack_bobs_charge( fd_pack_bobs_t * bobs,
                     long             now,
                     int              reason ) {
  /* Time only moves forward: a stale now (e.g. read before a flush)
     charges nothing and doesn't move last_time back. */
  if( FD_LIKELY( now>bobs->last_time ) ) {
    if( FD_LIKELY( bobs->last_reason!=FD_PACK_BOBS_REASON_NONE ) ) bobs->blocked[ bobs->last_reason ] += (ulong)(now-bobs->last_time);
    bobs->last_time = now;
  }
  bobs->last_reason = reason;
}

void
fd_pack_bobs_flush( fd_pack_bobs_t * bobs,
                    long             now ) {
  fd_pack_bobs_charge( bobs, now, bobs->last_reason );
}

ulong const *
fd_pack_bobs_blocked( fd_pack_bobs_t const * bobs ) {
  return bobs->blocked;
}

fd_pack_bobs_ele_t *
fd_pack_bobs_acquire( fd_pack_bobs_t * bobs ) {
  if( FD_UNLIKELY( !bobs->free_cnt ) ) return NULL;
  ulong idx = bobs->free[ --bobs->free_cnt ];
  fd_pack_bobs_ele_t * ele = bobs->ele + idx;
  ulong gen = ele->gen + 1UL;
  memset( ele, 0, sizeof(fd_pack_bobs_ele_t) );
  ele->gen        = gen;
  ele->state      = FD_PACK_BOBS_STATE_PENDING;
  ele->pack_idx   = IDX_NULL;
  ele->prev_sched = IDX_NULL;
  ele->next_sched = IDX_NULL;
  memcpy( ele->blocked_snap, bobs->blocked, sizeof(bobs->blocked) );
  bobs->used++;
  return ele;
}

void
fd_pack_bobs_register( fd_pack_bobs_t *     bobs,
                       fd_pack_bobs_ele_t * ele,
                       ulong                pack_idx ) {
  FD_TEST( pack_idx<bobs->pack_idx_max );
  FD_TEST( !bobs->by_pack[ pack_idx ] );
  FD_TEST( ele->state==FD_PACK_BOBS_STATE_PENDING );
  bobs->by_pack[ pack_idx ] = (uint)(ele-bobs->ele) + 1U;
  ele->pack_idx = pack_idx;
}

fd_pack_bobs_ele_t *
fd_pack_bobs_query( fd_pack_bobs_t * bobs,
                    ulong            pack_idx ) {
  if( FD_UNLIKELY( pack_idx>=bobs->pack_idx_max ) ) return NULL;
  uint i = bobs->by_pack[ pack_idx ];
  return i ? bobs->ele + (i-1U) : NULL;
}

static inline void
unregister( fd_pack_bobs_t *     bobs,
            fd_pack_bobs_ele_t * ele ) {
  if( FD_LIKELY( ele->pack_idx!=IDX_NULL ) ) {
    bobs->by_pack[ ele->pack_idx ] = 0U;
    ele->pack_idx = IDX_NULL;
  }
}

ulong
fd_pack_bobs_id( fd_pack_bobs_t const *     bobs,
                 fd_pack_bobs_ele_t const * ele ) {
  return (ele->gen<<32) | ((ulong)(ele-bobs->ele)+1UL);
}

ulong
fd_pack_bobs_scheduled( fd_pack_bobs_t *     bobs,
                        fd_pack_bobs_ele_t * ele ) {
  unregister( bobs, ele );
  for( ulong i=0UL; i<FD_PACK_BOBS_REASON_CNT; i++ ) ele->blocked_snap[ i ] = bobs->blocked[ i ] - ele->blocked_snap[ i ];
  ele->wait_frozen = 1;
  ulong idx = (ulong)(ele-bobs->ele);
  ele->state      = FD_PACK_BOBS_STATE_SCHEDULED;
  ele->prev_sched = bobs->sched_tail;
  ele->next_sched = IDX_NULL;
  if( bobs->sched_tail!=IDX_NULL ) bobs->ele[ bobs->sched_tail ].next_sched = idx;
  else                             bobs->sched_head = idx;
  bobs->sched_tail = idx;
  return fd_pack_bobs_id( bobs, ele );
}

fd_pack_bobs_ele_t *
fd_pack_bobs_query_id( fd_pack_bobs_t * bobs,
                       ulong            id ) {
  ulong idx1 = id & 0xFFFFFFFFUL;
  if( FD_UNLIKELY( !idx1 || idx1>bobs->ele_max ) ) return NULL;
  fd_pack_bobs_ele_t * ele = bobs->ele + (idx1-1UL);
  if( FD_UNLIKELY( ele->state==FD_PACK_BOBS_STATE_FREE || (ele->gen&0xFFFFFFFFUL)!=(id>>32) ) ) return NULL;
  return ele;
}

fd_pack_bobs_ele_t *
fd_pack_bobs_oldest_scheduled( fd_pack_bobs_t * bobs ) {
  return bobs->sched_head==IDX_NULL ? NULL : bobs->ele + bobs->sched_head;
}

void
fd_pack_bobs_release( fd_pack_bobs_t *     bobs,
                      fd_pack_bobs_ele_t * ele ) {
  FD_TEST( ele->state!=FD_PACK_BOBS_STATE_FREE );
  if( ele->state==FD_PACK_BOBS_STATE_PENDING ) {
    unregister( bobs, ele );
  } else {
    if( ele->prev_sched!=IDX_NULL ) bobs->ele[ ele->prev_sched ].next_sched = ele->next_sched;
    else                            bobs->sched_head                        = ele->next_sched;
    if( ele->next_sched!=IDX_NULL ) bobs->ele[ ele->next_sched ].prev_sched = ele->prev_sched;
    else                            bobs->sched_tail                        = ele->prev_sched;
  }
  ele->state = FD_PACK_BOBS_STATE_FREE;
  bobs->free[ bobs->free_cnt++ ] = (ulong)(ele-bobs->ele);
  bobs->used--;
}

ulong
fd_pack_bobs_used( fd_pack_bobs_t const * bobs ) {
  return bobs->used;
}

void
fd_pack_bobs_delta( fd_pack_bobs_t const *     bobs,
                    fd_pack_bobs_ele_t const * ele,
                    ulong                      out[ static FD_PACK_BOBS_REASON_CNT ] ) {
  for( ulong i=0UL; i<FD_PACK_BOBS_REASON_CNT; i++ ) out[ i ] = fd_ulong_if( ele->wait_frozen, ele->blocked_snap[ i ], bobs->blocked[ i ] - ele->blocked_snap[ i ] );
}

int
fd_pack_bobs_phase( long  arrival,
                    int   is_leader,
                    long  slot_start,
                    long  slot_end,
                    long  last_end,
                    ulong last_slot,
                    long  slot_dur ) {
  if( is_leader ) {
    long len = fd_long_max( slot_end-slot_start, 3L );
    long off = arrival-slot_start;
    if( off*3L<len    ) return FD_PACK_BOBS_PHASE_EARLY;
    if( off*3L<2L*len ) return FD_PACK_BOBS_PHASE_MID;
    return FD_PACK_BOBS_PHASE_LATE;
  }
  if( last_slot!=ULONG_MAX && arrival-last_end<slot_dur ) {
    /* Just after one of our slots.  If it was the last slot of a
       rotation, the bundle missed our window; otherwise our next slot
       is about to start. */
    return (last_slot%FD_PACK_BOBS_SLOTS_PER_ROTATION)==FD_PACK_BOBS_SLOTS_PER_ROTATION-1UL ? FD_PACK_BOBS_PHASE_AFTER_WINDOW
                                                                                            : FD_PACK_BOBS_PHASE_EARLY;
  }
  return FD_PACK_BOBS_PHASE_BEFORE_WINDOW;
}

int
fd_pack_bobs_cause_exec( int   landed,
                         int   err_kind,
                         ulong interference ) {
  if( landed ) return FD_PACK_BOBS_CAUSE_LANDED;
  switch( err_kind ) {
    case FD_PACK_BOBS_EXEC_ERR_INSTRUCTION:
      switch( interference & 0xFFUL ) {
        case FD_PACK_WRITER_TXN:    return FD_PACK_BOBS_CAUSE_EXEC_STATE_TPU;
        case FD_PACK_WRITER_BUNDLE: return FD_PACK_BOBS_CAUSE_EXEC_STATE_BUNDLE;
        default:                    return FD_PACK_BOBS_CAUSE_EXEC_STATE_OTHER;
      }
    case FD_PACK_BOBS_EXEC_ERR_DUPLICATE: return FD_PACK_BOBS_CAUSE_EXEC_DUPLICATE;
    case FD_PACK_BOBS_EXEC_ERR_OTHER:     return FD_PACK_BOBS_CAUSE_EXEC_OTHER;
    default:                              return FD_PACK_BOBS_CAUSE_EXEC_UNKNOWN;
  }
}

int
fd_pack_bobs_cause_unscheduled( int         leave_reason,
                                ulong const delta[ static FD_PACK_BOBS_REASON_CNT ],
                                int         phase ) {
  if( leave_reason==FD_PACK_BUNDLE_LEAVE_DELETED ) return FD_PACK_BOBS_CAUSE_DUP_DELETED;

  ulong best     = 0UL;
  int   best_idx = -1;
  for( int i=0; i<FD_PACK_BOBS_REASON_CNT; i++ ) {
    if( delta[ i ]>best ) { best = delta[ i ]; best_idx = i; }
  }
  if( best_idx>=0 ) return FD_PACK_BOBS_CAUSE_BLOCKED_BASE + best_idx;

  if( phase==FD_PACK_BOBS_PHASE_AFTER_WINDOW ) return FD_PACK_BOBS_CAUSE_LATE;
  if( (leave_reason==FD_PACK_BUNDLE_LEAVE_EVICTED) | (leave_reason==FD_PACK_BUNDLE_LEAVE_REPLACED) ) return FD_PACK_BOBS_CAUSE_EVICTED;
  return FD_PACK_BOBS_CAUSE_EXPIRED;
}
