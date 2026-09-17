#include "fd_repair_stats.h"

#define FD_REPAIR_STATS_MAGIC (0xf17eda2ce75747f5UL) /* firedancer repair stats v1 */

struct fd_repair_stats {
  ulong                    slot_max;
  fd_repair_stats_slot_t * slots;         /* slot_max records, indexed by slot % slot_max */
  ulong                    magic;
};

FD_FN_CONST ulong
fd_repair_stats_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_repair_stats_footprint( ulong slot_max ) {
  if( FD_UNLIKELY( !slot_max ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_stats_t),      sizeof(fd_repair_stats_t)                );
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_stats_slot_t), slot_max*sizeof(fd_repair_stats_slot_t) );
  return FD_LAYOUT_FINI( l, fd_repair_stats_align() );
}

void *
fd_repair_stats_new( void * mem,
                     ulong  slot_max ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_repair_stats_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_repair_stats_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max %lu", slot_max ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_repair_stats_t *      self  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_stats_t),      sizeof(fd_repair_stats_t)                );
  fd_repair_stats_slot_t * slots = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_stats_slot_t), slot_max*sizeof(fd_repair_stats_slot_t) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_repair_stats_align() )==(ulong)mem+footprint );

  self->slot_max      = slot_max;
  self->slots         = slots;
  for( ulong i=0UL; i<slot_max; i++ ) slots[ i ].slot = ULONG_MAX;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( self->magic ) = FD_REPAIR_STATS_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_repair_stats_t *
fd_repair_stats_join( void * mem ) {
  fd_repair_stats_t * self = (fd_repair_stats_t *)mem;
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( self->magic!=FD_REPAIR_STATS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return self;
}

void *
fd_repair_stats_leave( fd_repair_stats_t const * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL stats" ));
    return NULL;
  }
  return (void *)self;
}

void *
fd_repair_stats_delete( void * mem ) {
  fd_repair_stats_t * self = (fd_repair_stats_t *)mem;
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( self->magic!=FD_REPAIR_STATS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  FD_COMPILER_MFENCE();
  FD_VOLATILE( self->magic ) = 0UL;
  FD_COMPILER_MFENCE();
  return mem;
}

/* record_start returns slot's record, starting its clock at now if it
   has none.  A different slot at the table position is overwritten,
   whether it completed long ago or never will. */

static inline fd_repair_stats_slot_t *
record_start( fd_repair_stats_t * self,
              ulong               slot,
              long                now ) {
  fd_repair_stats_slot_t * r = &self->slots[ slot % self->slot_max ];
  if( FD_LIKELY( r->slot==slot ) ) return r;
  *r = (fd_repair_stats_slot_t){ .slot = slot, .first_shred_ts = now };
  return r;
}

void
fd_repair_stats_slot_start( fd_repair_stats_t * self,
                            ulong               slot,
                            long                now ) {
  record_start( self, slot, now );
}

void
fd_repair_stats_shred_received( fd_repair_stats_t * self,
                                ulong               slot,
                                int                 is_data,
                                uint                shred_src,
                                long                now ) {
  fd_repair_stats_slot_t * r = record_start( self, slot, now );
  if( FD_UNLIKELY( !is_data ) ) {
    r->code_cnt++;
    return;
  }
  /* data shreds */
  switch( shred_src ) {
    case SHRED_SIG_SRC_REPAIR:        r->repair_cnt++; break;
    case SHRED_SIG_SRC_TURBINE:       r->turbine_cnt++; break;
    case SHRED_SIG_SRC_RECONSTRUCTED: r->recovered_cnt++; break;
    default: break;
  }
}

void
fd_repair_stats_print_slot( fd_repair_stats_t const * self,
                            ulong                     slot,
                            long                      complete_ts ) {
  fd_repair_stats_slot_t const * r = &self->slots[ slot % self->slot_max ];
  if( FD_UNLIKELY( r->slot!=slot ) ) return;
  FD_LOG_NOTICE(( "slot %lu complete in %ld ms: turbine %u repair %u recovered %u code %u",
                  slot, ( complete_ts - r->first_shred_ts )/1000000L,
                  r->turbine_cnt, r->repair_cnt, r->recovered_cnt, r->code_cnt ));
}

int
fd_repair_stats_query( fd_repair_stats_t const * self,
                       ulong                     slot,
                       fd_repair_stats_slot_t *  out ) {
  fd_repair_stats_slot_t const * r = &self->slots[ slot % self->slot_max ];
  if( FD_UNLIKELY( r->slot!=slot ) ) return 0;
  *out = *r;
  return 1;
}
