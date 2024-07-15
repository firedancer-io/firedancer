#ifndef HEADER_fd_src_flamenco_runtime_fd_pending_slots_h
#define HEADER_fd_src_flamenco_runtime_fd_pending_slots_h

#include "../../util/fd_util.h"


#define FD_PENDING_MAX      ( 1U << 14U ) /* 16 kb */
#define FD_PENDING_MASK     ( FD_PENDING_MAX - 1U )

struct fd_pending_slots {
  ulong start;
  ulong end;
  ulong lo_wmark;
  ulong lock;
  long * pending; /* pending slots to try to prepare */
};
typedef struct fd_pending_slots fd_pending_slots_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_pending_slots_align( void ) {
  return alignof( fd_pending_slots_t );
}

FD_FN_CONST static inline ulong
fd_pending_slots_footprint( void ) {
  return sizeof( fd_pending_slots_t ) + (sizeof(long) * FD_PENDING_MAX);
}

void *
fd_pending_slots_new( void * mem, ulong lo_wmark );

fd_pending_slots_t *
fd_pending_slots_join( void * pending_slots );

void *
fd_pending_slots_leave( fd_pending_slots_t const * pending_slots );

void *
fd_pending_slots_delete( void * pending_slots );

void
fd_pending_slots_add( fd_pending_slots_t * pending_slots,
                      ulong slot,
                      long when );
void
fd_pending_slots_set_lo_wmark( fd_pending_slots_t * pending_slots,
                               ulong slot );

ulong
fd_pending_slots_iter_init( fd_pending_slots_t * pending_slots );

ulong
fd_pending_slots_iter_next( fd_pending_slots_t * pending_slots,
                            long now,
                            ulong i );                

FD_PROTOTYPES_END

#endif
