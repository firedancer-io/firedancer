#ifndef HEADER_fd_src_tango_validators_fd_leader_schedule_h
#define HEADER_fd_src_tango_validators_fd_leader_schedule_h

#include "../fd_tango_base.h"
#include "../mvcc/fd_mvcc.h"

#define DEFAULT_SLOTS_PER_EPOCH 432000

typedef uchar Pubkey[32];

typedef struct {
  ulong size;
  fd_mvcc_t mvcc;
  Pubkey schedule[DEFAULT_SLOTS_PER_EPOCH];
} fd_leader_schedule_t;

FD_FN_CONST static inline ulong fd_leader_schedule_align     ( void ) { return alignof( fd_leader_schedule_t ); }
FD_FN_CONST static inline ulong fd_leader_schedule_footprint ( void ) { return sizeof ( fd_leader_schedule_t ); }

void * fd_leader_schedule_new( void * mem );

FD_FN_UNUSED static inline void *
fd_leader_schedule_delete( void                 * _leader_schedule ) { return (void                 *)_leader_schedule; }

FD_FN_UNUSED static inline fd_leader_schedule_t *
fd_leader_schedule_join  ( void                 * _leader_schedule ) { return (fd_leader_schedule_t *)_leader_schedule; }

fd_leader_schedule_t * fd_leader_schedule_get( char const * app_name );

FD_FN_UNUSED static inline void *
fd_leader_schedule_leave ( fd_leader_schedule_t * leader_schedule  ) { return (void                 *) leader_schedule; }

#endif /* HEADER_fd_src_tango_validators_fd_leader_schedule_h */
