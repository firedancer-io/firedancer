#include "fd_event_map.h"

fd_event_map_t *
fd_event_map_new( void * mem,
                  ulong  in_cnt,
                  ulong  cons_cnt ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_event_map_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_event_map_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_map_t), sizeof(fd_event_map_t) );

  ulong event_cnt = 1UL + in_cnt + cons_cnt;
  self->event_map = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort), sizeof(ushort)*event_cnt );
  self->event_cnt = event_cnt;
  self->event_seq = 0UL;

  /* init event map */
  fd_event_map_init(self, in_cnt, cons_cnt );

  return self;
}
