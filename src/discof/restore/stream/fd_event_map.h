#ifndef HEADER_fd_src_discof_restore_fd_event_map_h
#define HEADER_fd_src_discof_restore_fd_event_map_h

#include "../../../util/fd_util_base.h"
#include "../../../util/bits/fd_bits.h"
#include "../../../util/rng/fd_rng.h"
#include "fd_stream_reader.h"

struct fd_event_map {
  ulong    event_cnt;
  ulong    event_seq;
  ushort * event_map;
};
typedef struct fd_event_map fd_event_map_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_event_map_align( void ) {
  return alignof(fd_event_map_t);
}

FD_FN_CONST static inline ulong
fd_event_map_footprint( ulong in_cnt,
                        ulong out_cnt ) {
  ulong event_cnt = 1UL + in_cnt + out_cnt;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND(l, alignof(fd_event_map_t), sizeof(fd_event_map_t) );
  l = FD_LAYOUT_APPEND(l, alignof(ushort),         sizeof(ushort)*event_cnt );
  return FD_LAYOUT_FINI( l, fd_event_map_align() );
}

fd_event_map_t *
fd_event_map_new( void * mem,
                  ulong in_cnt,
                  ulong stream_in_cnt,
                  ulong frag_in_cnt,
                  ulong out_cnt );

static inline void
fd_event_map_init( fd_event_map_t * map,
                   ulong            stream_in_cnt,
                   ulong            frag_in_cnt,
                   ulong            out_cnt ) {
  ulong idx = 0UL;
  map->event_map[ idx++ ] = (ushort)out_cnt;
  for( ulong in_idx=0UL; in_idx<stream_in_cnt; in_idx++ )
    map->event_map[ idx++ ] = (ushort)(in_idx+out_cnt+1UL);
  for( ulong in_idx=0UL; in_idx<frag_in_cnt; in_idx++ )
    map->event_map[ idx++ ] = (ushort)(in_idx+stream_in_cnt+out_cnt+1UL);
  for( ulong cons_idx=0UL; cons_idx<out_cnt; cons_idx++ )
    map->event_map[ idx++ ] = (ushort)cons_idx;
}

static inline ushort
fd_event_map_get_event( fd_event_map_t * map ) {
  return map->event_map[ map->event_seq ];
}

static inline void
fd_event_map_randomize( fd_event_map_t * map,
                        fd_rng_t * rng ) {
  ulong swap_idx             = (ulong)fd_rng_uint_roll( rng, (uint)map->event_cnt );
  ushort map_tmp             = map->event_map[ swap_idx ];
  map->event_map[ swap_idx ] = map->event_map[ 0        ];
  map->event_map[ 0        ] = map_tmp;
}

static inline void
fd_event_map_randomize_inputs( void **    in,
                               ulong      in_cnt,
                               fd_rng_t * rng ) {
  if( FD_LIKELY( in_cnt>1UL ) ) {
    ulong swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)in_cnt );
    void * in_tmp  = in[ swap_idx ];
    in[ swap_idx ] = in[ 0        ];
    in[ 0        ] = in_tmp;
  }
}

static inline void
fd_event_map_advance( fd_event_map_t * map,
                      fd_rng_t * rng,
                      void **    stream_in,
                      ulong      stream_in_cnt,
                      void **    frag_in,
                      ulong      frag_in_cnt ) {
  map->event_seq++;
  if( FD_UNLIKELY( map->event_seq>=map->event_cnt) ) {
    map->event_seq = 0UL;

    fd_event_map_randomize( map, rng );

    fd_event_map_randomize_inputs( stream_in, stream_in_cnt, rng );

    fd_event_map_randomize_inputs( frag_in, frag_in_cnt, rng );
  }
}

static inline void *
fd_event_map_delete( fd_event_map_t * map ) {
  fd_memset(map, 0, sizeof(fd_event_map_t) );
  return (void *)map;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_event_map_h */
