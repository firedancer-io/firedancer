#ifndef HEADER_fd_src_disco_metrics_fd_metrics_h
#define HEADER_fd_src_disco_metrics_fd_metrics_h

#include "fd_metrics_base.h"

#include "generated/fd_metrics_all.h"
#include "generated/fd_metrics_quic.h"
#include "generated/fd_metrics_pack.h"
#include "generated/fd_metrics_bank.h"
#include "generated/fd_metrics_poh.h"

#include "../../tango/tempo/fd_tempo.h"

/* fd_metrics mostly defines way of laying out metrics in shared memory
   so that a producer and consumer can agree on where they are, and can
   read and wite them quickly and with little to no boilerplate.

   At initialization time, a thread can call fd_metrics_register which
   saves a thread local base pointer.  Then, macros are provided which
   given a macro "name", maps it to an offset from that base pointer and
   does a write of the corresponding ulong.

   For low-frequency metrics like incrementing rarely hit error
   counters, it is OK to use the macros inline.  For high frequency
   metrics in core loops, it may be preferable to accumulate local
   metric values in the tile and drain them to the metrics shared memory
   periodically, eg, via. a housekeeping step.

   The metrics area is minimal and contains no metadata itself.  For
   example, histograms in the metrics shared memory are just the bucket
   values, and there is no metadata about the edges.  The consumer will
   determine the edges by looking at the statically compiled metadata.

   This is to reduce cache traffic and keep the metrics area small, so
   it can be copied to produce a snapshot quickly.  When updating
   metrics, the producer should do atomic writes so that these snapshots
   will see consistent values.  In particular, the producer should not
   do a memcpy into the metrics region. */

/* The metrics region is laid out like

    [ in_link_N ulong ]
    [ out_link_N ulong]
    [ in_link_0_metrics ... in_link_N_metrics ]
    [ out_link_0_metrics ... out_link_N_metrics ]
    [ tile_metrics ]

   where every value is a ulong.  Tile metrics come after link metrics,
   so this base pointer points at the very start of the layout.  You
   shouldn't need to use this directly, instead it's used by the mux
   tile when it's computing the metrics for specific links. */
extern FD_TL ulong * fd_metrics_base_tl;

/* All metrics in the application are ulongs, and are laid out
   sequentially, so this thread local is a pointer to the first tile
   specific metric in the layout, or the "tile_metrics" start as defined
   above.  All tile metrics are defined as an offset from this metrics
   pointer.  You shouldn't need to use this directly, instead it is used
   by the macros below like FD_MCNT_SET etc.  The thread local should be
   set by calling fd_metrics_register. */
extern FD_TL ulong * fd_metrics_tl;

#define FD_METRICS_ALIGN (128UL)
#define FD_METRICS_FOOTPRINT(in_link_cnt, out_link_reliable_consumer_cnt)                                   \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND ( FD_LAYOUT_APPEND ( FD_LAYOUT_INIT, \
    8UL, 16UL ),                                                                                            \
    8UL, (in_link_cnt)*FD_METRICS_ALL_LINK_IN_TOTAL*sizeof(ulong) ),                                        \
    8UL, (out_link_reliable_consumer_cnt)*FD_METRICS_ALL_LINK_OUT_TOTAL*sizeof(ulong) ),                    \
    8UL, FD_METRICS_TOTAL_SZ ),                                                                             \
    FD_METRICS_ALIGN )

/* The following macros are convenience helpers for updating tile metric
   values in shared memory, and can be used like
     
     FD_MGAUGE_SET( QUIC, CONNECTIONS_CREATED_COUNT, conn_cnt );
     
   This compiles to a single write to an offset of the metrics pointer
   above. */

#define FD_MGAUGE_SET( group, measurement, value ) do {         \
    fd_metrics_tl[ MIDX(GAUGE, group, measurement) ] = (value); \
  } while(0)

#define FD_MGAUGE_GET( group, measurement ) (fd_metrics_tl[ MIDX(GAUGE, group, measurement) ])

#define FD_MCNT_GET( group, measurement ) (fd_metrics_tl[ MIDX(COUNTER, group, measurement) ])

#define FD_MCNT_SET( group, measurement, value ) do {             \
    fd_metrics_tl[ MIDX(COUNTER, group, measurement) ] = (value); \
  } while(0)

#define FD_MCNT_INC( group, measurement, value ) do {              \
    fd_metrics_tl[ MIDX(COUNTER, group, measurement) ] += (value); \
  } while(0)

#define FD_MHIST_MIN( group, measurement ) (FD_METRICS_HISTOGRAM_##group##_##measurement##_MIN)
#define FD_MHIST_SECONDS_MIN( group, measurement ) (fd_metrics_convert_seconds_to_ticks(FD_METRICS_HISTOGRAM_##group##_##measurement##_MIN))
#define FD_MHIST_MAX( group, measurement ) (FD_METRICS_HISTOGRAM_##group##_##measurement##_MAX)
#define FD_MHIST_SECONDS_MAX( group, measurement ) (fd_metrics_convert_seconds_to_ticks(FD_METRICS_HISTOGRAM_##group##_##measurement##_MAX))

#define FD_MHIST_COPY( group, measurement, hist ) do {                   \
    ulong __fd_metrics_off = MIDX(HISTOGRAM, group, measurement);        \
    for( ulong i=0; i<FD_HISTF_BUCKET_CNT; i++ ) {                       \
      fd_metrics_tl[ __fd_metrics_off + i ] = hist->counts[ i ];         \
    }                                                                    \
    fd_metrics_tl[ __fd_metrics_off + FD_HISTF_BUCKET_CNT ] = hist->sum; \
  } while(0)

#define FD_MHIST_SUM( group, measurement ) (fd_metrics_tl[ MIDX(HISTOGRAM, group, measurement) + FD_HISTF_BUCKET_CNT ])

#define FD_MCNT_ENUM_COPY( group, measurement, values ) do {                    \
    ulong __fd_metrics_off = MIDX(COUNTER, group, measurement);                 \
    for( ulong i=0; i<FD_METRICS_COUNTER_##group##_##measurement##_CNT; i++ ) { \
      fd_metrics_tl[ __fd_metrics_off + i ] = values[ i ];                      \
    }                                                                           \
  } while(0)

#define FD_MGAUGE_ENUM_COPY( group, measurement, values ) do {                \
    ulong __fd_metrics_off = MIDX(GAUGE, group, measurement);                 \
    for( ulong i=0; i<FD_METRICS_GAUGE_##group##_##measurement##_CNT; i++ ) { \
      fd_metrics_tl[ __fd_metrics_off + i ] = values[ i ];                    \
    }                                                                         \
  } while(0)

FD_PROTOTYPES_BEGIN

/* fd_metrics_tile returns a pointer to the tile-specific metrics area
   for the given metrics object.  */
static inline ulong *
fd_metrics_tile( ulong * metrics ) { return metrics + 2UL + FD_METRICS_ALL_LINK_IN_TOTAL*metrics[ 0 ] + FD_METRICS_ALL_LINK_OUT_TOTAL*metrics[ 1 ]; }

/* fd_metrics_link_in returns a pointer the in-link metrics area for the
   given in link index of this metrics object. */
static inline ulong *
fd_metrics_link_in( ulong * metrics, ulong in_idx ) { return metrics + 2UL + FD_METRICS_ALL_LINK_IN_TOTAL*in_idx; }

/* fd_metrics_link_in returns a pointer the in-link metrics area for the
   given out link index of this metrics object. */
static inline ulong *
fd_metrics_link_out( ulong * metrics, ulong out_idx ) { return metrics + 2UL + FD_METRICS_ALL_LINK_IN_TOTAL*metrics[0] + FD_METRICS_ALL_LINK_OUT_TOTAL*out_idx; }

/* fd_metrics_new formats an unused memory region for use as a metrics.
   Assumes shmem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment.  All of the
   mtrics will be initialized to zero.  Returns shmem (and the memory
   region it points to will be formatted as a metrics, caller is not
   joined). */

static inline void *
fd_metrics_new( void * shmem,
                ulong  in_link_cnt,
                ulong  out_link_consumer_cnt ) {
  fd_memset( shmem, 0, FD_METRICS_FOOTPRINT(in_link_cnt, out_link_consumer_cnt) );
  ulong * metrics = shmem;
  metrics[0] = in_link_cnt;
  metrics[1] = out_link_consumer_cnt;
  return shmem;
}

/* fd_metrics_register sets the thread local values used by the macros
   like FD_MCNT_SET to point to the provided metrics object. */
static inline ulong *
fd_metrics_register( ulong * metrics ) {
  if( FD_UNLIKELY( !metrics ) ) FD_LOG_ERR(( "NULL metrics" ));

  fd_metrics_base_tl = metrics;
  fd_metrics_tl = fd_metrics_tile( metrics );
  return metrics;
}

static inline ulong
fd_metrics_convert_seconds_to_ticks( double seconds ) {
  /* The tick_per_ns() value needs to be the same across the tile doing
     the sampling and the tile doing the reporting so that they compute
     the same bucket edges for histograms. */
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  return (ulong)(seconds * tick_per_ns * 1e9);
}

static inline double
fd_metrics_convert_ticks_to_seconds( ulong ticks ) {
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  return (double)ticks / (tick_per_ns * 1e9);
}

static inline ulong * fd_metrics_join  ( void * mem ) { return mem; }
static inline void *  fd_metrics_leave ( void * mem ) { return (void *)mem; }
static inline void *  fd_metrics_delete( void * mem ) { return (void *)mem; }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_metrics_fd_metrics_h */
