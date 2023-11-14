#ifndef HEADER_fd_src_disco_metrics_fd_metrics_h
#define HEADER_fd_src_disco_metrics_fd_metrics_h

#include "fd_metrics_generated.h"

static ulong * fd_metrics_tl;

#define FD_METRICS_ALIGN (128UL)
#define FD_METRICS_FOOTPRINT()                      \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
    128UL, FD_METRICS_TOTAL_SZ ),                   \
    FD_METRICS_ALIGN )

#define F( group, measurement ) (FD_METRICS_GROUP_##group##_OFF + FD_METRICS_##group##_##measurement##_OFF)

#define FD_MGAUGE_SET( group, measurement, value ) do { \
    fd_metrics_tl[ F(group, measurement) ] = (value);   \
  } while(0)

#define FD_MCNT_INC( group, measurement, value ) do {  \
    fd_metrics_tl[ F(group, measurement) ] += (value); \
  } while(0)

#define FD_MHIST_COPY( group, measurement, hist ) do {            \
    ulong __fd_metrics_off = F(group, measurement);               \
    for( ulong i=0; i<fd_hist_bucket_cnt( hist ); i++ ) {         \
      fd_metrics_tl[ __fd_metrics_off + i ] = hist->buckets[ i ]; \
    }                                                             \
  } while(0)

FD_PROTOTYPES_BEGIN

static inline void *
fd_metrics_new( void * mem ) {
  fd_memset( mem, 0, FD_METRICS_FOOTPRINT() );
  return mem;
}

static inline ulong * fd_metrics_join  ( void * mem ) { fd_metrics_tl = mem; return mem; }
static inline void *  fd_metrics_leave ( void * mem ) { fd_metrics_tl = NULL; return (void *)mem; }
static inline void *  fd_metrics_delete( void * mem ) { return (void *)mem; }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_metrics_fd_metrics_h */
