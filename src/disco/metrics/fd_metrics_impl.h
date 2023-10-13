#ifndef HEADER_fd_src_util_metrics_fd_metrics_impl_h
#define HEADER_fd_src_util_metrics_fd_metrics_impl_h

#include "fd_metrics.h"

/* Per tile struct that allows the metrics tile to know where the metrics are coming from
 * and for tracking mcache */
struct metrics_t {
  metrics_tile_t tile;
  ulong   idx;
  fd_frag_meta_t * mcache;
  ulong * sync;
  ulong   seq;
  ulong   seq_consumer;
  ulong   depth;
};

typedef struct metrics_tag {
  char key[ METRICS_VALUE_STRING_SZ ];
  char value[ METRICS_VALUE_STRING_SZ ];
} metrics_kv_t;

/* Takes a datapoint with associated tags and formats it into a string
 * suitable for sending to InfluxDB */
int
fd_metrics_format( char         * buf,
                   ulong          buf_sz,
                   char         * tile_name,
                   metrics_kv_t * tags,
                   ulong          tags_sz,
                   Datapoint *    datapoints,
                   ulong          datapoints_sz,
                   long           ts );

/* Converts a tag and value into a Datapoint
 * Used in conjunction with metrics_tags_t and metrics_definition */
void
fd_metrics_tag_value_to_datapoint( uint tag, ulong val, Datapoint * d );

/* Underlying functions for metrics_boot */
void
metrics_boot_unmanaged( uchar const * pod, const metrics_tile_t tile, const ulong idx, metrics_t * m );

/* Underlying functions for metrics_push */
void
metrics_push_unmanaged( metrics_t * m, uint tag, ulong value );

/* Potential return values of metrics_pop family functions */
typedef enum {
  METRICS_STATUS_OK,
  METRICS_STATUS_EMPTY,
  METRICS_STATUS_OVERRUN,
  METRICS_STATUS_UNINITIALIZED
} metrics_status_t;

/* Pop a tag and value from metrics_t * m */
metrics_status_t
metrics_pop_unmanaged( metrics_t * m, uint * tag, ulong * value );

#endif /* HEADER_fd_src_util_metrics_fd_metrics_impl_h */
