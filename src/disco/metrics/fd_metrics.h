#ifndef HEADER_fd_src_util_metrics_fd_metrics_h
#define HEADER_fd_src_util_metrics_fd_metrics_h

#include "../fd_disco_base.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/tempo/fd_tempo.h"
#include <stdbool.h>

/* metrics_tags_t is used to define the tags which are available
 * for ALL tiles.
 *
 * Used in conjunction with metrics_definition
 */
typedef enum {
  METRIC_MUX_TEST_TAG,
} metrics_tags_t;

typedef enum {
  METRICS_DATATYPE_FLOAT,
  METRICS_DATATYPE_INT,
  METRICS_DATATYPE_STRING,
  METRICS_DATATYPE_BOOL,
} metrics_datatype_t;

#define METRICS_NAME_SZ 40

typedef struct {
  metrics_datatype_t  type;
  char                name[METRICS_NAME_SZ];
} Measurement;

/* metrics_definition is used to define the metrics which are
 * available for ALL tiles. This is used by the fd_metrics_pop
 * function to convert the tag into a string name and ulong value
 * into the correct InfluxDB wire protocol type.
 *
 * * Used in conjunction with metrics_tags_t
 */
extern Measurement metrics_definition[];

/* metrics_t is an opaque type which is used to track the
 * metrics for a given tile.
 *
 * Used in conjunction with metrics_tile_t
 */
struct metrics_t;
typedef struct metrics_t metrics_t;

/* metrics_tile_t is used to identify the type of tile when calling fd_metrics_boot */
typedef enum {
  metrics_quic,
  metrics_verify,
  metrics_dedup,
  metrics_pack,
  metrics_bank,
} metrics_tile_t;

/* Used in conjunction with metrics_tile_t to turn the enum into a string */
extern char * metrics_tile_names[];

/* A union of the types of metrics values we support */
#define METRICS_VALUE_STRING_SZ 128
typedef struct {
  long   i;
  double f;
  bool   b;
  char   s[METRICS_VALUE_STRING_SZ];
} metrics_value;

/* Datapoint is used to store a single value for a measurement. In practice this translates to a single line
 * in a POST to metrics.solana.com */
typedef struct {
  Measurement   measurement;
  metrics_value value;
} Datapoint;

FD_PROTOTYPES_BEGIN

/* fd_metrics_boot is used to initialize the metrics for a given tile. This should be called once per tile
 * at startup. */
void fd_metrics_boot( uchar const * pod, const metrics_tile_t tile, const ulong idx );

/* fd_metrics_push is used to push a single metric value into the mcache. */
void fd_metrics_push( uint tag, ulong value );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_metrics_fd_metrics_h */
