/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */

#include "../fd_metrics_base.h"
#include "fd_metrics_enums.h"

#define FD_METRICS_GAUGE_SNAPDC_STATE_OFF  (16UL)
#define FD_METRICS_GAUGE_SNAPDC_STATE_NAME "snapdc_state"
#define FD_METRICS_GAUGE_SNAPDC_STATE_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_SNAPDC_STATE_DESC "State of the tile. 0 = waiting for compressed byte stream, 1 = decompressing full snapshot, 2 = decompressing incremental snapshot, 3 = done."
#define FD_METRICS_GAUGE_SNAPDC_STATE_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_GAUGE_SNAPDC_FULL_COMPRESSED_BYTES_READ_OFF  (17UL)
#define FD_METRICS_GAUGE_SNAPDC_FULL_COMPRESSED_BYTES_READ_NAME "snapdc_full_compressed_bytes_read"
#define FD_METRICS_GAUGE_SNAPDC_FULL_COMPRESSED_BYTES_READ_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_SNAPDC_FULL_COMPRESSED_BYTES_READ_DESC "Number of bytes read so far from the compressed full snapshot file. Might decrease if snapshot load is aborted and restarted"
#define FD_METRICS_GAUGE_SNAPDC_FULL_COMPRESSED_BYTES_READ_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_GAUGE_SNAPDC_FULL_DECOMPRESSED_BYTES_READ_OFF  (18UL)
#define FD_METRICS_GAUGE_SNAPDC_FULL_DECOMPRESSED_BYTES_READ_NAME "snapdc_full_decompressed_bytes_read"
#define FD_METRICS_GAUGE_SNAPDC_FULL_DECOMPRESSED_BYTES_READ_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_SNAPDC_FULL_DECOMPRESSED_BYTES_READ_DESC "Number of bytes read so far from the decompressed file. Might decrease if snapshot load is aborted and restarted"
#define FD_METRICS_GAUGE_SNAPDC_FULL_DECOMPRESSED_BYTES_READ_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_COMPRESSED_BYTES_READ_OFF  (19UL)
#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_COMPRESSED_BYTES_READ_NAME "snapdc_incremental_compressed_bytes_read"
#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_COMPRESSED_BYTES_READ_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_COMPRESSED_BYTES_READ_DESC "Number of bytes read so far from the compressed incremental snapshot file. Might decrease if snapshot load is aborted and restarted"
#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_COMPRESSED_BYTES_READ_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_DECOMPRESSED_BYTES_READ_OFF  (20UL)
#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_DECOMPRESSED_BYTES_READ_NAME "snapdc_incremental_decompressed_bytes_read"
#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_DECOMPRESSED_BYTES_READ_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_DECOMPRESSED_BYTES_READ_DESC "Number of bytes read so far from the decompressed incremental snapshot file. Might decrease if snapshot load is aborted and restarted"
#define FD_METRICS_GAUGE_SNAPDC_INCREMENTAL_DECOMPRESSED_BYTES_READ_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_SNAPDC_TOTAL (5UL)
extern const fd_metrics_meta_t FD_METRICS_SNAPDC[FD_METRICS_SNAPDC_TOTAL];
