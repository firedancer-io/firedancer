#include "fd_restore_base.h"
#include "stream/fd_stream_ctx.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"

#define NAME "SnapIdx"
#define LINK_IN_MAX 1UL

#define SNAP_IDX_STATUS_WAITING 0UL