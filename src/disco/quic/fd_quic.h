#ifndef HEADER_fd_src_disco_quic_fd_quic_h
#define HEADER_fd_src_disco_quic_fd_quic_h

/* fd_quic provides a TPU/QUIC server. */

#include "../fd_disco_base.h"
#include "../../tango/quic/fd_quic.h"

#if FD_HAS_HOSTED

/* An fd_quic_tile will use the cnc application region to accumulate
   the following tile specific counters:

     CHUNK_IDX          is the chunk idx where quic tile should start publishing payloads on boot (ignored if not valid on boot)
     TPU_PUB_CNT        is the number of txns ingested by the QUIC server
     TPU_PUB_SZ         is the number of txn bytes ingested by the QUIC server
     TPU_CONN_LIVE_CNT  is the number of currently open QUIC conns

   As such, the cnc app region must be at least 64B in size.

   Except for IN_BACKP, none of the diagnostics are cleared at
   tile startup (as such that they can be accumulated over multiple
   runs).  Clearing is up to monitoring scripts. */

#define FD_QUIC_CNC_DIAG_CHUNK_IDX         (2UL) /* On 1st cache line of app region, updated by producer, frequently */
#define FD_QUIC_CNC_DIAG_TPU_PUB_CNT       (3UL) /* ", frequently */
#define FD_QUIC_CNC_DIAG_TPU_PUB_SZ        (4UL) /* ", frequently */
#define FD_QUIC_CNC_DIAG_TPU_CONN_LIVE_CNT (5UL) /* ", frequently */

FD_PROTOTYPES_BEGIN

/* fd_quic_tile runs a TPU/QUIC server  */

FD_FN_CONST ulong
fd_quic_tile_scratch_align( void );

FD_FN_CONST ulong
fd_quic_tile_scratch_footprint( ulong stream_par_cnt );

int
fd_quic_tile( fd_cnc_t *         cnc,            /* Local join to the tile's command-and-control */
              ulong              shard,          /* QUIC tile shard index of QUIC server */
              fd_quic_t *        quic,           /* Local join to the QUIC server */
              fd_quic_config_t * quic_cfg,       /* QUIC server config (modified by tile) */
              fd_frag_meta_t *   mcache,         /* Local join to the tile's txn output mcache */
              uchar *            dcache,         /* Local join to the tile's txn output dcache */
              ulong              stream_par_cnt, /* Number of concurrent streams */
              fd_rng_t *         rng,
              void *             scratch );      /* Tile scratch memory */

FD_PROTOTYPES_END

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_disco_tpu_fd_tpu_h */
