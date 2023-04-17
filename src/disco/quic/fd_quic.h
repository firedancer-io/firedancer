#ifndef HEADER_fd_src_disco_quic_fd_quic_h
#define HEADER_fd_src_disco_quic_fd_quic_h

/* fd_quic provides a QUIC server tile.

   ### TPU/QUIC

   At present, TPU is the only protocol deployed on QUIC.  It allows
   clients to send transactions to block producers (this tile).  For
   each txn to be transferred, the client opens a unidirectional QUIC
   stream and sends its serialization (see fd_txn_parse).  In QUIC, this
   can occur in as little as a single packet (and an ACK by the server).
   For txn exceeding MTU size, the txn is fragmented over multiple
   packets.  For more information, see the specification:
   https://github.com/solana-foundation/specs/blob/main/p2p/tpu.md

   ### Tango semantics

   The fd_quic tile acts as a plain old Tango producer writing to a cnc,
   an mcache, and a dcache.  The tile will defragment multi-packet
   TPU streams coming in from QUIC, such that each mcache/dcache pair
   forms a complete txn.  This requires the dcache mtu to be at least
   that of the largest allowed serialized txn size.

   To facilitate defragmentation, the fd_quic tile stores non-standard
   stream information in the dcache's application region.  (An array of
   fd_quic_tpu_msg_ctx_t)

   ### Networking

   Each QUIC tile serves a single network device RX queue.  Serving
   multiple network interfaces or multiple queues (receive side scaling)
   requires multiple QUIC tiles.  Multi-queue deployments require the use
   of flow steering to ensure that each QUIC connection only reaches one
   QUIC tile at a time.  Flow steering based on UDP/IP source hashing as
   frequently implemented by hardware-RSS is a practical mechanism to do
   so. */

#include "../fd_disco_base.h"
#include "../../tango/quic/fd_quic.h"
#include "../../tango/xdp/fd_xdp.h"
#include "../../ballet/txn/fd_txn.h"

#if FD_HAS_HOSTED

/* FD_TPU_MTU is the max serialized byte size of a txn sent over TPU. */
#define FD_TPU_MTU (1232UL)

/* FD_TPU_DCACHE_MTU is the max size of a dcache entry */
#define FD_TPU_DCACHE_MTU (FD_TPU_MTU + FD_TXN_MAX_SZ + 2UL)

/* An fd_quic_tile will use the cnc application region to accumulate
   the following tile specific counters:

     CHUNK_IDX          is the chunk idx where quic tile should start publishing payloads on boot (ignored if not valid on boot)
     TPU_PUB_CNT        is the number of txns ingested by the QUIC server
     TPU_PUB_SZ         is the number of txn bytes ingested by the QUIC server
     TPU_CONN_LIVE_CNT  is the number of currently open QUIC conns
     TPU_CONN_SEQ       is the sequence number of the last QUIC conn opened

   As such, the cnc app region must be at least 64B in size.

   Except for IN_BACKP, none of the diagnostics are cleared at
   tile startup (as such that they can be accumulated over multiple
   runs).  Clearing is up to monitoring scripts. */

#define FD_QUIC_CNC_DIAG_CHUNK_IDX         ( 6UL) /* On 1st cache line of app region, updated by producer, frequently */
#define FD_QUIC_CNC_DIAG_TPU_PUB_CNT       ( 7UL) /* ", frequently */
#define FD_QUIC_CNC_DIAG_TPU_PUB_SZ        ( 8UL) /* ", frequently */
#define FD_QUIC_CNC_DIAG_TPU_CONN_LIVE_CNT ( 9UL) /* ", frequently */
#define FD_QUIC_CNC_DIAG_TPU_CONN_SEQ      (10UL) /* ", frequently */

/* fd_quic_tpu_msg_ctx_t is the message context of a txn being received
   by the QUIC tile over the TPU protocol. It is used to detect dcache
   overruns by identifying which QUIC stream is currently bound to a
   dcache chunk. An array of fd_quic_tpu_msg_ctx_t to fit <depth> entries
   forms the dcache's app region.

   This is necessary for stream defrag, during which multiple QUIC
   streams produce into multiple dcache chunks concurrently. In the worst
   case, a defrag is started for every available chunk in the dcache.
   When the producer wraps around to the first dcache entry, it will
   override the existing defrag process. This overrun is then safely
   detected through a change in conn/stream IDs when this previous defrag
   process continues. */

struct __attribute__((aligned(32UL))) fd_quic_tpu_msg_ctx {
  ulong   conn_id;
  ulong   stream_id;  /* ULONG_MAX marks completed msg */
  uchar * data;       /* Points to first byte of dcache entry */
  uint    sz;
  uint    tsorig;
};
typedef struct fd_quic_tpu_msg_ctx fd_quic_tpu_msg_ctx_t;

/* fd_quic_dcache_app_footprint returns the required footprint in bytes
   for the QUIC tile's out dcache app region of the given depth. */

FD_FN_CONST static inline ulong
fd_quic_dcache_app_footprint( ulong depth ) {
  return depth * sizeof(fd_quic_tpu_msg_ctx_t);
}

/* FD_QUIC_TILE_SCRATCH_ALIGN specifies the alignment and needed for a
   QUIC tile scratch region.  ALIGN is an integer power of 2 of at least
   double cache line to mitigate various kinds of false sharing. */

#define FD_QUIC_TILE_SCRATCH_ALIGN (128UL)

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_quic_tile_scratch_align( void ) {
  return FD_QUIC_TILE_SCRATCH_ALIGN;
}

FD_FN_CONST ulong
fd_quic_tile_scratch_footprint( ulong depth );

int
fd_quic_tile( fd_cnc_t *         cnc,        /* Local join to the tile's command-and-control */
              fd_quic_t *        quic,       /* QUIC without active join */
              fd_xsk_aio_t *     xsk_aio,    /* Local join to QUIC XSK aio */
              fd_frag_meta_t *   mcache,     /* Local join to the tile's txn output mcache */
              uchar *            dcache,     /* Local join to the tile's txn output dcache */
              long               lazy,       /* Laziness, <=0 means use a reasonable default */
              fd_rng_t *         rng,        /* Local join to the rng this tile should use */
              void *             scratch );  /* Tile scratch memory */

FD_PROTOTYPES_END

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_disco_tpu_fd_tpu_h */
