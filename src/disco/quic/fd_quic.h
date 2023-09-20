#ifndef HEADER_fd_src_disco_quic_fd_quic_h
#define HEADER_fd_src_disco_quic_fd_quic_h

#include "../fd_disco_base.h"

/* fd_quic provides a QUIC server tile.

   At present, TPU is the only protocol deployed on QUIC.  It allows
   clients to send transactions to block producers (this tile).  For
   each txn to be transferred, the client opens a unidirectional QUIC
   stream and sends its serialization (see fd_txn_parse).  In QUIC, this
   can occur in as little as a single packet (and an ACK by the server).
   For txn exceeding MTU size, the txn is fragmented over multiple
   packets.  For more information, see the specification:
   https://github.com/solana-foundation/specs/blob/main/p2p/tpu.md

   The fd_quic tile acts as a plain old Tango producer writing to a cnc,
   an mcache, and a dcache.  The tile will defragment multi-packet TPU
   streams coming in from QUIC, such that each mcache/dcache pair forms
   a complete txn.  This requires the dcache mtu to be at least that of
   the largest allowed serialized txn size.

   To facilitate defragmentation, the fd_quic tile stores non-standard
   stream information in the dcache's application region.  (An array of
   fd_quic_tpu_msg_ctx_t)

   Each QUIC tile serves a single network device RX queue, and
   optionally a loopback RX queue.  Serving multiple network interfaces
   or multiple queues aside from loopback (receive side scaling)
   requires multiple QUIC tiles.  Multi-queue deployments require the
   use of flow steering to ensure that each QUIC connection only reaches
   one QUIC tile at a time.  Flow steering based on UDP/IP source
   hashing as frequently implemented by hardware-RSS is a practical
   mechanism to do so. */

#include "../fd_disco_base.h"
#include "../../tango/quic/fd_quic.h"
#include "../../tango/xdp/fd_xdp.h"

/* An fd_quic_tile will use the cnc application region to accumulate the
   following tile specific counters:

     TPU_CONN_LIVE_CNT  is the number of currently open QUIC conns

     TPU_CONN_SEQ       is the sequence number of the last QUIC conn
                        opened

   As such, the cnc app region must be at least 64B in size.

   Except for IN_BACKP, none of the diagnostics are cleared at tile
   startup (as such that they can be accumulated over multiple runs).
   Clearing is up to monitoring scripts. */

#define FD_QUIC_CNC_DIAG_TPU_CONN_LIVE_CNT (6UL) /* ", frequently */
#define FD_QUIC_CNC_DIAG_TPU_CONN_SEQ      (7UL) /* ", frequently */

#define FD_QUIC_TILE_SCRATCH_ALIGN (128UL)

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_quic_dcache_app_footprint( ulong depth );

FD_FN_CONST ulong
fd_quic_tile_scratch_align( void );

FD_FN_CONST ulong
fd_quic_tile_scratch_footprint( ulong depth,
                                ulong in_cnt,
                                ulong out_cnt );

int
fd_quic_tile( fd_cnc_t *       cnc,                     /* Local join to the quic's command-and-control */
              ulong            pid,                     /* Tile PID for diagnostic purposes */
              fd_quic_t *      quic,                    /* Local join to the quic's quic context */
              ushort           legacy_transaction_port, /* Port to "listen" on for non-QUIC (raw UDP) transactions */
              ulong            xsk_aio_cnt,             /* Number of xsk_aio producers to poll, indexed [0,xsk_aio_cnt)] */
              fd_xsk_aio_t **  xsk_aio,                 /* xsk_aio[xsk_aio_idx] is the local join to xsk_aio producer */
              fd_frag_meta_t * mcache,                  /* Local join to the quic's frag stream output mcache */
              uchar *          dcache,                  /* Local join to the quic's frag stream output dcache */
              ulong            cr_max,                  /* Maximum number of flow control credits, 0 means use a reasonable default */
              long             lazy,                    /* Lazyiness, <=0 means use a reasonable default */
              fd_rng_t *       rng,                     /* Local join to the rng this quic should use */
              void *           scratch );               /* Tile scratch memory */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_quic_fd_quic_h */
