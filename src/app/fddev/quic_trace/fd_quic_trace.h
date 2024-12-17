#ifndef HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h
#define HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h

#include "../../../disco/topo/fd_topo.h"
#include "../../../disco/quic/fd_quic_tile.h"

/* fd_quic_trace_ctx is the relocated fd_quic_ctx_t of the target quic
   tile.  fd_quic_trace_ctx_remote is the original fd_quic_ctx_t, but
   the pointer itself is in the local address space. */

extern fd_quic_ctx_t         fd_quic_trace_ctx;
extern fd_quic_ctx_t const * fd_quic_trace_ctx_remote;
extern ulong                 fd_quic_trace_ctx_raddr;
extern ulong volatile *      fd_quic_trace_link_metrics;
extern void const *          fd_quic_trace_log_base;

/* fd_quic_trace_target_fseq are the fseq counters published by the
   target quic tile */

extern ulong ** fd_quic_trace_target_fseq;

struct fd_quic_trace_frame_ctx {
  ulong  conn_id;
  uint   src_ip;
  ushort src_port;
  ulong  pkt_num;
};

typedef struct fd_quic_trace_frame_ctx fd_quic_trace_frame_ctx_t;

FD_PROTOTYPES_BEGIN

void
fd_quic_trace_frames( fd_quic_trace_frame_ctx_t * context,
                      uchar const * data,
                      ulong         data_sz );

void
fd_quic_trace_rx_tile( fd_frag_meta_t const * in_mcache );

void
fd_quic_trace_log_tile( fd_frag_meta_t const * in_mcache );

FD_PROTOTYPES_END


#define translate_ptr( ptr ) __extension__({              \
    ulong rel   = (ulong)(ptr) - fd_quic_trace_ctx_raddr; \
    ulong laddr = (ulong)fd_quic_trace_ctx_remote + rel;  \
    (__typeof__(ptr))(laddr);                             \
  })

#endif /* HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h */
