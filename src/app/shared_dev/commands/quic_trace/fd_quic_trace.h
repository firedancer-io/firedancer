#ifndef HEADER_fd_src_app_shared_dev_commands_quic_trace_fd_quic_trace_h
#define HEADER_fd_src_app_shared_dev_commands_quic_trace_fd_quic_trace_h

#include "../../../shared/fd_config.h"
#include "../../../shared/fd_action.h"
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/quic/fd_quic_tile.h"
#include "../../../../waltz/quic/fd_quic_private.h"

/* map cpeer_conn_id->conn_idx */
struct peer_conn_id_map {
  ulong             conn_id;  /* the peer conn_id isn't restricted to len 8 */
                              /* however, we don't know the size, so we assume */
                              /* the size is at least 8, and truncate the rest */
  uint              hash;     /* for memoizing the hash value */
  uint              conn_idx; /* the connection index */
};

typedef struct peer_conn_id_map peer_conn_id_map_t;

#define MAP_NAME              peer_conn_id_map
#define MAP_KEY               conn_id
#define MAP_T                 peer_conn_id_map_t
#define PEER_MAP_LG_SLOT_CNT  20
#define MAP_LG_SLOT_CNT       PEER_MAP_LG_SLOT_CNT
#include "../../../../util/tmpl/fd_map.c"

/* fd_quic_trace_ctx_remote is the original fd_quic_ctx_t, but the
   pointer itself is in the local address space. */
extern void const         *  fd_quic_trace_tile_ctx_remote; /* local ptr to remote ctx */
extern ulong                 fd_quic_trace_tile_ctx_raddr;  /* remote addr of remote ctx */
extern ulong volatile     *  fd_quic_trace_link_metrics;
extern void const         *  fd_quic_trace_log_base;
extern peer_conn_id_map_t    _fd_quic_trace_peer_map[1UL<<PEER_MAP_LG_SLOT_CNT];
extern peer_conn_id_map_t *  fd_quic_trace_peer_map;

/* fd_quic_trace_target_fseq are the fseq counters published by the
   target quic tile */

extern ulong ** fd_quic_trace_target_fseq;

struct fd_quic_trace_ctx {
  int   dump;         /* whether the user requested --dump */
  int   dump_config;  /* whether the user requested --dump-config */
  int   dump_conns;   /* whether the user requested --dump-conns */
  int   trace_send;   /* whether the user requested tracing send tile (1) or quic tile (0) */
  ulong net_out_base; /* base address of net-out chunks in local addr space */

  fd_quic_t * quic;  /* local join to remote quic */
  fd_net_rx_bounds_t net_in_bounds[1]; /* bounds of net-in chunks in local addr space */
  uchar buffer[ FD_NET_MTU ];
};

typedef struct fd_quic_trace_ctx fd_quic_trace_ctx_t;

struct fd_quic_trace_frame_ctx {
  ulong  conn_id;
  uint   src_ip;
  ushort src_port;
  uchar  pkt_type;
  ulong  pkt_num;
};

typedef struct fd_quic_trace_frame_ctx fd_quic_trace_frame_ctx_t;

#define translate_ptr( ptr ) __extension__({                   \
  ulong rel   = (ulong)(ptr) - fd_quic_trace_tile_ctx_raddr; \
  ulong laddr = (ulong)fd_quic_trace_tile_ctx_remote + rel;  \
  (__typeof__(ptr))(laddr);                                  \
})

#define tile_member( ctx_ptr, field, is_send ) \
*fd_ptr_if( is_send, &(((fd_txsend_tile_ctx_t*)(ctx_ptr))->field), &(((fd_quic_ctx_t*)(ctx_ptr))->field))


FD_PROTOTYPES_BEGIN

void
fd_quic_trace_frames( fd_quic_trace_frame_ctx_t * context,
                      uchar               const * data,
                      ulong                       data_sz );

void
fd_quic_trace_rx_tile( fd_quic_trace_ctx_t  * trace_ctx,
                       fd_frag_meta_t const * rx_mcache,
                       fd_frag_meta_t const * tx_mcache );

void
fd_quic_trace_log_tile( fd_quic_trace_ctx_t  * ctx,
                        fd_frag_meta_t const * in_mcache );

static inline fd_quic_conn_t const *
fd_quic_trace_conn_at_idx( fd_quic_t const * quic, ulong idx ) {
  fd_quic_state_t const * state = fd_quic_get_state_const( quic );
  ulong const local_conn_base   = translate_ptr( state->conn_base );
  return (fd_quic_conn_t *)( local_conn_base + idx * state->conn_sz );
}

FD_PROTOTYPES_END


extern action_t fd_action_quic_trace;

#endif /* HEADER_fd_src_app_shared_dev_commands_quic_trace_fd_quic_trace_h */
