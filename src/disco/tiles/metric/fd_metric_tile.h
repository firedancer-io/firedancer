#ifndef HEADER_fd_src_disco_tiles_metric_fd_metric_tile_h
#define HEADER_fd_src_disco_tiles_metric_fd_metric_tile_h

/* The metric tile reads metrics updates from other tiles, maybe
   presents them on a local HTTP endpoint, and maybe uploads them to a
   server InfluxDB endpoint. */

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"
#include "../../topo/fd_topo.h"

#include <poll.h>

#define FD_METRIC_TILE_MAX_CONNS 128

#define FD_METRIC_TILE_ALIGN (128UL)

struct fd_metric_tile_args {
  ushort prometheus_listen_port;
};

typedef struct fd_metric_tile_args fd_metric_tile_args_t;

struct fd_metric_tile_topo {
  /* TODO: Untestable tile uses topology. Replace with a custom struct. */
  fd_topo_t const *     topo;
};

typedef struct fd_metric_tile_topo fd_metric_tile_topo_t;

typedef struct {
  ulong bytes_read;
  char input[ 1024 ];

  ulong output_len;
  char output[ 1048576 ];
  ulong bytes_written;
} fd_metric_tile_connection_t;

struct __attribute__((aligned(FD_METRIC_TILE_ALIGN))) fd_metric_tile_private {
  fd_topo_t topo[ 1 ];

  int socket_fd;

  fd_metric_tile_connection_t conns[ FD_METRIC_TILE_MAX_CONNS ];
  struct pollfd               fds[ FD_METRIC_TILE_MAX_CONNS+1 ];

  ulong conn_id;
};

typedef struct fd_metric_tile_private fd_metric_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_metric_tile_align( void );

FD_FN_PURE ulong
fd_metric_tile_footprint( fd_metric_tile_args_t const * args );

ulong
fd_metric_tile_seccomp_policy( void *               shmetric,
                               struct sock_filter * out,
                               ulong                out_cnt );

ulong
fd_metric_tile_allowed_fds( void * shmetric,
                            int *  out,
                            ulong  out_cnt );

void
fd_metric_tile_join_privileged( void *        shmetric,
                                uchar const * pod,
                                char const *  id );

fd_metric_tile_t *
fd_metric_tile_join( void *        shmetric,
                     uchar const * pod,
                     char const *  id );

void
fd_metric_tile_run( fd_metric_tile_t *      ctx,
                    fd_cnc_t *              cnc,
                    ulong                   in_cnt,
                    fd_frag_meta_t const ** in_mcache,
                    ulong **                in_fseq,
                    fd_frag_meta_t *        mcache,
                    ulong                   out_cnt,
                    ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_metric_fd_metric_tile_h */
