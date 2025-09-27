#ifndef HEADER_fd_src_discof_ipecho_fd_ipecho_server_h
#define HEADER_fd_src_discof_ipecho_fd_ipecho_server_h

#include "../../util/fd_util_base.h"

#define FD_IPECHO_SERVER_MAGIC (0xF17EDA2CE5185EC8) /* FIREDANCER SIPECHO V0 */

struct fd_ipecho_server;
typedef struct fd_ipecho_server fd_ipecho_server_t;

struct fd_ipecho_server_metrics {
  ulong connection_cnt;
  ulong bytes_read;
  ulong bytes_written;
  ulong connections_closed_ok;
  ulong connections_closed_error;
};

typedef struct fd_ipecho_server_metrics fd_ipecho_server_metrics_t;

FD_FN_CONST ulong
fd_ipecho_server_align( void );

FD_FN_CONST ulong
fd_ipecho_server_footprint( ulong max_connection_cnt );

void *
fd_ipecho_server_new( void * shmem,
                      ulong  max_connection_cnt );

fd_ipecho_server_t *
fd_ipecho_server_join( void * shipe );

void
fd_ipecho_server_init( fd_ipecho_server_t * server,
                       uint                 address,
                       ushort               port,
                       ushort               shred_version );

void
fd_ipecho_server_poll( fd_ipecho_server_t * server,
                       int *                charge_busy,
                       int                  timeout_ms );

fd_ipecho_server_metrics_t *
fd_ipecho_server_metrics( fd_ipecho_server_t * server );

int
fd_ipecho_server_sockfd( fd_ipecho_server_t * server );

#endif /* HEADER_fd_src_discof_ipecho_fd_ipecho_server_h */
