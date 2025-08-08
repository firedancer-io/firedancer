#ifndef HEADER_fd_src_discof_ipecho_fd_ipecho_client_h
#define HEADER_fd_src_discof_ipecho_fd_ipecho_client_h

#include "../../util/net/fd_net_headers.h"

#define FD_IPECHO_CLIENT_ALIGN 8UL

#define FD_IPECHO_CLIENT_MAGIC (0xF17EDA2CE518EC80) /* FIREDANCER IPECHO V0 */

struct fd_ipecho_client_private;
typedef struct fd_ipecho_client_private fd_ipecho_client_t;

FD_FN_CONST ulong
fd_ipecho_client_align( void );

FD_FN_CONST ulong
fd_ipecho_client_footprint( void );

void *
fd_ipecho_client_new( void * shmem );

fd_ipecho_client_t *
fd_ipecho_client_join( void * shipe );

void
fd_ipecho_client_init( fd_ipecho_client_t *  client,
                       fd_ip4_port_t const * servers,
                       ulong                 servers_len );

int
fd_ipecho_client_poll( fd_ipecho_client_t * client,
                       ushort *             shred_version,
                       int *                charge_busy );

#endif
