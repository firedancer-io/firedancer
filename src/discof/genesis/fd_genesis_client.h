#ifndef HEADER_fd_src_discof_genesis_fd_genesis_client_h
#define HEADER_fd_src_discof_genesis_fd_genesis_client_h

#include "../../util/net/fd_net_headers.h"

#define FD_GENESIS_CLIENT_ALIGN 8UL

#define FD_GENESIS_CLIENT_MAGIC (0xF17EDA2CE58E1EC0) /* FIREDANCER GENEC V0 */

struct fd_genesis_client_private;
typedef struct fd_genesis_client_private fd_genesis_client_t;

FD_FN_CONST ulong
fd_genesis_client_align( void );

/* peer_max is the number of concurrent download peers provisioned,
   at most FD_TOPO_GOSSIP_ENTRYPOINTS_MAX. */

FD_FN_CONST ulong
fd_genesis_client_footprint( ulong peer_max );

void *
fd_genesis_client_new( void * shmem,
                       ulong  peer_max );

fd_genesis_client_t *
fd_genesis_client_join( void * shgen );

void
fd_genesis_client_init( fd_genesis_client_t * client,
                        fd_ip4_port_t const * servers,
                        ulong                 servers_len );

int
fd_genesis_client_poll( fd_genesis_client_t * client,
                        fd_ip4_port_t *       peer,
                        uchar **              buffer,
                        ulong *               buffer_sz,
                        int *                 charge_busy );

struct pollfd const *
fd_genesis_client_get_pollfds( fd_genesis_client_t * client );

#endif
