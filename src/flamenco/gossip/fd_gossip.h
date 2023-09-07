#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_h

#include "../types/fd_types.h"
#include "../../util/valloc/fd_valloc.h"
#include <netinet/in.h>

/* Global state of gossip protocol */
typedef struct fd_gossip_global fd_gossip_global_t;
ulong                fd_gossip_global_align    ( void );
ulong                fd_gossip_global_footprint( void );
void *               fd_gossip_global_new      ( void * shmem, ulong seed, fd_valloc_t valloc );
fd_gossip_global_t * fd_gossip_global_join     ( void * shmap );
void *               fd_gossip_global_leave    ( fd_gossip_global_t * join );
void *               fd_gossip_global_delete   ( void * shmap, fd_valloc_t valloc );

/* fd_gossip_credentials holds the node's gossip private credentials. */

struct fd_gossip_credentials {
    fd_pubkey_t public_key;
    uchar private_key[ 32 ];
};
typedef struct fd_gossip_credentials fd_gossip_credentials_t;

struct __attribute__((aligned(8UL))) fd_gossip_network_addr {
    sa_family_t family;   /* AF_INET or AF_INET6 */
    in_port_t   port;     /* port number, network byte order */
    uint        addr[4];  /* IPv4 or v6 address, network byte order */
};
typedef struct fd_gossip_network_addr fd_gossip_network_addr_t;

fd_gossip_network_addr_t * fd_gossip_resolve_hostport(const char* str /* host:port */,
                                                      fd_gossip_network_addr_t * res);

typedef void (*fd_gossip_data_deliver_fun)(fd_crds_data_t* data, void* arg, long now);

struct fd_gossip_config {
    fd_gossip_credentials_t my_creds;
    fd_gossip_network_addr_t my_addr;
    ushort shred_version;
    fd_gossip_data_deliver_fun deliver_fun;
    void * deliver_fun_arg;
};
typedef struct fd_gossip_config fd_gossip_config_t;

int fd_gossip_global_set_config( fd_gossip_global_t * glob, const fd_gossip_config_t * config );

int fd_gossip_add_active_peer( fd_gossip_global_t * glob, fd_gossip_network_addr_t * addr );

/* Publish an outgoing value. The source id and wallclock are set by this function */
int fd_gossip_push_value( fd_gossip_global_t * glob, fd_crds_data_t* data );

/* Main loop for socket reading/writing. Does not return until stopflag is non-zero */
int fd_gossip_main_loop( fd_gossip_global_t * glob, fd_valloc_t valloc, volatile int * stopflag );

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_h */
