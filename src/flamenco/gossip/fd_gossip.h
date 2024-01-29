#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_h

#include "../types/fd_types.h"
#include "../../util/valloc/fd_valloc.h"

/* Global state of gossip protocol */
typedef struct fd_gossip fd_gossip_t;
ulong         fd_gossip_align    ( void );
ulong         fd_gossip_footprint( void );
void *        fd_gossip_new      ( void * shmem, ulong seed, fd_valloc_t valloc );
fd_gossip_t * fd_gossip_join     ( void * shmap );
void *        fd_gossip_leave    ( fd_gossip_t * join );
void *        fd_gossip_delete   ( void * shmap, fd_valloc_t valloc );


union fd_gossip_peer_addr {
    struct {
        uint   addr;  /* IPv4 address, network byte order (big endian) */
        ushort port;  /* port number, network byte order (big endian) */
        ushort pad;   /* Must be zero */
    };
    ulong l;          /* Combined port and address */
};
typedef union fd_gossip_peer_addr fd_gossip_peer_addr_t;

int
fd_gossip_from_soladdr(fd_gossip_peer_addr_t * dst, fd_gossip_socket_addr_t const * src );

int
fd_gossip_to_soladdr( fd_gossip_socket_addr_t * dst, fd_gossip_peer_addr_t const * src );

/* Callback when a new message is received */
typedef void (*fd_gossip_data_deliver_fun)(fd_crds_data_t* data, void* arg);

/* Callback for sending a packet. addr is the address of the destination. */
typedef void (*fd_gossip_send_packet_fun)( uchar const * msg, size_t msglen, fd_gossip_peer_addr_t const * addr, void * arg );

struct fd_gossip_config {
    fd_pubkey_t * public_key;
    uchar * private_key;
    fd_gossip_peer_addr_t my_addr;
    ushort shred_version;
    fd_gossip_data_deliver_fun deliver_fun;
    fd_gossip_send_packet_fun send_fun;
    void * fun_arg;
};
typedef struct fd_gossip_config fd_gossip_config_t;

/* Initialize the gossip data structure */
int fd_gossip_set_config( fd_gossip_t * glob, const fd_gossip_config_t * config );

/* Update the binding addr */
int fd_gossip_update_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * addr );

/* Update the repair service addr */
int fd_gossip_update_repair_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * serve );

/* Set the shred version (after receiving a contact info msg) */
void fd_gossip_set_shred_version( fd_gossip_t * glob, ushort shred_version );

/* Add a peer to talk to */
int fd_gossip_add_active_peer( fd_gossip_t * glob, fd_gossip_peer_addr_t * addr );

/* Publish an outgoing value. The source id and wallclock are set by this function. The gossip key for the value is optionally returned. */
int fd_gossip_push_value( fd_gossip_t * glob, fd_crds_data_t* data, fd_hash_t * key_opt );

/* Set the current protocol time in nanosecs. Call this as often as feasible. */
void fd_gossip_settime( fd_gossip_t * glob, long ts );

/* Get the current protocol time in nanosecs */
long fd_gossip_gettime( fd_gossip_t * glob );

/* Start timed events and other protocol behavior. settime MUST be called before this. */
int fd_gossip_start( fd_gossip_t * glob );

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. calling settime first is recommended. */
int fd_gossip_continue( fd_gossip_t * glob );

/* Pass a raw gossip packet into the protocol. addr is the address of the sender */
int fd_gossip_recv_packet( fd_gossip_t * glob, uchar const * msg, ulong msglen, fd_gossip_peer_addr_t const * addr );

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_h */
