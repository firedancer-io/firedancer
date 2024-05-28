#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_h

#include "../types/fd_types.h"
#include "../../util/valloc/fd_valloc.h"

/* Max number of validators that can be known */
#define FD_PEER_KEY_MAX (1<<14)

/* Global state of gossip protocol */
typedef struct fd_gossip fd_gossip_t;
ulong         fd_gossip_align    ( void );
ulong         fd_gossip_footprint( void );
void *        fd_gossip_new      ( void * shmem, ulong seed );
fd_gossip_t * fd_gossip_join     ( void * shmap );
void *        fd_gossip_leave    ( fd_gossip_t * join );
void *        fd_gossip_delete   ( void * shmap );


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

/* Callback for signing */
typedef void (*fd_gossip_sign_fun)( void * ctx, uchar * sig, uchar const * buffer, ulong len );

struct fd_gossip_config {
    fd_pubkey_t * public_key;
    uchar * private_key;
    fd_gossip_peer_addr_t my_addr;
    fd_gossip_version_v2_t my_version;
    ushort shred_version;
    fd_gossip_data_deliver_fun deliver_fun;
    void * deliver_arg;
    fd_gossip_send_packet_fun send_fun;
    void * send_arg;
    fd_gossip_sign_fun sign_fun;
    void * sign_arg;
};
typedef struct fd_gossip_config fd_gossip_config_t;

/* Initialize the gossip data structure */
int fd_gossip_set_config( fd_gossip_t * glob, const fd_gossip_config_t * config );

/* Update the binding addr */
int fd_gossip_update_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * addr );

/* Update the repair service addr */
int fd_gossip_update_repair_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * serve );

/* Update the tvu rx addr */
int
fd_gossip_update_tvu_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tvu, const fd_gossip_peer_addr_t * tvu_fwd );

/* Update the tpu addr */
int
fd_gossip_update_tpu_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tpu );

/* Update the tpu vote addr */
int fd_gossip_update_tpu_vote_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tpu_vote );

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

const char * fd_gossip_addr_str( char * dst, ulong dstlen, fd_gossip_peer_addr_t const * src );

ushort fd_gossip_get_shred_version( fd_gossip_t const * glob );

void fd_gossip_set_stake_weights( fd_gossip_t * gossip, fd_stake_weight_t const * stake_weights, ulong stake_weights_cnt );

void fd_gossip_set_entrypoints( fd_gossip_t * gossip, uint allowed_entrypoints[static 16], ulong allowed_entrypoints_cnt, ushort * ports );

uint fd_gossip_is_allowed_entrypoint( fd_gossip_t * gossip, fd_gossip_peer_addr_t * addr );

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_h */
