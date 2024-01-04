#ifndef HEADER_fd_src_flamenco_repair_fd_repair_h
#define HEADER_fd_src_flamenco_repair_fd_repair_h

#include "../types/fd_types.h"
#include "../../util/valloc/fd_valloc.h"
#include "../gossip/fd_gossip.h"
#include "../../ballet/shred/fd_shred.h"

#define FD_REPAIR_DELIVER_FAIL_TIMEOUT -1
#define FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED -2

/* Global state of repair protocol */
typedef struct fd_repair fd_repair_t;
ulong         fd_repair_align    ( void );
ulong         fd_repair_footprint( void );
void *        fd_repair_new      ( void * shmem, ulong seed, fd_valloc_t valloc );
fd_repair_t * fd_repair_join     ( void * shmap );
void *        fd_repair_leave    ( fd_repair_t * join );
void *        fd_repair_delete   ( void * shmap, fd_valloc_t valloc );

typedef fd_gossip_peer_addr_t fd_repair_peer_addr_t;

/* Callback when a new shred is received */
typedef void (*fd_repair_shred_deliver_fun)( fd_shred_t const * shred, ulong shred_len, fd_repair_peer_addr_t const * from, fd_pubkey_t const * id, void * arg );

/* Callback for sending a packet. addr is the address of the destination. */
typedef void (*fd_repair_send_packet_fun)( uchar const * msg, size_t msglen, fd_repair_peer_addr_t const * addr, void * arg );

/* Callback for when a request fails. Echoes back the request parameters. */
typedef void (*fd_repair_shred_deliver_fail_fun)( fd_pubkey_t const * id, ulong slot, uint shred_index, void * arg, int reason );

struct fd_repair_config {
    fd_pubkey_t * public_key;
    uchar * private_key;
    fd_repair_peer_addr_t my_addr;
    fd_repair_shred_deliver_fun deliver_fun;
    fd_repair_send_packet_fun send_fun;
    fd_repair_shred_deliver_fail_fun deliver_fail_fun;
    void * fun_arg;
};
typedef struct fd_repair_config fd_repair_config_t;

/* Initialize the repair data structure */
int fd_repair_set_config( fd_repair_t * glob, const fd_repair_config_t * config );

/* Update the binding addr */
int fd_repair_update_addr( fd_repair_t * glob, const fd_repair_peer_addr_t * addr );

/* Add a peer to talk to */
int fd_repair_add_active_peer( fd_repair_t * glob, fd_repair_peer_addr_t const * addr, fd_pubkey_t const * id );

/* Set the current protocol time in nanosecs. Call this as often as feasible. */
void fd_repair_settime( fd_repair_t * glob, long ts );

/* Get the current protocol time in nanosecs */
long fd_repair_gettime( fd_repair_t * glob );

/* Start timed events and other protocol behavior. settime MUST be called before this. */
int fd_repair_start( fd_repair_t * glob );

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. calling settime first is recommended. */
int fd_repair_continue( fd_repair_t * glob );

/* Pass a raw repair packet into the protocol. addr is the address of the sender */
int fd_repair_recv_packet( fd_repair_t * glob, uchar const * msg, ulong msglen, fd_repair_peer_addr_t const * addr );

/* Determine if the request queue is full */
int fd_repair_is_full( fd_repair_t * glob );

/* Register a request for a shred */
int fd_repair_need_window_index( fd_repair_t * glob, fd_pubkey_t const * id, ulong slot, uint shred_index );

int fd_repair_need_highest_window_index( fd_repair_t * glob, fd_pubkey_t const * id, ulong slot, uint shred_index );

int fd_repair_need_orphan( fd_repair_t * glob, fd_pubkey_t const * id, ulong slot );

#endif /* HEADER_fd_src_flamenco_repair_fd_repair_h */
