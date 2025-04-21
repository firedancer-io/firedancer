#ifndef HEADER_fd_src_flamenco_repair_fd_repair_h
#define HEADER_fd_src_flamenco_repair_fd_repair_h

#include "../gossip/fd_gossip.h"
#include "../../ballet/shred/fd_shred.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../../disco/metrics/generated/fd_metrics_repair.h"
//#include "../../tango/tcache/fd_tcache.h"


#define FD_REPAIR_DELIVER_FAIL_TIMEOUT -1
#define FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED -2

/* Maximum size of a network packet */
#define FD_REPAIR_MAX_PACKET_SIZE 1232

/* Scratch space is used by the repair library to allocate an
   active element table and to shuffle that table.
   TODO: update comment to reflect the reasoning behind
   these constants once they are fully understood and updated. */
#define FD_REPAIR_SCRATCH_MAX    (1UL << 30UL)
#define FD_REPAIR_SCRATCH_DEPTH  (1UL << 11UL)
#define FD_REPAIR_TIMEOUT_THRESH ( 1000 * 1000 * 150 ) /* 150ms */
/* Number of peers to send requests to. */
#define FD_REPAIR_NUM_NEEDED_PEERS (4)
/* Max number of pending shred requests */
#define FD_NEEDED_KEY_MAX (1<<20)


struct req_ts {
   ulong key; /* type(2) | slot (32) | shred_idx (15) */
   uint  hash;
   long  when;  /* time in nanosecs */
   uchar signature[64]; /* cached sig */
 };
 typedef struct req_ts fd_req_ts_t;

 #define MAP_NAME fd_req_timeout
 #define MAP_T    fd_req_ts_t
 #include "../../util/tmpl/fd_map_dynamic.c"

typedef fd_gossip_peer_addr_t fd_repair_peer_addr_t;


/* Test if two hash values are equal */
FD_FN_PURE static int fd_repair_hash_eq( const fd_hash_t * key1, const fd_hash_t * key2 ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    if (key1->ul[i] != key2->ul[i])
      return 0;
  return 1;
}

/* Hash a hash value */
FD_FN_PURE static ulong fd_repair_hash_hash( const fd_hash_t * key, ulong seed ) {
  return key->ul[0] ^ seed;
}

/* Copy a hash value */
static void fd_repair_hash_copy( fd_hash_t * keyd, const fd_hash_t * keys ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    keyd->ul[i] = keys->ul[i];
}

/* Active table element. This table is all validators that we are
   asking for repairs. */
struct fd_active_elem {
    fd_pubkey_t key;  /* Public identifier and map key */
    ulong next; /* used internally by fd_map_giant */

    fd_repair_peer_addr_t addr;
    ulong avg_reqs; /* Moving average of the number of requests */
    ulong avg_reps; /* Moving average of the number of requests */
    long  avg_lat;  /* Moving average of response latency */
    uchar sticky;
    long  first_request_time;
    ulong stake;
};
typedef struct fd_active_elem fd_active_elem_t;

/* Active table */
#define MAP_NAME     fd_active_table
#define MAP_KEY_T    fd_pubkey_t
#define MAP_KEY_EQ   fd_repair_hash_eq
#define MAP_KEY_HASH fd_repair_hash_hash
#define MAP_KEY_COPY fd_repair_hash_copy
#define MAP_T        fd_active_elem_t
#include "../../util/tmpl/fd_map_giant.c"

/* Global state of repair protocol */
typedef struct fd_repair fd_repair_t;
FD_FN_CONST ulong         fd_repair_align    ( void );
FD_FN_CONST ulong         fd_repair_footprint( ulong needed_max );
            void *        fd_repair_new      ( void * shmem, ulong needed_max, ulong seed );
            fd_repair_t * fd_repair_join     ( void * shmap );
            void *        fd_repair_leave    ( fd_repair_t * join );
            void *        fd_repair_delete   ( void * shmap );

/* Callback when a new shred is received */
typedef void (*fd_repair_shred_deliver_fun)( fd_shred_t const * shred, ulong shred_len, fd_repair_peer_addr_t const * from, fd_pubkey_t const * id, void * arg );

/* Callbacks when a repair is requested. shred_idx==-1 means the last index. */
typedef long (*fd_repair_serv_get_shred_fun)( ulong slot, uint shred_idx, void * buf, ulong buf_max, void * arg );
typedef ulong (*fd_repair_serv_get_parent_fun)( ulong slot, void * arg );

/* Callback for sending a packet. addr is the address of the destination. */
typedef void (*fd_repair_send_packet_fun)( uchar const * msg, size_t msglen, fd_repair_peer_addr_t const * dst_addr, uint src_ip4_addr, void * arg );

/* Callback signing */
typedef void (*fd_repair_sign_fun)( void * ctx, uchar * sig, uchar const * buffer, ulong len, int sign_type );

/* Callback for when a request fails. Echoes back the request parameters. */
typedef void (*fd_repair_shred_deliver_fail_fun)( fd_pubkey_t const * id, ulong slot, uint shred_index, void * arg, int reason );

struct fd_repair_config {
    fd_pubkey_t * public_key;
    uchar * private_key;
    fd_repair_peer_addr_t service_addr;
    fd_repair_peer_addr_t intake_addr;
    fd_repair_shred_deliver_fun deliver_fun;
    fd_repair_serv_get_shred_fun serv_get_shred_fun;
    fd_repair_serv_get_parent_fun serv_get_parent_fun;
    fd_repair_send_packet_fun clnt_send_fun; /* sending client requests */
    fd_repair_send_packet_fun serv_send_fun; /* sending service responses */
    fd_repair_shred_deliver_fail_fun deliver_fail_fun;
    void * fun_arg;
    fd_repair_sign_fun sign_fun;
    void * sign_arg;
    int good_peer_cache_file_fd;
};
typedef struct fd_repair_config fd_repair_config_t;

/* Initialize the repair data structure */
int fd_repair_set_config( fd_repair_t * glob, const fd_repair_config_t * config );

/* Update the binding addr */
int fd_repair_update_addr( fd_repair_t * glob, const fd_repair_peer_addr_t * intake_addr, const fd_repair_peer_addr_t * service_addr );

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

/* Pass a raw client response packet into the protocol. addr is the address of the sender */
int
fd_repair_recv_clnt_packet( fd_repair_t *                 glob,
                            uchar const *                 msg,
                            ulong                         msglen,
                            fd_repair_peer_addr_t const * src_addr,
                            uint                          dst_ip4_addr );

/* Pass a raw service request packet into the protocol.
   src_addr is the address of the sender
   dst_ip4_addr is the dst IPv4 address of the incoming packet (i.e. our IP) */
int
fd_repair_recv_serv_packet( fd_repair_t *                 glob,
                            uchar *                       msg,
                            ulong                         msglen,
                            fd_repair_peer_addr_t const * src_addr,
                            uint                          dst_ip4_addr );

/* Determine if the request queue is full */
int fd_repair_is_full( fd_repair_t * glob );

/* Register a request for a shred */
ulong fd_repair_need_window_index( fd_repair_t * glob, ulong slot, uint shred_index );

ulong fd_repair_need_highest_window_index( fd_repair_t * glob, ulong slot, uint shred_index );

ulong fd_repair_need_orphan( fd_repair_t * glob, ulong slot );

void fd_repair_add_sticky( fd_repair_t * glob, fd_pubkey_t const * id );

void fd_repair_set_stake_weights( fd_repair_t * repair,
                                  fd_stake_weight_t const * stake_weights,
                                  ulong stake_weights_cnt );

void
fd_repair_send_request( fd_repair_t * glob, ulong tag, fd_active_elem_t * active );

void
get_peers( fd_repair_t * glob, fd_pubkey_t ** ids, uint max_ids );

fd_active_elem_t *
fd_repair_active_query( fd_repair_t * repair, fd_pubkey_t const * id );

/* Repair Metrics */
struct fd_repair_metrics {
  ulong recv_clnt_pkt;
  ulong recv_serv_pkt;
  ulong recv_serv_corrupt_pkt;
  ulong recv_serv_invalid_signature;
  ulong recv_serv_full_ping_table;
  ulong recv_serv_pkt_types[FD_METRICS_ENUM_REPAIR_SERV_PKT_TYPES_CNT];
  ulong recv_pkt_corrupted_msg;
  ulong send_pkt_cnt;
  ulong sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_CNT];
};
typedef struct fd_repair_metrics fd_repair_metrics_t;
#define FD_REPAIR_METRICS_FOOTPRINT ( sizeof( fd_repair_metrics_t ) )

fd_repair_metrics_t *
fd_repair_get_metrics( fd_repair_t * repair );


#endif /* HEADER_fd_src_flamenco_repair_fd_repair_h */
