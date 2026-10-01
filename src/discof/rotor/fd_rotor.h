#ifndef HEADER_fd_src_discof_rotor_fd_rotor_h
#define HEADER_fd_src_discof_rotor_fd_rotor_h

#include "../repair/fd_repair.h"
#include "../../disco/store/fd_store.h"

/* Event-driven rotor model (rotor4.md).  This module is single-threaded
   and uses caller-owned memory.  It does not replace fd_rotor_tile yet.

   frag_* accepts decoded, validated tile fragments.  The adapter must
   check packet framing, nonces, Merkle proofs and parent marker encoding
   before calling these functions.  Shred responses use frag_shred.
   Gossip, ping/pong and signing remain transport responsibilities.

   Two independent heaps contain individual repair requests.  Shred
   enqueue failure drops the request, never the admitted fragment.
   Deferred shred recovery is deliberately not implemented.  Metadata
   generation retains a cursor when its heap is full.  All cancellation
   is lazy; pool generations protect requests and signing reservations.

   Times are monotonic nanoseconds.  Call advance on every local credit
   turn, even without replay credits, then request_next as transport
   capacity permits.  Each call bounds its request-generation/pop work. */

#define FD_ROTOR_BLOCK_MAX_DEFAULT (20000UL)
#define FD_ROTOR_SHRED_REQUEST_MAX_DEFAULT (FD_ROTOR_BLOCK_MAX_DEFAULT*2048UL)
#define FD_ROTOR_VERSION_MAX (7UL)
#define FD_ROTOR_ACCEPT (1)
#define FD_ROTOR_IGNORE (0)
#define FD_ROTOR_AGAIN  (-1) /* state capacity or redelivery barrier; retain input */

struct fd_rotor_request {
  uint      kind;
  ulong     slot;
  uint      idx;
  fd_hash_t block_id; /* zero for positional requests, even after turbine rekey */
  fd_hash_t fec_root;
};
typedef struct fd_rotor_request fd_rotor_request_t;

struct fd_rotor_config {
  ulong block_max;          /* includes the root anchor and all versions */
  ulong max_shreds;         /* positive multiple of 32, runtime protocol limit */
  ulong shred_request_max;
  ulong seed_window;        /* at most this many slots above root */
  long  turbine_grace;
  long  highest_delay;
  long  retry_delay;
  ulong seed_peer_min;
  int   block_id_only;
};
typedef struct fd_rotor_config fd_rotor_config_t;

typedef struct fd_rotor fd_rotor_t;

/* A token reserves an entry while signing.  Exactly one request_sent
   call is required per successful request_next, including failed sends.
   Sent requests keep their dedup entry and retry after retry_delay. */
struct fd_rotor_token { ulong generation; uint idx; uint queue; };
typedef struct fd_rotor_token fd_rotor_token_t;

#define FD_ROTOR_SHRED_DATA     (0)
#define FD_ROTOR_SHRED_COMPLETE (1)
#define FD_ROTOR_SHRED_EVICTED  (2)
#define FD_ROTOR_SHRED_EQVOC    (3)
#define FD_ROTOR_SHRED_INVALID  (4)
#define FD_ROTOR_SHRED_CODE     (5)
#define FD_ROTOR_SRC_TURBINE    (0)
#define FD_ROTOR_SRC_REPAIR     (1)
#define FD_ROTOR_SRC_RECOVERED  (2)
#define FD_ROTOR_SRC_LEADER     (3)

struct fd_rotor_shred {
  int       kind;
  int       src;
  ulong     slot;
  uint      idx;           /* shred index for DATA, FEC start otherwise */
  fd_hash_t merkle_root;   /* full root */
  int       slot_complete;
  int       data_complete;
  int       is_leader;
  int       has_parent;    /* validated header or permitted UpdateParent marker */
  ulong     parent_slot;
  fd_hash_t parent_id;
};
typedef struct fd_rotor_shred fd_rotor_shred_t;

struct fd_rotor_net {
  uint      kind;          /* AG_REPAIR_KIND_PARENT_FEC_COUNT or FEC_ROOT */
  ulong     slot;
  fd_hash_t block_id;
  uint      fec_count;
  ulong     parent_slot;
  fd_hash_t parent_id;
  uint      fec_idx;
  uchar     root_prefix[ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_rotor_net fd_rotor_net_t;

struct fd_rotor_delivery {
  ulong     slot;
  fd_hash_t block_id;
  ulong     parent_slot;
  fd_hash_t parent_id;
  uint      fec_idx;
  fd_hash_t merkle_root;
  int       turbine;
  int       slot_complete;
  int       data_complete;
  int       is_leader;
  int       redelivery;
};
typedef struct fd_rotor_delivery fd_rotor_delivery_t;

/* Read-only snapshots for diagnostics.  Missing FECs have no pool entry. */
struct fd_rotor_block_info {
  fd_hash_t block_id;
  ulong parent_slot;
  uint required_shreds;
  uint complete_idx;
  uint delivered_shreds;
  uint recovered_cnt;
  int turbine;
  int cancel;
  int final;
  int connected;
};
typedef struct fd_rotor_block_info fd_rotor_block_info_t;
struct fd_rotor_fec_info { fd_hash_t merkle_root; uint received; int complete; int owner; };
typedef struct fd_rotor_fec_info fd_rotor_fec_info_t;
struct fd_rotor_stats {
  ulong blocks;
  ulong fecs;
  ulong shred_requests; /* includes signing/inflight */
  ulong other_requests;
  ulong other_request_max;
  ulong shred_dropped;
  ulong stale_popped;
  ulong highest_delivered;
};
typedef struct fd_rotor_stats fd_rotor_stats_t;

FD_PROTOTYPES_BEGIN

fd_rotor_config_t fd_rotor_config_default( void );
ulong fd_rotor_align( void );
ulong fd_rotor_footprint( fd_rotor_config_t const * config );
/* store is optional (NULL in standalone tests); borrowed for the rotor lifetime. */
void * fd_rotor_new( void * mem, fd_rotor_config_t const * config, ulong seed, fd_store_t * store );
fd_rotor_t * fd_rotor_join( void * mem );
void * fd_rotor_leave( fd_rotor_t * rotor );
void * fd_rotor_delete( void * mem );

int fd_rotor_frag_snapshot( fd_rotor_t * rotor, ulong root, fd_hash_t const * block_id );
int fd_rotor_frag_genesis( fd_rotor_t * rotor );
int fd_rotor_frag_shred( fd_rotor_t * rotor, fd_rotor_shred_t const * frag, long now );
int fd_rotor_frag_net( fd_rotor_t * rotor, fd_rotor_net_t const * verified, long now );
/* is_final means a final/fast-final certificate, otherwise a REPAIR notification. */
int fd_rotor_frag_votor( fd_rotor_t * rotor, ulong slot, fd_hash_t const * block_id, int is_final, long now );
/* Root updates are retained internally until queued deliveries drain. */
int fd_rotor_frag_replay_root( fd_rotor_t * rotor, ulong slot, fd_hash_t const * block_id, long now );
/* Redeliver ancestry preceding the next ordinary delivery, using retained FECs. */
void fd_rotor_frag_replay_missing( fd_rotor_t * rotor );

void fd_rotor_set_block_id_only( fd_rotor_t * rotor, int enabled, long now );
void fd_rotor_advance( fd_rotor_t * rotor, long now, ulong peer_cnt, ulong budget );
int fd_rotor_request_next( fd_rotor_t * rotor, long now, ulong budget, fd_rotor_request_t * request, fd_rotor_token_t * token );
void fd_rotor_request_sent( fd_rotor_t * rotor, fd_rotor_token_t token, int sent, long now );
/* delivery_next borrows a delivery until delivery_pop, which acknowledges
   publication.  Do not retain references across pop.  Finality is held
   while a delivery is borrowed or ancestry redelivery is in progress. */
int fd_rotor_delivery_next( fd_rotor_t * rotor, fd_rotor_delivery_t * delivery );
void fd_rotor_delivery_pop( fd_rotor_t * rotor, long now );

int fd_rotor_block_query( fd_rotor_t * rotor, ulong slot, fd_hash_t const * block_id, fd_rotor_block_info_t * out );
int fd_rotor_fec_query( fd_rotor_t * rotor, ulong slot, fd_hash_t const * block_id, uint fec_idx, fd_rotor_fec_info_t * out );
void fd_rotor_stats( fd_rotor_t const * rotor, fd_rotor_stats_t * out );
int fd_rotor_verify( fd_rotor_t * rotor );

FD_PROTOTYPES_END
#endif
