#ifndef HEADER_fd_src_disco_repair_fd_repair_strat_h
#define HEADER_fd_src_disco_repair_fd_repair_strat_h

/* fd_repair_strat picks the repair peer for each request.  It does no
   I/O: the rotor tile feeds it contact infos, epoch stakes and request
   outcomes.  Peers sit in slots by stake rank, unstaked last, and in
   latency buckets by srtt+rttvar/4.  A pick takes the fastest
   bucket's cheaper of the next two peers by srtt*(out_cnt+1), the
   cursor advancing one peer so every peer meets every neighbor,
   every FD_REPAIR_STRAT_EXPLORE-th pick tries an unmeasured peer first,
   and a request is hedged after srtt+4*rttvar (RFC 6298).  It also
   estimates each leader's turbine time, which decides how long a
   missing FEC set waits for turbine before it is repaired. */

#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../flamenco/stakes/fd_stake_weight.h"

#define FD_REPAIR_STRAT_PEER_MAX     FD_CONTACT_INFO_TABLE_SIZE
#define FD_REPAIR_STRAT_INFLIGHT_MAX (8U)
#define FD_REPAIR_STRAT_EXPLORE      (16UL) /* every 16th pick tries an unmeasured peer first */
#define FD_REPAIR_STRAT_ESCAPE_TOP   (100UL) /* an escape pick draws only from the top stake ranks, small stakers are often far or offline */
#define FD_REPAIR_STRAT_EXPIRED_MAX  (32U)  /* requests in a row a peer leaves unanswered before it is banned */
#define FD_REPAIR_STRAT_BYID_MAX     (4U)   /* by-id requests in a row, other replies aside */
#define FD_REPAIR_STRAT_HEDGE_NS     (100L*1000000L) /* hedge time of an unmeasured peer, and the longest any request waits for a retry */
#define FD_REPAIR_STRAT_EAGER_MIN_NS (20L*1000000L)
#define FD_REPAIR_STRAT_EAGER_MAX_NS (250L*1000000L)  /* also the eager wait until turbine is measured */
#define FD_REPAIR_STRAT_TURBINE_MIN  (8UL)            /* samples before a leader's own estimate is used */

/* Latency buckets, fastest first.  UNMEASURED holds peers with no rtt
   sample yet. */

#define FD_REPAIR_STRAT_BUCKET_25MS       (0UL)
#define FD_REPAIR_STRAT_BUCKET_50MS       (1UL)
#define FD_REPAIR_STRAT_BUCKET_100MS      (2UL)
#define FD_REPAIR_STRAT_BUCKET_200MS      (3UL)
#define FD_REPAIR_STRAT_BUCKET_SLOW       (4UL)
#define FD_REPAIR_STRAT_BUCKET_UNMEASURED (5UL)
#define FD_REPAIR_STRAT_BUCKET_CNT        (6UL)

struct fd_repair_strat_peer {
  fd_pubkey_t id_key;
  ulong       next;           /* map chain */
  uint        ip4;            /* 0 while gossip has no address for it */
  ushort      port;
  ulong       bucket;         /* the bucket of its rtt */
  long        ping_ts;        /* last ping, 0 if none */
  long        ban_ts;         /* skipped until this time */
  uint        expired_cnt;    /* requests in a row it left unanswered */
  uint        byid_expired_cnt; /* by-id requests in a row it left unanswered */
  long        turbine_srtt;   /* as leader, smoothed time from a FEC set's first shred to complete, 0 if never measured */
  long        turbine_rttvar; /* its mean deviation */
  ulong       turbine_cnt;    /* its samples */
  uint        out_cnt;        /* outstanding requests (in-flight) */
  long        srtt_ns;        /* smoothed round trip, 0 if never measured */
  long        rttvar_ns;      /* its mean deviation */
};
typedef struct fd_repair_strat_peer fd_repair_strat_peer_t;

#define MAP_NAME               fd_repair_strat_peer_map
#define MAP_ELE_T              fd_repair_strat_peer_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY                id_key
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0), (k1), sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( (seed)^FD_LOAD( ulong, (key)->uc ) )
#include "../../util/tmpl/fd_map_chain.c"

#define SET_NAME fd_repair_strat_set
#define SET_MAX  FD_REPAIR_STRAT_PEER_MAX
#include "../../util/tmpl/fd_set.c"

/* Slots and their map are double buffered so the epoch re-sort can
   read the old order while it builds the new one. */

struct fd_repair_strat_order {
  fd_repair_strat_peer_t *     peers; /* FD_REPAIR_STRAT_PEER_MAX slots */
  fd_repair_strat_peer_map_t * map;
};
typedef struct fd_repair_strat_order fd_repair_strat_order_t;

struct fd_repair_strat_private {
  fd_repair_strat_order_t cur;
  fd_repair_strat_order_t old;
  ulong                   staked_cnt;
  uint *                  free;     /* unstaked slots not in use, a stack */
  ulong                   free_cnt;
  fd_repair_strat_set_t * buckets[ FD_REPAIR_STRAT_BUCKET_CNT ];
  ulong                   cursor [ FD_REPAIR_STRAT_BUCKET_CNT ]; /* slot last picked in each bucket */
  ulong                   pick_cnt;
  ulong                   seed;
  ulong                   epoch_cnt;
  long                    turbine_srtt;   /* over all leaders */
  long                    turbine_rttvar;
};
typedef struct fd_repair_strat_private fd_repair_strat_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_repair_strat_align( void );

FD_FN_CONST ulong
fd_repair_strat_footprint( void );

void *
fd_repair_strat_new( void * shmem,
                     ulong  seed );

fd_repair_strat_t *
fd_repair_strat_join( void * shstrat );

/* fd_repair_strat_epoch_advanced re-sorts the peers by the epoch's
   identity stakes, ids sorted by stake descending.  Peers keep their
   address, rtt and ping state.  Invalidates peer pointers. */

void
fd_repair_strat_epoch_advanced( fd_repair_strat_t *       strat,
                                fd_stake_weight_t const * ids,
                                ulong                     id_cnt );

/* fd_repair_strat_contact_info_updated records a peer's repair address
   from gossip.  A new address resets its rtt and ping.  A new unstaked
   peer is dropped if every unstaked slot is in use. */

void
fd_repair_strat_contact_info_updated( fd_repair_strat_t * strat,
                                      fd_pubkey_t const * id_key,
                                      uint                ip4,
                                      ushort              port );

/* fd_repair_strat_contact_info_removed forgets a peer's address.  A
   staked peer keeps its slot. */

void
fd_repair_strat_contact_info_removed( fd_repair_strat_t * strat,
                                      fd_pubkey_t const * id_key );

/* fd_repair_strat_pick returns the peer for a request and counts it in
   flight, or NULL if none is available.  staked restricts it to staked
   peers.  The fastest bucket with an available peer wins; within it the
   cheaper of the next two peers after its cursor, in stake order.
   Banned peers are skipped, and slot avoid unless no other peer is
   available (ULONG_MAX for none). */

fd_repair_strat_peer_t *
fd_repair_strat_pick( fd_repair_strat_t * strat,
                      long                now,
                      int                 staked,
                      ulong               avoid );

/* fd_repair_strat_pick_staked returns a staked peer at random among the
   top FD_REPAIR_STRAT_ESCAPE_TOP stake ranks, higher ranks likelier,
   other than slot avoid, for a request the bucket
   order keeps failing, and counts it in flight.  r is a random number.
   NULL if none is available. */

fd_repair_strat_peer_t *
fd_repair_strat_pick_staked( fd_repair_strat_t * strat,
                             long                now,
                             ulong               avoid,
                             ulong               r );

/* fd_repair_strat_request_done ends a request picked from id_key with a
   reply that verified.  rtt is its round trip, byid if it answered a
   by-id request. */

void
fd_repair_strat_request_done( fd_repair_strat_t * strat,
                              fd_pubkey_t const * id_key,
                              long                rtt,
                              int                 byid );

/* fd_repair_strat_request_failed ends a request picked from id_key with
   a reply that failed to verify, or no reply at all, and skips the peer
   until ban_ts.  It takes no rtt sample. */

void
fd_repair_strat_request_failed( fd_repair_strat_t * strat,
                                fd_pubkey_t const * id_key,
                                long                ban_ts );

/* fd_repair_strat_request_expired ends a request picked from id_key that
   a live peer should have answered but did not.  It takes no rtt
   sample; after FD_REPAIR_STRAT_EXPIRED_MAX in a row with no reply, or
   FD_REPAIR_STRAT_BYID_MAX by-id ones (byid) with no by-id reply, the
   peer is skipped until ban_ts.  Returns 1 if the by-id run banned it,
   -1 if the run of any kind did, 0 if not banned. */

int
fd_repair_strat_request_expired( fd_repair_strat_t * strat,
                                 fd_pubkey_t const * id_key,
                                 long                ban_ts,
                                 int                 byid );

/* fd_repair_strat_turbine_done records t, the time from a FEC set's
   first shred to its completion, for the slot's leader id_key. */

void
fd_repair_strat_turbine_done( fd_repair_strat_t * strat,
                              fd_pubkey_t const * id_key,
                              long                t );

/* fd_repair_strat_eager_ns returns how long a missing FEC set of
   leader id_key waits for turbine before it is repaired: about the p95
   of its turbine time, from all leaders until it has
   FD_REPAIR_STRAT_TURBINE_MIN samples.  id_key may be NULL. */

long
fd_repair_strat_eager_ns( fd_repair_strat_t * strat,
                          fd_pubkey_t const * id_key );

/* fd_repair_strat_hedge_ns returns how long a request to peer may be
   outstanding before it is hedged to another peer. */

static inline long
fd_repair_strat_hedge_ns( fd_repair_strat_peer_t const * peer ) {
  return fd_long_if( !!peer->srtt_ns, peer->srtt_ns+4L*peer->rttvar_ns, FD_REPAIR_STRAT_HEDGE_NS );
}

fd_repair_strat_peer_t *
fd_repair_strat_query( fd_repair_strat_t * strat,
                       fd_pubkey_t const * id_key );

/* fd_repair_strat_slot_remap returns the slot now held by the peer that
   held slot idx before the last epoch re-sort, or ULONG_MAX if it is
   gone or idx is ULONG_MAX. */

ulong
fd_repair_strat_slot_remap( fd_repair_strat_t const * strat,
                            ulong                     idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_repair_fd_repair_strat_h */
