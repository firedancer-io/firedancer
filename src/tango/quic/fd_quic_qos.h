#ifndef HEADER_fd_src_tango_quic_fd_quic_qos_h
#define HEADER_fd_src_tango_quic_fd_quic_qos_h

#include "../../ballet/txn/fd_txn.h"
#include "../../util/fd_util.h"
#include "../../util/fd_util_base.h"
#include "../stake/fd_stake.h"
#include "../tcache/fd_tcache.h"
#include "fd_quic_common.h"
#include "fd_quic_conn.h"
#include <openssl/x509.h>

#define FD_QUIC_QOS_LRU_ALIGN ( 128UL )
#define FD_QUIC_QOS_ALIGN     ( 128UL )

/* Default limits */
#define FD_QUIC_QOS_DEFAULT_MIN_STREAMS   ( 1UL << 7 )
#define FD_QUIC_QOS_DEFAULT_MAX_STREAMS   ( 1UL << 11 )
#define FD_QUIC_QOS_DEFAULT_TOTAL_STREAMS ( 1UL << 16 )
#define FD_QUIC_QOS_DEFAULT_PRIV_CONNS    ( 1UL << 16 )
#define FD_QUIC_QOS_DEFAULT_UNPRIV_CONNS  ( 1UL << 16 )

/* Configurable limits */
struct fd_quic_qos_limits {
  ulong min_streams;     /* the min # of concurrent streams that can be alloted to a single conn */
  ulong max_streams;     /* the max # of concurrent streams that can be alloted to a single conn */
  ulong total_streams;   /* the total # of streams that can be alloted across all conns */
  int   pq_lg_slot_cnt;  /* the lg max # of "prioritized" conns. stake-based (priority) eviction. */
  int   lru_lg_slot_cnt; /* the lg max # of "unprioritzed" conns. LRU eviction. */
};
typedef struct fd_quic_qos_limits fd_quic_qos_limits_t;

// /* priority queue for "prioritized traffic". eviction is done by random sampling vs. strict minimum.
//  * connections in the priority queue will _probably_ have stake, but it is not a requirement. */
// struct fd_quic_qos_pq {
//   ulong            key; /* conn_id */
//   uint             hash;
//   fd_quic_conn_t * conn;
// };
// typedef struct fd_quic_qos_pq fd_quic_qos_priv_conn_t;
// #define MAP_NAME fd_quic_qos_priv_conn
// #define MAP_T    fd_quic_qos_priv_conn_t
// #include "../../util/tmpl/fd_map_dynamic.c"

// /* LRU for "unprioritized traffic". connections in the LRU _probably_ will not have stake, but it is
//  * possible a staked connection will end up in the LRU because it didn't meet the threshold to evict
//  * from the priority queue. */
// struct fd_quic_qos_lru_map {
//   ulong       key; /* conn_id */
//   uint        hash;
//   fd_list_t * list;
// };
// typedef struct fd_quic_qos_lru_map fd_quic_qos_lru_map_t;

// #define MAP_NAME fd_quic_qos_unpriv_conn_map
// #define MAP_T    fd_quic_qos_unpriv_conn_map_t
// #include "../../util/tmpl/fd_map_dynamic.c"

// struct fd_quic_qos_lru {
//   int                     lg_slot_cnt;
//   fd_list_t *             used_list;
//   fd_list_t *             free_list;
//   fd_quic_qos_lru_map_t * map;
// };
// typedef struct fd_quic_qos_lru fd_quic_qos_lru_t;

struct fd_quic_qos {
  fd_quic_qos_limits_t      limits;
  fd_stake_t *              stake;
  fd_rng_t *                rng;
  // fd_quic_qos_priv_conn_t * pq;
  fd_tcache_t *             lru;
  // fd_quic_qos_lru_t *       lru;
};
typedef struct fd_quic_qos fd_quic_qos_t;

// FD_PROTOTYPES_BEGIN

// /* Extract the ed25519 public key from an X509 cert */
// int
// fd_quic_qos_pubkey_from_cert( fd_stake_pubkey_t * pubkey, X509 * cert );

// ulong
// fd_quic_qos_lru_align( void );

// ulong
// fd_quic_qos_lru_footprint( int lg_slot_cnt );

// void *
// fd_quic_qos_lru_new( void * mem, int lg_slot_cnt );

// fd_quic_qos_lru_t *
// fd_quic_qos_lru_join( void * mem );

// /* Upserts to an LRU cache with eviction if the cache is full.
//    New connections get cached in the LRU map for O(1) subsequent update / remove. */
// fd_quic_qos_lru_t *
// fd_quic_qos_lru_upsert( fd_quic_qos_lru_t * lru, fd_quic_conn_t * conn );

// ulong
// fd_quic_qos_align( void );

// ulong
// fd_quic_qos_footprint( fd_quic_qos_limits_t * limits );

// void *
// fd_quic_qos_new( void * mem, fd_quic_qos_limits_t * limits );

// fd_quic_qos_t *
// fd_quic_qos_join( void * mem );

// /* Determine how many streams to allocate to this conn */
// void
// fd_quic_qos_conn_new( fd_quic_qos_t * qos, fd_quic_conn_t * conn );

// /* Determine which conn to evict */
// void
// fd_quic_qos_conn_evict( fd_quic_qos_t * qos, fd_quic_conn_t * conn );

// FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_quic_fd_quic_qos_h */
