#ifndef HEADER_fd_src_tango_quic_fd_quic_qos_h
#define HEADER_fd_src_tango_quic_fd_quic_qos_h

#include "../../ballet/txn/fd_txn.h"
#include "../../util/fd_util.h"
#include "../../util/fd_util_base.h"
#include "../lru/fd_lru.h"
#include "../stake/fd_stake.h"
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
  ulong lru_depth;       /* the lg max # of "unprioritzed" conns. LRU eviction. */
  int   cnt_lg_slot_cnt; /* the lg max # of origins (pubkey or IpV4) we track conn cnts. */
  ulong cnt_max_conns;   /* the max # of conns allowed per conn origin key. */
};
typedef struct fd_quic_qos_limits fd_quic_qos_limits_t;

struct fd_quic_qos_pq {
  ulong             key; /* conn->local_conn_id */
  uint              hash;
  fd_quic_conn_t *  conn;
  fd_stake_pubkey_t pubkey;
};
typedef struct fd_quic_qos_pq fd_quic_qos_pq_t;
#define MAP_NAME fd_quic_qos_pq
#define MAP_T    fd_quic_qos_pq_t
#include "../../util/tmpl/fd_map_dynamic.c"

union fd_quic_qos_cnt_key {
  fd_stake_pubkey_t pubkey;
  uint              ip4_addr;
};
typedef union fd_quic_qos_cnt_key fd_quic_qos_cnt_key_t;
static fd_quic_qos_cnt_key_t      cnt_key_null = { 0 };

struct fd_quic_qos_cnt {
  fd_quic_qos_cnt_key_t key;
  uint                  hash;
  ulong                 count;
};
typedef struct fd_quic_qos_cnt fd_quic_qos_cnt_t;
#define MAP_NAME                fd_quic_qos_cnt
#define MAP_T                   fd_quic_qos_cnt_t
#define MAP_KEY_T               fd_quic_qos_cnt_key_t
#define MAP_KEY_NULL            cnt_key_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &cnt_key_null, sizeof( fd_quic_qos_cnt_key_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( &k0 ), ( &k1 ), sizeof( fd_quic_qos_cnt_key_t ) ) )
#define MAP_KEY_EQUAL_IS_SLOW   1
#define MAP_KEY_HASH( key )     ( (uint)( fd_hash( 0UL, &key, sizeof( fd_quic_qos_cnt_key_t ) ) ) )
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_quic_qos {
  fd_quic_qos_limits_t limits;
  fd_stake_t *         stake;
  fd_rng_t *           rng;
  /* priority queue for "prioritized traffic". eviction is done by removing the minimum element of a
   * random lg(n) sample (vs. global minimum). connections in the pq will _probably_ have stake, but
   * it is not a strict requirement. */
  fd_quic_qos_pq_t * pq;
  /* LRU cache for "unprioritized traffic". connections in the lru will probably not have stake, but
   * it is not strictly the case: a staked connection will end up in the LRU if it doesn't meet the
   * threshold to evict from the pq. */
  fd_lru_t * lru;
  /* counter of connections for a given pubkey / IPv4 address */
  fd_quic_qos_cnt_t * cnt;
};
typedef struct fd_quic_qos fd_quic_qos_t;

FD_PROTOTYPES_BEGIN

ulong
fd_quic_qos_align( void );

ulong
fd_quic_qos_footprint( fd_quic_qos_limits_t * limits );

void *
fd_quic_qos_new( void * mem, fd_quic_qos_limits_t * limits );

fd_quic_qos_t *
fd_quic_qos_join( void * mem );

/* fd_quic_qos_conn_new attempts to place conn in the PQ or LRU, as well as how many lifetime QUIC
 streams (client-initiated, unidirectional) to allocate to this conn. It is designed to work with
 fd_quic's conn_new callback */
void
fd_quic_qos_conn_new( fd_quic_qos_t *     qos,
                      fd_stake_t *        stake,
                      fd_rng_t *          rng,
                      fd_quic_conn_t *    conn,
                      fd_stake_pubkey_t * pubkey );

/* fd_quic_qos_pq_upsert upserts conn into the pq map.

   - If there is space in the map, it inserts conn and returns NULL.
   - If there is no space in the map, it will look for an eviction candidate by randomly sampling
   lg(n) conns, and evicting the lowest stake one that is also less than the incoming conn's stake.
     - If it finds a candidate, it will evict and return candidate, and insert the incoming conn.
     - Otherwise, it will return the incoming conn itself. */
fd_quic_conn_t *
fd_quic_qos_pq_conn_upsert( fd_quic_qos_t *     qos,
                            fd_stake_t *        stake,
                            fd_rng_t *          rng,
                            fd_quic_conn_t *    conn,
                            fd_stake_pubkey_t * pubkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_quic_fd_quic_qos_h */
