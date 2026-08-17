#ifndef HEADER_fd_src_discof_repair_fd_rserve_h
#define HEADER_fd_src_discof_repair_fd_rserve_h

#include "../../flamenco/fd_flamenco_base.h"

/* Repair server. */

/* TODO: We want to consider not using a ping-cache, and instead rely on
   the existing set of "good" nodes we'd need to know about from Gossip.
   A ping-cache is a simple solution for the time being. */

/* Ping cache TTL in nanoseconds (1280 seconds). */
#define FD_RSERVE_PING_CACHE_TTL_NS (1280UL * 1000000000UL)
/* Token rotation period in nanoseconds (640 seconds, half of TTL). */
#define FD_RSERVE_TOKEN_ROTATE_NS   (640UL * 1000000000UL)


struct __attribute__((packed)) ping_cache_key {
  fd_pubkey_t pubkey; /* pubkey of the node which sent the ping */
  uint        ip4;    /* source ipv4 address of the pong */
  ushort      port;   /* source udp port of the pong */
};
typedef struct ping_cache_key ping_cache_key_t;

typedef struct {
  ping_cache_key_t key;  /* (pubkey, address) that completed a ping */
  ulong       next;      /* Pool free-list next. */
  struct {
    ulong prev;
    ulong next;
  } map;                 /* fd_map_chain prev/next. */
  struct {
    ulong prev;
    ulong next;
  } dlist;               /* LRU dlist prev/next. */
  ulong       timestamp; /* The time at which the pong was received. Stored in nanoseconds. */
} ping_cache_entry_t;

#define POOL_NAME  ping_pool
#define POOL_T     ping_cache_entry_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           ping_map
#define MAP_ELE_T                          ping_cache_entry_t
#define MAP_KEY_T                          ping_cache_key_t
#define MAP_KEY                            key
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0),(k1),sizeof(ping_cache_key_t)))
#define MAP_KEY_HASH(key,seed)             fd_ulong_hash( fd_hash( (seed), key->pubkey.uc, sizeof(fd_pubkey_t) ) ^ ((ulong)(key)->ip4) ^ (((ulong)(key)->port)<<32) ^ (seed) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  ping_dlist
#define DLIST_ELE_T ping_cache_entry_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

typedef struct {
  ping_cache_entry_t * ping_pool;
  ping_map_t         * ping_map;
  ping_dlist_t       * ping_dlist;

  uchar secret_master[ 32 ];
  uchar secret_cur   [ 32 ];
  uchar secret_prev  [ 32 ];
  ulong token_idx;
  ulong last_rotate_ts;

  ulong seed;
} fd_rserve_t;

FD_FN_CONST static inline ulong
fd_rserve_align( void ) {
  return 128UL;
}

ulong
fd_rserve_footprint( ulong ping_cache_entries );

void *
fd_rserve_new( void      * shmem,
               ulong       ping_cache_entries,
               ulong       seed,
               uchar const secret[ 32 ] );

fd_rserve_t *
fd_rserve_join( void * shrserve );

void *
fd_rserve_leave( fd_rserve_t const * rserve );

void *
fd_rserve_delete( void * rserve );

void
fd_rserve_ping_token( fd_rserve_t const * rserve,
                      uchar               token[ 32 ],
                      fd_pubkey_t const * from,
                      uint                ip4,
                      ushort              port );

int
fd_rserve_pong_token_verify( fd_rserve_t const * rserve,
                             uchar const       * pong_hash,
                             fd_pubkey_t const * from,
                             uint                ip4,
                             ushort              port );

void
fd_rserve_maybe_rotate( fd_rserve_t * rserve,
                        ulong         now_ns );

#endif /* HEADER_fd_src_discof_repair_fd_rserve_h */
