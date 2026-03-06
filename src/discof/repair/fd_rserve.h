#ifndef HEADER_fd_src_discof_repair_fd_rserve_h
#define HEADER_fd_src_discof_repair_fd_rserve_h

#include "../../flamenco/types/fd_types_custom.h"

/* Repair server. */

/* TODO: We want to consider not using a ping-cache, and instead rely on
   the existing set of "good" nodes we'd need to know about from Gossip.
   A ping-cache is a simple solution for the time being. */

/* Ping cache TTL in nanoseconds (1280 seconds). */
#define FD_RSERVE_PING_CACHE_TTL_NS (1280UL * 1000000000UL)
/* Token rotation period in nanoseconds (640 seconds, half of TTL). */
#define FD_RSERVE_TOKEN_ROTATE_NS   (640UL * 1000000000UL)

typedef struct {
  fd_pubkey_t addr;      /* The public key of the validator which sent the ping. */
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
#define MAP_KEY_T                          fd_pubkey_t
#define MAP_KEY                            addr
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0)->key,(k1)->key,sizeof(fd_pubkey_t)))
#define MAP_KEY_HASH(key,seed)             fd_ulong_hash( fd_ulong_load_8( (key)->uc ) ^ (seed) )
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

  /* Ping tokens to send in responses. We maintain two tokens so that
     a pong arriving shortly after a rotation is still accepted. */
  uchar token_cur [ 32 ];
  uchar token_prev[ 32 ];
  ulong token_idx;
  ulong last_rotate_ts;
  ulong seed;
} fd_rserve_t;

FD_FN_CONST static inline ulong
fd_rserve_align( void ) {
  return alignof(fd_rserve_t);
}

ulong
fd_rserve_footprint( ulong ping_cache_entries );

void *
fd_rserve_new( void * shmem,
               ulong  ping_cache_entries,
               ulong  seed );

fd_rserve_t *
fd_rserve_join( void * shrserve );

void *
fd_rserve_leave( fd_rserve_t const * rserve );

void *
fd_rserve_delete( void * rserve );

/* fd_rserve_pong_token_verify checks whether the pong hash matches
   either the current or previous token.  Returns 1 if valid, 0 if
   not.  pong_hash is the 32-byte hash field from the pong message. */
int
fd_rserve_pong_token_verify( fd_rserve_t const * rserve,
                             uchar const       * pong_hash );

static void
fd_rserve_derive_token( uchar token[ 32 ],
                        ulong seed,
                        ulong idx ) {
  /* The first 16 bytes are the "SOLANA_PING_PONG" domain prefix.
     This is required by the keyguard signing tile, which validates
     that any payload signed with FD_KEYGUARD_SIGN_TYPE_ED25519 for
     the rserve role starts with this prefix.  The remaining 16
     bytes are derived pseudo-randomly. */
  memcpy( token, "SOLANA_PING_PONG", 16UL );
  for( ulong i=0UL; i<2UL; i++ ) {
    ulong v = fd_ulong_hash( seed ^ fd_ulong_hash( idx*2UL + i ) );
    FD_STORE( ulong, token + 16UL + i*8UL, v );
  }
}

#endif /* HEADER_fd_src_discof_repair_fd_rserve_h */
