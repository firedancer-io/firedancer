#ifndef HEADER_fd_src_discof_repair_fd_rserve_h
#define HEADER_fd_src_discof_repair_fd_rserve_h

#include "../../flamenco/types/fd_types_custom.h"

/* Repair server. */

/* TODO: We want to consider not using a ping-cache, and instead rely on
   the existing set of "good" nodes we'd need to know about from Gossip.
   A ping-cache is a simple solution for the time being. */

/* In seconds for now, TODO: change */
#define FD_RSERVE_PING_CACHE_TTL 1280UL

typedef struct {
  fd_pubkey_t addr;      /* The public key of the validator which sent the ping. */
  uint        hash;      /* reserved for use by fd_map */
  ulong       timestamp; /* The time at which the ping was received. Stored in nanoseconds. */
} ping_cache_entry_t;

#define MAP_NAME               ping_cache
#define MAP_T                  ping_cache_entry_t
#define MAP_KEY                addr
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(k,seed)   ((uint)fd_ulong_hash( fd_ulong_load_8( (k).uc ) ^ seed ))
#include "../../util/tmpl/fd_map_dynamic.c"

typedef struct {
  ping_cache_entry_t * ping_cache;
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

#endif /* HEADER_fd_src_discof_repair_fd_rserve_h */
