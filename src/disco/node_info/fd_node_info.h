#ifndef HEADER_fd_src_disco_node_info_fd_node_info_h
#define HEADER_fd_src_disco_node_info_fd_node_info_h

/* fd_node_info provides a shared topology object that holds
   validator-level information which cannot be represented as simple
   scalar metrics (e.g. 32-byte public keys and hashes).

   The replay tile is the sole writer.  The watch command and other
   consumers read it in a lock-free manner. */

#include "../../util/log/fd_log.h"
#include "../../flamenco/types/fd_types_custom.h"
#if FD_HAS_ATOMIC
#include <stdatomic.h>
#endif

#define FD_NODE_INFO_MAGIC (0xf17eda2c4e490000UL) /* firedancer ni ver 0 */

struct fd_node_info {
  /* fields are zero until known */
  fd_pubkey_t vote_account;
  fd_pubkey_t identity;
  fd_hash_t   genesis_hash;
};

typedef struct fd_node_info fd_node_info_t;

struct fd_node_info_box {
  ulong        magic;     /* ==FD_NODE_INFO_MAGIC */
  _Atomic uint seq_lock;  /* lsb==1 implies active write */

  fd_node_info_t info;
};

typedef struct fd_node_info_box fd_node_info_box_t;

FD_PROTOTYPES_BEGIN

static inline void *
fd_node_info_box_new( void * shmem ) {
  fd_node_info_box_t * ni = (fd_node_info_box_t *)shmem;
  if( FD_UNLIKELY( !ni ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  fd_memset( ni, 0, sizeof(fd_node_info_box_t) );
  FD_VOLATILE( ni->magic ) = FD_NODE_INFO_MAGIC;
  return (void *)ni;
}

static inline fd_node_info_box_t *
fd_node_info_box_join( void * shni ) {
  if( FD_UNLIKELY( !shni ) ) {
    FD_LOG_WARNING(( "NULL shni" ));
    return NULL;
  }
  fd_node_info_box_t * ni = (fd_node_info_box_t *)shni;
  if( FD_UNLIKELY( ni->magic!=FD_NODE_INFO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return ni;
}

#if FD_HAS_ATOMIC

/* fd_node_info_read does an atomic read of a shared fd_node_info_t. */

static inline fd_node_info_t *
fd_node_info_read( fd_node_info_t *           dst,
                   fd_node_info_box_t const * src ) {
  for(;;) {
    ulong lock0 = atomic_load_explicit( &src->seq_lock, memory_order_acquire );
    memcpy( dst, &src->info, sizeof(fd_node_info_t) );
    atomic_thread_fence( memory_order_acquire );
    ulong lock1 = atomic_load_explicit( &src->seq_lock, memory_order_relaxed );
    if( FD_LIKELY( lock0==lock1 && !(lock0 & 1UL) ) ) break;
    FD_SPIN_PAUSE();
  }
  return dst;
}

/* fd_node_info_write_{begin,end} are used to gain exclusive access to a
   node_info for writes. */

static inline void
fd_node_info_write_begin( fd_node_info_box_t * dst ) {
  for(;;) {
    uint lock = atomic_load_explicit( &dst->seq_lock, memory_order_relaxed );
    if( FD_LIKELY( !(lock & 1UL) &&
        atomic_compare_exchange_weak_explicit( &dst->seq_lock, &lock, lock+1UL,
                                               memory_order_acquire, memory_order_relaxed ) ) ) {
      break;
    }
    FD_SPIN_PAUSE();
  }
}

static inline void
fd_node_info_write_end( fd_node_info_box_t * dst ) {
  atomic_fetch_add_explicit( &dst->seq_lock, 1UL, memory_order_release );
}

#endif /* FD_HAS_ATOMIC */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_node_info_fd_node_info_h */
