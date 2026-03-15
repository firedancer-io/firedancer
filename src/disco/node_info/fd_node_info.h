#ifndef HEADER_fd_src_disco_node_info_fd_node_info_h
#define HEADER_fd_src_disco_node_info_fd_node_info_h

/* fd_node_info provides a shared topology object that holds
   validator-level information which cannot be represented as simple
   scalar metrics (e.g. 32-byte public keys and hashes).

   The replay tile is the sole writer.  The watch command and other
   consumers read it in a lock-free manner. */

#include "../../util/log/fd_log.h"

#define FD_NODE_INFO_ALIGN     (128UL)
#define FD_NODE_INFO_FOOTPRINT (128UL)

#define FD_NODE_INFO_MAGIC (0xf17eda2c4e490000UL) /* firedancer ni ver 0 */

struct __attribute__((aligned(FD_NODE_INFO_ALIGN))) fd_node_info_private {
  uchar identity_pubkey[ 32 ]; /* All-zeros until known */
  uchar genesis_hash[ 32 ];    /* All-zeros until known */

  ulong magic;                 /* ==FD_NODE_INFO_MAGIC */

  /* Padding to FD_NODE_INFO_ALIGN here */
};

typedef struct fd_node_info_private fd_node_info_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_node_info_align( void ) {
  return FD_NODE_INFO_ALIGN;
}

FD_FN_CONST static inline ulong
fd_node_info_footprint( void ) {
  return FD_NODE_INFO_FOOTPRINT;
}

static inline void *
fd_node_info_new( void * shmem ) {
  fd_node_info_t * ni = (fd_node_info_t *)shmem;

  if( FD_UNLIKELY( !ni ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_node_info_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_node_info_footprint();

  fd_memset( ni, 0, footprint );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ni->magic ) = FD_NODE_INFO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)ni;
}

static inline fd_node_info_t *
fd_node_info_join( void * shni ) {
  if( FD_UNLIKELY( !shni ) ) {
    FD_LOG_WARNING(( "NULL shni" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shni, fd_node_info_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shni" ));
    return NULL;
  }

  fd_node_info_t * ni = (fd_node_info_t *)shni;

  if( FD_UNLIKELY( ni->magic!=FD_NODE_INFO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ni;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_node_info_fd_node_info_h */
