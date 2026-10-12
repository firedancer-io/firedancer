#ifndef HEADER_fd_src_flamenco_alpenglow_fd_footer_cache_h
#define HEADER_fd_src_flamenco_alpenglow_fd_footer_cache_h

/* fd_footer_cache is replay's footer verify cache, kept across footers:
   a memo of recent footer cert H(m)s keyed by the signing payload,
   evicting oldest first. */

#include "../../ballet/bls/fd_bls.h"

#define FD_FOOTER_CACHE_ALIGN   (64UL)
#define FD_FOOTER_CACHE_MAGIC   (0xf17eda2cef0c0000UL) /* firedancer footer cache ver 0 */

#define FD_FOOTER_CACHE_MSG_MAX (64UL)

struct fd_footer_cache;
typedef struct fd_footer_cache fd_footer_cache_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_footer_cache_align( void );

FD_FN_CONST ulong
fd_footer_cache_footprint( void );

void *
fd_footer_cache_new( void * shmem );

fd_footer_cache_t *
fd_footer_cache_join( void * shcache );

/* fd_footer_cache_hash_msg sets h to H(msg), from the cache if there,
   otherwise computed and inserted.  msg_sz must be in
   [1,FD_FOOTER_CACHE_MSG_MAX]. */

void
fd_footer_cache_hash_msg( fd_footer_cache_t * cache,
                          uchar const *       msg,
                          ulong               msg_sz,
                          blst_p2_affine *    h );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_alpenglow_fd_footer_cache_h */
