#if FD_HAS_OPENSSL

#ifndef HEADER_fd_src_waltz_openssl_fd_openssl_tile_h
#define HEADER_fd_src_waltz_openssl_fd_openssl_tile_h

#include <openssl/ssl.h>

#include "../../util/alloc/fd_alloc.h"

/* Each tile that uses OpenSSL must initialize the thread-local
   fd_ossl_alloc alloc object so that openSSL can allocate out of the
   tile's wksp.  The tile must also define a loose_footprint callback
   function to allocate extra memory in the tile's workspace. */
extern FD_TL fd_alloc_t * fd_ossl_alloc;

/* Stores the number of ssl alloc errors per tile.  Can be optionally
   written back to a tile metric in METRICS_WRITE. */
extern FD_TL ulong        fd_ossl_alloc_errors;

/* fd_ossl_tile_init is called in a tile's privileged init to
   initialize OpenSSL. See fd_snapld_tile.c for reference. */
void
fd_ossl_tile_init( fd_alloc_t * alloc );

/* fd_ossl_load_certs manually loads certificates into an SSL_CTX
   object.  This should be called right after calling SSL_CTX_new in
   privileged init in a tile. */
void
fd_ossl_load_certs( SSL_CTX * ssl_ctx );

#endif /* HEADER_fd_src_waltz_openssl_fd_openssl_tile_h */

#endif /* FD_HAS_OPENSSL */
