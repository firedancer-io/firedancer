#if FD_HAS_OPENSSL
#include "../../util/alloc/fd_alloc.h"

#include <openssl/ssl.h>

/* fd_openssl_tile provides utilities to use OpenSSL in a tile without
   breaking the sandbox.  To use, define OPENSSL_MEM_FUNCTION_CTX to a
   thread-local fd_alloc_t pointer and include fd_openssl_tile.c.  Then,
   in privileged_init, initialize the fd_alloc_t object and call
   openssl's CRYPTO_set_mem_functions with the functions crypto_malloc,
   crypto_realloc, and crypto_free.  The tile must include define a
   loose_footprint callback function to allocate extra memory in the
   tile's workspace. See fd_snapct_tile.c for reference. OpenSSL tries
   to read files and allocate memory and other dumb things on a thread
   local basis, so we need a special initializer process to make
   OpenSSL use our custom allocators before seccomp kicks in.

   OpenSSL allows us to specify custom memory allocation functions,
   which we want to point to an fd_alloc_t, but it does not let us use a
   context object.  Instead we stash it in this thread local, which is
   OK because the parent workspace exists for the duration of the SSL
   context, and the process only has one thread.

   Currently fd_alloc doesn't support realloc, so it's implemented on
   top of malloc and free, and then also it doesn't support getting the
   size of an allocation from the pointer, which we need for realloc, so
   we pad each alloc by 8 bytes and stuff the size into the first 8
   bytes. */

/* OPENSSL_MEM_FUNCTION_CTX is a thread local fd_alloc_t object that is
   created once per tile.  Each tile that wants to use openssl must
   instantiate and define OPENSSL_MEM_FUNCTION_CTX. */
#ifndef OPENSSL_MEM_FUNCTION_CTX
#error "OPENSSL_MEM_FUNCTION_CTX must be defined"
#endif

/* OPENSSL_ALLOC_ERROR_CALLBACK is an callback to handle malloc errors,
   usually due to lack of memory in the OPENSSL_MEM_FUNCTION_CTX.  The
   callback takes num, file, and line as parameters.  It is intended
   to be used for accumulating metrics. */

static void *
crypto_malloc( ulong        num,
               char const * file,
               int          line ) {
  (void)file;
  (void)line;
  void * result = fd_alloc_malloc( OPENSSL_MEM_FUNCTION_CTX, 8UL, num + 8UL );
  if( FD_UNLIKELY( !result ) ) {
#ifdef OPENSSL_ALLOC_ERROR_CALLBACK
    OPENSSL_ALLOC_ERROR_CALLBACK( num, file, line );
#endif
    return NULL;
  }
  *(ulong*)result = num;
  return (uchar*)result + 8UL;
}

static void
crypto_free( void *       addr,
             char const * file,
             int          line ) {
  (void)file;
  (void)line;

  if( FD_UNLIKELY( !addr ) ) return;
  fd_alloc_free( OPENSSL_MEM_FUNCTION_CTX, (uchar*)addr - 8UL );
}

static void *
crypto_realloc( void *       addr,
                ulong        num,
                char const * file,
                int          line ) {
  (void)file;
  (void)line;

  if( FD_UNLIKELY( !addr ) ) return crypto_malloc( num, file, line );
  if( FD_UNLIKELY( !num ) ) {
    crypto_free( addr, file, line );
    return NULL;
  }

  void * new = fd_alloc_malloc( OPENSSL_MEM_FUNCTION_CTX, 8UL, num + 8UL );
  if( FD_UNLIKELY( !new ) ) return NULL;

  ulong old_num = *(ulong*)( (uchar*)addr - 8UL );
  fd_memcpy( (uchar*)new + 8, (uchar*)addr, fd_ulong_min( old_num, num ) );
  fd_alloc_free( OPENSSL_MEM_FUNCTION_CTX, (uchar*)addr - 8UL );
  *(ulong*)new = num;
  return (uchar*)new + 8UL;
}

#undef OPENSSL_MEM_FUNCTION_CTX

#endif /* FD_HAS_OPENSSL */
