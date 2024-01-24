#ifndef HEADER_fd_src_disco_keyguard_fd_keyguard_client_h
#define HEADER_fd_src_disco_keyguard_fd_keyguard_client_h

/* A simple blocking client to a remote signing server, based on a pair
   of (input, output) mcaches and data regions.

   For maximum security, the caller should ensure a few things before
   using,
   
    (a) The request mcache and data region are placed in a shared memory
        map that is accessible exclusively to the calling tile, and the
        keyguard tile.  The keyguard tile should map the memory as read
        only.

    (b) The response mcache and data region are placed in a shared
        memory map that is accessible exclusively to the calling tile,
        and the keyguard tile.  The calling tile should map the memory
        as read only.

    (c) No other data is placed in these shared memory maps, and no
        other tiles have access to them.

    (d) Each input/output mcache correspond to a single role, and the
        keyguard tile verifies that all incoming requests are
        specifically formatted for that role. */        

#include "../fd_disco_base.h"

#define FD_KEYGUARD_CLIENT_ALIGN (128UL)
#define FD_KEYGUARD_CLIENT_FOOTPRINT (128UL)

struct __attribute__((aligned(FD_KEYGUARD_CLIENT_ALIGN))) fd_keyguard_client {
  fd_frag_meta_t * request;
  ulong            request_seq;
  uchar          * request_data;

  fd_frag_meta_t * response;
  ulong            response_seq;
  uchar          * response_data;
};
typedef struct fd_keyguard_client fd_keyguard_client_t;

FD_PROTOTYPES_BEGIN

void *
fd_keyguard_client_new( void *           shmem,
                        fd_frag_meta_t * request_mcache,
                        uchar *          request_data,
                        fd_frag_meta_t * response_mcache,
                        uchar *          response_data );

static inline fd_keyguard_client_t *
fd_keyguard_client_join( void * shclient ) { return (fd_keyguard_client_t*)shclient; }

static inline void *
fd_keyguard_client_leave( fd_keyguard_client_t * client ) { return (void*)client; }

static inline void *
fd_keyguard_client_delete( void * shclient ) { return shclient; }

/* fd_keyguard_client_sign sends a remote signing request to the signing
    server, and blocks (spins) until the response is received.
    
    Signing is treated as infallible, and there are no error codes or
    results. If the remote signer is stuck or not running, this function
    will not timeout and instead hangs forever waiting for a response.
    This is currently by design.
    
    sign_data should be a pointer to a buffer, with length sign_data_len
    that will be signed.  The data should correspond to one of the
    roles described in fd_keyguard.h.  If the remote signing tile
    receives a malformed signing request, or one for a role that does
    not correspond to the role assigned to the receiving mcache, it
    will abort the whole program with a critical error.
    
    The response, a 64 byte signature, will be written into the signature
    buffer, which must be at least this size. */

void
fd_keyguard_client_sign( fd_keyguard_client_t * client,
                         uchar *                signature,
                         uchar const *          sign_data,
                         ulong                  sign_data_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_keyguard_fd_keyguard_client_h */
