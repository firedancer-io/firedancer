#ifndef HEADER_fd_src_disco_keyguard_fd_remote_signer_h
#define HEADER_fd_src_disco_keyguard_fd_remote_signer_h

#include "../fd_disco_base.h"

#define FD_REMOTE_SIGNER_ALIGN (128UL)
#define FD_REMOTE_SIGNER_FOOTPRINT (128UL)

struct __attribute__((aligned(FD_REMOTE_SIGNER_ALIGN))) fd_remote_signer {
  fd_frag_meta_t * request;
  ulong            request_seq;
  uchar          * request_data;

  fd_frag_meta_t * response;
  ulong            response_seq;
  uchar          * response_data;
};
typedef struct fd_remote_signer fd_remote_signer_t;

FD_PROTOTYPES_BEGIN

void *
fd_remote_signer_new( void *           shmem,
                      fd_frag_meta_t * request_mcache,
                      uchar *          request_data,
                      fd_frag_meta_t * response_mcache,
                      uchar *          response_data );

static inline fd_remote_signer_t *
fd_remote_signer_join( void * shsign ) { return (fd_remote_signer_t*)shsign; }

static inline void *
fd_remote_signer_leave( fd_remote_signer_t * signer ) { return (void*)signer; }

static inline void *
fd_remote_signer_delete( void * shsign ) { return shsign; }

void
fd_remote_signer_sign_leader( fd_remote_signer_t * signer,
                              uchar *              signature,
                              uchar const *        merkle_root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_keyguard_fd_remote_signer_h */
