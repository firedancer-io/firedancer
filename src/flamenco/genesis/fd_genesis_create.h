#ifndef HEADER_fd_src_flamenco_genesis_fd_genesis_create_h
#define HEADER_fd_src_flamenco_genesis_fd_genesis_create_h

/* fd_genesis_create.h is a tool for creating Solana genesis blobs.
   A genesis blob is used to bootstrap a Solana ledger. */

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

/* fd_genesis_create creates a 'genesis.bin' compatible genesis blob.
   (Bincode encoded fd_genesis_solana_t)  [buf,bufsz) it the output
   memory region into which the genesis blob will be written.  pod
   points to an fd_pod containing the genesis configuration parameters.
   (Refer to fd_genesis.c code for the pod layout, there are no docs.)

   Returns the number of bytes in the output memory region used on
   success.  On failure, returns 0UL and logs reason for error.

   Assumes that caller is attached to an fd_scratch with sufficient
   memory to buffer intermediate data (8192 + 128*n space, 2 frames).

   THIS METHOD IS NOT SAFE FOR PRODUCTION USE.
   It is intended for development only. */

ulong
fd_genesis_create( void *        buf,
                   ulong         bufsz,
                   uchar const * pod );

/* TODO Add method to estimate the scratch and genesis blob size given a pod */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_genesis_fd_genesis_create_h */
