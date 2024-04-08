#ifndef HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h
#define HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h

/* fd_secp256k1 provides APIs for secp256K1 signature computations. Currently this library wraps
   libsecp256k1. */

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

/* fd_secp256k1_recover recovers a public key from a recoverable SECP256K1 signature.

   msg_hash is assumed to point to the first byte of a 32-byte memory region
   which holds the message to verify.

   sig is assumed to point to the first byte of a 64-byte memory region
   which holds the recoverable signature of the message.

   public_key is assumed to point to first byte of a 64-byte memory
   region that will hold public key recovered from the signature.

   recovery_id is the recovery id number used in the signing process.

   Does no input argument checking.  This function takes a write
   interest in public_key and a read interest in msg_hash, public_key and
   private_key for the duration the call.  Returns public_key on success and
   NULL on failure. */

void *
fd_secp256k1_recover( void *       public_key,
                      void const * msg_hash,
                      void const * sig,
                      int          recovery_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h */
