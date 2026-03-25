#ifndef HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h
#define HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h

/* fd_secp256k1 provides APIs for secp256K1 signature computations. */

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

/* fd_secp256k1_recover recovers a public key from a recoverable SECP256K1 signature.

   public_key will hold the public key recovered from the signature.

   msg_hash holds the message to verify.

   sig holds the recoverable signature of the message.

   recovery_id is the recovery id number used in the signing process.

   Does no input argument checking.  This function takes a write
   interest in public_key and a read interest in msg_hash and sig
   for the duration the call.  Returns public_key on success and
   NULL on failure. */

uchar *
fd_secp256k1_recover( uchar        public_key[64],
                      uchar const  msg_hash[32],
                      uchar const  sig[64],
                      int          recovery_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h */
