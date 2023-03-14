#ifndef HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h
#define HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h

/* fd_secp256k1 provides APIs for secp256K1 signature computations. Currently this library wraps
   libsecp256k1. */

#include "../fd_ballet_base.h"

/* FD_SECP256K1_ERR_* gives a number of error codes used by fd_secp256k1
   APIs. */

#define FD_SECP256K1_SUCCESS    ( 0) /* Operation was succesful */
#define FD_SECP256K1_ERR_SIG    (-1) /* Operation failed because the signature was obviously invalid */

/* FD_SECP256K1_SIG_SZ: the size of an secp256k1 signature in bytes. */
#define FD_SECP256K1_SIG_SZ (32UL)

/* An secp256k1 signature. */
typedef uchar fd_secp256k1_sig_t[ FD_SECP256K1_SIG_SZ ];

FD_PROTOTYPES_BEGIN

/* fd_secp256k1_public_from_private computes the public_key corresponding
   to the given private key.

   public_key is assumed to point to the first byte of a 64-byte memory
   region which will hold the public key on return.

   private_key assumed to point to first byte of a 32-byte memory region
   private key for which the public key is desired.

   sha is a handle of a local join to a sha256 calculator.

   Does no input argument checking.  The caller takes a write interest
   in public_key and a read interest in public_key for the
   duration the call.  Sanitizes the sha and stack to minimize risk of
   leaking private key info before returning.  Returns public_key. */

void *
fd_secp256k1_public_from_private( void *        public_key,
                                  void const *  private_key );

/* fd_secp256k1_sign signs a message according to the SECP256K1 standard.

   sig is assumed to point to the first byte of a 64-byte memory region
   which will hold the signature on return.

   msg_hash is assumed to point to the first byte of a 32-byte memory region
   which holds the message hash to sign.

   public_key is assumed to point to first byte of a 64-byte memory
   region that holds the public key to use to sign this message.

   private_key is assumed to point to first byte of a 32-byte memory
   region that holds the private key to use to sign this message.

   Does no input argument checking.  Sanitizes the stack to
   minimize risk of leaking private key info after return.  The caller
   takes a write interest in sig and sha and a read interest in msg_hash,
   public_key and private_key for the duration the call.  Returns sig. */

void *
fd_secp256k1_sign( void *        sig,
                   void const *  msg_hash,
                   void const *  private_key );

/* fd_secp256k1_verify verifies message according to the SECP256K1 standard.

   msg_hash is assumed to point to the first byte of a 32-byte memory region
   which holds the message to verify.

   sig is assumed to point to the first byte of a 32-byte memory region
   which holds the signature of the message.

   public_key is assumed to point to first byte of a 64-byte memory
   region that holds the public key to use to verify this message.

   Does no input argument checking.  This function takes a write
   interest in sig and a read interest in msg_hash, public_key and
   private_key for the duration the call.  Sanitizes the sha and stack
   to minimize risk of leaking private key info after return.  Returns
   FD_SECP256K1_SUCCESS (0) if the message verified successfully or a
   FD_SECP256K1_ERR_* code indicating the failure reason otherwise. */

int
fd_secp256k1_verify( void const *  msg_hash,
                     void const *  sig,
                     void const *  public_key );

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

/* fd_secp256k1_strerror converts an FD_SECP256K1_SUCCESS / FD_SECP256K1_ERR_*
   code into a human readable cstr.  The lifetime of the returned
   pointer is infinite.  The returned pointer is always to a non-NULL
   cstr. */

FD_FN_CONST char const *
fd_secp256k1_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_secp256k1_fd_secp256k1_h */
