#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_h

/* fd_ed25519 provides APIs for ED25519 signature computations */

#include "../sha512/fd_sha512.h"

/* FD_ED25519_ERR_* gives a number of error codes used by fd_ed25519
   APIs. */

#define FD_ED25519_SUCCESS    ( 0) /* Operation was succesful */
#define FD_ED25519_ERR_SIG    (-1) /* Operation failed because the signature was obviously invalid */
#define FD_ED25519_ERR_PUBKEY (-2) /* Operation failed because the public key was obviously invalid */
#define FD_ED25519_ERR_MSG    (-3) /* Operation failed because the message didn't match the signature for the given key */

/* FD_ED25519_SIG_SZ: the size of an Ed25519 signature in bytes. */
#define FD_ED25519_SIG_SZ (64UL)

/* An Ed25519 signature. */
typedef uchar fd_ed25519_sig_t[ FD_ED25519_SIG_SZ ];

FD_PROTOTYPES_BEGIN

/* fd_ed25519_public_from_private computes the public_key corresponding
   to the given private key.

   public_key is assumed to point to the first byte of a 32-byte memory
   region which will hold the public key on return.

   private_key assumed to point to first byte of a 32-byte memory region
   private key for which the public key is desired.

   sha is a handle of a local join to a sha512 calculator.

   Does no input argument checking.  The caller takes a write interest
   in public_key and sha and a read interest in public_key for the
   duration the call.  Sanitizes the sha and stack to minimize risk of
   leaking private key info before returning.  Returns public_key. */

void *
fd_ed25519_public_from_private( void *        public_key,
                                void const *  private_key,
                                fd_sha512_t * sha );

/* fd_ed25519_sign signs a message according to the ED25519 standard.

   sig is assumed to point to the first byte of a 64-byte memory region
   which will hold the signature on return.

   msg is assumed to point to the first byte of a sz byte memory region
   which holds the message to sign (sz==0 fine, msg==NULL fine if
   sz==0).

   public_key is assumed to point to first byte of a 32-byte memory
   region that holds the public key to use to sign this message.

   private_key is assumed to point to first byte of a 32-byte memory
   region that holds the private key to use to sign this message.

   sha is a handle of a local join to a sha512 calculator.

   Does no input argument checking.  Sanitizes the sha and stack to
   minimize risk of leaking private key info after return.  The caller
   takes a write interest in sig and sha and a read interest in msg,
   public_key and private_key for the duration the call.  Returns sig. */

void *
fd_ed25519_sign( void *        sig,
                 void const *  msg,
                 ulong         sz,
                 void const *  public_key,
                 void const *  private_key,
                 fd_sha512_t * sha );

/* fd_ed25519_verify verifies message according to the ED25519 standard.

   msg is assumed to point to the first byte of a sz byte memory region
   which holds the message to verify (sz==0 fine, msg==NULL fine if
   sz==0).

   sig is assumed to point to the first byte of a 64 byte memory region
   which holds the signature of the message.

   public_key is assumed to point to first byte of a 32-byte memory
   region that holds the public key to use to verify this message.

   sha is a handle of a local join to a sha512 calculator.

   Does no input argument checking.  This function takes a write
   interest in sig and sha and a read interest in msg, public_key and
   private_key for the duration the call.  Sanitizes the sha and stack
   to minimize risk of leaking private key info after return.  Returns
   FD_ED25519_SUCCESS (0) if the message verified successfully or a
   FD_ED25519_ERR_* code indicating the failure reason otherwise. */

int
fd_ed25519_verify( void const *  msg,
                   ulong         sz,
                   void const *  sig,
                   void const *  public_key,
                   fd_sha512_t * sha );

/* fd_ed25519_strerror converts an FD_ED25519_SUCCESS / FD_ED25519_ERR_*
   code into a human readable cstr.  The lifetime of the returned
   pointer is infinite.  The returned pointer is always to a non-NULL
   cstr. */

FD_FN_CONST char const *
fd_ed25519_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ed25519_h */
