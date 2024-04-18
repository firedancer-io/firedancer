#ifndef HEADER_fd_src_disco_keyguard_fd_keyload_h
#define HEADER_fd_src_disco_keyguard_fd_keyload_h

#include "../fd_disco_base.h"

/* fd_keyload_load() reads the key file from disk and stores the parsed
   contents in a specially mapped page in memory that will not appear in
   core dumps, will not be paged out to disk, is readonly, and is
   protected by guard pages that cannot be accessed.
   
   key_path must point to the first letter in a NUL-terminated cstr that
   is the path on disk of the key file.  The key file must exist, be
   readable, and have the form of a Solana keypair (64 element JSON
   array of bytes).  If public_key_only is non-zero, zeros out the
   private part of the key and returns a pointer to the first byte (of
   32) of the public part of the key in binary format.  If
   public_key_only is zero, returns a pointer to the first byte (of 64)
   of the key in binary format.
   
   If the key file is not found, is not parsable, or any IO or other
   error is encountered while reading it, the process will be terminated
   with an error message.

   The error messages assume that you are loading the identity key path
   that has been specified in the user configuration file of fdctl so
   that they are most helpful in production use.  This is a slight
   layering violation, and the error messages might not be correct if
   a different key is being loaded, or it is not being loaded for use
   in the production binary. */

uchar const * FD_FN_SENSITIVE
fd_keyload_load( char const * key_path,
                 int          public_key_only );

/* fd_keyload_unload() unloads a key from shared memory that was loaded
   with fd_keyload_load.  The argument public_key_only must match the
   one provided when the key was loaded.  The key should not be accessed
   once this function returns and the memory is no longer valid. */

void FD_FN_SENSITIVE
fd_keyload_unload( uchar const * key,
                   int           public_key_only );

#endif /* HEADER_fd_src_disco_keyguard_fd_keyload_h */
