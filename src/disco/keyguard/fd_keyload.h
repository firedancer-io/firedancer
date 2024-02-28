#ifndef HEADER_fd_src_disco_keyguard_fd_keyload_h
#define HEADER_fd_src_disco_keyguard_fd_keyload_h

#include "../fd_disco_base.h"

/* fd_keyload_load() reads the key file from disk and
   stores the parsed contents in a specially mapped page in memory that
   will not appear in core dumps, will not be paged out to disk, is
   readonly, and is protected by guard pages that cannot be accessed.
   key_path must point to the first letter in a nul-terminated cstr that
   is the path on disk of the key file.  The key file must exist, be
   readable, and have the form of a Solana keypair (64 element JSON
   array of bytes).  If public_key_only is non-zero, zeros out the
   private part of the key and returns a pointer to the first byte (of
   32) of the public part of the key in binary format.  If
   public_key_only is zero, returns a pointer to the first byte (of 64)
   of the key in binary format.  Terminates the process by calling
   FD_LOG_ERR with details on any error, so from the perspective of the
   caller, it cannot fail. */

uchar const *
fd_keyload_load( char const * key_path, int public_key_only );

#endif /* HEADER_fd_src_disco_keyguard_fd_keyload_h */
