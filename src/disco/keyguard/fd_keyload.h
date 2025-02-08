#ifndef HEADER_fd_src_disco_keyguard_fd_keyload_h
#define HEADER_fd_src_disco_keyguard_fd_keyload_h

#include "../fd_disco_base.h"

/* fd_keyload_read() reads a JSON encoded keypair from the provided file
   descriptor.  The key_path is not opened or read from, it is only used
   to output diagnostic error messages if reading the key fails.

   The keypair provided must be a full page (4096) bytes, not just 64
   bytes, as additional metadata will be temporarily stored in it while
   reading and parsing the key.

   If the key data from the file descriptor is not parsable, or any IO
   or other error is encountered while reading it, the process will be
   terminated with an error message. */

uchar * FD_FN_SENSITIVE
fd_keyload_read( int          key_fd,
                 char const * key_path,
                 uchar *      keypair );

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

uchar * FD_FN_SENSITIVE
fd_keyload_load( char const * key_path,
                 int          public_key_only );

/* fd_keyload_unload() unloads a key from shared memory that was loaded
   with fd_keyload_load.  The argument public_key_only must match the
   one provided when the key was loaded.  The key should not be accessed
   once this function returns and the memory is no longer valid. */

void FD_FN_SENSITIVE
fd_keyload_unload( uchar const * key,
                   int           public_key_only );

/* fd_keyload_alloc_protected_pages allocates `page_cnt` regular (4 kB)
   pages of memory protected by `guard_page_cnt` pages of unreadable and
   unwritable memory on each side.  Additionally the OS is configured so
   that the page_cnt pages in the middle will not be paged out to disk
   in a swap file, appear in core dumps, and will be wiped on fork so it
   is not readable by any child process forked off from this process.
   Terminates the calling process with FD_LOG_ERR with details if the
   operation fails.  Returns a pointer to the first byte of the
   protected memory.  Precisely, if ptr is the returned pointer, then
   ptr[i] for i in [0, 4096*page_cnt) is readable and writable, but
   ptr[i] for i in [-4096*guard_page_cnt, 0) U [4096*page_cnt,
   4096*(page_cnt+guard_page_cnt) ) will cause a SIGSEGV.  For current
   use cases, there's no use in freeing the pages allocated by this
   function, so no free function is provided. */

void * FD_FN_SENSITIVE
fd_keyload_alloc_protected_pages( ulong page_cnt,
                                  ulong guard_page_cnt );

#endif /* HEADER_fd_src_disco_keyguard_fd_keyload_h */
