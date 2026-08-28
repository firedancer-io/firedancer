#ifndef HEADER_fd_flamenco_accdb_fd_zle_h
#define HEADER_fd_flamenco_accdb_fd_zle_h

/* fd_zle.h is a fast compression algorithm based on zero run length
   coding.

   fd_zle was designed for and tuned on compressing Solana mainnet
   account data (individually), and is about an order of magnitude
   faster than LZ4 and Zstandard at this task, without compromising on
   compression ratio. */

#include "../../util/fd_util_base.h"

#define FD_ZLE_OVERHEAD (8UL)
#define FD_ZLE_COMPRESS_BOUND( in_sz ) (FD_ZLE_OVERHEAD + (in_sz))

#define FD_ZLE_ERR_SPACE   (-1L) /* out of buffer space */
#define FD_ZLE_ERR_CORRUPT (-2L) /* malformed compressed data */

FD_PROTOTYPES_BEGIN

/* fd_zle_compress compresses data_sz bytes at data.  Writes up to
   FD_ZLE_COMPRESS_BOUND( data_sz ) compressed bytes to comp.  Returns
   the number of compressed bytes written. */

ulong
fd_zle_compress( void *       FD_RESTRICT comp,
                 void const * FD_RESTRICT data,
                 ulong                    data_sz );

/* fd_zle_decompress takes an fd_zle compressed blob at comp.  Writes up
   to data_sz decompressed bytes to data.  Returns the number of bytes
   decompressed (>=0) on success, or a negative FD_ZLE_ERR_* number on
   failure. */

long
fd_zle_decompress( void *       FD_RESTRICT data,
                   ulong                    data_sz,
                   void const * FD_RESTRICT comp,
                   ulong                    comp_sz );

/* fd_zle_strerror returns a static-lifetime cstr describing the error
   code returned by fd_zle_decompress(). */

char const *
fd_zle_strerror( long res );

FD_PROTOTYPES_END

#endif /* HEADER_fd_flamenco_accdb_fd_zle_h */
