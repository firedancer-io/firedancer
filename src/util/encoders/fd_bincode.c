
#include "fd_bincode.h"

void fd_decode_varint( ulong* self, void const** data, void const* dataend ) {
  const uchar *ptr = (const uchar *) *data;

  /* Determine how many bytes were used to encode the varint.
     The MSB of each byte indicates if more bytes have been used to encode the varint, so we consume
     until the MSB is 0 or we reach the maximum allowed number of bytes (to avoid an infinite loop).   
   */
  ulong bytes = 1;
  const ulong max_bytes = 8;
  while ( ( ( ptr[bytes - 1] & 0x80 ) != 0 ) && bytes < max_bytes ) {
    bytes = bytes + 1;
  }

  /* Use the lowest 7 bits of each byte */
  *self = 0;
  ulong shift = 0;
  for ( ulong i = 0; i < bytes; i++ ) {
    if (FD_UNLIKELY((void const *) (ptr + i) > dataend )) {
      FD_LOG_ERR(( "buffer underflow"));
    }

    *self |= (ulong)(( ptr[i] & 0x7F ) << shift);
    shift += 7;
  }

  *data = ptr + bytes;
}
