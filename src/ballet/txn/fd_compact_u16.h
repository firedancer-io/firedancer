#ifndef HEADER_fd_src_ballet_txn_fd_compact_u16_h
#define HEADER_fd_src_ballet_txn_fd_compact_u16_h

/* This file declares some utility methods for decoding compact-u16, a variable
   length encoding format for unsigned 16 bit numbers that Solana transactions
   use in the wireline format.
   The format is documented at
   https://docs.solana.com/developing/programming-model/transactions#compact-u16-format
   but briefly:
     If the 16 bit number has (big endian bits) ponmlkji hgfedcba
     [  0x00,    0x80)   (implies [h..p] = 0) ->  0gfedcba                      (1 byte )
     [  0x80,  0x4000)   (implies [o..p] = 0) ->  1gfedcba 0nmlkjih             (2 bytes)
     [0x4000, 0x10000)                        ->  1gfedcba 1nmlkjih 000000po    (3 bytes)
   Numbers must be encoded with the minimal number of bytes possible.

   This encoding format is filled with sadness, some of which this API
   reflects.  To limit the sadness, this header is for internal use in fd_txn
   and not exported more widely. */

#include "../fd_ballet_base.h"


FD_PROTOTYPES_BEGIN
/* fd_cu16_dec_fixed: Reads a compact-u16 whose width is known.  High
   performance API that does no error checking, and as such, it's designed to
   be used with fd_cu16_dec_sz, which performs all necessary valiation to
   ensure this is safe.  buf points to the first byte of the encoded value.
   sz in {1, 2, 3}. Reads exactly sz bytes. */
static inline ushort
fd_cu16_dec_fixed( uchar const * buf,
                   ulong         sz ) {
  /* Branch-free hardware friendly format that is slower on a CPU. If you
     switch to this version, be sure to update the documentation to note that
     it reads more than sz bytes. */
  /*
     ulong w   = (ulong)*(uint *)buf;
     ulong b0  = (w & 0x00007FUL);
     ulong b1  = (w & 0x007F00UL)>>1UL;
     ulong b2  = (w & 0xFF0000UL)>>2UL;
     ulong m0  = (ulong)(((long)(1UL-sz))>>63); *//* Maps [0,1] to 0; [2,3] to 0xFF..FF */
  /* ulong m01 = (ulong)(((long)(2UL-sz))>>63); *//* Maps [0,2] to 0; [3,3] to 0xFF..FF */
  /* return (ushort)((b0) | (b1 & m0) | (b2 & m01)); */

  /* This version is actually substantially faster */
#if FD_TXN_HANDHOLDING
  FD_TEST( (1<=sz) & (sz<=3) )
#endif
  if( FD_LIKELY( sz==1 ) )
      return (ushort)buf[0];
  if( FD_LIKELY( sz==2 ) )
      return (ushort)((ulong)(buf[0]&0x7F) + (((ulong)buf[1])<<7));
  return (ushort)((ulong)(buf[0]&0x7F) + (((ulong)buf[1]&0x7F)<<7) + (((ulong)buf[2])<<14));
}

/*fd_cu16_dec_sz: Returns the number of bytes in the compact-u16.  Also
  validates that it is a legally-encoded compact-u16 and that it is stored in
  no more than bytes_avail bytes.  buf points to the first byte of the encoded
  value.  Result will be in {0, 1, 2, 3}, where 0 indicates validation failed
  (not enough bytes avail, illegal encoding, or number is larger than a u16).*/
static inline ulong
fd_cu16_dec_sz( uchar const * buf,
                ulong         bytes_avail ) {
  if( FD_LIKELY( bytes_avail>=1 && !(0x80UL & buf[0]) ) ) {
    return 1UL;
  }
  if( FD_LIKELY( bytes_avail>=2 && !(0x80UL & buf[1]) ) ) {
    if( FD_UNLIKELY( !buf[1] ) ) return 0UL; /* Detect non-minimal encoding */
    return 2UL;
  }
  if( FD_LIKELY( bytes_avail>=3 && !(0xFCUL & buf[2]) ) ) {
    if( FD_UNLIKELY( !buf[2] ) ) return 0UL; /* Detect non-minimal encoding */
    return 3UL;
  }
  return 0UL;
}

/* fd_cu16_dec: Reads a compact-u16.  buf points to the first byte of the
   encoded value.  Validates that the compact-u16 is legally encoded, and
   returns 0 to indicate that validation failed.  If the compact-u16 is valid,
   the decoded value is stored in the location pointed to by result_out.  On
   success, returns the length of the encoded compact-u16. */
static inline ulong
fd_cu16_dec( uchar const * buf,
             ulong         bytes_avail,
             ushort *      result_out ) {
  ulong sz = fd_cu16_dec_sz( buf, bytes_avail );
  if( sz ) *result_out = fd_cu16_dec_fixed( buf, sz );
  return sz;
}

static inline uint
fd_cu16_enc( ushort val, uchar * out ) {
  ulong v = (ulong)val;
  ulong byte0 = (v    )&0x7FUL;
  ulong byte1 = (v>> 7)&0x7FUL;
  ulong byte2 = (v>>14);
  int needs_byte1 = (v>0x007FUL);
  int needs_byte2 = (v>0x3FFFUL);
  fd_uchar_store_if( 1,           out + 0, (uchar)(byte0 | ((ulong)needs_byte1<<7)) );
  fd_uchar_store_if( needs_byte1, out + 1, (uchar)(byte1 | ((ulong)needs_byte2<<7)) );
  fd_uchar_store_if( needs_byte2, out + 2, (uchar)(byte2                          ) );
  return (uint)(1+needs_byte1+needs_byte2);
}

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_ballet_txn_fd_compact_u16_h */
