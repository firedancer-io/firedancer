#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_codec_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_codec_h

/* fd_solfuzz_codec.h provides Protobuf encoding / decoding helper
   functions for all harnesses. */

#include "../../../ballet/nanopb/pb_encode.h"
#include "../../../ballet/nanopb/pb_decode.h"

FD_PROTOTYPES_BEGIN

static FD_FN_UNUSED void *
sol_compat_decode_lenient( void *               decoded,
                           uchar const *        in,
                           ulong                in_sz,
                           pb_msgdesc_t const * decode_type ) {
  pb_istream_t istream = pb_istream_from_buffer( in, in_sz );
  int decode_ok = pb_decode_ex( &istream, decode_type, decoded, PB_DECODE_NOINIT );
  if( !decode_ok ) {
    pb_release( decode_type, decoded );
    return NULL;
  }
  return decoded;
}

static FD_FN_UNUSED void *
sol_compat_decode( void *               decoded,
                   uchar const *        in,
                   ulong                in_sz,
                   pb_msgdesc_t const * decode_type ) {
  pb_istream_t istream = pb_istream_from_buffer( in, in_sz );
  int decode_ok = pb_decode_ex( &istream, decode_type, decoded, PB_DECODE_NOINIT );
  if( !decode_ok ) {
    pb_release( decode_type, decoded );
    return NULL;
  }
  ulong size;
  if( FD_UNLIKELY( !pb_get_encoded_size( &size, decode_type, decoded ) ) ) {
    pb_release( decode_type, decoded );
    return NULL;
  }
  if( FD_UNLIKELY( size != in_sz ) ) {
    pb_release( decode_type, decoded );
    return NULL;
  }
  return decoded;
}

static FD_FN_UNUSED void const *
sol_compat_encode( uchar *              out,
                   ulong *              out_sz,
                   void const *         to_encode,
                   pb_msgdesc_t const * encode_type ) {
  pb_ostream_t ostream = pb_ostream_from_buffer( out, *out_sz );
  int encode_ok = pb_encode( &ostream, encode_type, to_encode );
  if( !encode_ok ) {
    return NULL;
  }
  *out_sz = ostream.bytes_written;
  return to_encode;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_codec_h */
