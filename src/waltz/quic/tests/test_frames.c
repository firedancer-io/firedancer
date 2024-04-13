#include "../fd_quic_common.h"
#include "../fd_quic_types.h"
#include "../templ/fd_quic_parse_util.h"

#include "../fd_quic_types.h"
#include "../fd_quic_proto.h"

/* define empty functions for handlers */
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                     \
          static ulong                                      \
          fd_quic_frame_handle_##NAME(                      \
                    void *                    context,      \
                    fd_quic_##NAME##_t *      data,         \
                    uchar const *             p,            \
                    ulong                     p_sz ) {      \
            (void)context; (void)data; (void)p; (void)p_sz; \
            return 0u;                                      \
          }
#include "../templ/fd_quic_dft.h"
#include "../templ/fd_quic_frames_templ.h"
#include "../templ/fd_quic_undefs.h"

uchar raw_crypto_frame[] =
"\x06\x00\x41\x79\x01\x00\x01\x75\x03\x03\x6f\x2d\xa1\x28\xdd\x7e"
"\xff\xa9\x8c\x1c\xe4\x84\x55\x04\xa2\xcc\xc6\x35\x46\xfa\xfa\xfa"
"\x47\xa3\xf7\xff\x2a\xaa\x7f\xa4\x28\x0b\x00\x00\x06\x13\x02\x13"
"\x01\x13\x03\x01\x00\x01\x46\x00\x33\x00\xa7\x00\xa5\x00\x17\x00"
"\x41\x04\x6d\x7d\xad\xed\xf2\x09\x94\x79\x7a\xe9\x3c\xce\x69\x55"
"\xc0\xca\x94\xd7\x0c\xbe\x06\xd3\x35\x2c\xfa\x09\xda\x7e\xd7\x8e"
"\xda\x0b\x99\xb4\x31\xba\x1e\x52\x9c\x9c\xaf\xc5\x16\xcb\x7d\xb5"
"\xf5\x14\x3f\xaf\x26\x3e\x0a\x0d\x85\x54\x9f\x64\x38\x75\x12\xe7"
"\x23\xad\x00\x1d\x00\x20\x0f\x3d\x20\xaa\x73\x05\xad\x27\x77\x35"
"\xa3\xd8\xe2\x34\xf4\xab\x55\x06\xb9\x1e\x3e\xaf\x5b\x6d\x48\x6b"
"\x6b\x16\xde\x4b\x50\x7a\x00\x1e\x00\x38\x16\xe8\xe2\x5d\x14\x8d"
"\x2c\x81\xc4\x42\xf7\x3e\x6e\x55\x6b\x94\xf3\x5e\x91\x5b\xcf\xe8"
"\x31\x21\x2b\xb5\xef\x50\x51\xca\xf0\xa8\x36\xe3\xd0\xf3\xfe\x3a"
"\xda\xab\x58\xc0\xca\x33\xb2\xd8\x99\x6f\xfc\x87\x92\x1c\xc6\xce"
"\x86\x2a\x00\x2b\x00\x03\x02\x03\x04\x00\x0d\x00\x0e\x00\x0c\x08"
"\x04\x04\x03\x04\x01\x02\x01\x08\x07\x08\x08\x00\x0a\x00\x08\x00"
"\x06\x00\x17\x00\x1d\x00\x1e\x00\x2d\x00\x02\x01\x01\x00\x00\x00"
"\x0e\x00\x0c\x00\x00\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x00"
"\x10\x00\x1d\x00\x1b\x02\x68\x33\x05\x68\x33\x2d\x33\x32\x05\x68"
"\x33\x2d\x33\x31\x05\x68\x33\x2d\x33\x30\x05\x68\x33\x2d\x32\x39"
"\x00\x39\x00\x39\x01\x04\x80\x00\xea\x60\x04\x04\x80\x10\x00\x00"
"\x05\x04\x80\x10\x00\x00\x06\x04\x80\x10\x00\x00\x07\x04\x80\x10"
"\x00\x00\x08\x02\x40\x80\x09\x02\x40\x80\x0a\x01\x03\x0b\x01\x19"
"\x0e\x01\x08\x0f\x08\xec\x73\x1b\x41\xa0\xd5\xc6\xfe";


void
test_crypto_frame( void ) {
  fd_quic_common_frag_t common_frag[1];
  fd_quic_crypto_frame_t crypto_frame[1];

  uchar * cur_ptr = raw_crypto_frame;
  ulong  cur_sz  = sizeof( raw_crypto_frame ) - 1; /* account for NUL byte */

  ulong rc = fd_quic_decode_common_frag( common_frag, cur_ptr, cur_sz );
  FD_TEST( rc!=FD_QUIC_PARSE_FAIL );

  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_decode_crypto_frame( crypto_frame, cur_ptr, cur_sz );
  FD_TEST( rc!=FD_QUIC_PARSE_FAIL );

  FD_LOG_NOTICE(( "parsed crypto_frame" ));
  fd_quic_dump_struct_common_frag( common_frag );
  fd_quic_dump_struct_crypto_frame( crypto_frame );

  /* check footprints */
  FD_LOG_NOTICE(( "crypto_frame footprint: %lu",
                  (ulong)fd_quic_encode_footprint_crypto_frame( crypto_frame ) ));

  /* adjust and try again */
  crypto_frame->length -= 100;
  FD_LOG_NOTICE(( "crypto_frame after subtracting 100 in length:" ));
  FD_LOG_NOTICE(( "crypto_frame footprint: %lu",
                  (ulong)fd_quic_encode_footprint_crypto_frame( crypto_frame ) ));

  crypto_frame->length += 100;

  /* now try encoding */
  uchar buf[4096];

  rc = fd_quic_encode_crypto_frame( buf, sizeof( buf ), crypto_frame );
  FD_TEST( rc!=FD_QUIC_PARSE_FAIL );

  FD_LOG_HEXDUMP_NOTICE(( "encoded", buf, rc ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_crypto_frame();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

