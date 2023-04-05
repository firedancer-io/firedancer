#include "fd_hmac.h"

struct fd_hmac_sha256_test_vector {
  char const * key;
  ulong        key_sz;
  char const * msg;
  ulong        msg_sz;
  uchar        hash[ 32UL ];
};

typedef struct fd_hmac_sha256_test_vector fd_hmac_sha256_test_vector_t;

static fd_hmac_sha256_test_vector_t const fd_hmac_sha256_test_vector[] = {
  /* RFC 2104 Test Vectors */
  {
    .key_sz =  16UL, .key = "\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb",
    .msg_sz =   8UL, .msg = "Hi There",
    .hash = "\x49\x2c\xe0\x20\xfe\x25\x34\xa5\x78\x9d\xc3\x84\x88\x06\xc7\x8f\x4f\x67\x11\x39\x7f\x08\xe7\xe7\xa1\x2c\xa5\xa4\x48\x3c\x8a\xa6"
  },
  {
    .key_sz =   4UL, .key = "Jefe",
    .msg_sz =  28UL, .msg = "what do ya want for nothing?",
    .hash = "\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43"
  },
  {
    .key_sz = 100UL, .key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    .msg_sz = 100UL, .msg = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    .hash = "\xf8\x0b\x45\x22\x4d\xbb\xa3\x82\x56\x88\x6e\x16\x3f\x5b\x9f\x21\x83\x48\xff\xab\xcf\x57\x96\xe4\x1d\x90\xcd\xe0\xb4\x0a\x31\x14"
  },
  {0}
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar hash[ 32 ] __attribute__((aligned(32)));

  for( fd_hmac_sha256_test_vector_t const * vec = fd_hmac_sha256_test_vector; vec->msg; vec++ ) {
    char const *  key      = vec->key;
    ulong         key_sz   = vec->key_sz;
    char const *  msg      = vec->msg;
    ulong         msg_sz   = vec->msg_sz;
    uchar const * expected = vec->hash;

    FD_TEST( fd_hmac_sha256( msg, msg_sz, key, key_sz, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
      FD_LOG_ERR(( "FAIL (key_sz %lu msg_sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, key_sz, msg_sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
