#include "fd_hmac.h"

#include "../sha256/fd_sha256.h"
#include "../sha512/fd_sha512.h"

struct fd_hmac_test_vector {
  char const * key;
  ulong        key_sz;
  char const * msg;
  ulong        msg_sz;
  uchar        hash[ 64UL ];
};

typedef struct fd_hmac_test_vector fd_hmac_test_vector_t;

static fd_hmac_test_vector_t const fd_hmac_sha256_test_vector[] = {
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

static fd_hmac_test_vector_t const fd_hmac_sha384_test_vector[] = {
  /* RFC 2104 Test Vectors */
  {
    .key_sz =  16UL, .key = "\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb",
    .msg_sz =   8UL, .msg = "Hi There",
    .hash = "\x7a\xfa\xa6\x33\xe2\x0d\x37\x9b\x02\x39\x59\x15\xfb\xc3\x85\xff\x8d\xc2\x7d\xcd\x38\x85\xe1\x06\x8a\xb9\x42\xee\xab\x52\xec\x1f\x20\xad\x38\x2a\x92\x37\x0d\x8b\x2e\x0a\xc8\xb8\x3c\x4d\x53\xbf"
  },
  {
    .key_sz =   4UL, .key = "Jefe",
    .msg_sz =  28UL, .msg = "what do ya want for nothing?",
    .hash = "\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49"
  },
  {
    .key_sz = 200UL, .key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    .msg_sz = 200UL, .msg = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    .hash = "\xff\xd6\xb2\xe8\x76\x8c\xe5\x65\x43\xdf\xa8\x05\x49\xf8\x93\x83\xc3\x99\x1f\x10\xe9\xb0\x00\x23\xc2\x73\x8c\x7f\x1b\x0e\x32\x05\x42\xa2\xfd\x83\x10\x9e\xfd\xd0\x68\x8f\x56\x0f\xbd\xd6\x5d\x4f"
  },
  {0}
};

static fd_hmac_test_vector_t const fd_hmac_sha512_test_vector[] = {
  /* RFC 2104 Test Vectors */
  {
    .key_sz =  16UL, .key = "\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb",
    .msg_sz =   8UL, .msg = "Hi There",
    .hash = "\x76\x41\xc4\x8a\x3b\x4a\xa8\xf8\x87\xc0\x7b\x3e\x83\xf9\x6a\xff\xb8\x9c\x97\x8f\xed\x8c\x96\xfc\xbb\xf4\xad\x59\x6e\xeb\xfe\x49\x6f\x9f\x16\xda\x6c\xd0\x80\xba\x39\x3c\x6f\x36\x5a\xd7\x2b\x50\xd1\x5c\x71\xbf\xb1\xd6\xb8\x1f\x66\xa9\x11\x78\x6c\x6c\xe9\x32"
  },
  {
    .key_sz =   4UL, .key = "Jefe",
    .msg_sz =  28UL, .msg = "what do ya want for nothing?",
    .hash = "\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37"
  },
  {
    .key_sz = 200UL, .key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    .msg_sz = 200UL, .msg = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    .hash = "\xdb\x7f\xe3\x77\x9c\xbe\x4f\xa6\x0b\xc2\xf5\x83\xec\x58\x34\x9e\x11\xe3\x78\x89\x20\x7a\xe2\x05\x0f\x55\xac\x2b\x27\xc5\xd8\xed\xc1\xb9\x93\xff\x9a\xe4\xf6\x28\x81\x6f\xd4\x5b\xce\xa3\x24\x30\x5d\x2e\xf7\x1f\x04\x68\x91\xb4\x28\xb9\xa3\xe7\x40\xcb\xdb\xf3"
  },
  {0}
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar hash[ 64UL ] __attribute__((aligned(64UL)));

  for( fd_hmac_test_vector_t const * vec = fd_hmac_sha256_test_vector; vec->msg; vec++ ) {
    char const *  key      = vec->key;
    ulong         key_sz   = vec->key_sz;
    char const *  msg      = vec->msg;
    ulong         msg_sz   = vec->msg_sz;
    uchar const * expected = vec->hash;

    FD_TEST( fd_hmac_sha256( msg, msg_sz, key, key_sz, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA256_HASH_SZ ) ) )
      FD_LOG_ERR(( "HMAC-SHA256 FAIL (key_sz %lu msg_sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT, key_sz, msg_sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));
  }
  FD_LOG_INFO(( "OK: HMAC-SHA256" ));

  for( fd_hmac_test_vector_t const * vec = fd_hmac_sha384_test_vector; vec->msg; vec++ ) {
    char const *  key      = vec->key;
    ulong         key_sz   = vec->key_sz;
    char const *  msg      = vec->msg;
    ulong         msg_sz   = vec->msg_sz;
    uchar const * expected = vec->hash;

    FD_TEST( fd_hmac_sha384( msg, msg_sz, key, key_sz, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA384_HASH_SZ ) ) )
      FD_LOG_ERR(( "HMAC-SHA384 FAIL (key_sz %lu msg_sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT, key_sz, msg_sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ), FD_LOG_HEX16_FMT_ARGS(     hash+32 ),
                   FD_LOG_HEX16_FMT_ARGS( expected ), FD_LOG_HEX16_FMT_ARGS( expected+16 ), FD_LOG_HEX16_FMT_ARGS( expected+32 ) ));
  }
  FD_LOG_INFO(( "OK: HMAC-SHA384" ));

  for( fd_hmac_test_vector_t const * vec = fd_hmac_sha512_test_vector; vec->msg; vec++ ) {
    char const *  key      = vec->key;
    ulong         key_sz   = vec->key_sz;
    char const *  msg      = vec->msg;
    ulong         msg_sz   = vec->msg_sz;
    uchar const * expected = vec->hash;

    FD_TEST( fd_hmac_sha512( msg, msg_sz, key, key_sz, hash )==hash );
    if( FD_UNLIKELY( memcmp( hash, expected, FD_SHA512_HASH_SZ ) ) )
      FD_LOG_ERR(( "HMAC-SHA512 FAIL (key_sz %lu msg_sz %lu)"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
                   key_sz, msg_sz,
                   FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                   FD_LOG_HEX16_FMT_ARGS(     hash+32 ), FD_LOG_HEX16_FMT_ARGS(     hash+48 ),
                   FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ),
                   FD_LOG_HEX16_FMT_ARGS( expected+32 ), FD_LOG_HEX16_FMT_ARGS( expected+48 ) ));
  }
  FD_LOG_INFO(( "OK: HMAC-SHA512" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

