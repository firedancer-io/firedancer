#include "fd_hpack.h"
#include "../../util/log/fd_log.h"

static uchar const rfc7541_c31_bin[] = {
  0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77,
  0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
  0x2e, 0x63, 0x6f, 0x6d
};

static fd_h2_hdr_t const rfc7541_c31_dec[] = {
  { .name =":method", .name_len =7,  .hint=2 | FD_H2_HDR_HINT_INDEXED,
    .value="GET",     .value_len=3 },
  { .name =":scheme", .name_len =7,  .hint=6 | FD_H2_HDR_HINT_INDEXED,
    .value="http",    .value_len=4 },
  { .name =":path",   .name_len =5,  .hint=4 | FD_H2_HDR_HINT_INDEXED,
    .value="/",       .value_len=1 },
  { .name =":authority",      .name_len =10, .hint=1 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="www.example.com", .value_len=15 },
  {0}
};

static uchar const rfc7541_c32_bin[] = {
  0x82, 0x86, 0x84, /* 0xbe, */ 0x58, 0x08, 0x6e, 0x6f,
  0x2d, 0x63, 0x61, 0x63, 0x68, 0x65
};

static fd_h2_hdr_t const rfc7541_c32_dec[] = {
  { .name =":method", .name_len =7,  .hint=2 | FD_H2_HDR_HINT_INDEXED,
    .value="GET",     .value_len=3 },
  { .name =":scheme", .name_len =7,  .hint=6 | FD_H2_HDR_HINT_INDEXED,
    .value="http",    .value_len=4 },
  { .name =":path",   .name_len =5,  .hint=4 | FD_H2_HDR_HINT_INDEXED,
    .value="/",       .value_len=1 },
  // FIXME removed dynamic table entry
  //{ .name =":authority",      .name_len =10, .hint=1 | FD_H2_HDR_HINT_NAME_INDEXED,
  //  .value="www.example.com", .value_len=15 },
  { .name ="cache-control", .name_len =13, .hint=24 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="no-cache",      .value_len=8 },
  {0}
};

static uchar const rfc7541_c33_bin[] = {
  0x82, 0x87, 0x85, /* 0xbf, */ 0x40, 0x0a, 0x63, 0x75,
  0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
  0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d,
  0x76, 0x61, 0x6c, 0x75, 0x65
};

static fd_h2_hdr_t const rfc7541_c33_dec[] = {
  { .name =":method",      .name_len =7,  .hint=2 | FD_H2_HDR_HINT_INDEXED,
    .value="GET",          .value_len=3 },
  { .name =":scheme",      .name_len =7,  .hint=7 | FD_H2_HDR_HINT_INDEXED,
    .value="https",        .value_len=5 },
  { .name =":path",        .name_len =5,  .hint=5 | FD_H2_HDR_HINT_INDEXED,
    .value="/index.html",  .value_len=11 },
  // FIXME removed dynamic table entry
  //{ .name =":authority",      .name_len =10, .hint=1 | FD_H2_HDR_HINT_NAME_INDEXED,
  //  .value="www.example.com", .value_len=15 },
  { .name ="custom-key",   .name_len =10,
    .value="custom-value", .value_len=12 },
  {0}
};

static void
test_hpack_rd( uchar const *       bin,
               ulong               binsz,
               fd_h2_hdr_t const * dec ) {
  fd_hpack_rd_t rd[1];
  fd_hpack_rd_init( rd, bin, binsz );
  for( fd_h2_hdr_t const * expected=dec; expected->name; expected++ ) {
    FD_TEST( !fd_hpack_rd_done( rd ) );
    fd_h2_hdr_t hdr[1];
    FD_TEST( fd_hpack_rd_next( rd, hdr )==FD_H2_SUCCESS );
    FD_TEST( hdr->name_len  == expected->name_len  );
    FD_TEST( hdr->value_len == expected->value_len );
    FD_TEST( fd_memeq( hdr->name,  expected->name,  expected->name_len  ) );
    FD_TEST( fd_memeq( hdr->value, expected->value, expected->value_len ) );
    FD_TEST( hdr->hint == expected->hint );
  }
  FD_TEST( fd_hpack_rd_done( rd ) );
}

void
test_hpack( void ) {
  test_hpack_rd( rfc7541_c31_bin, sizeof(rfc7541_c31_bin), rfc7541_c31_dec );
  test_hpack_rd( rfc7541_c32_bin, sizeof(rfc7541_c32_bin), rfc7541_c32_dec );
  test_hpack_rd( rfc7541_c33_bin, sizeof(rfc7541_c33_bin), rfc7541_c33_dec );
}
