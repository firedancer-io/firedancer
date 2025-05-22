#include "fd_hpack_private.h"
#include "fd_hpack_wr.h"
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

static uchar const rfc7541_c41_bin[] = {
  0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
  0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
  0xff
};

static uchar const rfc7541_c42_bin[] = {
  0x82, 0x86, 0x84, /* 0xbe, */ 0x58, 0x86, 0xa8, 0xeb,
  0x10, 0x64, 0x9c, 0xbf
};

static uchar const rfc7541_c43_bin[] = {
  0x82, 0x87, 0x85, /* 0xbf, */ 0x40, 0x88, 0x25, 0xa8,
  0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25,
  0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf
};

static uchar const rfc7541_c51_bin[] = {
  0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70,
  0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x61, 0x1d,
  0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20,
  0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33,
  0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32,
  0x31, 0x20, 0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68,
  0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77,
  0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
  0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
};

static fd_h2_hdr_t const rfc7541_c51_dec[] = {
  { .name=":status",       .name_len = 7,  .hint=8 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="302",          .value_len= 3 },
  { .name="cache-control", .name_len =13,  .hint=24 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="private",      .value_len= 7 },
  { .name="date",          .name_len = 4,  .hint=33 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="Mon, 21 Oct 2013 20:13:21 GMT", .value_len=29 },
  { .name="location",      .name_len = 8,  .hint=46 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="https://www.example.com", .value_len=23 },
  {0}
};

static uchar const rfc7541_c61_bin[] = {
  0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3,
  0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe,
  0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05,
  0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6,
  0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad,
  0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8,
  0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3
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
    uchar buf[ 128 ];
    uchar * bufp = buf;
    FD_TEST( fd_hpack_rd_next( rd, hdr, &bufp, buf+sizeof(buf) )==FD_H2_SUCCESS );
    FD_TEST( bufp>=buf && bufp<=buf+sizeof(buf) );
    FD_TEST( hdr->name_len  == expected->name_len  );
    FD_TEST( hdr->value_len == expected->value_len );
    FD_TEST( fd_memeq( hdr->name,  expected->name,  expected->name_len  ) );
    FD_TEST( fd_memeq( hdr->value, expected->value, expected->value_len ) );
    FD_TEST( hdr->hint == expected->hint );
  }
  FD_TEST( fd_hpack_rd_done( rd ) );
}

struct test_hpack_case {
  ulong res;
  uchar enc[ 8 ];
  uchar bits;
  uchar prefix;
  uchar len;
};

typedef struct test_hpack_case test_hpack_case_t;

static test_hpack_case_t const test_hpack_cases[] = {
  { .bits=1, .prefix=0x00, .len=0, .res=   0UL },
  { .bits=2, .prefix=0x02, .len=0, .res=   2UL },
  { .bits=3, .prefix=0x06, .len=0, .res=   6UL },
  { .bits=4, .prefix=0x0e, .len=0, .res=  14UL },
  { .bits=5, .prefix=0x1e, .len=0, .res=  30UL },
  { .bits=6, .prefix=0x3e, .len=0, .res=  62UL },
  { .bits=7, .prefix=0x7e, .len=0, .res= 126UL },
  { .bits=8, .prefix=0xfe, .len=0, .res= 254UL },
  { .bits=5, .prefix=0xff, .len=2, .res=1337UL, .enc={0x9a, 0x0a} },
  { .bits=5, .prefix=0x9f, .len=2, .res=1337UL, .enc={0x9a, 0x0a} },
  { .bits=5, .prefix=0xbf, .len=2, .res=1337UL, .enc={0x9a, 0x0a} },
  { .bits=7, .prefix=0x7f, .len=1, .res= 179UL, .enc={0x34} },
  { .bits=0 }
};

static void
test_hpack_rd_varint( void ) {
  for( test_hpack_case_t const * c=test_hpack_cases; c->bits; c++ ) {
    for( ulong len=0UL; len<=8UL; len++ ) {
      fd_hpack_rd_t rd = { .src=c->enc, .src_end=c->enc+len };
      ulong res = fd_hpack_rd_varint( &rd, c->prefix, (1U<<(c->bits))-1U );
      if( len < c->len ) {
        FD_TEST( res==ULONG_MAX );
      } else {
        FD_TEST( res==c->res );
      }
    }
  }
}

static void
test_hpack_wr_varint( void ) {
  for( test_hpack_case_t const * c=test_hpack_cases; c->bits; c++ ) {
    uchar buf[ 16 ];
    uint  addend = (1U<<(c->bits))-1U;
    uint  prefix = c->prefix & ~addend;
    ulong len    = fd_hpack_wr_varint( buf, prefix, addend, c->res );
    FD_TEST( len == (ulong)c->len+1 );
    FD_TEST( buf[0] == c->prefix );
    FD_TEST( fd_memeq( buf+1, c->enc, c->len ) );
  }
}

void
test_hpack( void ) {
  test_hpack_rd( rfc7541_c31_bin, sizeof(rfc7541_c31_bin), rfc7541_c31_dec );
  test_hpack_rd( rfc7541_c32_bin, sizeof(rfc7541_c32_bin), rfc7541_c32_dec );
  test_hpack_rd( rfc7541_c33_bin, sizeof(rfc7541_c33_bin), rfc7541_c33_dec );
  test_hpack_rd( rfc7541_c41_bin, sizeof(rfc7541_c41_bin), rfc7541_c31_dec );
  test_hpack_rd( rfc7541_c42_bin, sizeof(rfc7541_c42_bin), rfc7541_c32_dec );
  test_hpack_rd( rfc7541_c43_bin, sizeof(rfc7541_c43_bin), rfc7541_c33_dec );
  test_hpack_rd( rfc7541_c51_bin, sizeof(rfc7541_c51_bin), rfc7541_c51_dec );
  test_hpack_rd( rfc7541_c61_bin, sizeof(rfc7541_c61_bin), rfc7541_c51_dec );
  test_hpack_rd_varint();
  test_hpack_wr_varint();
}
