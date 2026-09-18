#include "fd_hpack_private.h"
#include "fd_hpack_wr.h"
#include "../../util/log/fd_log.h"

/* Test vectors from RFC 7541 Appendix C.  Each group of blocks shares
   one dynamic table, as they would on a real connection. */

/* C.3 Request Examples without Huffman Coding */

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
  0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f,
  0x2d, 0x63, 0x61, 0x63, 0x68, 0x65
};

static fd_h2_hdr_t const rfc7541_c32_dec[] = {
  { .name =":method", .name_len =7,  .hint=2 | FD_H2_HDR_HINT_INDEXED,
    .value="GET",     .value_len=3 },
  { .name =":scheme", .name_len =7,  .hint=6 | FD_H2_HDR_HINT_INDEXED,
    .value="http",    .value_len=4 },
  { .name =":path",   .name_len =5,  .hint=4 | FD_H2_HDR_HINT_INDEXED,
    .value="/",       .value_len=1 },
  { .name =":authority",      .name_len =10, .hint=62 | FD_H2_HDR_HINT_INDEXED,
    .value="www.example.com", .value_len=15 },
  { .name ="cache-control", .name_len =13, .hint=24 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="no-cache",      .value_len=8 },
  {0}
};

static uchar const rfc7541_c33_bin[] = {
  0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75,
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
  { .name =":authority",      .name_len =10, .hint=63 | FD_H2_HDR_HINT_INDEXED,
    .value="www.example.com", .value_len=15 },
  { .name ="custom-key",   .name_len =10,
    .value="custom-value", .value_len=12 },
  {0}
};

/* C.4 Request Examples with Huffman Coding */

static uchar const rfc7541_c41_bin[] = {
  0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
  0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
  0xff
};

static uchar const rfc7541_c42_bin[] = {
  0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb,
  0x10, 0x64, 0x9c, 0xbf
};

static uchar const rfc7541_c43_bin[] = {
  0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8,
  0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25,
  0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf
};

/* C.5 Response Examples without Huffman Coding
   (SETTINGS_HEADER_TABLE_SIZE is 256) */

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

static uchar const rfc7541_c52_bin[] = {
  0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf
};

static fd_h2_hdr_t const rfc7541_c52_dec[] = {
  { .name=":status",       .name_len = 7,  .hint=8 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="307",          .value_len= 3 },
  { .name="cache-control", .name_len =13,  .hint=65 | FD_H2_HDR_HINT_INDEXED,
    .value="private",      .value_len= 7 },
  { .name="date",          .name_len = 4,  .hint=64 | FD_H2_HDR_HINT_INDEXED,
    .value="Mon, 21 Oct 2013 20:13:21 GMT", .value_len=29 },
  { .name="location",      .name_len = 8,  .hint=63 | FD_H2_HDR_HINT_INDEXED,
    .value="https://www.example.com", .value_len=23 },
  {0}
};

static uchar const rfc7541_c53_bin[] = {
  0x88, 0xc1, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c,
  0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20,
  0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a,
  0x31, 0x33, 0x3a, 0x32, 0x32, 0x20, 0x47, 0x4d,
  0x54, 0xc0, 0x5a, 0x04, 0x67, 0x7a, 0x69, 0x70,
  0x77, 0x38, 0x66, 0x6f, 0x6f, 0x3d, 0x41, 0x53,
  0x44, 0x4a, 0x4b, 0x48, 0x51, 0x4b, 0x42, 0x5a,
  0x58, 0x4f, 0x51, 0x57, 0x45, 0x4f, 0x50, 0x49,
  0x55, 0x41, 0x58, 0x51, 0x57, 0x45, 0x4f, 0x49,
  0x55, 0x3b, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61,
  0x67, 0x65, 0x3d, 0x33, 0x36, 0x30, 0x30, 0x3b,
  0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
  0x3d, 0x31
};

static fd_h2_hdr_t const rfc7541_c53_dec[] = {
  { .name=":status",       .name_len = 7,  .hint=8 | FD_H2_HDR_HINT_INDEXED,
    .value="200",          .value_len= 3 },
  { .name="cache-control", .name_len =13,  .hint=65 | FD_H2_HDR_HINT_INDEXED,
    .value="private",      .value_len= 7 },
  { .name="date",          .name_len = 4,  .hint=33 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="Mon, 21 Oct 2013 20:13:22 GMT", .value_len=29 },
  { .name="location",      .name_len = 8,  .hint=64 | FD_H2_HDR_HINT_INDEXED,
    .value="https://www.example.com", .value_len=23 },
  { .name="content-encoding", .name_len=16, .hint=26 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="gzip",          .value_len= 4 },
  { .name="set-cookie",    .name_len =10,  .hint=55 | FD_H2_HDR_HINT_NAME_INDEXED,
    .value="foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
    .value_len=56 },
  {0}
};

/* C.6 Response Examples with Huffman Coding
   (SETTINGS_HEADER_TABLE_SIZE is 256) */

static uchar const rfc7541_c61_bin[] = {
  0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3,
  0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe,
  0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05,
  0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6,
  0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad,
  0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8,
  0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3
};

static uchar const rfc7541_c62_bin[] = {
  0x48, 0x83, 0x64, 0x0e, 0xff, 0xc1, 0xc0, 0xbf
};

static uchar const rfc7541_c63_bin[] = {
  0x88, 0xc1, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94,
  0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95,
  0x04, 0x0b, 0x81, 0x66, 0xe0, 0x84, 0xa6, 0x2d,
  0x1b, 0xff, 0xc0, 0x5a, 0x83, 0x9b, 0xd9, 0xab,
  0x77, 0xad, 0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2,
  0xe6, 0xc7, 0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b,
  0x39, 0x60, 0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36,
  0x72, 0xc1, 0xab, 0x27, 0x0f, 0xb5, 0x29, 0x1f,
  0x95, 0x87, 0x31, 0x60, 0x65, 0xc0, 0x03, 0xed,
  0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07
};

/* Expected dynamic table contents.  Index 0 of each list is HPACK index
   62, the most recently inserted entry. */

struct test_hpack_dtable_entry {
  char const * name;
  char const * value;
  ulong        sz;
};

typedef struct test_hpack_dtable_entry test_hpack_dtable_entry_t;

static test_hpack_dtable_entry_t const rfc7541_c31_tbl[] = {
  { ":authority", "www.example.com", 57 },
  {0}
};

static test_hpack_dtable_entry_t const rfc7541_c32_tbl[] = {
  { "cache-control", "no-cache",        53 },
  { ":authority",    "www.example.com", 57 },
  {0}
};

static test_hpack_dtable_entry_t const rfc7541_c33_tbl[] = {
  { "custom-key",    "custom-value",    54 },
  { "cache-control", "no-cache",        53 },
  { ":authority",    "www.example.com", 57 },
  {0}
};

static test_hpack_dtable_entry_t const rfc7541_c51_tbl[] = {
  { "location",      "https://www.example.com",       63 },
  { "date",          "Mon, 21 Oct 2013 20:13:21 GMT", 65 },
  { "cache-control", "private",                       52 },
  { ":status",       "302",                           42 },
  {0}
};

static test_hpack_dtable_entry_t const rfc7541_c52_tbl[] = {
  { ":status",       "307",                           42 },
  { "location",      "https://www.example.com",       63 },
  { "date",          "Mon, 21 Oct 2013 20:13:21 GMT", 65 },
  { "cache-control", "private",                       52 },
  {0}
};

static test_hpack_dtable_entry_t const rfc7541_c53_tbl[] = {
  { "set-cookie",       "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", 98 },
  { "content-encoding", "gzip",                          52 },
  { "date",             "Mon, 21 Oct 2013 20:13:22 GMT", 65 },
  {0}
};

static void
test_hpack_expect_dtable( fd_hpack_dtable_t const *         dtable,
                          test_hpack_dtable_entry_t const * expected ) {
  ulong cnt = 0UL;
  ulong sz  = 0UL;
  for( test_hpack_dtable_entry_t const * e=expected; e->name; e++ ) {
    uchar   buf[ FD_HPACK_DTABLE_SZ_MAX ];
    uchar * bufp = buf;
    fd_h2_hdr_t hdr[1];
    FD_TEST( fd_hpack_dtable_query( dtable, 62UL+cnt, hdr, &bufp, buf+sizeof(buf) )==FD_H2_SUCCESS );
    FD_TEST( hdr->name_len ==strlen( e->name  ) );
    FD_TEST( hdr->value_len==strlen( e->value ) );
    FD_TEST( fd_memeq( hdr->name,  e->name,  hdr->name_len  ) );
    FD_TEST( fd_memeq( hdr->value, e->value, hdr->value_len ) );
    FD_TEST( (ulong)hdr->name_len + hdr->value_len + 32UL == e->sz );
    cnt++;
    sz += e->sz;
  }
  FD_TEST( dtable->entry_cnt==cnt );
  FD_TEST( dtable->used_sz  ==sz  );
  /* The first index past the table is out of bounds */
  uchar   buf[ 64 ];
  uchar * bufp = buf;
  fd_h2_hdr_t hdr[1];
  FD_TEST( fd_hpack_dtable_query( dtable, 62UL+cnt, hdr, &bufp, buf+sizeof(buf) )==FD_H2_ERR_COMPRESSION );
  FD_TEST( bufp==buf );
}

static void
test_hpack_rd( fd_hpack_dtable_t *               dtable,
               uchar const *                     bin,
               ulong                             binsz,
               fd_h2_hdr_t const *               dec,
               test_hpack_dtable_entry_t const * tbl ) {
  fd_hpack_rd_t rd[1];
  FD_TEST( fd_hpack_rd_init_dtable( rd, bin, binsz, dtable )==rd );
  for( fd_h2_hdr_t const * expected=dec; expected->name; expected++ ) {
    FD_TEST( !fd_hpack_rd_done( rd ) );
    fd_h2_hdr_t hdr[1];
    uchar buf[ 256 ];
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
  if( tbl ) test_hpack_expect_dtable( dtable, tbl );
}

/* test_hpack_rd_err decodes a field block that must fail. */

static void
test_hpack_rd_err( fd_hpack_dtable_t * dtable,
                   uchar const *       bin,
                   ulong               binsz ) {
  fd_hpack_rd_t rd[1];
  if( FD_UNLIKELY( !fd_hpack_rd_init_dtable( rd, bin, binsz, dtable ) ) ) return;
  for(;;) {
    if( fd_hpack_rd_done( rd ) ) FD_TEST( 0 ); /* block decoded without error */
    fd_h2_hdr_t hdr[1];
    uchar buf[ 256 ];
    uchar * bufp = buf;
    uint err = fd_hpack_rd_next( rd, hdr, &bufp, buf+sizeof(buf) );
    if( err ) {
      FD_TEST( err==FD_H2_ERR_COMPRESSION );
      return;
    }
  }
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

FD_UNIT_TEST( hpack_rfc7541_requests ) {
  fd_hpack_dtable_t dtable[1];

  /* C.3: requests without Huffman coding */
  FD_TEST( fd_hpack_dtable_init( dtable, FD_HPACK_DTABLE_SZ_MAX )==dtable );
  test_hpack_rd( dtable, rfc7541_c31_bin, sizeof(rfc7541_c31_bin), rfc7541_c31_dec, rfc7541_c31_tbl );
  test_hpack_rd( dtable, rfc7541_c32_bin, sizeof(rfc7541_c32_bin), rfc7541_c32_dec, rfc7541_c32_tbl );
  test_hpack_rd( dtable, rfc7541_c33_bin, sizeof(rfc7541_c33_bin), rfc7541_c33_dec, rfc7541_c33_tbl );

  /* C.4: the same requests with Huffman coding */
  FD_TEST( fd_hpack_dtable_init( dtable, FD_HPACK_DTABLE_SZ_MAX )==dtable );
  test_hpack_rd( dtable, rfc7541_c41_bin, sizeof(rfc7541_c41_bin), rfc7541_c31_dec, rfc7541_c31_tbl );
  test_hpack_rd( dtable, rfc7541_c42_bin, sizeof(rfc7541_c42_bin), rfc7541_c32_dec, rfc7541_c32_tbl );
  test_hpack_rd( dtable, rfc7541_c43_bin, sizeof(rfc7541_c43_bin), rfc7541_c33_dec, rfc7541_c33_tbl );
}

FD_UNIT_TEST( hpack_rfc7541_responses ) {
  fd_hpack_dtable_t dtable[1];

  /* C.5: responses without Huffman coding, table size 256 */
  FD_TEST( fd_hpack_dtable_init( dtable, 256UL )==dtable );
  test_hpack_rd( dtable, rfc7541_c51_bin, sizeof(rfc7541_c51_bin), rfc7541_c51_dec, rfc7541_c51_tbl );
  test_hpack_rd( dtable, rfc7541_c52_bin, sizeof(rfc7541_c52_bin), rfc7541_c52_dec, rfc7541_c52_tbl );
  test_hpack_rd( dtable, rfc7541_c53_bin, sizeof(rfc7541_c53_bin), rfc7541_c53_dec, rfc7541_c53_tbl );

  /* C.6: the same responses with Huffman coding */
  FD_TEST( fd_hpack_dtable_init( dtable, 256UL )==dtable );
  test_hpack_rd( dtable, rfc7541_c61_bin, sizeof(rfc7541_c61_bin), rfc7541_c51_dec, rfc7541_c51_tbl );
  test_hpack_rd( dtable, rfc7541_c62_bin, sizeof(rfc7541_c62_bin), rfc7541_c52_dec, rfc7541_c52_tbl );
  test_hpack_rd( dtable, rfc7541_c63_bin, sizeof(rfc7541_c63_bin), rfc7541_c53_dec, rfc7541_c53_tbl );
}

/* test_hpack_dtable exercises the dynamic table directly. */

FD_UNIT_TEST( hpack_dtable ) {
  fd_hpack_dtable_t dtable[1];

  /* The table is embedded in fd_h2_conn_t, so its footprint is part of
     the per-connection cost */
  FD_TEST( sizeof(fd_hpack_dtable_t)<=5120UL );
  FD_LOG_NOTICE(( "sizeof(fd_hpack_dtable_t)=%lu", sizeof(fd_hpack_dtable_t) ));

  FD_TEST( !fd_hpack_dtable_init( dtable, FD_HPACK_DTABLE_SZ_MAX+1UL ) );

  FD_TEST( fd_hpack_dtable_init( dtable, 64UL )==dtable );
  FD_TEST( dtable->limit_sz==64U );
  FD_TEST( dtable->max_sz  ==64U );
  FD_TEST( dtable->used_sz ==0U  );

  /* Two 32 byte entries fit exactly */
  fd_hpack_dtable_insert( dtable, "", 0UL, "", 0UL );
  fd_hpack_dtable_insert( dtable, "", 0UL, "", 0UL );
  FD_TEST( dtable->entry_cnt==2U && dtable->used_sz==64U );

  /* A 34 byte entry evicts both of them */
  fd_hpack_dtable_insert( dtable, "a", 1UL, "b", 1UL );
  FD_TEST( dtable->entry_cnt==1U && dtable->used_sz==34U );
  {
    uchar   buf[ 64 ];
    uchar * bufp = buf;
    fd_h2_hdr_t hdr[1];
    FD_TEST( fd_hpack_dtable_query( dtable, 62UL, hdr, &bufp, buf+sizeof(buf) )==FD_H2_SUCCESS );
    FD_TEST( hdr->name_len==1 && hdr->value_len==1 );
    FD_TEST( hdr->name[0]=='a' && hdr->value[0]=='b' );
    FD_TEST( hdr->hint==( 62 | FD_H2_HDR_HINT_NAME_INDEXED ) );
  }

  /* RFC 7541 Section 4.4: an entry larger than the table empties it */
  fd_hpack_dtable_insert( dtable, "0123456789012345678901234567890123", 34UL, "", 0UL );
  FD_TEST( dtable->entry_cnt==0U && dtable->used_sz==0U );

  /* A size update above the SETTINGS bound is an error, below it evicts */
  fd_hpack_dtable_insert( dtable, "abcd", 4UL, "efgh", 4UL );
  FD_TEST( dtable->entry_cnt==1U && dtable->used_sz==40U );
  FD_TEST( fd_hpack_dtable_set_max_sz( dtable, 65UL )==FD_H2_ERR_COMPRESSION );
  FD_TEST( dtable->max_sz==64U && dtable->entry_cnt==1U );
  FD_TEST( fd_hpack_dtable_set_max_sz( dtable, 39UL )==FD_H2_SUCCESS );
  FD_TEST( dtable->max_sz==39U && dtable->entry_cnt==0U && dtable->used_sz==0U );
  FD_TEST( fd_hpack_dtable_set_max_sz( dtable, 64UL )==FD_H2_SUCCESS );

  /* A NULL table behaves like a table with limit zero */
  FD_TEST( fd_hpack_dtable_set_max_sz( NULL, 0UL )==FD_H2_SUCCESS          );
  FD_TEST( fd_hpack_dtable_set_max_sz( NULL, 1UL )==FD_H2_ERR_COMPRESSION  );
  fd_hpack_dtable_insert( NULL, "a", 1UL, "b", 1UL );
  {
    uchar   buf[ 64 ];
    uchar * bufp = buf;
    fd_h2_hdr_t hdr[1];
    FD_TEST( fd_hpack_dtable_query( NULL, 62UL, hdr, &bufp, buf+sizeof(buf) )==FD_H2_ERR_COMPRESSION );
  }

  /* Insert and evict enough entries to wrap both rings several times.
     Entry names are distinct so that a stale ring offset shows up. */
  FD_TEST( fd_hpack_dtable_init( dtable, FD_HPACK_DTABLE_SZ_MAX )==dtable );
  for( ulong i=0UL; i<4096UL; i++ ) {
    char name [ 32 ];
    char value[ 512 ];
    ulong name_len  = 0UL;
    FD_TEST( fd_cstr_printf_check( name, sizeof(name), &name_len, "hdr-%lu", i ) );
    ulong value_len = 1UL + ( i % sizeof(value) );
    fd_memset( value, (int)( 'a' + i%26 ), value_len );
    fd_hpack_dtable_insert( dtable, name, name_len, value, value_len );

    FD_TEST( dtable->used_sz  <= dtable->max_sz              );
    FD_TEST( dtable->entry_cnt<= FD_HPACK_DTABLE_ENTRY_MAX   );

    uchar   buf[ FD_HPACK_DTABLE_SZ_MAX ];
    uchar * bufp = buf;
    fd_h2_hdr_t hdr[1];
    FD_TEST( fd_hpack_dtable_query( dtable, 62UL, hdr, &bufp, buf+sizeof(buf) )==FD_H2_SUCCESS );
    FD_TEST( hdr->name_len==name_len && fd_memeq( hdr->name, name, name_len ) );
    FD_TEST( hdr->value_len==value_len && fd_memeq( hdr->value, value, value_len ) );

    /* Every live entry stays readable and the sizes add up */
    ulong used_sz = 0UL;
    for( ulong j=1UL; j<=dtable->entry_cnt; j++ ) {
      uchar   buf2[ FD_HPACK_DTABLE_SZ_MAX ];
      uchar * bufp2 = buf2;
      fd_h2_hdr_t hdr2[1];
      FD_TEST( fd_hpack_dtable_query( dtable, 61UL+j, hdr2, &bufp2, buf2+sizeof(buf2) )==FD_H2_SUCCESS );
      used_sz += (ulong)hdr2->name_len + hdr2->value_len + 32UL;
    }
    FD_TEST( used_sz==dtable->used_sz );
  }
}

/* test_hpack_rd_bad covers malformed field blocks.  Each must fail with
   FD_H2_ERR_COMPRESSION rather than crash. */

/* RFC 7541 Section 4.4: adding an entry that does not fit the table
   even when empty clears the table. */

FD_UNIT_TEST( hpack_rd_oversize_insert ) {
  static uchar const blk[] = {
    /* "a: b", entry size 34 */
    0x40, 0x01, 'a', 0x01, 'b',
    /* 10 byte name, 20 byte value, entry size 62 */
    0x40, 0x0a, '0','1','2','3','4','5','6','7','8','9',
          0x14, '0','1','2','3','4','5','6','7','8','9',
                '0','1','2','3','4','5','6','7','8','9',
    /* 10 byte name, 30 byte value, entry size 72 */
    0x40, 0x0a, 'a','b','c','d','e','f','g','h','i','j',
          0x1e, 'x','x','x','x','x','x','x','x','x','x',
                'x','x','x','x','x','x','x','x','x','x',
                'x','x','x','x','x','x','x','x','x','x'
  };
  static ulong const used_sz_expected[] = { 34UL, 62UL, 0UL };
  static uint  const entry_cnt_expected[] = { 1U, 1U, 0U };

  fd_hpack_dtable_t dtable[1];
  FD_TEST( fd_hpack_dtable_init( dtable, 64UL )==dtable );

  fd_hpack_rd_t rd[1];
  FD_TEST( fd_hpack_rd_init_dtable( rd, blk, sizeof(blk), dtable )==rd );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( !fd_hpack_rd_done( rd ) );
    fd_h2_hdr_t hdr[1];
    uchar buf[ 128 ];
    uchar * bufp = buf;
    FD_TEST( fd_hpack_rd_next( rd, hdr, &bufp, buf+sizeof(buf) )==FD_H2_SUCCESS );
    FD_TEST( dtable->used_sz  ==used_sz_expected  [ i ] );
    FD_TEST( dtable->entry_cnt==entry_cnt_expected[ i ] );
  }
  FD_TEST( fd_hpack_rd_done( rd ) );

  /* The oversized field was still delivered, it just is not indexable */
  fd_h2_hdr_t hdr[1];
  uchar buf[ 128 ];
  uchar * bufp = buf;
  FD_TEST( fd_hpack_dtable_query( dtable, 62UL, hdr, &bufp, buf+sizeof(buf) )==FD_H2_ERR_COMPRESSION );
}

FD_UNIT_TEST( hpack_rd_bad ) {
  fd_hpack_dtable_t dtable[1];

  static uchar const idx_zero      [] = { 0x80 };                   /* indexed, index 0 */
  static uchar const idx_static_oob[] = { 0x80|62 };                /* first dynamic index, table empty */
  static uchar const idx_huge      [] = { 0xff, 0xff, 0xff, 0x7f }; /* indexed, index 2097215 */
  static uchar const idx_unterm    [] = { 0xff, 0xff, 0xff, 0xff }; /* unterminated varint */
  static uchar const upd_oversize  [] = { 0x3f, 0xe2, 0x1f };       /* size update to 4097 */
  static uchar const upd_unterm    [] = { 0x3f, 0xff };             /* unterminated size update */
  static uchar const upd_late      [] = { 0x82, 0x20 };             /* size update after a header */
  static uchar const lit_trunc_name[] = { 0x40, 0x08, 'a', 'b' };   /* name len past end of block */
  static uchar const lit_trunc_val [] = { 0x40, 0x01, 'a', 0x08, 'b' };
  static uchar const lit_trunc_hdr [] = { 0x40 };
  static uchar const lit_idx_novalue[] = { 0x41 };                  /* name index, no value */
  static uchar const huff_bad      [] = { 0x40, 0x81, 0xff, 0x01, 'a' }; /* EOS padding in name */

# define TEST_BAD(blk) do {                                       \
    FD_TEST( fd_hpack_dtable_init( dtable, 4096UL )==dtable );    \
    test_hpack_rd_err( dtable, blk, sizeof(blk) );                \
  } while(0)

  TEST_BAD( idx_zero       );
  TEST_BAD( idx_static_oob );
  TEST_BAD( idx_huge       );
  TEST_BAD( idx_unterm     );
  TEST_BAD( upd_oversize   );
  TEST_BAD( upd_unterm     );
  TEST_BAD( upd_late       );
  TEST_BAD( lit_trunc_name );
  TEST_BAD( lit_trunc_val  );
  TEST_BAD( lit_trunc_hdr  );
  TEST_BAD( lit_idx_novalue);
  TEST_BAD( huff_bad       );

# undef TEST_BAD

  /* A size update above the advertised table size fails even when the
     value would be legal for a larger table */
  FD_TEST( fd_hpack_dtable_init( dtable, 256UL )==dtable );
  static uchar const upd_over_settings[] = { 0x3f, 0xe2, 0x01 }; /* size update to 288 */
  fd_hpack_rd_t rd[1];
  FD_TEST( !fd_hpack_rd_init_dtable( rd, upd_over_settings, sizeof(upd_over_settings), dtable ) );

  /* Every prefix of a valid block either decodes or errors cleanly */
  for( ulong prefix_sz=0UL; prefix_sz<sizeof(rfc7541_c53_bin); prefix_sz++ ) {
    FD_TEST( fd_hpack_dtable_init( dtable, 256UL )==dtable );
    fd_hpack_rd_t rd2[1];
    if( FD_UNLIKELY( !fd_hpack_rd_init_dtable( rd2, rfc7541_c53_bin, prefix_sz, dtable ) ) ) continue;
    while( !fd_hpack_rd_done( rd2 ) ) {
      fd_h2_hdr_t hdr[1];
      uchar buf[ 256 ];
      uchar * bufp = buf;
      uint err = fd_hpack_rd_next( rd2, hdr, &bufp, buf+sizeof(buf) );
      if( err ) {
        FD_TEST( err==FD_H2_ERR_COMPRESSION );
        break;
      }
    }
  }

  /* Out of scratch space is an error, not an overflow */
  FD_TEST( fd_hpack_dtable_init( dtable, 4096UL )==dtable );
  {
    fd_hpack_rd_t rd3[1];
    FD_TEST( fd_hpack_rd_init_dtable( rd3, rfc7541_c41_bin, sizeof(rfc7541_c41_bin), dtable )==rd3 );
    fd_h2_hdr_t hdr[1];
    uchar buf[ 4 ];
    uchar * bufp = buf;
    /* The first three headers are fully indexed, the fourth Huffman codes
       a 15 byte value */
    for( ulong i=0UL; i<3UL; i++ ) {
      FD_TEST( fd_hpack_rd_next( rd3, hdr, &bufp, buf+sizeof(buf) )==FD_H2_SUCCESS );
    }
    FD_TEST( fd_hpack_rd_next( rd3, hdr, &bufp, buf+sizeof(buf) )==FD_H2_ERR_COMPRESSION );
    FD_TEST( bufp==buf );
  }
}

FD_UNIT_TEST( hpack ) {
  test_hpack_rd_varint();
  test_hpack_wr_varint();
}
