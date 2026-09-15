/* test_gui_tile checks the embedded frontend assets and the static file
   serving path of the gui tile: every STATIC_FILES entry's zstd and gzip
   representations round-trip to the raw bytes (and the zstd frames stay
   within the 8 MiB window browsers accept, RFC 9659), and
   gui_http_request negotiates Content-Encoding, Vary and the per
   representation index.html ETag / 304 as intended. */

#define FD_TILE_TEST
#include "fd_gui_tile.c"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <stdlib.h>

static uint
crc32_( uchar const * p,
        ulong         sz ) {
  uint crc = ~0U;
  for( ulong i=0UL; i<sz; i++ ) {
    crc ^= p[ i ];
    for( int b=0; b<8; b++ ) crc = (crc>>1) ^ (0xEDB88320U & (0U-(crc&1U)));
  }
  return ~crc;
}

/* Minimal RFC 1951 inflate (nothing in the tree decodes deflate; the
   vendored zlib is compress-only).  Bit-at-a-time canonical Huffman
   decode, fine for a test. */

typedef struct {
  uchar const * in;  ulong in_sz;  ulong in_pos;
  uchar *       out; ulong out_sz; ulong out_pos;
  uint bitbuf; int bitcnt;
} inf_t;

typedef struct { ushort count[ 16 ]; ushort symbol[ 288 ]; } huff_t;

static uint
inf_bits( inf_t * s,
          int     n ) {
  while( s->bitcnt<n ) { FD_TEST( s->in_pos<s->in_sz ); s->bitbuf |= (uint)s->in[ s->in_pos++ ]<<s->bitcnt; s->bitcnt += 8; }
  uint v = s->bitbuf & ((1U<<n)-1U);
  s->bitbuf >>= n; s->bitcnt -= n;
  return v;
}

static void
huff_build( huff_t *      h,
            uchar const * len,
            int           n ) {
  memset( h->count, 0, sizeof(h->count) );
  for( int i=0; i<n; i++ ) h->count[ len[ i ] ]++;
  h->count[ 0 ] = 0;
  ushort offs[ 16 ] = {0};
  for( int l=1; l<15; l++ ) offs[ l+1 ] = (ushort)(offs[ l ]+h->count[ l ]);
  for( int i=0; i<n; i++ ) if( len[ i ] ) h->symbol[ offs[ len[ i ] ]++ ] = (ushort)i;
}

static int
huff_decode( inf_t *        s,
             huff_t const * h ) {
  int code = 0, first = 0, index = 0;
  for( int l=1; l<16; l++ ) {
    code |= (int)inf_bits( s, 1 );
    int count = h->count[ l ];
    if( code-count<first ) return h->symbol[ index+(code-first) ];
    index += count; first = (first+count)<<1; code <<= 1;
  }
  FD_LOG_ERR(( "bad huffman code" ));
  return -1;
}

static void
inf_codes( inf_t *        s,
           huff_t const * lencode,
           huff_t const * distcode ) {
  static ushort const lbase[ 29 ] = { 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258 };
  static uchar  const lext [ 29 ] = { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };
  static ushort const dbase[ 30 ] = { 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577 };
  static uchar  const dext [ 30 ] = { 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };
  for(;;) {
    int sym = huff_decode( s, lencode );
    if( sym==256 ) return;
    if( sym<256 ) { FD_TEST( s->out_pos<s->out_sz ); s->out[ s->out_pos++ ] = (uchar)sym; continue; }
    sym -= 257; FD_TEST( sym<29 );
    ulong len  = lbase[ sym ]+inf_bits( s, lext[ sym ] );
    int   dsym = huff_decode( s, distcode ); FD_TEST( dsym<30 );
    ulong dist = dbase[ dsym ]+inf_bits( s, dext[ dsym ] );
    FD_TEST( dist<=s->out_pos && s->out_pos+len<=s->out_sz );
    for( ulong i=0UL; i<len; i++, s->out_pos++ ) s->out[ s->out_pos ] = s->out[ s->out_pos-dist ];
  }
}

static void
inflate_( inf_t * s ) {
  int last;
  do {
    last = (int)inf_bits( s, 1 );
    int type = (int)inf_bits( s, 2 );
    if( type==0 ) { /* stored */
      s->bitbuf = 0; s->bitcnt = 0;
      FD_TEST( s->in_pos+4UL<=s->in_sz );
      ulong len = fd_ushort_load_2( s->in+s->in_pos ), nlen = fd_ushort_load_2( s->in+s->in_pos+2UL );
      FD_TEST( len==(~nlen&0xFFFFUL) ); s->in_pos += 4UL;
      FD_TEST( s->in_pos+len<=s->in_sz && s->out_pos+len<=s->out_sz );
      memcpy( s->out+s->out_pos, s->in+s->in_pos, len ); s->in_pos += len; s->out_pos += len;
      continue;
    }
    huff_t lencode, distcode;
    uchar lengths[ 320 ] = {0};
    if( type==1 ) { /* fixed */
      for( int i=0;   i<144; i++ ) lengths[ i ] = 8;
      for( int i=144; i<256; i++ ) lengths[ i ] = 9;
      for( int i=256; i<280; i++ ) lengths[ i ] = 7;
      for( int i=280; i<288; i++ ) lengths[ i ] = 8;
      huff_build( &lencode, lengths, 288 );
      memset( lengths, 5, 30 );
      huff_build( &distcode, lengths, 30 );
    } else { /* dynamic */
      FD_TEST( type==2 );
      static uchar const order[ 19 ] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
      int nlen = (int)inf_bits( s, 5 )+257, ndist = (int)inf_bits( s, 5 )+1, ncode = (int)inf_bits( s, 4 )+4;
      for( int i=0; i<ncode; i++ ) lengths[ order[ i ] ] = (uchar)inf_bits( s, 3 );
      huff_build( &lencode, lengths, 19 );
      for( int i=0; i<nlen+ndist; ) {
        int sym = huff_decode( s, &lencode );
        if( sym<16 ) { lengths[ i++ ] = (uchar)sym; continue; }
        uchar l = 0; int rep;
        if(      sym==16 ) { FD_TEST( i ); l = lengths[ i-1 ]; rep = 3+(int)inf_bits( s, 2 ); }
        else if( sym==17 ) rep = 3+(int)inf_bits( s, 3 );
        else               rep = 11+(int)inf_bits( s, 7 );
        FD_TEST( i+rep<=nlen+ndist );
        while( rep-- ) lengths[ i++ ] = l;
      }
      huff_build( &lencode,  lengths,      nlen  );
      huff_build( &distcode, lengths+nlen, ndist );
    }
    inf_codes( s, &lencode, &distcode );
  } while( !last );
}

/* RFC 1952 member: header, deflate body, CRC32 + ISIZE trailer */

static void
gunzip_( uchar const * gz,
         ulong         gz_sz,
         uchar *       out,
         ulong         out_sz ) {
  FD_TEST( gz_sz>=18UL && gz[ 0 ]==0x1f && gz[ 1 ]==0x8b && gz[ 2 ]==8 );
  uint flg = gz[ 3 ];
  ulong pos = 10UL;
  if( flg&4U ) pos += 2UL+fd_ushort_load_2( gz+pos );            /* FEXTRA */
  if( flg&8U ) { while( gz[ pos ] ) pos++; pos++; }               /* FNAME */
  if( flg&16U ) { while( gz[ pos ] ) pos++; pos++; }              /* FCOMMENT */
  if( flg&2U ) pos += 2UL;                                        /* FHCRC */
  FD_TEST( pos<gz_sz-8UL );
  inf_t s = { .in = gz, .in_sz = gz_sz-8UL, .in_pos = pos, .out = out, .out_sz = out_sz };
  inflate_( &s );
  FD_TEST( s.in_pos==gz_sz-8UL && s.out_pos==out_sz );
  FD_TEST( fd_uint_load_4( gz+gz_sz-8UL )==crc32_( out, out_sz ) );
  FD_TEST( fd_uint_load_4( gz+gz_sz-4UL )==(uint)out_sz );
}

static void
test_assets( void ) {
  ulong cnt = 0UL;
  for( fd_http_static_file_t const * f = STATIC_FILES; f->name; f++, cnt++ ) {
    FD_TEST( f->data && f->data_len && f->zstd_data && f->zstd_data_len && f->gzip_data && f->gzip_data_len );
    ulong raw_sz = *(f->data_len);

    ZSTD_frameHeader fh;
    FD_TEST( !ZSTD_getFrameHeader( &fh, f->zstd_data, *(f->zstd_data_len) ) );
    FD_TEST( fh.frameType==ZSTD_frame );
    FD_TEST( fh.windowSize<=(8UL<<20) );
    FD_TEST( fh.checksumFlag );
    uchar * buf = malloc( raw_sz+1UL );
    FD_TEST( buf );
    FD_TEST( ZSTD_decompress( buf, raw_sz+1UL, f->zstd_data, *(f->zstd_data_len) )==raw_sz );
    FD_TEST( !memcmp( buf, f->data, raw_sz ) );

    memset( buf, 0, raw_sz );
    gunzip_( f->gzip_data, *(f->gzip_data_len), buf, raw_sz );
    FD_TEST( !memcmp( buf, f->data, raw_sz ) );
    free( buf );
  }
  FD_TEST( cnt );
  FD_LOG_NOTICE(( "%lu assets ok", cnt ));
}

static fd_http_server_response_t
get( fd_gui_ctx_t * ctx,
     char const *   path,
     char const *   accept_encoding,
     char const *   if_none_match ) {
  fd_http_server_request_t request = {
    .method                  = FD_HTTP_SERVER_METHOD_GET,
    .path                    = path,
    .ctx                     = ctx,
    .headers.accept_encoding = accept_encoding,
    .headers.if_none_match   = if_none_match,
  };
  return gui_http_request( &request );
}

static void
expect( fd_http_server_response_t const * r,
        fd_http_static_file_t const *     f,
        char const *                      encoding ) {
  uchar const * data     = f->data;
  ulong const * data_len = f->data_len;
  if( encoding && !strcmp( encoding, "zstd" ) ) { data = f->zstd_data; data_len = f->zstd_data_len; }
  if( encoding && !strcmp( encoding, "gzip" ) ) { data = f->gzip_data; data_len = f->gzip_data_len; }
  FD_TEST( r->status==200UL );
  FD_TEST( r->static_body==data && r->static_body_len==*data_len );
  FD_TEST( !encoding ? !r->content_encoding : (r->content_encoding && !strcmp( r->content_encoding, encoding )) );
  FD_TEST( r->vary && !strcmp( r->vary, "Accept-Encoding" ) );
}

static void
test_negotiation( fd_gui_ctx_t * ctx ) {
  fd_http_static_file_t const * index_html = NULL;
  for( fd_http_static_file_t const * f = STATIC_FILES; f->name; f++ ) {
    if( !strcmp( f->name, "/index.html" ) ) index_html = f;
    int zstd_ok = *(f->zstd_data_len)<*(f->data_len);
    int gzip_ok = *(f->gzip_data_len)<*(f->data_len);

    fd_http_server_response_t r;
    r = get( ctx, f->name, NULL,                       "" ); expect( &r, f, NULL );
    r = get( ctx, f->name, "",                         "" ); expect( &r, f, NULL );
    r = get( ctx, f->name, "identity",                 "" ); expect( &r, f, NULL );
    r = get( ctx, f->name, "*",                        "" ); expect( &r, f, NULL );
    r = get( ctx, f->name, "gzip, deflate",            "" ); expect( &r, f, gzip_ok ? "gzip" : NULL );
    r = get( ctx, f->name, "gzip, deflate, br, zstd",  "" ); expect( &r, f, zstd_ok ? "zstd" : gzip_ok ? "gzip" : NULL );
    r = get( ctx, f->name, "ZSTD",                     "" ); expect( &r, f, zstd_ok ? "zstd" : NULL );
    r = get( ctx, f->name, "zstd;q=0, gzip",           "" ); expect( &r, f, gzip_ok ? "gzip" : NULL );
    r = get( ctx, f->name, "zstd;q=0.1, gzip",         "" ); expect( &r, f, gzip_ok ? "gzip" : zstd_ok ? "zstd" : NULL );
    r = get( ctx, f->name, "zstd;q=0.5, gzip;q=0.5",   "" ); expect( &r, f, zstd_ok ? "zstd" : gzip_ok ? "gzip" : NULL );
    r = get( ctx, f->name, "gzip;q=0.9, zstd;q=1",     "" ); expect( &r, f, zstd_ok ? "zstd" : gzip_ok ? "gzip" : NULL );
    r = get( ctx, f->name, "zstd;q=0, gzip;q=0",       "" ); expect( &r, f, NULL );
    r = get( ctx, f->name, "x-zstd, gzipped",          "" ); expect( &r, f, NULL );
  }
  FD_TEST( index_html );

  /* one ETag per representation; 304 only against the negotiated one */
  char const * ae[ 3 ]  = { "", "zstd", "gzip" };
  char const * enc[ 3 ] = { NULL, "zstd", "gzip" };
  for( ulong e=0UL; e<3UL; e++ ) {
    char const * etag = ctx->index_html_etag[ e ];
    FD_TEST( etag[ 0 ]=='"' );
    for( ulong o=0UL; o<e; o++ ) FD_TEST( strcmp( etag, ctx->index_html_etag[ o ] ) );

    fd_http_server_response_t r = get( ctx, "/index.html", ae[ e ], "" );
    expect( &r, index_html, enc[ e ] );
    FD_TEST( r.etag==etag );

    r = get( ctx, "/", ae[ e ], etag );
    FD_TEST( r.status==304UL && r.etag==etag && !r.static_body );
    FD_TEST( r.vary && !strcmp( r.vary, "Accept-Encoding" ) );

    r = get( ctx, "/index.html", ae[ e ], ctx->index_html_etag[ (e+1UL)%3UL ] );
    expect( &r, index_html, enc[ e ] );
  }

  /* assets carry no ETag */
  for( fd_http_static_file_t const * f = STATIC_FILES; f->name; f++ ) {
    if( f==index_html ) continue;
    fd_http_server_response_t r = get( ctx, f->name, "zstd", "*" );
    FD_TEST( r.status==200UL && !r.etag );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_gui_ctx_t * ctx = aligned_alloc( alignof(fd_gui_ctx_t), sizeof(fd_gui_ctx_t) );
  FD_TEST( ctx );
  memset( ctx, 0, sizeof(fd_gui_ctx_t) );
  index_html_etag_init( ctx );

  test_assets();
  test_negotiation( ctx );

  free( ctx );

  (void)rlimit_file_cnt; (void)populate_allowed_seccomp; (void)populate_allowed_fds;
  (void)scratch_align; (void)scratch_footprint; (void)loose_footprint;
  (void)privileged_init; (void)unprivileged_init; (void)stem_run;

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
