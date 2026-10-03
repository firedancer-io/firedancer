#include "fd_hpack.h"
#include "fd_h2_base.h"
#include "fd_hpack_private.h"
#include "nghttp2_hd_huffman.h"
#include "../../util/log/fd_log.h"

fd_hpack_static_entry_t const
fd_hpack_static_table[ 62 ] = {
  [  1 ] = { ":authority",                       10,  0 },
  [  2 ] = { ":method"         "GET",             7,  3 },
  [  3 ] = { ":method"         "POST",            7,  4 },
  [  4 ] = { ":path"           "/",               5,  1 },
  [  5 ] = { ":path"           "/index.html",     5, 11 },
  [  6 ] = { ":scheme"         "http",            7,  4 },
  [  7 ] = { ":scheme"         "https",           7,  5 },
  [  8 ] = { ":status"         "200",             7,  3 },
  [  9 ] = { ":status"         "204",             7,  3 },
  [ 10 ] = { ":status"         "206",             7,  3 },
  [ 11 ] = { ":status"         "304",             7,  3 },
  [ 12 ] = { ":status"         "400",             7,  3 },
  [ 13 ] = { ":status"         "404",             7,  3 },
  [ 14 ] = { ":status"         "500",             7,  3 },
  [ 15 ] = { "accept-charset",                   14,  0 },
  [ 16 ] = { "accept-encoding" "gzip, deflate",  15, 13 },
  [ 17 ] = { "accept-language",                  15,  0 },
  [ 18 ] = { "accept-ranges",                    13,  0 },
  [ 19 ] = { "accept",                            6,  0 },
  [ 20 ] = { "access-control-allow-origin",      27,  0 },
  [ 21 ] = { "age",                               3,  0 },
  [ 22 ] = { "allow",                             5,  0 },
  [ 23 ] = { "authorization",                    13,  0 },
  [ 24 ] = { "cache-control",                    13,  0 },
  [ 25 ] = { "content-disposition",              19,  0 },
  [ 26 ] = { "content-encoding",                 16,  0 },
  [ 27 ] = { "content-language",                 16,  0 },
  [ 28 ] = { "content-length",                   14,  0 },
  [ 29 ] = { "content-location",                 16,  0 },
  [ 30 ] = { "content-range",                    13,  0 },
  [ 31 ] = { "content-type",                     12,  0 },
  [ 32 ] = { "cookie",                            6,  0 },
  [ 33 ] = { "date",                              4,  0 },
  [ 34 ] = { "etag",                              4,  0 },
  [ 35 ] = { "expect",                            6,  0 },
  [ 36 ] = { "expires",                           7,  0 },
  [ 37 ] = { "from",                              4,  0 },
  [ 38 ] = { "host",                              4,  0 },
  [ 39 ] = { "if-match",                          8,  0 },
  [ 40 ] = { "if-modified-since",                17,  0 },
  [ 41 ] = { "if-none-match",                    13,  0 },
  [ 42 ] = { "if-range",                          8,  0 },
  [ 43 ] = { "if-unmodified-since",              19,  0 },
  [ 44 ] = { "last-modified",                    13,  0 },
  [ 45 ] = { "link",                              4,  0 },
  [ 46 ] = { "location",                          8,  0 },
  [ 47 ] = { "max-forwards",                     12,  0 },
  [ 48 ] = { "proxy-authenticate",               18,  0 },
  [ 49 ] = { "proxy-authorization",              19,  0 },
  [ 50 ] = { "range",                             5,  0 },
  [ 51 ] = { "referer",                           7,  0 },
  [ 52 ] = { "refresh",                           7,  0 },
  [ 53 ] = { "retry-after",                      11,  0 },
  [ 54 ] = { "server",                            6,  0 },
  [ 55 ] = { "set-cookie",                       10,  0 },
  [ 56 ] = { "strict-transport-security",        25,  0 },
  [ 57 ] = { "transfer-encoding",                17,  0 },
  [ 58 ] = { "user-agent",                       10,  0 },
  [ 59 ] = { "vary",                              4,  0 },
  [ 60 ] = { "via",                               3,  0 },
  [ 61 ] = { "www-authenticate",                 16,  0 }
};

fd_hpack_rd_t *
fd_hpack_rd_init( fd_hpack_rd_t * rd,
                  uchar const *   src,
                  ulong           srcsz ) {
  *rd = (fd_hpack_rd_t) {
    .src     = src,
    .src_end = src+srcsz
  };
  /* Skip Dynamic Table Size Updates to zero.  Others fail in rd_next. */
  while( rd->src<rd->src_end && rd->src[0]==0x20 ) rd->src++;
  return rd;
}

/* fd_hpack_rd_indexed selects a header from HPACK dictionaries.
   Currently, only supports the static table.  (Pretends that the
   dynamic table size is 0). */

static uint
fd_hpack_rd_indexed( fd_h2_hdr_t * hdr,
                     ulong         idx ) {
  if( FD_UNLIKELY( idx==0 || idx>61 ) ) return FD_H2_ERR_COMPRESSION;
  fd_hpack_static_entry_t const * entry = &fd_hpack_static_table[ idx ];
  *hdr = (fd_h2_hdr_t) {
    .name      = entry->entry,
    .name_len  = entry->name_len,
    .value     = entry->entry + entry->name_len,
    .value_len = entry->value_len,
    .hint      = (ushort)idx | FD_H2_HDR_HINT_NAME_INDEXED,
  };
  return FD_H2_SUCCESS;
}

static uint
fd_hpack_rd_next_raw( fd_hpack_rd_t * rd,
                      fd_h2_hdr_t *   hdr ) {
  uchar const * end = rd->src_end;
  if( FD_UNLIKELY( rd->src >= end ) ) FD_LOG_CRIT(( "fd_hpack_rd_next called out of bounds" ));

  uint b0 = *(rd->src++);

  if( (b0&0xc0)==0x80 ) {
    /* name indexed, value indexed, index in [0,63], varint sz 0 */
    uint err = fd_hpack_rd_indexed( hdr, b0&0x7f );
    hdr->hint |= FD_H2_HDR_HINT_VALUE_INDEXED;
    return err;
  }

  if( b0==0x40 || b0==0x00 || b0==0x10 ) {
    /* name literal, value literal */
    if( FD_UNLIKELY( rd->src+2 > end ) ) return FD_H2_ERR_COMPRESSION;

    uint  name_word = *(rd->src++);
    ulong name_len  = fd_hpack_rd_varint( rd, name_word, 0x7f );
    if( FD_UNLIKELY( name_len==ULONG_MAX     ) ) return FD_H2_ERR_COMPRESSION;
    if( FD_UNLIKELY( rd->src+name_len >= end ) ) return FD_H2_ERR_COMPRESSION;
    uchar const * name_p = rd->src;
    rd->src += name_len;

    uint  value_word = *(rd->src++);
    ulong value_len  = fd_hpack_rd_varint( rd, value_word, 0x7f );
    if( FD_UNLIKELY( value_len==ULONG_MAX    ) ) return FD_H2_ERR_COMPRESSION;
    if( FD_UNLIKELY( rd->src+value_len > end ) ) return FD_H2_ERR_COMPRESSION;
    uchar const * value_p = rd->src;
    rd->src += value_len;

    hdr->name      = (char const *)name_p;
    hdr->name_len  = (ushort)name_len;
    hdr->value     = (char const *)value_p;
    hdr->value_len = (uint)value_len;
    hdr->hint      = fd_ushort_if( name_word&0x80,  FD_H2_HDR_HINT_NAME_HUFFMAN,  0 ) |
                     fd_ushort_if( value_word&0x80, FD_H2_HDR_HINT_VALUE_HUFFMAN, 0 );
    return FD_H2_SUCCESS;
  }

  if( (b0&0xc0)==0x40 || (b0&0xf0)==0x00 || (b0&0xf0)==0x10 ) {
    /* name indexed, value literal */
    uint  name_mask = (b0&0xc0)==0x40 ? 0x3f : 0x0f;
    ulong name_idx  = fd_hpack_rd_varint( rd, b0, name_mask );

    if( FD_UNLIKELY( rd->src >= end ) ) return FD_H2_ERR_COMPRESSION;
    uint  value_word = *(rd->src++);
    ulong value_len  = fd_hpack_rd_varint( rd, value_word, 0x7f );
    if( FD_UNLIKELY( value_len==ULONG_MAX    ) ) return FD_H2_ERR_COMPRESSION;
    if( FD_UNLIKELY( rd->src+value_len > end ) ) return FD_H2_ERR_COMPRESSION;
    uchar const * value_p = rd->src;
    rd->src += value_len;

    uint err = fd_hpack_rd_indexed( hdr, name_idx );
    if( FD_UNLIKELY( err ) ) return FD_H2_ERR_COMPRESSION;
    hdr->value     = (char const *)value_p;
    hdr->value_len = (uint)value_len;
    hdr->hint     |= fd_ushort_if( value_word&0x80, FD_H2_HDR_HINT_VALUE_HUFFMAN, 0 );
    return FD_H2_SUCCESS;
  }

  if( FD_UNLIKELY( (b0&0xc0)==0xc0 ) ) {
    /* name indexed, value indexed, index >=128 */
    ulong idx = fd_hpack_rd_varint( rd, b0, 0x7f ); /* may fail */
    return fd_hpack_rd_indexed( hdr, idx );
  }

  /* FIXME slow */
  /* Skip over Dynamic Table Size Updates */
  while( FD_LIKELY( rd->src < end ) ) {
    b0 = rd->src[0];
    if( FD_UNLIKELY( (b0&0xe0)==0x20 ) ) {
      ulong max_sz = fd_hpack_rd_varint( rd, b0, 0x1f );
      if( FD_UNLIKELY( max_sz!=0UL ) ) return FD_H2_ERR_COMPRESSION;
      rd->src++;
    } else {
      break;
    }
  }

  /* Unknown HPACK instruction */
  return FD_H2_ERR_COMPRESSION;
}

/* fd_hpack_decoded_sz_max returns an upper bound for the number of
   decoded bytes given an arbitrary HPACK Huffman coding of enc_sz
   bytes.  The smallest HPACK symbol is 5 bits large.  Therefore, the
   true bound is closer to (enc_sz*8)/5.  To defend against possible
   bugs in huff_decode_table, we use a more conservative estimate,
   namely the greatest amount of bytes that nghttp2_hd_huff_decode can
   produce regardless of the content of huff_decode_table. */

static inline ulong
fd_hpack_decoded_sz_max( ulong enc_sz ) {
  return enc_sz*2UL;
}

uint
fd_hpack_rd_next( fd_hpack_rd_t * hpack_rd,
                  fd_h2_hdr_t *   hdr,
                  uchar **        scratch,
                  uchar *         scratch_end ) {
  uint err = fd_hpack_rd_next_raw( hpack_rd, hdr );
  if( FD_UNLIKELY( err ) ) return err;

  uchar * scratch_ = *scratch;

  if( hdr->hint & FD_H2_HDR_HINT_NAME_HUFFMAN ) {
    if( FD_UNLIKELY( scratch_+fd_hpack_decoded_sz_max( hdr->name_len )>scratch_end ) ) return FD_H2_ERR_COMPRESSION;
    nghttp2_hd_huff_decode_context ctx[1];
    nghttp2_hd_huff_decode_context_init( ctx );
    nghttp2_buf buf = { .last = scratch_ };
    if( FD_UNLIKELY( nghttp2_hd_huff_decode( ctx, &buf, (uchar const *)hdr->name, hdr->name_len, 1 )<0 ) ) return FD_H2_ERR_COMPRESSION;
    hdr->name     = (char const *)scratch_;
    hdr->name_len = (ushort)( buf.last-scratch_ );
    scratch_      = buf.last;
  }

  if( hdr->hint & FD_H2_HDR_HINT_VALUE_HUFFMAN ) {
    if( FD_UNLIKELY( scratch_+fd_hpack_decoded_sz_max( hdr->value_len )>scratch_end ) ) return FD_H2_ERR_COMPRESSION;
    nghttp2_hd_huff_decode_context ctx[1];
    nghttp2_hd_huff_decode_context_init( ctx );
    nghttp2_buf buf = { .last = scratch_ };
    if( FD_UNLIKELY( nghttp2_hd_huff_decode( ctx, &buf, (uchar const *)hdr->value, hdr->value_len, 1 )<0 ) ) return FD_H2_ERR_COMPRESSION;
    hdr->value     = (char const *)scratch_;
    hdr->value_len = (uint)( buf.last-scratch_ );
    scratch_       = buf.last;
  }

  *scratch = scratch_;
  hdr->hint &= (ushort)~FD_H2_HDR_HINT_HUFFMAN;
  return FD_H2_SUCCESS;
}

/* Incremental decoding for fields that need not be retained.  Only one
   integer or one encoded string is pending at a time.  FIELD, NAME_LEN
   and VALUE_LEN each read one integer (name index or string length). */

#define FD_HPACK_SKIP_FIELD     0U
#define FD_HPACK_SKIP_NAME_LEN  1U
#define FD_HPACK_SKIP_VALUE_LEN 2U
#define FD_HPACK_SKIP_NAME      3U
#define FD_HPACK_SKIP_VALUE     4U
#define FD_HPACK_SKIP_ERROR     5U

/* fd_hpack_skip_next[ phase ][ integer==0 ] follows a completed integer */
static uchar const fd_hpack_skip_next[ 3 ][ 2 ] = {
  { FD_HPACK_SKIP_VALUE_LEN, FD_HPACK_SKIP_NAME_LEN  },
  { FD_HPACK_SKIP_NAME,      FD_HPACK_SKIP_VALUE_LEN },
  { FD_HPACK_SKIP_VALUE,     FD_HPACK_SKIP_FIELD     }
};

uint
fd_hpack_skip_feed( fd_hpack_skip_t * skip,
                    uchar const *     src,
                    ulong             srcsz,
                    int               fin ) {
  if( FD_UNLIKELY( skip->phase==FD_HPACK_SKIP_ERROR ) ) return FD_H2_ERR_COMPRESSION;
  while( srcsz ) {
    if( skip->phase>=FD_HPACK_SKIP_NAME ) {
      ulong chunk_sz = fd_ulong_min( srcsz, skip->integer );
      if( skip->huff_state ) {
        /* The decoder emits at most two symbols per encoded octet.
           Reuse a small sink while retaining only its decoding state. */
        uchar sink[ 256 ];
        nghttp2_hd_huff_decode_context ctx = { .fstate = skip->huff_state };
        chunk_sz = fd_ulong_min( chunk_sz, sizeof(sink)/2UL );
        nghttp2_buf buf = { .last = sink };
        if( FD_UNLIKELY( nghttp2_hd_huff_decode( &ctx, &buf, src, chunk_sz, chunk_sz==skip->integer )<0 ) ) goto fail;
        /* A decoded EOS reaches the terminal failure state even before
           the announced encoded string length has been consumed. */
        if( FD_UNLIKELY( (ctx.fstate&0x1ffU)==256U ) ) goto fail;
        skip->huff_state = ctx.fstate;
      }
      src           += chunk_sz;
      srcsz         -= chunk_sz;
      skip->integer -= chunk_sz;
      if( !skip->integer ) skip->phase = skip->phase==FD_HPACK_SKIP_NAME ? FD_HPACK_SKIP_VALUE_LEN : FD_HPACK_SKIP_FIELD;
      continue;
    }

    uint byte = *src++;
    srcsz--;
    if( skip->int_shift ) {
      /* Continuation octet.  At most eight, so the shift is at most 49. */
      skip->integer += (ulong)(byte&0x7fU) << (skip->int_shift-7U);
      if( FD_UNLIKELY( skip->phase==FD_HPACK_SKIP_FIELD && skip->integer>61UL ) ) goto fail;
      if( byte&0x80U ) {
        if( FD_UNLIKELY( skip->int_shift==56U ) ) goto fail;
        skip->int_shift = (uchar)( skip->int_shift+7U );
        continue;
      }
    } else {
      uint mask = 0x7fU;
      if( skip->phase==FD_HPACK_SKIP_FIELD ) {
        if( (byte&0xe0U)==0x20U ) {
          if( FD_UNLIKELY( byte!=0x20U || skip->field_seen ) ) goto fail;
          continue;
        }
        skip->field_seen = 1U;
        /* Every supported indexed field fits in its seven-bit prefix. */
        if( byte&0x80U ) {
          if( FD_UNLIKELY( !(byte&0x7fU) || (byte&0x7fU)>61U ) ) goto fail;
          continue;
        }
        mask = byte&0x40U ? 0x3fU : 0x0fU;
        if( FD_UNLIKELY( (byte&mask)>61U ) ) goto fail;
      } else {
        /* All Huffman DFA states are nonzero, leaving zero for raw data. */
        skip->huff_state = byte&0x80U ? NGHTTP2_HUFF_ACCEPTED : 0U;
      }
      skip->integer = byte&mask;
      if( skip->integer==mask ) {
        skip->int_shift = 7U;
        continue;
      }
    }
    skip->int_shift = 0U;
    skip->phase     = fd_hpack_skip_next[ skip->phase ][ !skip->integer ];
  }
  if( FD_UNLIKELY( fin && ( skip->phase || skip->int_shift ) ) ) goto fail;
  return FD_H2_SUCCESS;

fail:
  skip->phase = FD_HPACK_SKIP_ERROR;
  return FD_H2_ERR_COMPRESSION;
}
