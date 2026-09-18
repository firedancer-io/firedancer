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

/* The HPACK dynamic table is a byte ring (buf) holding the name and
   value bytes of every live entry, plus a descriptor ring (entry)
   locating them.  See fd_hpack.h for the size bounds. */

FD_STATIC_ASSERT( 61+FD_HPACK_DTABLE_ENTRY_MAX<=255, hint_index_width );

fd_hpack_dtable_t *
fd_hpack_dtable_init( fd_hpack_dtable_t * dtable,
                      ulong               limit_sz ) {
  if( FD_UNLIKELY( limit_sz>FD_HPACK_DTABLE_SZ_MAX ) ) {
    FD_LOG_WARNING(( "fd_hpack_dtable_init: limit_sz %lu exceeds %u", limit_sz, FD_HPACK_DTABLE_SZ_MAX ));
    return NULL;
  }
  *dtable = (fd_hpack_dtable_t) {
    .limit_sz = (uint)limit_sz,
    .max_sz   = (uint)limit_sz
  };
  return dtable;
}

/* fd_hpack_dtable_slot returns the descriptor ring slot of the entry
   with 1-based dynamic index dyn_idx (1 is the newest entry). */

FD_FN_PURE static inline uint
fd_hpack_dtable_slot( fd_hpack_dtable_t const * dtable,
                      ulong                     dyn_idx ) {
  return (uint)( ( dtable->entry_hi + FD_HPACK_DTABLE_ENTRY_MAX - dyn_idx ) % FD_HPACK_DTABLE_ENTRY_MAX );
}

/* fd_hpack_dtable_evict drops the oldest entry.  Assumes the table is
   not empty. */

static void
fd_hpack_dtable_evict( fd_hpack_dtable_t * dtable ) {
  fd_hpack_dtable_entry_t const * entry = dtable->entry + fd_hpack_dtable_slot( dtable, dtable->entry_cnt );
  dtable->used_sz -= (uint)entry->name_len + (uint)entry->value_len + 32U;
  dtable->entry_cnt--;
}

/* fd_hpack_dtable_{read,write} copy sz bytes {out of,into} the byte
   ring starting at offset off.  Assumes off<FD_HPACK_DTABLE_DATA_MAX
   and sz<=FD_HPACK_DTABLE_DATA_MAX. */

static void
fd_hpack_dtable_read( fd_hpack_dtable_t const * dtable,
                      ulong                     off,
                      uchar *                   out,
                      ulong                     sz ) {
  ulong sz0 = fd_ulong_min( sz, FD_HPACK_DTABLE_DATA_MAX-off );
  fd_memcpy( out,     dtable->buf+off, sz0    );
  fd_memcpy( out+sz0, dtable->buf,     sz-sz0 );
}

static void
fd_hpack_dtable_write( fd_hpack_dtable_t * dtable,
                       ulong               off,
                       char const *        in,
                       ulong               sz ) {
  ulong sz0 = fd_ulong_min( sz, FD_HPACK_DTABLE_DATA_MAX-off );
  fd_memcpy( dtable->buf+off, in,     sz0    );
  fd_memcpy( dtable->buf,     in+sz0, sz-sz0 );
}

uint
fd_hpack_dtable_set_max_sz( fd_hpack_dtable_t * dtable,
                            ulong               max_sz ) {
  ulong limit_sz = dtable ? dtable->limit_sz : 0UL;
  if( FD_UNLIKELY( max_sz>limit_sz ) ) return FD_H2_ERR_COMPRESSION;
  if( FD_UNLIKELY( !dtable ) ) return FD_H2_SUCCESS;
  dtable->max_sz = (uint)max_sz;
  while( FD_UNLIKELY( dtable->entry_cnt && dtable->used_sz>dtable->max_sz ) ) {
    fd_hpack_dtable_evict( dtable );
  }
  return FD_H2_SUCCESS;
}

void
fd_hpack_dtable_insert( fd_hpack_dtable_t * dtable,
                        char const *        name,
                        ulong               name_len,
                        char const *        value,
                        ulong               value_len ) {
  if( FD_UNLIKELY( !dtable ) ) return;

  ulong data_len = name_len + value_len;
  ulong entry_sz = data_len + 32UL;

  /* RFC 7541 Section 4.4: an entry larger than the maximum size empties
     the table and is not added. */
  if( FD_UNLIKELY( entry_sz>dtable->max_sz ) ) {
    dtable->entry_cnt = 0U;
    dtable->used_sz   = 0U;
    return;
  }

  while( dtable->entry_cnt &&
         ( ( dtable->used_sz+entry_sz > dtable->max_sz               ) |
           ( dtable->entry_cnt        >= FD_HPACK_DTABLE_ENTRY_MAX   ) ) ) {
    fd_hpack_dtable_evict( dtable );
  }

  /* Every entry costs at least 32 units, so a table bounded by
     FD_HPACK_DTABLE_SZ_MAX has room for this entry's bytes in buf. */
  ulong off = dtable->data_hi;
  fd_hpack_dtable_write( dtable, off, name, name_len );
  fd_hpack_dtable_write( dtable, (off+name_len)%FD_HPACK_DTABLE_DATA_MAX, value, value_len );

  dtable->entry[ dtable->entry_hi ] = (fd_hpack_dtable_entry_t) {
    .off       = (ushort)off,
    .name_len  = (ushort)name_len,
    .value_len = (ushort)value_len
  };
  dtable->entry_hi  = (uint)( ( dtable->entry_hi+1UL      ) % FD_HPACK_DTABLE_ENTRY_MAX );
  dtable->data_hi   = (uint)( ( off+data_len              ) % FD_HPACK_DTABLE_DATA_MAX  );
  dtable->entry_cnt++;
  dtable->used_sz  += (uint)entry_sz;
}

uint
fd_hpack_dtable_query( fd_hpack_dtable_t const * dtable,
                       ulong                     idx,
                       fd_h2_hdr_t *             hdr,
                       uchar **                  scratch,
                       uchar *                   scratch_end ) {
  if( FD_UNLIKELY( !dtable ) ) return FD_H2_ERR_COMPRESSION;
  ulong dyn_idx = idx-61UL;
  if( FD_UNLIKELY( ( idx<=61UL ) | ( dyn_idx>dtable->entry_cnt ) ) ) return FD_H2_ERR_COMPRESSION;

  fd_hpack_dtable_entry_t const * entry = dtable->entry + fd_hpack_dtable_slot( dtable, dyn_idx );
  ulong   data_len = (ulong)entry->name_len + (ulong)entry->value_len;
  uchar * out      = *scratch;
  if( FD_UNLIKELY( data_len > (ulong)( scratch_end-out ) ) ) return FD_H2_ERR_COMPRESSION;
  fd_hpack_dtable_read( dtable, entry->off, out, data_len );

  *hdr = (fd_h2_hdr_t) {
    .name      = (char const *)out,
    .name_len  = entry->name_len,
    .value     = (char const *)out + entry->name_len,
    .value_len = entry->value_len,
    .hint      = (ushort)( idx | FD_H2_HDR_HINT_NAME_INDEXED )
  };
  *scratch = out+data_len;
  return FD_H2_SUCCESS;
}

fd_hpack_rd_t *
fd_hpack_rd_init( fd_hpack_rd_t * rd,
                  uchar const *   src,
                  ulong           srcsz ) {
  *rd = (fd_hpack_rd_t) {
    .src     = src,
    .src_end = src+srcsz
  };
  /* FIXME slow */
  /* Skip over Dynamic Table Size Updates */
  while( FD_LIKELY( rd->src < rd->src_end ) ) {
    uint b0 = rd->src[0];
    if( FD_UNLIKELY( (b0&0xe0)==0x20 ) ) {
      ulong max_sz = fd_hpack_rd_varint( rd, b0, 0x1f );
      if( FD_UNLIKELY( max_sz!=0UL ) ) break; /* FIXME hacky */
      rd->src++;
    } else {
      break;
    }
  }
  return rd;
}

fd_hpack_rd_t *
fd_hpack_rd_init_dtable( fd_hpack_rd_t *     rd,
                         uchar const *       src,
                         ulong               srcsz,
                         fd_hpack_dtable_t * dtable ) {
  *rd = (fd_hpack_rd_t) {
    .src     = src,
    .src_end = src+srcsz,
    .dtable  = dtable
  };
  /* RFC 7541 Section 4.2: a dynamic table size update only occurs at
     the start of a header block.  Apply the ones found here so that the
     remainder of the block is a pure sequence of header field
     representations. */
  while( rd->src < rd->src_end ) {
    uint b0 = rd->src[0];
    if( FD_LIKELY( (b0&0xe0)!=0x20 ) ) break;
    rd->src++;
    ulong max_sz = fd_hpack_rd_varint( rd, b0, 0x1f );
    if( FD_UNLIKELY( max_sz==ULONG_MAX                              ) ) return NULL;
    if( FD_UNLIKELY( fd_hpack_dtable_set_max_sz( dtable, max_sz )!=FD_H2_SUCCESS ) ) return NULL;
  }
  return rd;
}

/* fd_hpack_rd_indexed selects a header from the HPACK static table or
   from the connection's dynamic table.  Dynamic table entries are
   copied to *scratch. */

static uint
fd_hpack_rd_indexed( fd_hpack_rd_t const * rd,
                     fd_h2_hdr_t *         hdr,
                     ulong                 idx,
                     uchar **              scratch,
                     uchar *               scratch_end ) {
  if( FD_UNLIKELY( idx==0 ) ) return FD_H2_ERR_COMPRESSION;
  if( FD_UNLIKELY( idx>61 ) ) return fd_hpack_dtable_query( rd->dtable, idx, hdr, scratch, scratch_end );
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
                      fd_h2_hdr_t *   hdr,
                      uchar **        scratch,
                      uchar *         scratch_end ) {
  uchar const * end = rd->src_end;
  if( FD_UNLIKELY( rd->src >= end ) ) FD_LOG_CRIT(( "fd_hpack_rd_next called out of bounds" ));

  uint b0 = *(rd->src++);

  if( (b0&0xc0)==0x80 ) {
    /* name indexed, value indexed, index in [0,63], varint sz 0 */
    uint err = fd_hpack_rd_indexed( rd, hdr, b0&0x7f, scratch, scratch_end );
    if( FD_UNLIKELY( err ) ) return err;
    hdr->hint |= FD_H2_HDR_HINT_VALUE_INDEXED;
    return FD_H2_SUCCESS;
  }

  if( b0==0x40 || b0==0x00 || b0==0x10 ) {
    /* name literal, value literal */
    if( FD_UNLIKELY( (ulong)( end-rd->src )<2UL ) ) return FD_H2_ERR_COMPRESSION;

    uint  name_word = *(rd->src++);
    ulong name_len  = fd_hpack_rd_varint( rd, name_word, 0x7f );
    if( FD_UNLIKELY( name_len==ULONG_MAX ) ) return FD_H2_ERR_COMPRESSION;
    if( FD_UNLIKELY( name_len>USHORT_MAX ) ) return FD_H2_ERR_COMPRESSION;
    if( FD_UNLIKELY( name_len>=(ulong)( end-rd->src ) ) ) return FD_H2_ERR_COMPRESSION;
    uchar const * name_p = rd->src;
    rd->src += name_len;

    uint  value_word = *(rd->src++);
    ulong value_len  = fd_hpack_rd_varint( rd, value_word, 0x7f );
    if( FD_UNLIKELY( value_len==ULONG_MAX ) ) return FD_H2_ERR_COMPRESSION;
    if( FD_UNLIKELY( value_len>(ulong)( end-rd->src ) ) ) return FD_H2_ERR_COMPRESSION;
    uchar const * value_p = rd->src;
    rd->src += value_len;

    hdr->name      = (char const *)name_p;
    hdr->name_len  = (ushort)name_len;
    hdr->value     = (char const *)value_p;
    hdr->value_len = (uint)value_len;
    hdr->hint      = fd_ushort_if( name_word&0x80,  FD_H2_HDR_HINT_NAME_HUFFMAN,  0 ) |
                     fd_ushort_if( value_word&0x80, FD_H2_HDR_HINT_VALUE_HUFFMAN, 0 ) |
                     fd_ushort_if( b0==0x40,        FD_HPACK_HINT_INSERT,         0 );
    return FD_H2_SUCCESS;
  }

  if( (b0&0xc0)==0x40 || (b0&0xf0)==0x00 || (b0&0xf0)==0x10 ) {
    /* name indexed, value literal */
    uint  name_mask = (b0&0xc0)==0x40 ? 0x3f : 0x0f;
    ulong name_idx  = fd_hpack_rd_varint( rd, b0, name_mask );

    if( FD_UNLIKELY( rd->src >= end ) ) return FD_H2_ERR_COMPRESSION;
    uint  value_word = *(rd->src++);
    ulong value_len  = fd_hpack_rd_varint( rd, value_word, 0x7f );
    if( FD_UNLIKELY( value_len==ULONG_MAX ) ) return FD_H2_ERR_COMPRESSION;
    if( FD_UNLIKELY( value_len>(ulong)( end-rd->src ) ) ) return FD_H2_ERR_COMPRESSION;
    uchar const * value_p = rd->src;
    rd->src += value_len;

    uint err = fd_hpack_rd_indexed( rd, hdr, name_idx, scratch, scratch_end );
    if( FD_UNLIKELY( err ) ) return FD_H2_ERR_COMPRESSION;
    hdr->value     = (char const *)value_p;
    hdr->value_len = (uint)value_len;
    hdr->hint     |= fd_ushort_if( value_word&0x80, FD_H2_HDR_HINT_VALUE_HUFFMAN, 0 ) |
                     fd_ushort_if( (b0&0xc0)==0x40, FD_HPACK_HINT_INSERT,         0 );
    return FD_H2_SUCCESS;
  }

  if( FD_UNLIKELY( (b0&0xc0)==0xc0 ) ) {
    /* name indexed, value indexed, index >=128 */
    ulong idx = fd_hpack_rd_varint( rd, b0, 0x7f ); /* may fail */
    uint  err = fd_hpack_rd_indexed( rd, hdr, idx, scratch, scratch_end );
    if( FD_UNLIKELY( err ) ) return err;
    hdr->hint |= FD_H2_HDR_HINT_VALUE_INDEXED;
    return FD_H2_SUCCESS;
  }

  /* Dynamic table size update outside the start of the header block
     (RFC 7541 Section 4.2) */
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
  uchar * scratch_ = *scratch;

  uint err = fd_hpack_rd_next_raw( hpack_rd, hdr, &scratch_, scratch_end );
  if( FD_UNLIKELY( err ) ) return err;

  if( hdr->hint & FD_H2_HDR_HINT_NAME_HUFFMAN ) {
    if( FD_UNLIKELY( fd_hpack_decoded_sz_max( hdr->name_len )>(ulong)( scratch_end-scratch_ ) ) ) return FD_H2_ERR_COMPRESSION;
    nghttp2_hd_huff_decode_context ctx[1];
    nghttp2_hd_huff_decode_context_init( ctx );
    nghttp2_buf buf = { .last = scratch_ };
    if( FD_UNLIKELY( nghttp2_hd_huff_decode( ctx, &buf, (uchar const *)hdr->name, hdr->name_len, 1 )<0 ) ) return FD_H2_ERR_COMPRESSION;
    if( FD_UNLIKELY( buf.last-scratch_>USHORT_MAX ) ) return FD_H2_ERR_COMPRESSION;
    hdr->name     = (char const *)scratch_;
    hdr->name_len = (ushort)( buf.last-scratch_ );
    scratch_      = buf.last;
  }

  if( hdr->hint & FD_H2_HDR_HINT_VALUE_HUFFMAN ) {
    if( FD_UNLIKELY( fd_hpack_decoded_sz_max( hdr->value_len )>(ulong)( scratch_end-scratch_ ) ) ) return FD_H2_ERR_COMPRESSION;
    nghttp2_hd_huff_decode_context ctx[1];
    nghttp2_hd_huff_decode_context_init( ctx );
    nghttp2_buf buf = { .last = scratch_ };
    if( FD_UNLIKELY( nghttp2_hd_huff_decode( ctx, &buf, (uchar const *)hdr->value, hdr->value_len, 1 )<0 ) ) return FD_H2_ERR_COMPRESSION;
    hdr->value     = (char const *)scratch_;
    hdr->value_len = (uint)( buf.last-scratch_ );
    scratch_       = buf.last;
  }

  if( hdr->hint & FD_HPACK_HINT_INSERT ) {
    fd_hpack_dtable_insert( hpack_rd->dtable,
                            hdr->name,  hdr->name_len,
                            hdr->value, hdr->value_len );
  }

  *scratch = scratch_;
  hdr->hint &= (ushort)~( FD_H2_HDR_HINT_HUFFMAN | FD_HPACK_HINT_INSERT );
  return FD_H2_SUCCESS;
}
