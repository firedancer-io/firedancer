#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "../fd_util.h"
#include "fd_textstream.h"

struct fd_textstream_blk {
    struct fd_textstream_blk * next;
    ulong used;
};
typedef struct fd_textstream_blk fd_textstream_blk_t;

fd_textstream_t * fd_textstream_new( fd_textstream_t * strm,
                                     fd_valloc_t       valloc,
                                     ulong             alloc_sz) {
  strm->valloc = valloc;
  strm->alloc_sz = alloc_sz;
  fd_textstream_blk_t * blk = (fd_textstream_blk_t *)
    fd_valloc_malloc(valloc, alignof(fd_textstream_blk_t), sizeof(fd_textstream_blk_t) + alloc_sz);
  if ( blk == NULL )
    return NULL;
  blk->next = NULL;
  blk->used = 0;
  strm->first_blk = strm->last_blk = blk;
  return strm;
}

void fd_textstream_destroy( fd_textstream_t * strm ) {
  for ( fd_textstream_blk_t * blk = strm->first_blk; blk; ) {
    fd_textstream_blk_t * next = blk->next;
    fd_valloc_free(strm->valloc, blk);
    blk = next;
  }
}

void fd_textstream_clear( fd_textstream_t * strm ) {
  for ( fd_textstream_blk_t * blk = strm->first_blk->next; blk; ) {
    fd_textstream_blk_t * next = blk->next;
    fd_valloc_free(strm->valloc, blk);
    blk = next;
  }
  fd_textstream_blk_t * blk = strm->first_blk;
  blk->next = NULL;
  blk->used = 0;
  strm->last_blk = blk;
}

fd_textstream_blk_t * fd_textstream_new_blk( fd_textstream_t * strm ) {
  fd_textstream_blk_t * blk = (fd_textstream_blk_t *)
    fd_valloc_malloc(strm->valloc, alignof(fd_textstream_blk_t), sizeof(fd_textstream_blk_t) + strm->alloc_sz);
  if ( blk == NULL )
    return NULL;
  blk->next = NULL;
  blk->used = 0;
  strm->last_blk->next = blk;
  strm->last_blk = blk;
  return blk;
}

int fd_textstream_append( fd_textstream_t * strm,
                          const char *      text,
                          ulong             text_sz ) {
  fd_textstream_blk_t * blk = strm->last_blk;
  if ( FD_LIKELY( blk->used + text_sz <= strm->alloc_sz ) ) {
    /* pass */
  } else if ( text_sz > strm->alloc_sz ) {
    return -1;
  } else {
    blk = fd_textstream_new_blk( strm );
    if ( blk == NULL )
      return -1;
  }
  char* buf = (char*)(blk + 1);
  fd_memcpy(buf + blk->used, text, text_sz);
  blk->used += text_sz;
  return 0;
}

ulong fd_textstream_total_size( fd_textstream_t * strm ) {
  ulong tot = 0;
  for ( fd_textstream_blk_t * blk = strm->first_blk; blk; blk = blk->next )
    tot += blk->used;
  return tot;
}

int fd_textstream_get_output( fd_textstream_t * strm,
                              char * outbuf) {
  ulong tot = 0;
  for ( fd_textstream_blk_t * blk = strm->first_blk; blk; blk = blk->next ) {
    fd_memcpy(outbuf + tot, blk+1, blk->used);
    tot += blk->used;
  }
  return 0;
}

ulong fd_textstream_get_iov_count( fd_textstream_t * strm ) {
  ulong tot = 0;
  for ( fd_textstream_blk_t * blk = strm->first_blk; blk; blk = blk->next )
    tot++;
  return tot;
}

int fd_textstream_get_iov( fd_textstream_t * strm,
                           struct fd_iovec * iov) {
  ulong tot = 0;
  for ( fd_textstream_blk_t * blk = strm->first_blk; blk; blk = blk->next ) {
    iov[tot].iov_base = blk+1;
    iov[tot].iov_len = blk->used;
    tot++;
  }
  return 0;
}

int fd_textstream_encode_utf8( fd_textstream_t * strm,
                               const uint *      chars,
                               ulong             chars_sz ) {
  ulong out_sz = 0;
  for ( ulong i = 0; i < chars_sz; ++i ) {
    uint ch = chars[i];
    if (ch < 0x80)
      out_sz += 1;
    else if (ch < 0x800)
      out_sz += 2;
    else if (ch < 0x10000)
      out_sz += 3;
    else if (ch < 0x110000)
      out_sz += 4;
    else
      return -1;
  }

  fd_textstream_blk_t * blk = strm->last_blk;
  if ( FD_LIKELY( blk->used + out_sz <= strm->alloc_sz ) ) {
    /* pass */
  } else if ( out_sz > strm->alloc_sz ) {
    return -1;
  } else {
    blk = fd_textstream_new_blk( strm );
    if ( blk == NULL )
      return -1;
  }
  char* dest = (char*)(blk + 1) + blk->used;

  ulong j = 0;
  for ( ulong i = 0; i < chars_sz; ++i ) {
    uint ch = chars[i];
    if (ch < 0x80) {
      dest[j++] = (char)ch;
    } else if (ch < 0x800) {
      dest[j++] = (char)((ch>>6) | 0xC0);
      dest[j++] = (char)((ch & 0x3F) | 0x80);
    } else if (ch < 0x10000) {
      dest[j++] = (char)((ch>>12) | 0xE0);
      dest[j++] = (char)(((ch>>6) & 0x3F) | 0x80);
      dest[j++] = (char)((ch & 0x3F) | 0x80);
    } else if (ch < 0x110000) {
      dest[j++] = (char)((ch>>18) | 0xF0);
      dest[j++] = (char)(((ch>>12) & 0x3F) | 0x80);
      dest[j++] = (char)(((ch>>6) & 0x3F) | 0x80);
      dest[j++] = (char)((ch & 0x3F) | 0x80);
    }
  }

  blk->used += j;
  return 0;
}

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int fd_textstream_encode_base58( fd_textstream_t * strm,
                                 const void *      data,
                                 ulong             data_sz ) {
  /* Prevent explosive growth in computation */
  if (data_sz > (1U<<16))
    return -1;

  const uchar* bin = (const uchar*)data;
  ulong carry;
  ulong i, j, high, zcount = 0;
  ulong size;

  while (zcount < data_sz && !bin[zcount])
    ++zcount;

  /* Temporary buffer size */
  size = (data_sz - zcount) * 138 / 100 + 1;
  uchar buf[size];
  fd_memset(buf, 0, size);

  for (i = zcount, high = size - 1; i < data_sz; ++i, high = j) {
    for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
      carry += 256UL * (ulong)buf[j];
      buf[j] = (uchar)(carry % 58);
      carry /= 58UL;
      if (!j) {
        // Otherwise j wraps to maxint which is > high
        break;
      }
    }
  }

  for (j = 0; j < size && !buf[j]; ++j) ;

  ulong out_sz = zcount + size - j;
  fd_textstream_blk_t * blk = strm->last_blk;
  if ( FD_LIKELY( blk->used + out_sz <= strm->alloc_sz ) ) {
    /* pass */
  } else if ( out_sz > strm->alloc_sz ) {
    return -1;
  } else {
    blk = fd_textstream_new_blk( strm );
    if ( blk == NULL )
      return -1;
  }
  char* b58 = (char*)(blk + 1) + blk->used;

  if (zcount)
    fd_memset(b58, '1', zcount);
  for (i = zcount; j < size; ++i, ++j)
    b58[i] = b58digits_ordered[buf[j]];

  blk->used += i;

  return 0;
}

static char base64_encoding_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

int fd_textstream_encode_base64( fd_textstream_t * strm,
                                 const void *      data,
                                 ulong             data_sz ) {
  ulong out_sz = 4 * ((data_sz + 2) / 3);
  fd_textstream_blk_t * blk = strm->last_blk;
  if ( FD_LIKELY( blk->used + out_sz <= strm->alloc_sz ) ) {
    /* pass */
  } else if ( out_sz > strm->alloc_sz ) {
    return -1;
  } else {
    blk = fd_textstream_new_blk( strm );
    if ( blk == NULL )
      return -1;
  }
  char* out_data = (char*)(blk + 1) + blk->used;

  ulong j = 0;
  for (ulong i = 0; i < data_sz; ) {
    switch (data_sz - i) {
    default: { /* 3 and above */
      uint octet_a = ((uchar*)data)[i++];
      uint octet_b = ((uchar*)data)[i++];
      uint octet_c = ((uchar*)data)[i++];
      uint triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
      out_data[j++] = base64_encoding_table[(triple >> 3 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 2 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 1 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 0 * 6) & 0x3F];
      break;
    }
    case 2: {
      uint octet_a = ((uchar*)data)[i++];
      uint octet_b = ((uchar*)data)[i++];
      uint triple = (octet_a << 0x10) + (octet_b << 0x08);
      out_data[j++] = base64_encoding_table[(triple >> 3 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 2 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 1 * 6) & 0x3F];
      out_data[j++] = '=';
      break;
    }
    case 1: {
      uint octet_a = ((uchar*)data)[i++];
      uint triple = (octet_a << 0x10);
      out_data[j++] = base64_encoding_table[(triple >> 3 * 6) & 0x3F];
      out_data[j++] = base64_encoding_table[(triple >> 2 * 6) & 0x3F];
      out_data[j++] = '=';
      out_data[j++] = '=';
      break;
    }
    }
  }

  blk->used += j;
  return 0;
}

static const char hex_encoding_table[] = "0123456789ABCDEF";

int fd_textstream_encode_hex( fd_textstream_t * strm,
                              const void *      data,
                              ulong             data_sz ) {
  ulong out_sz = 2 * data_sz;
  fd_textstream_blk_t * blk = strm->last_blk;
  if ( FD_LIKELY( blk->used + out_sz <= strm->alloc_sz ) ) {
    /* pass */
  } else if ( out_sz > strm->alloc_sz ) {
    return -1;
  } else {
    blk = fd_textstream_new_blk( strm );
    if ( blk == NULL )
      return -1;
  }
  char* out_data = (char*)(blk + 1) + blk->used;

  ulong j = 0;
  for (ulong i = 0; i < data_sz; ) {
    uint octet = ((uchar*)data)[i++];
    out_data[j++] = hex_encoding_table[(octet >> 4) & 0xF];
    out_data[j++] = hex_encoding_table[octet & 0xF];
  }

  blk->used += j;
  return 0;
}

int fd_textstream_sprintf( fd_textstream_t * strm, const char* format, ... ) {
  fd_textstream_blk_t * blk = strm->last_blk;
  ulong remain = strm->alloc_sz - blk->used;
  char* buf = (char*)(blk + 1) + blk->used;
  va_list ap;
  va_start(ap, format);
  int r = vsnprintf(buf, remain, format, ap);
  va_end(ap);
  if (r >= 0 && (uint)r < remain) {
    blk->used += (uint)r;
    return 0;
  }

  blk = fd_textstream_new_blk( strm );
  if ( blk == NULL )
    return -1;

  remain = strm->alloc_sz;
  buf = (char*)(blk + 1);
  va_start(ap, format);
  r = vsnprintf(buf, remain, format, ap);
  va_end(ap);
  if (r >= 0 && (uint)r < remain) {
    blk->used = (uint)r;
    return 0;
  }

  return -1;
}
