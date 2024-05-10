#ifndef HEADER_fd_src_util_textstream_fd_textstream_h
#define HEADER_fd_src_util_textstream_fd_textstream_h

#include "../../util/valloc/fd_valloc.h"

struct fd_textstream_blk;

struct fd_textstream {
    fd_valloc_t valloc;
    ulong alloc_sz;
    struct fd_textstream_blk * first_blk;
    struct fd_textstream_blk * last_blk;
};

typedef struct fd_textstream fd_textstream_t;

fd_textstream_t * fd_textstream_new( fd_textstream_t * strm,
                                     fd_valloc_t       valloc,
                                     ulong             alloc_sz);

void fd_textstream_clear( fd_textstream_t * strm );

void fd_textstream_destroy( fd_textstream_t * strm );

int fd_textstream_append( fd_textstream_t * strm,
                          const char *      text,
                          ulong             text_sz );

ulong fd_textstream_total_size( fd_textstream_t * strm );

int fd_textstream_get_output( fd_textstream_t * strm,
                              char * outbuf);

struct fd_iovec {
  void  *iov_base;    /* Starting address */
  ulong  iov_len;     /* Number of bytes to transfer */
};
ulong fd_textstream_get_iov_count( fd_textstream_t * strm );

int fd_textstream_get_iov( fd_textstream_t * strm,
                           struct fd_iovec * iov);

int fd_textstream_encode_utf8( fd_textstream_t * strm,
                               const uint *      chars,
                               ulong             chars_sz );

int fd_textstream_encode_base58( fd_textstream_t * strm,
                                 const void *      data,
                                 ulong             data_sz );

int fd_textstream_encode_base64( fd_textstream_t * strm,
                                 const void *      data,
                                 ulong             data_sz );

int fd_textstream_encode_hex( fd_textstream_t * strm,
                              const void *      data,
                              ulong             data_sz );

int fd_textstream_sprintf( fd_textstream_t * strm, const char* format, ... )
  __attribute__ ((format (printf, 2, 3)));

#endif /* HEADER_fd_src_util_textstream_fd_textstream_h */
