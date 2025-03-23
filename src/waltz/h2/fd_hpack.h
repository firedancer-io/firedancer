#ifndef HEADER_fd_src_waltz_h2_fd_hpack_h
#define HEADER_fd_src_waltz_h2_fd_hpack_h

/* fd_hpack.h provides APIs for HPACK compression and decompression.

   Supports the static table and Huffman string coding.  Does not use
   the dynamic table while encoding.  Assumes that the endpoint used
   HTTP/2 SETTINGS to force the peer's dynamic table size to zero. */

#include "fd_h2_base.h"

/* fd_h2_hdr_t points to an HTTP/2 header name:value pair. */

struct fd_h2_hdr {
  char const * name;
  char const * value;
  ushort       name_len;
  ushort       hint; /* FIXME document */
  uint         value_len;
};

typedef struct fd_h2_hdr fd_h2_hdr_t;

#define FD_H2_HDR_HINT_NAME_HUFFMAN  ((ushort)0x8000) /* name is huffman coded */
#define FD_H2_HDR_HINT_VALUE_HUFFMAN ((ushort)0x4000) /* value is huffman coded */
#define FD_H2_HDR_HINT_HUFFMAN ((ushort)(FD_H2_HDR_HINT_NAME_HUFFMAN|FD_H2_HDR_HINT_VALUE_HUFFMAN))
#define FD_H2_HDR_HINT_NAME_INDEXED  ((ushort)0x2000) /* name was indexed from table */
#define FD_H2_HDR_HINT_VALUE_INDEXED ((ushort)0x1000) /* value was indexed from table */
#define FD_H2_HDR_HINT_INDEXED ((ushort)(FD_H2_HDR_HINT_NAME_INDEXED|FD_H2_HDR_HINT_VALUE_INDEXED))
#define FD_H2_HDR_HINT_GET_INDEX(hint) ((uchar)((hint)&0xFF))

/* An fd_hpack_rd_t object reads a single header block. */

struct fd_hpack_rd {
  uchar const * src;
  uchar const * src_end;
};

typedef struct fd_hpack_rd fd_hpack_rd_t;

FD_PROTOTYPES_BEGIN

/* fd_hpack_rd_init initializes a hpack_rd for reading of the header
   block in src. */

fd_hpack_rd_t *
fd_hpack_rd_init( fd_hpack_rd_t * rd,
                  uchar const *   src,
                  ulong           srcsz );

/* fd_hpack_rd_done returns 1 if all header entries were read from
   hpack_rd.  Returns 0 if fd_hpack_rd_next should be called again. */

static inline int
fd_hpack_rd_done( fd_hpack_rd_t const * rd ) {
  return rd->src >= rd->src_end;
}

/* fd_hpack_rd_next reads the next header from hpack_rd.  On success,
   returns FD_H2_SUCCESS and populates hdr.  The lifetime of hdr is that
   of the header block buffer passed to init.  On decompression failure,
   returns FD_H2_ERR_COMPRESSION. */

uint
fd_hpack_rd_next( fd_hpack_rd_t * hpack_rd,
                  fd_h2_hdr_t *   hdr );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_hpack_h */
