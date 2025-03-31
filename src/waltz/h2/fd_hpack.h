#ifndef HEADER_fd_src_waltz_h2_fd_hpack_h
#define HEADER_fd_src_waltz_h2_fd_hpack_h

/* fd_hpack.h provides APIs for HPACK compression and decompression.

   Supports the static table and Huffman string coding.  Does not use
   the dynamic table while encoding.  Assumes that the endpoint used
   HTTP/2 SETTINGS to force the peer's dynamic table size to zero. */

#include "fd_h2_base.h"

/* fd_h2_hdr_t points to an HTTP/2 header name:value pair.

   {name,value} point to decoded header values stored either in the
   hardcoded HPACK static table, the binary frame, or a scratch buffer.
   It is not guaranteed that these are valid ASCII.  These are NOT
   null-terminated.

   (hint&FD_H2_HDR_HINT_INDEXED) indicates that the HPACK coding of the
   header referenced a static table entry.  The index of the entry is
   in the low 6 bits.

   (hint&FD_H2_HDR_HINT_HUFFMAN) is internal and can be safely ignored,
   as fd_hpack_rd_next takes care of Huffman coding. */

struct fd_h2_hdr {
  char const * name;
  char const * value;
  ushort       name_len;
  ushort       hint;
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

/* An fd_hpack_rd_t object reads a block of HPACK-encoded HTTP/2
   headers.  For example usage, see test_hpack. */

struct fd_hpack_rd {
  uchar const * src;
  uchar const * src_end;
};

typedef struct fd_hpack_rd fd_hpack_rd_t;

FD_PROTOTYPES_BEGIN

/* fd_hpack_rd_init initializes a hpack_rd for reading of the header
   block in src.  hpack_rd has a read interest in src for its entire
   lifetime. */

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

/* fd_hpack_rd_next reads the next header from hpack_rd.  hdr is
   populated with pointers to the decoded data.  These pointers either
   point into hpack_rd->src or *scratch.

   *scratch is assumed to point to the next free byte in a scratch
   buffer.  scratch_end points one past the last byte of the scratch
   buffer.

   Returns FD_H2_SUCCESS, populates header, and updates *scratch on
   success.  On failure, returns FD_H2_ERR_COMPRESSION and leaves
   *scratch intact.  Reasons for failure include HPACK parse error,
   out-of-bounds table index, use of the dynamic table, Huffman coding
   error, or out of scratch space.  The caller should assume that *hdr
   and **scratch (the free bytes in the scratch buffer, not the pointer
   itself) are invalidated/filled with garbage on failure. */

uint
fd_hpack_rd_next( fd_hpack_rd_t * hpack_rd,
                  fd_h2_hdr_t *   hdr,
                  uchar **        scratch,
                  uchar *         scratch_end );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_hpack_h */
