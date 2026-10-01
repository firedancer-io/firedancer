#ifndef HEADER_fd_src_waltz_h2_fd_hpack_h
#define HEADER_fd_src_waltz_h2_fd_hpack_h

/* fd_hpack.h provides APIs for HPACK compression and decompression.

   The decoder implements RFC 7541 in full: the static table, Huffman
   string coding, and the dynamic table (indexed entries, literals with
   incremental indexing, and dynamic table size updates).

   The encoder (fd_hpack_wr.h) only uses the static table and Huffman
   coding.  It therefore holds no dynamic table state, and the value
   that the peer advertises for SETTINGS_HEADER_TABLE_SIZE is
   irrelevant to it. */

#include "fd_h2_base.h"

/* fd_h2_hdr_t points to an HTTP/2 header name:value pair.

   {name,value} point to decoded header values stored either in the
   hardcoded HPACK static table, the binary frame, or a scratch buffer.
   It is not guaranteed that these are valid ASCII.  These are NOT
   null-terminated.

   (hint&FD_H2_HDR_HINT_INDEXED) indicates that the HPACK coding of the
   header referenced a table entry.  The index of the entry is in the
   low 8 bits: indices in [1,61] are static table entries, indices
   above 61 are dynamic table entries.  Bits [8,12) are reserved.

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

/* FD_HPACK_DTABLE_SZ_MAX is the largest HPACK dynamic table size that
   an fd_hpack_dtable_t can hold, measured in the accounting units of
   RFC 7541 Section 4.1 (name bytes + value bytes + 32 per entry).

   4096 is the initial value of SETTINGS_HEADER_TABLE_SIZE in RFC 9113
   Section 6.5.2, i.e. the table size a peer's encoder is entitled to
   use from its very first header block, before it has read any SETTINGS
   frame of ours. */

#define FD_HPACK_DTABLE_SZ_MAX 4096U

/* Each entry costs 32 accounting units plus its name and value bytes.
   Therefore a table of at most FD_HPACK_DTABLE_SZ_MAX units holds at
   most FD_HPACK_DTABLE_ENTRY_MAX entries, and the name and value bytes
   of all entries sum to at most FD_HPACK_DTABLE_DATA_MAX. */

#define FD_HPACK_DTABLE_ENTRY_MAX (FD_HPACK_DTABLE_SZ_MAX/32U)  /*  128 */
#define FD_HPACK_DTABLE_DATA_MAX  (FD_HPACK_DTABLE_SZ_MAX-32U)  /* 4064 */

/* fd_hpack_dtable_entry_t locates one entry's bytes in the dtable ring.
   off is the offset of the first name byte.  The value bytes follow the
   name bytes (both wrap around the end of the ring). */

struct fd_hpack_dtable_entry {
  ushort off;
  ushort name_len;
  ushort value_len;
};

typedef struct fd_hpack_dtable_entry fd_hpack_dtable_entry_t;

/* fd_hpack_dtable_t is the receive-side HPACK dynamic table
   (RFC 7541 Section 2.3.2) of a connection.  It is a FIFO: the decoder
   prepends an entry whenever the peer's encoder indexes a header field,
   and evicts the oldest entries whenever the table would exceed its
   maximum size.  HPACK index 62 refers to the newest entry.

   All memory is embedded in the object, so the footprint is fixed at
   compile time (~4.9 KiB) and no allocator is involved.  entry[] and
   buf[] are ring buffers written at entry_hi and data_hi respectively;
   they are large enough that the live bytes of a table bounded by
   max_sz never wrap onto themselves. */

struct fd_hpack_dtable {
  uint limit_sz;  /* SETTINGS_HEADER_TABLE_SIZE advertised to the peer */
  uint max_sz;    /* max table size in [0,limit_sz] (RFC 7541 Section 6.3) */
  uint used_sz;   /* current table size in [0,max_sz] */
  uint entry_cnt; /* entries live in entry[] */
  uint entry_hi;  /* entry[] slot that the next insert writes */
  uint data_hi;   /* buf[] offset that the next insert writes */

  fd_hpack_dtable_entry_t entry[ FD_HPACK_DTABLE_ENTRY_MAX ];
  uchar                   buf  [ FD_HPACK_DTABLE_DATA_MAX  ];
};

typedef struct fd_hpack_dtable fd_hpack_dtable_t;

/* An fd_hpack_rd_t object reads a block of HPACK-encoded HTTP/2
   headers.  For example usage, see test_hpack. */

struct fd_hpack_rd {
  uchar const *       src;
  uchar const *       src_end;
  fd_hpack_dtable_t * dtable;
};

typedef struct fd_hpack_rd fd_hpack_rd_t;

FD_PROTOTYPES_BEGIN

/* fd_hpack_dtable_init initializes a dynamic table that holds at most
   limit_sz accounting units.  limit_sz is the value that the endpoint
   advertises for SETTINGS_HEADER_TABLE_SIZE and must not exceed
   FD_HPACK_DTABLE_SZ_MAX.  Returns dtable on success, or NULL if
   limit_sz is out of bounds (logs warning). */

fd_hpack_dtable_t *
fd_hpack_dtable_init( fd_hpack_dtable_t * dtable,
                      ulong               limit_sz );

/* fd_hpack_dtable_set_max_sz handles a dynamic table size update
   (RFC 7541 Section 6.3), evicting entries as needed.  Returns
   FD_H2_SUCCESS, or FD_H2_ERR_COMPRESSION if max_sz exceeds the
   advertised SETTINGS_HEADER_TABLE_SIZE.  A NULL dtable behaves like a
   table with a limit of zero. */

uint
fd_hpack_dtable_set_max_sz( fd_hpack_dtable_t * dtable,
                            ulong               max_sz );

/* fd_hpack_dtable_insert prepends a name:value entry to the table,
   evicting the oldest entries to make room.  Per RFC 7541 Section 4.4,
   an entry that does not fit the table even when empty clears the table
   and is not inserted.  A NULL dtable discards the entry. */

void
fd_hpack_dtable_insert( fd_hpack_dtable_t * dtable,
                        char const *        name,
                        ulong               name_len,
                        char const *        value,
                        ulong               value_len );

/* fd_hpack_dtable_query resolves the HPACK index idx (which must be
   greater than 61) against the dynamic table.  The entry's name and
   value bytes are copied to *scratch, and hdr is pointed at the copy.
   scratch_end points one past the last byte of the scratch buffer.

   Returns FD_H2_SUCCESS and advances *scratch on success.  Returns
   FD_H2_ERR_COMPRESSION if the index is not in the table or the scratch
   buffer is too small, leaving *scratch intact. */

uint
fd_hpack_dtable_query( fd_hpack_dtable_t const * dtable,
                       ulong                     idx,
                       fd_h2_hdr_t *             hdr,
                       uchar **                  scratch,
                       uchar *                   scratch_end );

/* fd_hpack_rd_init initializes a hpack_rd for reading of the header
   block in src.  hpack_rd has a read interest in src for its entire
   lifetime.  The reader carries no dynamic table, so a reference to a
   dynamic table entry is a decode error; use fd_hpack_rd_init_dtable to
   read against a dynamic table. */

fd_hpack_rd_t *
fd_hpack_rd_init( fd_hpack_rd_t * rd,
                  uchar const *   src,
                  ulong           srcsz );

/* fd_hpack_rd_init_dtable is like fd_hpack_rd_init but reads against the
   connection's receive-side dynamic table, which is updated while
   reading the block.  dtable may be NULL, which behaves like a table
   with a size limit of zero (any reference to a dynamic entry is then a
   decode error).

   Dynamic table size updates are only valid at the start of a header
   block (RFC 7541 Section 4.2), so fd_hpack_rd_init_dtable consumes
   them.  Returns rd on success.  Returns NULL if a size update is
   malformed or exceeds the advertised SETTINGS_HEADER_TABLE_SIZE, which
   the caller should treat like a fd_hpack_rd_next failure. */

fd_hpack_rd_t *
fd_hpack_rd_init_dtable( fd_hpack_rd_t *     rd,
                         uchar const *       src,
                         ulong               srcsz,
                         fd_hpack_dtable_t * dtable );

/* fd_hpack_rd_done returns 1 if all header entries were read from
   hpack_rd.  Returns 0 if fd_hpack_rd_next should be called again. */

static inline int
fd_hpack_rd_done( fd_hpack_rd_t const * rd ) {
  return rd->src >= rd->src_end;
}

/* fd_hpack_rd_next reads the next header from hpack_rd.  hdr is
   populated with pointers to the decoded data.  These pointers point
   into hpack_rd->src, the HPACK static table, or *scratch.  Dynamic
   table entries are copied to *scratch, so a header remains readable
   after later entries evict it.

   *scratch is assumed to point to the next free byte in a scratch
   buffer.  scratch_end points one past the last byte of the scratch
   buffer.  A scratch buffer of FD_HPACK_DTABLE_SZ_MAX bytes holds any
   single header that the decoder can produce from a dynamic table
   entry; Huffman-coded literals need twice their encoded size.

   Returns FD_H2_SUCCESS, populates header, and updates *scratch on
   success.  On failure, returns FD_H2_ERR_COMPRESSION and leaves
   *scratch intact.  Reasons for failure include HPACK parse error,
   out-of-bounds table index, misplaced dynamic table size update,
   Huffman coding error, or out of scratch space.  The caller should
   assume that *hdr and **scratch (the free bytes in the scratch buffer,
   not the pointer itself) are invalidated/filled with garbage on
   failure. */

uint
fd_hpack_rd_next( fd_hpack_rd_t * hpack_rd,
                  fd_h2_hdr_t *   hdr,
                  uchar **        scratch,
                  uchar *         scratch_end );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_hpack_h */
