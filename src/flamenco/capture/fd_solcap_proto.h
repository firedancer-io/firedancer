#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_proto_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_proto_h

#include "../fd_flamenco_base.h"

/* fd_solcap_proto defines the capture data format "solcap".

   solcap is a portable file format for capturing Solana runtime data
   suitable for replay and debugging.  It is laid out as follows:

     File Header
     File Protobuf Object
     Chunk 0
       Chunk Header
       Chunk Protobuf Object
       Data ...
     Chunk 1
       Chunk Header
       Chunk Protobuf Object
       Data ...
     Chunk N ...

   The file header briefly describes the file's content type and points
   to the first chunk.  Additional metadata, such as slot bounds, are
   stored in a Protobuf blob following the header.  Currently, the
   following content types are implemented:

     SOLCAP_V1_BANK:  Bank pre-image, version 0
                      (assumed to only contain SOLCAP_V1_BANK chunks)

   Capture content is divided into variable-length chunks. Each chunk 
   contains a fixed-size binary header containing type and length 
   information. Following the header is a serialized Protobuf object 
   with chunk-specific information.

   Typically, readers sequentially read in chunks, loading one chunk
   into memory at a time.  Within a chunk, data structures are laid out
   in arbitrary order which requires random access.  Random access out-
   side of chunks is rarely required.  Readers should ignore chunks of
   unknown content type.

   Furthermore:
   - Byte order is little endian
   - There should be no gaps between slots
   - Suffix `_foff` ("file offset") refers to an offset from the
     beginning of a stream
   - Suffix `_coff` ("chunk offset") refers to an offset from the first
     byte of the header of the current chunk

   Why a mix of C structs and Protobufs?  We prefer the use of Protobuf
   to easily support additions to the schema.  Fixed-size/fixed-offset
   structures are only used to support navigating the file. */

/* TODO Pending features:
   - Fork support
   - Compression
   - Chunk Table */

/* FD_SOLCAP_V1_FILE_MAGIC identifies a solcap version 0 file. */

#define FD_SOLCAP_V1_FILE_MAGIC (0x806fe7581b1da4b7UL)

/* fd_solcap_fhdr_t is the file header of a capture file. */

struct fd_solcap_fhdr {
  /* 0x00 */ ulong magic;        /* ==FD_SOLCAP_V1_NULL_MAGIC */
  /* 0x08 */ ulong chunk0_foff;  /* Offset of first chunk from begin of stream */

  /* Metadata;  Protobuf fd_solcap_FileMeta */
  /* 0x10 */ uint meta_sz;
  /* 0x14 */ uint _pad14[3];
};

typedef struct fd_solcap_fhdr fd_solcap_fhdr_t;

/* FD_SOLCAP_V1_{...}_MAGIC identifies a chunk type.

     NULL: ignored chunk -- can be used to patch out existing chunks
     ACCT: account chunk
     ACTB: account table chunk
     BANK: bank hash preimage capture
           Metadata Protobuf type fd_solcap_BankChunk */

#define FD_SOLCAP_V1_MAGIC_MASK (0xfffffffffffff000UL)
#define FD_SOLCAP_V1_NULL_MAGIC (0x805fe7580b1da000UL)
#define FD_SOLCAP_V1_ACCT_MAGIC (0x805fe7580b1da4bAUL)
#define FD_SOLCAP_V1_ACTB_MAGIC (0x805fe7580b1da4bBUL)
#define FD_SOLCAP_V1_BANK_MAGIC (0x805fe7580b1da4b8UL)

FD_PROTOTYPES_BEGIN

static inline int
fd_solcap_is_chunk_magic( ulong magic ) {
  return (magic & FD_SOLCAP_V1_MAGIC_MASK) == FD_SOLCAP_V1_NULL_MAGIC;
}

FD_PROTOTYPES_END

/* fd_solcap_chunk_t is the fixed size header of a chunk.  A "chunk
   offset" points to the first byte of this structure.  Immediately
   following this structure is a serialized Protobuf blob, the type of
   which is decided by the chunk's magic.  meta_sz indicates the size
   of such blob. */

struct fd_solcap_chunk {
  /* 0x00 */ ulong magic;
  /* 0x08 */ ulong total_sz;
  /* 0x10 */ uint  meta_coff;
  /* 0x14 */ uint  meta_sz;
  /* 0x18 */ ulong _pad18;
  /* 0x20 */
};

typedef struct fd_solcap_chunk fd_solcap_chunk_t;

/* fd_solcap_account_tbl_t is an entry of the table of accounts that
   were changed in a block.  meta_coff points to the chunk offset of a
   Protobuf-serialized fd_solcap_AccountMeta object, with serialized
   size meta_sz.  key is the account address.  hash is the account hash
   (a leaf of the accounts delta accumulator).  data_coff points to the
   chunk offset of the account's data, with size data_sz.

   The table of accounts should ideally be sorted to match the order of
   accounts in the accounts delta vector. */

struct fd_solcap_account_tbl {
  /* 0x00 */ uchar key  [ 32 ];
  /* 0x20 */ uchar hash [ 32 ];
  /* 0x40 */ long  acc_coff;  /* chunk offset to account chunk */
  /* 0x48 */ ulong _pad48[3];
  /* 0x60 */
};

typedef struct fd_solcap_account_tbl fd_solcap_account_tbl_t;

/* Hardcoded limits ***************************************************/

/* FD_SOLCAP_FHDR_SZ is the number of bytes occupied by the file header.
   Immediately after the file header is the first chunk. */

#define FD_SOLCAP_FHDR_SZ (256UL)

/* FD_SOLCAP_ACC_TBL_CNT is the number of entries that fit in the in-
   memory buffer for the account table. */

#define FD_SOLCAP_ACC_TBL_CNT (4096U)

/* FD_SOLCAP_FILE_META_FOOTPRINT is the max size of the FileMeta
   Protobuf struct. */

#define FD_SOLCAP_FILE_META_FOOTPRINT (1024U)

/* FD_SOLCAP_ACTB_META_FOOTPRINT is the max size of the
   AccountChunkMeta Protobuf struct. */

#define FD_SOLCAP_ACTB_META_FOOTPRINT (128UL)

/* FD_SOLCAP_ACCOUNT_META_FOOTPRINT is the max size of the AccountMeta
   Protobuf struct. */

#define FD_SOLCAP_ACCOUNT_META_FOOTPRINT (1024UL)

/* FD_SOLCAP_BANK_PREIMAGE_FOOTPRINT is the max size of the BankPreimage
   Protobuf struct. */

#define FD_SOLCAP_BANK_PREIMAGE_FOOTPRINT (512UL)

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_proto_h */
