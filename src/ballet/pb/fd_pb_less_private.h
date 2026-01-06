#ifndef HEADER_fd_src_ballet_pb_fd_pb_less_private_h
#define HEADER_fd_src_ballet_pb_fd_pb_less_private_h

/* fd_pb_less_private.h provides fd_pb_less internal data structure.

   This header file exists to support unit testing. */

#include "fd_pb_less.h"
#include "../../util/bits/fd_bits.h"

/* FD_PB_DESC_* give Protobuf field descriptor types. */

#define FD_PB_DESC_FREE   0  /* no field */
#define FD_PB_DESC_INT    1  /* varint/fixed-int/float */
#define FD_PB_DESC_LP     2  /* unknown length-prefixed (LEN field) */
#define FD_PB_DESC_SUBMSG 3  /* decoded submessage */
/* FIXME support packed repeated varints */

/* fd_pb_desc_t is a Protobuf field descriptor.  I.e. an annotated
   pointer.  The off field has different meanings based on desc:

   ..._FREE:   ignore
   ..._INT:    offset into serialized message, to first byte of field
   ..._LP:                             - " -
   ..._SUBMSG: compressed offset into pb_less memory, to child pb_less
               to uncompress, shift left by FD_PB_LESS_LG_ALIGN */

struct fd_pb_desc {
  uint desc :  2; /* FD_PB_DESC_* type */
  uint off  : 30; /* message offset to varint tag */
};

typedef struct fd_pb_desc fd_pb_desc_t;

/* fd_pb_alloc_t is a bump allocator for the pb_less memory region. */

struct fd_pb_alloc {
  ulong laddr0;
  ulong laddr;
  ulong laddr1;
};

typedef struct fd_pb_alloc fd_pb_alloc_t;

#include "../../util/log/fd_log.h"

static inline void *
fd_pb_alloc( fd_pb_alloc_t * alloc,
             ulong           align,
             ulong           sz ) {
  ulong const laddr = alloc->laddr;
  ulong       next  = fd_ulong_align_up( laddr, align );
  /* */       next += sz;
  if( FD_UNLIKELY( next > alloc->laddr1 ) ) return NULL;
  alloc->laddr = next;
  return (void *)laddr;
}

/* fd_pb_less_root_t is the common root of all submessages in a pb_less
   tree. */

struct __attribute__((aligned(FD_PB_LESS_ALIGN))) fd_pb_less_root {
  fd_pb_alloc_t alloc;
  uchar const * msg0;
  uchar const * msg1;
};

typedef struct fd_pb_less_root fd_pb_less_root_t;

/* fd_pb_less_t is a descriptor table for a Protobuf message.  Each
   field in the message has an fd_pb_desc_t entry. */

struct __attribute__((aligned(FD_PB_LESS_ALIGN))) fd_pb_less {
  fd_pb_less_root_t * root;

  ulong        desc_cnt;
  fd_pb_desc_t desc[];
};

typedef struct fd_pb_less fd_pb_less_t;

#endif /* HEADER_fd_src_ballet_pb_fd_pb_less_private_h */
