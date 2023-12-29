#ifndef HEADER_fd_src_ballet_bmtree_fd_wbmtree_h
#define HEADER_fd_src_ballet_bmtree_fd_wbmtree_h

#include "../sha256/fd_sha256.h"

/* This files declares another implementation of the binary Merkle
   tree based on the SHA-256 hash function.

   This difference between this one and the fd_bmtree version is this
   one optimizes for performance at the expense of memory and uses the
   streaming sha256 APIs.
*/

struct fd_wbmtree32_leaf {
  unsigned char *data;
  unsigned long  data_len;
};
typedef struct fd_wbmtree32_leaf fd_wbmtree32_leaf_t;

struct fd_wbmtree32_node {
  uchar hash[ 33UL ];
};
typedef struct fd_wbmtree32_node fd_wbmtree32_node_t;

#define FD_WBMTREE32_ALIGN (128UL)

/* the alignment of fd_wbmtree32 needs to match the alignment of the
   fd_sha256_batch object */
struct __attribute__((aligned(FD_WBMTREE32_ALIGN))) fd_wbmtree32 {
  fd_sha256_batch_t   sha256_batch;
  ulong               leaf_cnt_max;
  ulong               leaf_cnt;
  fd_wbmtree32_node_t data[];
};
typedef struct fd_wbmtree32 fd_wbmtree32_t;

FD_PROTOTYPES_BEGIN

ulong            fd_wbmtree32_align     ( void );
ulong            fd_wbmtree32_footprint ( ulong leaf_cnt );
fd_wbmtree32_t*  fd_wbmtree32_init      ( void * mem, ulong leaf_cnt );
fd_wbmtree32_t*  fd_wbmtree32_join      ( void * mem );
void             fd_wbmtree32_append    ( fd_wbmtree32_t * bmt, fd_wbmtree32_leaf_t const * leaf, ulong leaf_cnt, uchar *mbuf );
uchar *          fd_wbmtree32_fini      ( fd_wbmtree32_t * bmt);

FD_PROTOTYPES_END

#endif  /*HEADER_fd_src_ballet_bmtree_fd_wbmtree_h*/
