#ifndef HEADER_fd_src_ballet_blake3_fd_blake3_private_h
#define HEADER_fd_src_ballet_blake3_fd_blake3_private_h

#include "fd_blake3.h"

/* Set FD_BLAKE3_TRACING to 1 to dump out a high-level trace of BLAKE3
   operations to the debug log.  This is useful during debugging or
   development. */
#define FD_BLAKE3_TRACING 0

#if FD_BLAKE3_TRACING
#define FD_BLAKE3_TRACE( ... ) FD_LOG_DEBUG( __VA_ARGS__ )
#else
#define FD_BLAKE3_TRACE( ... ) (void)0
#endif

/* Protocol constants *************************************************/

static const uchar FD_BLAKE3_MSG_SCHEDULE[7][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  {  2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8 },
  {  3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1 },
  { 10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6 },
  { 12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4 },
  {  9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7 },
  { 11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13 },
};

static const uint FD_BLAKE3_IV[8] = {
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

#define FD_BLAKE3_FLAG_CHUNK_START (1u<<0) /* 1 */
#define FD_BLAKE3_FLAG_CHUNK_END   (1u<<1) /* 2 */
#define FD_BLAKE3_FLAG_PARENT      (1u<<2) /* 4 */
#define FD_BLAKE3_FLAG_ROOT        (1u<<3) /* 8 */

/* Possible flag combinations:
   0x1:  first block of a chunk with at least 2 blocks
   0x2:  last block of a chunk, tree that has at least 1 parent
   0x3:  last chunk (<=64 bytes), input >1024 bytes
   0x4:  non-root parent node
   0xa:  last block of the only chunk, input_sz>64 input_sz<=1024
   0xb:  only block, input_sz<=64
   0xc:  root parent node */

/* Scheduler **********************************************************/

union __attribute__((aligned(32))) fd_blake3_op {

  struct {
    uchar const * msg;
    uchar *       out;

    ulong         counter;
    union {
      struct {
        ushort    off;
        ushort    sz;
      };
      uint        off_sz;
    };
    uchar         flags;
  };

};

typedef union fd_blake3_op fd_blake3_op_t;

/* Compression function ***********************************************/

FD_PROTOTYPES_BEGIN

void
fd_blake3_fini_xof_compress( fd_blake3_t * sha,
                             uchar *       root_msg,
                             uchar *       root_cv_pre );

void
fd_blake3_ref_compress1( uchar * restrict       out, /* align==1 len==32 */
                         uchar const * restrict msg, /* align==1 len==64 */
                         uint                   msg_sz,
                         ulong                  counter,
                         uint                   flags,
                         uchar * restrict       out_chain,  /* optional, 16 byte output chaining value of last block */
                         uchar const * restrict in_chain ); /* optional, 16 byte input chaining value of first block (default IV) */

#if FD_HAS_SSE

void
fd_blake3_sse_compress1( uchar * restrict       out, /* align==1 len==32 */
                         uchar const * restrict msg, /* align==1 len==64 */
                         uint                   msg_sz,
                         ulong                  counter,
                         uint                   flags,
                         uchar * restrict       out_chain,
                         uchar const * restrict in_chain );

#endif /* FD_HAS_SSE */

#if FD_HAS_AVX

/* BLAKE3 AVX cores

   compress8 compresses one to eight tree nodes.  batch_cnt is the
   number of nodes to process.  For each node in the batch with index i,
   - _batch_data[i] points to the input data of the node (message bytes
     for leaf nodes, a pair of output chaining values for branch nodes)
   - batch_sz[i] is the input byte count of the node, from which the
     'len' value of each of the node's blocks is derived
   - ctr_vec[i] is the 'counter' value of the node
   - batch_flags[i] is the 'flag' value of the node
   - cv is optional.  If set, cv[i] is the 'chaining value' of the first
     block of the node.  This is useful for XOF.

   compress8 has three different output modes:
   - "LtHash in-place": If lthash is set, each node's output is expanded
     (XOF) to 2048 bytes and interpreted as an 'LtHash' value (i.e.
     a vector of 1024 uint16).  These vectors are then added together
     and the result is written to lthash.  The root flag MUST be set for
     all batch_flags inputs, otherwise this function will read OOB.
   - "Simple": Otherwise, _batch_hash[i] is populated with the 32-byte
      output chaining value.  (If node i is a root node, this is 'the
      BLAKE3 hash', i.e. the first 32 bytes of the XOF stream).

   These modes are all packed into the same function because the
   alternatives are worse (either worse code footprint due to duplicated
   core, or worse throughput due to high penalty passing vector regs
   between functions in SysV ABI).

   compress8_fast does a subset of what compress8 can, but is ~10-20%
   faster. */

void
fd_blake3_avx_compress8( ulong                   batch_cnt,
                         void   const * restrict _batch_data,   /* align==32 len in [1,8) */
                         uint   const * restrict batch_sz,      /* len in [1,8] */
                         ulong  const * restrict ctr_vec,       /* len==8 */
                         uint   const * restrict batch_flags,   /* align==32 len==8 */
                         void * const * restrict _batch_hash,   /* align==32 len in [1,8) */
                         ushort *       restrict lthash,        /* align==32 byte_sz=2048 */
                         uint                    out_sz,        /* 32 or 64 */
                         void const *   restrict batch_cv );    /* align==8 len==8 ele_align==32 optional */

void
fd_blake3_avx_compress8_fast( uchar const * restrict batch_data,  /* align==32 len==8*64 */
                              uchar       * restrict batch_hash,  /* align==32 len==8*32 */
                              ulong                  counter,
                              uchar                  flags );

#endif /* FD_HAS_AVX */

#if FD_HAS_AVX512

/* fd_blake3_avx512_compress16{,fast} are analogous to the avx APIs
   above.  The only difference is larger alignment assumptions and that
   these process up to sixteen elements. */

void
fd_blake3_avx512_compress16( ulong                   batch_cnt,
                             void const   * restrict _batch_data,   /* align=64 len=16 ele_align=1  */
                             uint const   * restrict batch_sz,      /* align= 4 len=16 */
                             ulong const  * restrict ctr_vec,       /* align= 8 len=16 */
                             uint const   * restrict batch_flags,   /* align= 4 len=16 */
                             void * const * restrict _batch_hash,   /* align=64 len=16 */
                             ushort *       restrict lthash,        /* align=32 byte_sz=2048 */
                             uint                    out_sz,        /* 32 or 64 */
                             void const *   restrict batch_cv );    /* align= 8 len=16 ele_align=16 optional */

void
fd_blake3_avx512_compress16_fast( uchar const * restrict batch_data,  /* align==32 len==16*64 */
                                  uchar       * restrict batch_hash,  /* align==32 len==16*32 */
                                  ulong                  counter,
                                  uchar                  flags );

#endif /* FD_HAS_AVX512 */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_blake3_fd_blake3_private_h */
