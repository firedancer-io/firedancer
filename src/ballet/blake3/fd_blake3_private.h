#ifndef HEADER_fd_src_ballet_blake3_fd_blake3_private_h
#define HEADER_fd_src_ballet_blake3_fd_blake3_private_h

#include "fd_blake3.h"

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

#define FD_BLAKE3_FLAG_CHUNK_START (uchar)(1<<0)
#define FD_BLAKE3_FLAG_CHUNK_END   (uchar)(1<<1)
#define FD_BLAKE3_FLAG_PARENT      (uchar)(1<<2)
#define FD_BLAKE3_FLAG_ROOT        (uchar)(1<<3)

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
fd_blake3_ref_compress1( uchar * restrict       out, /* align==1 len==32 */
                         uchar const * restrict msg, /* align==1 len==64 */
                         uint                   msg_sz,
                         ulong                  counter,
                         uint                   flags );

#if FD_HAS_SSE

void
fd_blake3_sse_compress1( uchar * restrict       out, /* align==1 len==32 */
                         uchar const * restrict msg, /* align==1 len==64 */
                         uint                   msg_sz,
                         ulong                  counter,
                         uint                   flags );

void
fd_blake3_sse_compress4_fast( uchar const * restrict msg, /* align== 1 len==4*64 */
                              uchar       * restrict out, /* align==16 len==4*32 */
                              ulong                  counter,
                              uchar                  flags );

#endif /* FD_HAS_SSE */

#if FD_HAS_AVX

void
fd_blake3_avx_compress8( ulong                   batch_cnt,
                         void   const * restrict _batch_data,    /* len in [0,8) */
                         uint   const * restrict  batch_sz,      /* len==8 */
                         void * const * restrict _batch_hash,    /* len in [0,8) */
                         ulong  const * restrict  ctr_vec,       /* len==8 */
                         uint   const * restrict  batch_flags ); /* len==8 */

void
fd_blake3_avx_compress8_fast( uchar const * restrict batch_data,  /* align==32 len==8*64 */
                              uchar       * restrict batch_hash,  /* align==32 len==8*32 */
                              ulong                  counter,
                              uchar                  flags );

#endif /* FD_HAS_AVX */

#if FD_HAS_AVX512

void
fd_blake3_avx512_compress16( ulong                   batch_cnt,
                             void const   * restrict _batch_data,   /* align= 1 len==16 */
                             uint const   * restrict batch_sz,      /* align= 4 len==16 */
                             void * const * restrict _batch_hash,   /* align=32 len==16 */
                             ulong const  * restrict ctr_vec,       /* align= 8 len==16 */
                             uint const   * restrict batch_flags ); /* align= 4 len==16 */

void
fd_blake3_avx512_compress16_fast( uchar const * restrict batch_data,  /* align==32 len==16*64 */
                                  uchar       * restrict batch_hash,  /* align==32 len==16*32 */
                                  ulong                  counter,
                                  uchar                  flags );

#endif /* FD_HAS_AVX512 */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_blake3_fd_blake3_private_h */
