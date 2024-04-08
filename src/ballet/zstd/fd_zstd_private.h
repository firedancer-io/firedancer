#include "fd_zstd.h"

#define FD_ZSTD_DSTREAM_ALIGN (32UL)
#define FD_ZSTD_DSTREAM_MAGIC (0x2a8657ef1bd33bc6UL)  /* random */

struct __attribute__((aligned(FD_ZSTD_DSTREAM_ALIGN))) fd_zstd_dstream {
  /* This point is 32-byte aligned */

  ulong magic;
  ulong mem_sz;

  uchar pad[16];

  /* This point is 32-byte aligned */

  __extension__ uchar mem[0];
};
