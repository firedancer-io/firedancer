#ifndef HEADER_fd_src_ballet_http_fd_hcache_private_h
#define HEADER_fd_src_ballet_http_fd_hcache_private_h

#include "fd_hcache.h"

/* FD_HCACHE_MAGIC is an ideally unique number that specifies the precise
   memory layout of a fd_hcache. */

#define FD_HCACHE_MAGIC (0xF17EDA2C3731C591UL) /* F17E=FIRE,DA2C/3R<>DANCER,8CAC8E<>HCACHE,0<>0 --> FIRE DANCER HCACHE VERSION 1 */

struct __attribute__((aligned(FD_HCACHE_ALIGN))) fd_hcache_private {
  ulong magic;    /* ==FD_HCACHE_MAGIC */
  ulong data_sz;  /* Size of data region */

  int   snap_err; /* If there has been an error appending to the buffer */
  ulong snap_off; /* Start offset of the append buffer */
  ulong snap_len; /* Length of the append buffer */

  fd_http_server_t * server; /* Server to send to and evict connections from */

  /* Padding to FD_HCACHE_ALIGN here */
};

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline uchar *
fd_hcache_private_data( fd_hcache_t * hcache ) {
  return (uchar *)(hcache+1UL);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_http_fd_hcache_private_h */
