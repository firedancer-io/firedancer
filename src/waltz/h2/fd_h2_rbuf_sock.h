#ifndef HEADER_fd_src_waltz_h2_fd_h2_rbuf_sock_h
#define HEADER_fd_src_waltz_h2_fd_h2_rbuf_sock_h

#include "fd_h2_rbuf.h"

#if FD_HAS_HOSTED

#include <errno.h>
#include <sys/socket.h>

static inline ulong
fd_h2_rbuf_prepare_recvmsg( fd_h2_rbuf_t * rbuf,
                            struct iovec   iov[2] ) {
  uchar * buf0      = rbuf->buf0;
  uchar * buf1      = rbuf->buf1;
  uchar * lo        = rbuf->lo;
  uchar * hi        = rbuf->hi;
  ulong   frame_max = rbuf->frame_max;

  if( lo<=hi ) {

    ulong used_sz = (ulong)( hi-lo );
    if( FD_UNLIKELY( used_sz>=frame_max ) ) return 0UL;
    ulong free_sz = frame_max-used_sz;
    iov[ 0 ].iov_base = hi;
    iov[ 0 ].iov_len  = fd_ulong_min( (ulong)( buf1-hi ), free_sz );
    free_sz -= iov[ 0 ].iov_len;
    iov[ 1 ].iov_base = buf0;
    iov[ 1 ].iov_len  = fd_ulong_min( (ulong)( lo-buf0 ), free_sz );
    return 2UL;

  } else {

    ulong free_sz = (ulong)( lo-hi );
    if( FD_UNLIKELY( free_sz<=frame_max ) ) return 0UL;
    iov[ 0 ].iov_base = hi;
    iov[ 0 ].iov_len  = free_sz-frame_max;
    iov[ 1 ].iov_base = NULL;
    iov[ 1 ].iov_len  = 0UL;
    return 2uL;

  }
}

static inline void
fd_h2_rbuf_commit_recvmsg( fd_h2_rbuf_t *     rbuf,
                           struct iovec const iovec[2],
                           ulong              sz ) {
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  struct iovec iov0 = iovec[0];
  struct iovec iov1 = iovec[1];
  rbuf->hi_off += sz;
  if( sz > iov0.iov_len ) {
    rbuf->hi = (uchar *)iov1.iov_base + ( sz - iov0.iov_len );
  } else {
    rbuf->hi = (uchar *)iov0.iov_base + sz;
  }
  if( rbuf->hi == buf1 ) rbuf->hi = buf0; /* cmov */
}

static inline int
fd_h2_rbuf_recvmsg( fd_h2_rbuf_t * rbuf,
                    int            sock ) {
  struct iovec iov[2];
  ulong iov_cnt = fd_h2_rbuf_prepare_recvmsg( rbuf, iov );
  if( FD_UNLIKELY( !iov_cnt ) ) return ENOBUFS;

  struct msghdr msg = {
    .msg_iov    = iov,
    .msg_iovlen = iov_cnt
  };
  ssize_t sz = recvmsg( sock, &msg, MSG_NOSIGNAL|MSG_DONTWAIT );
  if( sz<0 ) {
    if( FD_LIKELY( errno==EAGAIN ) ) return 0;
    return errno;
  } else if( FD_UNLIKELY( sz==0 ) ) {
    return EPIPE;
  }

  fd_h2_rbuf_commit_recvmsg( rbuf, iov, (ulong)sz );
  return 0;
}

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_waltz_h2_fd_h2_rbuf_sock_h */
