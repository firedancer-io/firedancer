#ifndef HEADER_fd_src_waltz_h2_fd_h2_rbuf_sock_h
#define HEADER_fd_src_waltz_h2_fd_h2_rbuf_sock_h

#include "fd_h2_rbuf.h"

#if FD_H2_HAS_SOCKETS

#include <errno.h>
#include <sys/socket.h>

static inline ulong
fd_h2_rbuf_prepare_recvmsg( fd_h2_rbuf_t * rbuf,
                            struct iovec   iov[2] ) {
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  uchar * lo   = rbuf->lo;
  uchar * hi   = rbuf->hi;
  ulong free_sz = fd_h2_rbuf_free_sz( rbuf );
  if( FD_UNLIKELY( !free_sz ) ) return 0UL;

  if( lo<=hi ) {

    iov[ 0 ].iov_base = hi;
    iov[ 0 ].iov_len  = fd_ulong_min( (ulong)( buf1-hi ), free_sz );
    free_sz -= iov[ 0 ].iov_len;
    iov[ 1 ].iov_base = buf0;
    iov[ 1 ].iov_len  = fd_ulong_min( (ulong)( lo-buf0 ), free_sz );
    return 2UL;

  } else {

    iov[ 0 ].iov_base = hi;
    iov[ 0 ].iov_len  = free_sz;
    iov[ 1 ].iov_base = NULL;
    iov[ 1 ].iov_len  = 0UL;
    return 1uL;

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
                    int            sock,
                    int            flags ) {
  struct iovec iov[2];
  ulong iov_cnt = fd_h2_rbuf_prepare_recvmsg( rbuf, iov );
  if( FD_UNLIKELY( !iov_cnt ) ) return 0;

  struct msghdr msg = {
    .msg_iov    = iov,
    .msg_iovlen = iov_cnt
  };
  ssize_t sz = recvmsg( sock, &msg, flags );
  if( sz<0 ) {
    if( FD_LIKELY( errno==EAGAIN ) ) return 0;
    return errno;
  } else if( FD_UNLIKELY( sz==0 ) ) {
    return EPIPE;
  }

  fd_h2_rbuf_commit_recvmsg( rbuf, iov, (ulong)sz );
  return 0;
}

static inline ulong
fd_h2_rbuf_prepare_sendmsg( fd_h2_rbuf_t * rbuf,
                            struct iovec   iov[2] ) {
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  uchar * lo   = rbuf->lo;
  uchar * hi   = rbuf->hi;
  ulong used_sz = fd_h2_rbuf_used_sz( rbuf );
  if( FD_UNLIKELY( !used_sz ) ) return 0UL;

  if( hi<=lo ) {

    iov[ 0 ].iov_base = lo;
    iov[ 0 ].iov_len  = fd_ulong_min( (ulong)( buf1-lo ), used_sz );
    used_sz -= iov[ 0 ].iov_len;
    iov[ 1 ].iov_base = buf0;
    iov[ 1 ].iov_len  = fd_ulong_min( (ulong)( hi-buf0 ), used_sz );
    return 2UL;

  } else {

    iov[ 0 ].iov_base = lo;
    iov[ 0 ].iov_len  = used_sz;
    iov[ 1 ].iov_base = NULL;
    iov[ 1 ].iov_len  = 0UL;
    return 1uL;

  }
}

static inline void
fd_h2_rbuf_commit_sendmsg( fd_h2_rbuf_t *     rbuf,
                           struct iovec const iovec[2],
                           ulong              sz ) {
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  struct iovec iov0 = iovec[0];
  struct iovec iov1 = iovec[1];
  rbuf->lo_off += sz;
  if( sz > iov0.iov_len ) {
    rbuf->lo = (uchar *)iov1.iov_base + ( sz - iov0.iov_len );
  } else {
    rbuf->lo = (uchar *)iov0.iov_base + sz;
  }
  if( rbuf->lo == buf1 ) rbuf->lo = buf0; /* cmov */
}

static inline int
fd_h2_rbuf_sendmsg( fd_h2_rbuf_t * rbuf,
                    int            sock,
                    int            flags ) {
  struct iovec iov[2];
  ulong iov_cnt = fd_h2_rbuf_prepare_sendmsg( rbuf, iov );
  if( FD_UNLIKELY( !iov_cnt ) ) return 0;

  struct msghdr msg = {
    .msg_iov    = iov,
    .msg_iovlen = iov_cnt
  };
  ssize_t sz = sendmsg( sock, &msg, flags );
  if( sz<0 ) {
    return errno;
  }

  fd_h2_rbuf_commit_sendmsg( rbuf, iov, (ulong)sz );
  return 0;
}

#endif /* FD_H2_HAS_SOCKETS */

#endif /* HEADER_fd_src_waltz_h2_fd_h2_rbuf_sock_h */
