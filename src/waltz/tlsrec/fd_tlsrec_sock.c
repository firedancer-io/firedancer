#if FD_HAS_HOSTED

#include "fd_tlsrec_sock.h"

#include <errno.h>
#include <sys/socket.h>

int
fd_tlsrec_sock_flush( fd_tlsrec_sock_t * sock,
                      int                fd ) {
  while( sock->tx_off<sock->tx_sz ) {
    long sent = send( fd, sock->tx_buf+sock->tx_off, sock->tx_sz-sock->tx_off, MSG_NOSIGNAL|MSG_DONTWAIT );
    if( FD_UNLIKELY( sent<0L ) ) {
      if( errno==EINTR ) continue;
      if( errno==EAGAIN || errno==EWOULDBLOCK ) return 1;
      return FD_TLSREC_SOCK_ERR_SEND;
    }
    sock->tx_off += (ulong)sent;
  }
  sock->tx_off = 0UL;
  sock->tx_sz  = 0UL;
  return 0;
}

int
fd_tlsrec_sock_rx( fd_tlsrec_sock_t * sock,
                   fd_tlsrec_conn_t * conn,
                   int                fd,
                   ulong *            opt_rx_sz ) {
  if( opt_rx_sz ) *opt_rx_sz = 0UL;

  ulong tx_free = sizeof(sock->tx_buf) - sock->tx_sz;
  if( FD_UNLIKELY( fd_tlsrec_sock_rx_avail( sock ) || tx_free<FD_TLSREC_SOCK_TX_RESERVE ) ) return 0;
  if( FD_UNLIKELY( conn->rx_closed ) ) return FD_TLSREC_SOCK_ERR_EOF;

  uchar tcp_rx_buf[ FD_TLSREC_SOCK_RX_MTU ];
  long  tcp_rx_sz;
  do {
    tcp_rx_sz = recv( fd, tcp_rx_buf, sizeof(tcp_rx_buf), MSG_NOSIGNAL|MSG_DONTWAIT );
  } while( FD_UNLIKELY( tcp_rx_sz<0L && errno==EINTR ) );
  if( tcp_rx_sz<0L ) {
    if( errno==EAGAIN || errno==EWOULDBLOCK ) tcp_rx_sz = 0L;
    else return FD_TLSREC_SOCK_ERR_RECV;
  } else if( FD_UNLIKELY( !tcp_rx_sz ) ) {
    return FD_TLSREC_SOCK_ERR_EOF;
  }

  fd_tlsrec_slice_t tcp_rx[1];
  fd_tlsrec_slice_init( tcp_rx, tcp_rx_buf, (ulong)tcp_rx_sz );
  ulong tcp_tx_sz = tx_free;
  ulong app_rx_sz = sizeof(sock->rx_buf);
  int err = fd_tlsrec_conn_rx( conn, tcp_rx_sz ? tcp_rx : NULL,
                               sock->tx_buf+sock->tx_sz, &tcp_tx_sz,
                               sock->rx_buf, &app_rx_sz );
  sock->rx_off = 0UL;
  sock->rx_sz  = app_rx_sz;
  sock->tx_sz += tcp_tx_sz;

  /* Send before reporting a TLS error so an alert reaches the peer */
  if( tcp_tx_sz && FD_UNLIKELY( fd_tlsrec_sock_flush( sock, fd )<0 ) ) return FD_TLSREC_SOCK_ERR_SEND;
  if( FD_UNLIKELY( err ) ) return err;
  if( FD_UNLIKELY( conn->rx_closed && !app_rx_sz ) ) return FD_TLSREC_SOCK_ERR_EOF;

  if( opt_rx_sz ) *opt_rx_sz = (ulong)tcp_rx_sz;
  return 0;
}

int
fd_tlsrec_sock_close( fd_tlsrec_sock_t * sock,
                      fd_tlsrec_conn_t * conn,
                      int                fd ) {
  ulong tcp_tx_sz = sizeof(sock->tx_buf) - sock->tx_sz;
  int err = fd_tlsrec_conn_close( conn, sock->tx_buf+sock->tx_sz, &tcp_tx_sz );
  if( FD_UNLIKELY( err ) ) return err;
  sock->tx_sz += tcp_tx_sz;
  return fd_tlsrec_sock_flush( sock, fd );
}

int
fd_tlsrec_sock_tx( fd_tlsrec_sock_t * sock,
                   fd_tlsrec_conn_t * conn,
                   int                fd,
                   void const *       app,
                   ulong              app_sz,
                   ulong *            opt_consumed ) {
  if( opt_consumed ) *opt_consumed = 0UL;
  if( FD_UNLIKELY( sock->tx_sz ) ) return 0;

  fd_tlsrec_slice_t app_tx[1];
  fd_tlsrec_slice_init( app_tx, (uchar *)app, app_sz );
  ulong tcp_tx_sz = sizeof(sock->tx_buf);
  int err = fd_tlsrec_conn_tx( conn, sock->tx_buf, &tcp_tx_sz, app_tx );
  if( FD_UNLIKELY( err ) ) return err;
  sock->tx_off = 0UL;
  sock->tx_sz  = tcp_tx_sz;
  if( opt_consumed ) *opt_consumed = app_sz - fd_tlsrec_slice_sz( app_tx );

  if( FD_UNLIKELY( fd_tlsrec_sock_flush( sock, fd )<0 ) ) return FD_TLSREC_SOCK_ERR_SEND;
  return 0;
}

char const *
fd_tlsrec_sock_strerror( int err ) {
  switch( err ) {
  case 0:                       return "success";
  case FD_TLSREC_SOCK_ERR_RECV: return "recv failed";
  case FD_TLSREC_SOCK_ERR_SEND: return "send failed";
  case FD_TLSREC_SOCK_ERR_EOF:  return "peer closed connection";
  default:                      return err>0 ? fd_tlsrec_strerror( err ) : "unknown";
  }
}

#endif /* FD_HAS_HOSTED */
