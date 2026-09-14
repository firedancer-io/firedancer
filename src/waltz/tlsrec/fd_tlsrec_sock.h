#ifndef HEADER_fd_src_waltz_tlsrec_fd_tlsrec_sock_h
#define HEADER_fd_src_waltz_tlsrec_fd_tlsrec_sock_h

/* fd_tlsrec_sock shuttles TLS records between a non-blocking TCP
   socket and an fd_tlsrec_conn.  It owns the two buffers every socket
   user of fd_tlsrec needs: ciphertext that the socket did not accept
   yet, and plaintext that the application did not consume yet.

   The socket is never read while plaintext is still held (it would be
   overwritten), and never read while the ciphertext buffer lacks room
   for the replies fd_tlsrec_conn_rx may generate (a KeyUpdate).  In
   both cases the TCP window back-pressures the peer.  A send parked on
   EAGAIN alone does not stop RX: whatever conn_rx emits is appended
   behind the parked bytes.

   All functions use MSG_DONTWAIT|MSG_NOSIGNAL and never block. */

#include "fd_tlsrec.h"

/* FD_TLSREC_SOCK_TX_RESERVE is the ciphertext headroom kept free for
   conn_rx output while a record is parked.  Post-handshake, one conn_rx
   call emits at most one 27 byte KeyUpdate record however many updates
   the peer requested.  FD_TLSREC_SOCK_RX_MTU is the most ciphertext
   read from the socket per call. */

#define FD_TLSREC_SOCK_TX_RESERVE (512UL)
#define FD_TLSREC_SOCK_TX_BUF_SZ  (FD_TLSREC_PLAINTEXT_MAX+22UL+FD_TLSREC_SOCK_TX_RESERVE)
#define FD_TLSREC_SOCK_RX_MTU     (FD_TLSREC_CAP)
#define FD_TLSREC_SOCK_RX_BUF_SZ  (FD_TLSREC_CAP+FD_TLSREC_SOCK_RX_MTU)

struct fd_tlsrec_sock {
  uchar tx_buf[ FD_TLSREC_SOCK_TX_BUF_SZ ];  /* ciphertext [tx_off,tx_sz) awaits send(2) */
  ulong tx_off;
  ulong tx_sz;

  uchar rx_buf[ FD_TLSREC_SOCK_RX_BUF_SZ ];  /* plaintext [rx_off,rx_sz) awaits the app */
  ulong rx_off;
  ulong rx_sz;
};

typedef struct fd_tlsrec_sock fd_tlsrec_sock_t;

/* Error codes.  Positive values are FD_TLSREC_ERR_{...}. */

#define FD_TLSREC_SOCK_ERR_RECV (-1)  /* recv(2) failed, errno set */
#define FD_TLSREC_SOCK_ERR_SEND (-2)  /* send(2) failed, errno set */
#define FD_TLSREC_SOCK_ERR_EOF  (-3)  /* peer closed the connection */

FD_PROTOTYPES_BEGIN

static inline void
fd_tlsrec_sock_init( fd_tlsrec_sock_t * sock ) {
  sock->tx_off = 0UL; sock->tx_sz = 0UL;
  sock->rx_off = 0UL; sock->rx_sz = 0UL;
}

FD_FN_PURE static inline int
fd_tlsrec_sock_tx_pending( fd_tlsrec_sock_t const * sock ) {
  return sock->tx_off!=sock->tx_sz;
}

/* Plaintext accessors: fd_tlsrec_sock_rx_avail is the number of
   decrypted bytes held, fd_tlsrec_sock_rx_data points to them, and
   fd_tlsrec_sock_rx_consume releases the first sz of them.
   fd_tlsrec_sock_rx_pop copies up to dst_max bytes out and returns the
   count. */

FD_FN_PURE static inline ulong
fd_tlsrec_sock_rx_avail( fd_tlsrec_sock_t const * sock ) {
  return sock->rx_sz - sock->rx_off;
}

FD_FN_PURE static inline uchar const *
fd_tlsrec_sock_rx_data( fd_tlsrec_sock_t const * sock ) {
  return sock->rx_buf + sock->rx_off;
}

static inline void
fd_tlsrec_sock_rx_consume( fd_tlsrec_sock_t * sock,
                           ulong              sz ) {
  sock->rx_off += sz;
  if( sock->rx_off==sock->rx_sz ) { sock->rx_off = 0UL; sock->rx_sz = 0UL; }
}

static inline ulong
fd_tlsrec_sock_rx_pop( fd_tlsrec_sock_t * sock,
                       void *             dst,
                       ulong              dst_max ) {
  ulong sz = fd_ulong_min( fd_tlsrec_sock_rx_avail( sock ), dst_max );
  fd_memcpy( dst, fd_tlsrec_sock_rx_data( sock ), sz );
  fd_tlsrec_sock_rx_consume( sock, sz );
  return sz;
}

/* fd_tlsrec_sock_flush writes parked ciphertext to fd until the buffer
   is empty or send blocks.  Returns 0 if the buffer is now empty, 1 if
   send would block (bytes remain, wait for POLLOUT), and
   FD_TLSREC_SOCK_ERR_SEND on a hard send error. */

int
fd_tlsrec_sock_flush( fd_tlsrec_sock_t * sock,
                      int                fd );

/* fd_tlsrec_sock_rx reads up to FD_TLSREC_SOCK_RX_MTU bytes of
   ciphertext from fd, decrypts them into the plaintext buffer, and
   sends whatever conn emitted in response (handshake flights, a
   KeyUpdate reply).  conn is stepped even if nothing was read, which
   is what produces the ClientHello.  The read is skipped, and the call
   is a no-op, while plaintext is held or the ciphertext buffer lacks
   FD_TLSREC_SOCK_TX_RESERVE bytes of headroom.

   Returns 0 on success with *opt_rx_sz set to the number of ciphertext
   bytes read (0 on EAGAIN or a skipped read).  Otherwise returns
   FD_TLSREC_SOCK_ERR_{RECV,SEND,EOF} or a positive FD_TLSREC_ERR code;
   the connection should be dropped.  ERR_EOF is also returned for a
   TLS close_notify, once the plaintext preceding it was consumed. */

int
fd_tlsrec_sock_rx( fd_tlsrec_sock_t * sock,
                   fd_tlsrec_conn_t * conn,
                   int                fd,
                   ulong *            opt_rx_sz );

/* fd_tlsrec_sock_close queues a close_notify alert behind any parked
   ciphertext and flushes.  Returns like fd_tlsrec_sock_flush: 0 when
   everything was sent, 1 if bytes remain (wait for POLLOUT, then flush),
   FD_TLSREC_SOCK_ERR_SEND, or a positive FD_TLSREC_ERR code (ERR_STATE
   if the connection is not established or already closed for writing,
   ERR_OOM if the parked bytes leave no room, in which case flush first). */

int
fd_tlsrec_sock_close( fd_tlsrec_sock_t * sock,
                      fd_tlsrec_conn_t * conn,
                      int                fd );

/* fd_tlsrec_sock_tx encrypts one record of application data from
   [app,app+app_sz) and sends it, parking any tail the socket did not
   accept.  Does nothing if ciphertext is already parked (flush first).
   *opt_consumed is set to the number of application bytes encrypted,
   at most FD_TLSREC_PLAINTEXT_MAX.  Returns 0 on success,
   FD_TLSREC_SOCK_ERR_SEND, or a positive FD_TLSREC_ERR code. */

int
fd_tlsrec_sock_tx( fd_tlsrec_sock_t * sock,
                   fd_tlsrec_conn_t * conn,
                   int                fd,
                   void const *       app,
                   ulong              app_sz,
                   ulong *            opt_consumed );

FD_FN_CONST char const *
fd_tlsrec_sock_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_tlsrec_fd_tlsrec_sock_h */
