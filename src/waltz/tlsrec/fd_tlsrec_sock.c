#if FD_HAS_HOSTED

#define _GNU_SOURCE
#include "fd_tlsrec_sock.h"
#include "../tls/fd_tls_proto.h"

#include <errno.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

/* Linux kTLS implements the record cipher only.  fd_tlsrec drives the
   handshake in userspace and this file switches both directions to
   kTLS exactly at the application traffic-key boundary. */

static int
fd_tlsrec_sock_bind( fd_tlsrec_sock_t * sock,
                     fd_tlsrec_conn_t * conn,
                     int                fd ) {
  if( sock->backend==FD_TLSREC_SOCK_BACKEND_SOFTWARE ) return 0;
  if( FD_UNLIKELY( (sock->conn && sock->conn!=conn) ||
                   (sock->ktls_fd!=-1 && sock->ktls_fd!=fd) ) ) {
    errno = EINVAL;
    return FD_TLSREC_SOCK_ERR_KTLS;
  }
  sock->conn    = conn;
  sock->ktls_fd = fd;
  return 0;
}

static int
fd_tlsrec_sock_ktls_attach( fd_tlsrec_sock_t * sock,
                            int                fd ) {
  if( sock->backend==FD_TLSREC_SOCK_BACKEND_SOFTWARE || sock->ktls_ulp ) return 0;
  static char const ulp[] = "tls";
  if( FD_UNLIKELY( setsockopt( fd, SOL_TCP, TCP_ULP, ulp, sizeof(ulp) ) ) )
    return FD_TLSREC_SOCK_ERR_KTLS;
  sock->ktls_ulp = 1U;
  return 0;
}

static void
fd_tlsrec_sock_ktls_crypto_info( struct tls12_crypto_info_aes_gcm_128 * info,
                                 uchar const                            key[ static 16 ],
                                 uchar const                            iv[ static 12 ],
                                 ulong                                  seq ) {
  fd_memset( info, 0, sizeof(*info) );
  info->info.version     = TLS_1_3_VERSION;
  info->info.cipher_type = TLS_CIPHER_AES_GCM_128;
  fd_memcpy( info->salt, iv,   TLS_CIPHER_AES_GCM_128_SALT_SIZE );
  fd_memcpy( info->iv,   iv+4, TLS_CIPHER_AES_GCM_128_IV_SIZE   );
  fd_memcpy( info->key,  key,  TLS_CIPHER_AES_GCM_128_KEY_SIZE  );
  for( uint i=0U; i<8U; i++ ) info->rec_seq[7U-i] = (uchar)(seq>>(8U*i));
}

static int
fd_tlsrec_sock_ktls_set_key( int          fd,
                             int          dir,
                             uchar const  key[ static 16 ],
                             uchar const  iv[ static 12 ],
                             ulong        seq ) {
  struct tls12_crypto_info_aes_gcm_128 info;
  fd_tlsrec_sock_ktls_crypto_info( &info, key, iv, seq );
  int rc = setsockopt( fd, SOL_TLS, dir, &info, sizeof(info) );
  fd_memzero_explicit( &info, sizeof(info) );
  return FD_UNLIKELY( rc ) ? FD_TLSREC_SOCK_ERR_KTLS : 0;
}

static void
fd_tlsrec_sock_next_key( uchar        next_secret[ static 32 ],
                         uchar        next_key[ static 16 ],
                         uchar        next_iv[ static 12 ],
                         uchar const  secret[ static 32 ] ) {
  fd_tls_hkdf_expand_label( next_secret, 32UL, secret, "traffic upd", 11UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( next_key,    16UL, next_secret, "key",     3UL, NULL, 0UL );
  fd_tls_hkdf_expand_label( next_iv,     12UL, next_secret, "iv",      2UL, NULL, 0UL );
}

static int
fd_tlsrec_sock_ktls_enable( fd_tlsrec_sock_t * sock,
                            int                fd ) {
  if( sock->backend!=FD_TLSREC_SOCK_BACKEND_KTLS ) return 0;

  fd_tlsrec_conn_t * conn = sock->conn;
  if( FD_UNLIKELY( !conn ) ) return 0;
  if( !fd_tlsrec_conn_is_ready( conn ) ) return 0;

  /* Bytes already consumed from TCP cannot be handed back to kTLS.
     Therefore activation waits for a complete userspace record and for
     every userspace-generated handshake byte to enter the TCP stack. */
  if( sock->tx_off!=sock->tx_sz || conn->rec_buf.sz || conn->hs_rbuf.sz ) return 0;

  fd_tlsrec_keys_t * keys = &conn->keys[1];
  int rc = fd_tlsrec_sock_ktls_set_key( fd, TLS_RX, keys->read_key, keys->read_iv, conn->read_seq );
  if( FD_UNLIKELY( rc ) ) return rc;
  rc = fd_tlsrec_sock_ktls_set_key( fd, TLS_TX, keys->write_key, keys->write_iv, conn->write_seq );
  if( FD_UNLIKELY( rc ) ) return rc; /* RX cannot be rolled back: caller must close fd */

  sock->backend = FD_TLSREC_SOCK_BACKEND_KTLS_ACTIVE;

  /* The kernel now owns AES-GCM.  Keep only the traffic secrets needed
     to derive future KeyUpdate epochs. */
  fd_memzero_explicit( &conn->keys[0], sizeof(conn->keys[0]) );
  fd_memzero_explicit( &keys->read_gcm,  sizeof(keys->read_gcm)  );
  fd_memzero_explicit( &keys->write_gcm, sizeof(keys->write_gcm) );
  fd_memzero_explicit( keys->read_key,   sizeof(keys->read_key)   );
  fd_memzero_explicit( keys->read_iv,    sizeof(keys->read_iv)    );
  fd_memzero_explicit( keys->write_key,  sizeof(keys->write_key)  );
  fd_memzero_explicit( keys->write_iv,   sizeof(keys->write_iv)   );
  fd_memzero_explicit( conn->tls.kex_private_key, sizeof(conn->tls.kex_private_key) );
  if( conn->hs.base.server ) {
    fd_memzero_explicit( conn->hs.srv.client_hs_secret, sizeof(conn->hs.srv.client_hs_secret) );
  } else {
    fd_memzero_explicit( conn->hs.cli.server_hs_secret, sizeof(conn->hs.cli.server_hs_secret) );
    fd_memzero_explicit( conn->hs.cli.client_hs_secret, sizeof(conn->hs.cli.client_hs_secret) );
    fd_memzero_explicit( conn->hs.cli.master_secret,    sizeof(conn->hs.cli.master_secret)    );
  }
  return 0;
}

static long
fd_tlsrec_sock_ktls_send_control( int          fd,
                                  uchar        record_type,
                                  void const * data,
                                  ulong        data_sz ) {
  struct iovec iov = { .iov_base = (void *)data, .iov_len = data_sz };
  union {
    struct cmsghdr align;
    uchar          buf[ CMSG_SPACE( sizeof(uchar) ) ];
  } control;
  fd_memset( &control, 0, sizeof(control) );

  struct msghdr msg = {
    .msg_iov        = &iov,
    .msg_iovlen     = 1UL,
    .msg_control    = control.buf,
    .msg_controllen = sizeof(control.buf),
  };
  struct cmsghdr * cmsg = CMSG_FIRSTHDR( &msg );
  cmsg->cmsg_level = SOL_TLS;
  cmsg->cmsg_type  = TLS_SET_RECORD_TYPE;
  cmsg->cmsg_len   = CMSG_LEN( sizeof(uchar) );
  *(uchar *)CMSG_DATA( cmsg ) = record_type;

  long sent;
  do {
    sent = sendmsg( fd, &msg, MSG_NOSIGNAL|MSG_DONTWAIT );
  } while( FD_UNLIKELY( sent<0L && errno==EINTR ) );
  return sent;
}

static int
fd_tlsrec_sock_ktls_flush( fd_tlsrec_sock_t * sock,
                           int                fd ) {
  fd_tlsrec_conn_t * conn = sock->conn;
  if( FD_UNLIKELY( !conn ) ) {
    errno = EINVAL;
    return FD_TLSREC_SOCK_ERR_KTLS;
  }

  if( sock->ktls_key_update ) {
    uchar request_update = (uchar)(sock->ktls_key_update-1U);
    uchar msg[5] = { FD_TLS_MSG_KEY_UPDATE, 0U, 0U, 1U, request_update };

    uchar next_secret[32];
    uchar next_key   [16];
    uchar next_iv    [12];
    fd_tlsrec_keys_t * keys = &conn->keys[1];
    fd_tlsrec_sock_next_key( next_secret, next_key, next_iv, keys->write_secret );

    long sent = fd_tlsrec_sock_ktls_send_control( fd, FD_TLS_REC_HANDSHAKE, msg, sizeof(msg) );
    if( FD_UNLIKELY( sent<0L ) ) {
      fd_memzero_explicit( next_secret, sizeof(next_secret) );
      fd_memzero_explicit( next_key,    sizeof(next_key)    );
      fd_memzero_explicit( next_iv,     sizeof(next_iv)     );
      if( errno==EAGAIN || errno==EWOULDBLOCK ) return 1;
      return FD_TLSREC_SOCK_ERR_SEND;
    }
    if( FD_UNLIKELY( sent!=(long)sizeof(msg) ) ) {
      fd_memzero_explicit( next_secret, sizeof(next_secret) );
      fd_memzero_explicit( next_key,    sizeof(next_key)    );
      fd_memzero_explicit( next_iv,     sizeof(next_iv)     );
      errno = EIO; /* A partial kTLS control record cannot be retried safely. */
      return FD_TLSREC_SOCK_ERR_KTLS;
    }

    int rc = fd_tlsrec_sock_ktls_set_key( fd, TLS_TX, next_key, next_iv, 0UL );
    if( FD_LIKELY( !rc ) ) {
      fd_memcpy( keys->write_secret, next_secret, sizeof(next_secret) );
      conn->write_seq       = 0UL;
      sock->ktls_key_update = 0U;
    }
    fd_memzero_explicit( next_secret, sizeof(next_secret) );
    fd_memzero_explicit( next_key,    sizeof(next_key)    );
    fd_memzero_explicit( next_iv,     sizeof(next_iv)     );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  if( sock->ktls_close ) {
    uchar const alert[2] = { 1U, FD_TLS_ALERT_CLOSE_NOTIFY };
    long sent = fd_tlsrec_sock_ktls_send_control( fd, FD_TLS_REC_ALERT, alert, sizeof(alert) );
    if( FD_UNLIKELY( sent<0L ) ) {
      if( errno==EAGAIN || errno==EWOULDBLOCK ) return 1;
      return FD_TLSREC_SOCK_ERR_SEND;
    }
    if( FD_UNLIKELY( sent!=(long)sizeof(alert) ) ) {
      errno = EIO;
      return FD_TLSREC_SOCK_ERR_KTLS;
    }
    sock->ktls_close = 0U;
    conn->tx_closed  = 1U;
  }

  return 0;
}

static int
fd_tlsrec_sock_ktls_fail( fd_tlsrec_sock_t * sock,
                          int                fd,
                          uint               alert,
                          ushort             reason ) {
  fd_tlsrec_conn_t * conn = sock->conn;
  conn->hs.base.state  = FD_TLS_HS_FAIL;
  conn->hs.base.reason = reason;
  sock->ktls_key_update = 0U;
  sock->ktls_close      = 0U;

  if( !conn->tx_closed ) {
    uchar msg[2] = { 2U, (uchar)alert };
    long sent = fd_tlsrec_sock_ktls_send_control( fd, FD_TLS_REC_ALERT, msg, sizeof(msg) );
    if( sent==(long)sizeof(msg) ) conn->tx_closed = 1U;
  }
  return FD_TLSREC_ERR_PROTO;
}

static int
fd_tlsrec_sock_ktls_rekey_rx( fd_tlsrec_sock_t * sock,
                              int                fd,
                              uchar              request_update ) {
  fd_tlsrec_conn_t * conn = sock->conn;
  fd_tlsrec_keys_t * keys = &conn->keys[1];
  uchar next_secret[32];
  uchar next_key   [16];
  uchar next_iv    [12];
  fd_tlsrec_sock_next_key( next_secret, next_key, next_iv, keys->read_secret );

  int rc = fd_tlsrec_sock_ktls_set_key( fd, TLS_RX, next_key, next_iv, 0UL );
  if( FD_LIKELY( !rc ) ) {
    fd_memcpy( keys->read_secret, next_secret, sizeof(next_secret) );
    conn->read_seq = 0UL;
    if( request_update && !conn->tx_closed )
      sock->ktls_key_update = fd_uchar_max( sock->ktls_key_update, (uchar)1U );
  }
  fd_memzero_explicit( next_secret, sizeof(next_secret) );
  fd_memzero_explicit( next_key,    sizeof(next_key)    );
  fd_memzero_explicit( next_iv,     sizeof(next_iv)     );
  return rc;
}

static ulong
fd_tlsrec_sock_hs_msg_sz( uchar const hdr[ static 4 ] ) {
  return 4UL + ((ulong)hdr[1]<<16) + ((ulong)hdr[2]<<8) + (ulong)hdr[3];
}

/* Process post-handshake handshake plaintext returned by kTLS.  Linux
   pauses RX as soon as a record starts with KeyUpdate, so RFC 8446's
   requirement that KeyUpdate occupy a standalone record is enforced
   here before installing the next RX key. */

static int
fd_tlsrec_sock_ktls_handshake( fd_tlsrec_sock_t * sock,
                               int                fd,
                               uchar const *      data,
                               ulong              data_sz ) {
  fd_tlsrec_conn_t * conn = sock->conn;
  fd_tlsrec_hs_rbuf_t * rbuf = &conn->hs_rbuf;

  if( FD_UNLIKELY( !data_sz ) )
    return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_HS_MSG_SIZE );

  if( !rbuf->sz && data[0]==FD_TLS_MSG_KEY_UPDATE ) {
    if( FD_UNLIKELY( data_sz!=5UL || data[1] || data[2] || data[3]!=1U ) )
      return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_KEY_UPDATE_PARSE );
    if( FD_UNLIKELY( data[4]>1U ) )
      return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_ILLEGAL_PARAMETER, FD_TLS_REASON_KEY_UPDATE_PARSE );
    return fd_tlsrec_sock_ktls_rekey_rx( sock, fd, data[4] );
  }

  while( data_sz ) {
    if( rbuf->sz<sizeof(fd_tls_msg_hdr_t) ) {
      ulong n = fd_ulong_min( sizeof(fd_tls_msg_hdr_t)-rbuf->sz, data_sz );
      fd_memcpy( rbuf->buf+rbuf->sz, data, n );
      rbuf->sz += n; data += n; data_sz -= n;
      if( rbuf->sz<sizeof(fd_tls_msg_hdr_t) ) return 0;
    }

    ulong msg_sz = fd_tlsrec_sock_hs_msg_sz( rbuf->buf );
    if( FD_UNLIKELY( msg_sz>FD_TLSREC_HS_MSG_CAP ) )
      return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_HS_MSG_SIZE );

    ulong n = fd_ulong_min( msg_sz-rbuf->sz, data_sz );
    fd_memcpy( rbuf->buf+rbuf->sz, data, n );
    rbuf->sz += n; data += n; data_sz -= n;
    if( rbuf->sz<msg_sz ) return 0;

    uchar msg_type = rbuf->buf[0];
    rbuf->sz = 0UL;
    if( FD_UNLIKELY( msg_type==FD_TLS_MSG_KEY_UPDATE ) )
      return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_HS_KEY_CHANGE );
    if( FD_UNLIKELY( msg_type!=FD_TLS_MSG_NEW_SESSION_TICKET || conn->hs.base.server ) )
      return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_POST_HS_MSG );
  }
  return 0;
}

static int
fd_tlsrec_sock_ktls_rx( fd_tlsrec_sock_t * sock,
                        int                fd,
                        ulong *            opt_rx_sz ) {
  if( FD_UNLIKELY( fd_tlsrec_sock_rx_avail( sock ) ) ) return 0;
  if( FD_UNLIKELY( sock->conn->rx_closed ) ) return FD_TLSREC_SOCK_ERR_EOF;

  int flush = fd_tlsrec_sock_ktls_flush( sock, fd );
  if( FD_UNLIKELY( flush<0 ) ) return flush;

  struct iovec iov = { .iov_base = sock->rx_buf, .iov_len = sizeof(sock->rx_buf) };
  union {
    struct cmsghdr align;
    uchar          buf[ CMSG_SPACE( sizeof(uchar) ) ];
  } control;
  fd_memset( &control, 0, sizeof(control) );
  struct msghdr msg = {
    .msg_iov        = &iov,
    .msg_iovlen     = 1UL,
    .msg_control    = control.buf,
    .msg_controllen = sizeof(control.buf),
  };

  long n;
  do {
    n = recvmsg( fd, &msg, MSG_NOSIGNAL|MSG_DONTWAIT );
  } while( FD_UNLIKELY( n<0L && errno==EINTR ) );
  if( FD_UNLIKELY( n<0L ) ) {
    if( errno==EAGAIN || errno==EWOULDBLOCK ) return 0;
    if( errno==EBADMSG ) {
      sock->conn->hs.base.state  = FD_TLS_HS_FAIL;
      sock->conn->hs.base.reason = FD_TLS_REASON_REC_MAC;
      return FD_TLSREC_ERR_CRYPTO;
    }
    return errno==EKEYEXPIRED ? FD_TLSREC_SOCK_ERR_KTLS : FD_TLSREC_SOCK_ERR_RECV;
  }
  if( opt_rx_sz ) *opt_rx_sz = (ulong)n;

  if( FD_UNLIKELY( msg.msg_flags & (MSG_CTRUNC|MSG_TRUNC) ) ) {
    errno = EIO;
    return FD_TLSREC_SOCK_ERR_KTLS;
  }

  uchar record_type = FD_TLS_REC_APPLICATION_DATA;
  struct cmsghdr * cmsg = CMSG_FIRSTHDR( &msg );
  if( cmsg ) {
    if( FD_UNLIKELY( cmsg->cmsg_level!=SOL_TLS ||
                     cmsg->cmsg_type !=TLS_GET_RECORD_TYPE ||
                     cmsg->cmsg_len  <CMSG_LEN( sizeof(uchar) ) ) ) {
      errno = EIO;
      return FD_TLSREC_SOCK_ERR_KTLS;
    }
    record_type = *(uchar *)CMSG_DATA( cmsg );
  } else if( FD_UNLIKELY( !n ) ) {
    return FD_TLSREC_SOCK_ERR_EOF;
  }

  switch( record_type ) {
  case FD_TLS_REC_APPLICATION_DATA:
    if( FD_UNLIKELY( sock->conn->hs_rbuf.sz ) )
      return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_HS_INTERLEAVED );
    sock->rx_off = 0UL;
    sock->rx_sz  = (ulong)n;
    return 0;

  case FD_TLS_REC_HANDSHAKE: {
    int rc = fd_tlsrec_sock_ktls_handshake( sock, fd, sock->rx_buf, (ulong)n );
    if( FD_UNLIKELY( rc ) ) return rc;
    rc = fd_tlsrec_sock_ktls_flush( sock, fd );
    return rc<0 ? rc : 0;
  }

  case FD_TLS_REC_ALERT:
    if( FD_UNLIKELY( sock->conn->hs_rbuf.sz || !n || (n&1L) ) )
      return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_DECODE_ERROR, FD_TLS_REASON_ALERT_PARSE );
    for( long off=0L; off<n; off+=2L ) {
      if( sock->rx_buf[off+1L]==FD_TLS_ALERT_CLOSE_NOTIFY ) {
        sock->conn->rx_closed = 1U;
        return FD_TLSREC_SOCK_ERR_EOF;
      }
      if( sock->rx_buf[off+1L]!=FD_TLS_ALERT_USER_CANCELED ) {
        sock->conn->hs.base.state  = FD_TLS_HS_FAIL;
        sock->conn->hs.base.reason = FD_TLS_REASON_PEER_ALERT;
        return FD_TLSREC_ERR_PROTO;
      }
    }
    return 0;

  default:
    return fd_tlsrec_sock_ktls_fail( sock, fd, FD_TLS_ALERT_UNEXPECTED_MESSAGE, FD_TLS_REASON_REC_TYPE );
  }
}

int
fd_tlsrec_sock_flush( fd_tlsrec_sock_t * sock,
                      int                fd ) {
  if( FD_UNLIKELY( sock->backend!=FD_TLSREC_SOCK_BACKEND_SOFTWARE &&
                   sock->ktls_fd!=-1 && sock->ktls_fd!=fd ) ) {
    errno = EINVAL;
    return FD_TLSREC_SOCK_ERR_KTLS;
  }
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

  if( sock->backend==FD_TLSREC_SOCK_BACKEND_KTLS && sock->conn ) {
    int rc = fd_tlsrec_sock_ktls_attach( sock, fd );
    if( FD_UNLIKELY( rc ) ) return rc;
    rc = fd_tlsrec_sock_ktls_enable( sock, fd );
    if( FD_UNLIKELY( rc ) ) return rc;
  }
  if( sock->backend==FD_TLSREC_SOCK_BACKEND_KTLS_ACTIVE )
    return fd_tlsrec_sock_ktls_flush( sock, fd );
  return 0;
}

static ulong
fd_tlsrec_sock_handshake_rx_max( fd_tlsrec_conn_t const * conn ) {
  fd_tlsrec_buf_t const * rbuf = &conn->rec_buf;
  if( rbuf->sz<sizeof(fd_tlsrec_hdr_t) ) return sizeof(fd_tlsrec_hdr_t)-rbuf->sz;
  ulong payload_sz = ((ulong)rbuf->buf[3]<<8) | (ulong)rbuf->buf[4];
  ulong rec_sz = sizeof(fd_tlsrec_hdr_t) + payload_sz;
  if( FD_UNLIKELY( rec_sz<=rbuf->sz ) ) return 1UL;
  return fd_ulong_min( rec_sz-rbuf->sz, FD_TLSREC_SOCK_RX_MTU );
}

int
fd_tlsrec_sock_rx( fd_tlsrec_sock_t * sock,
                   fd_tlsrec_conn_t * conn,
                   int                fd,
                   ulong *            opt_rx_sz ) {
  if( opt_rx_sz ) *opt_rx_sz = 0UL;
  int rc = fd_tlsrec_sock_bind( sock, conn, fd );
  if( FD_UNLIKELY( rc ) ) return rc;

  if( sock->backend!=FD_TLSREC_SOCK_BACKEND_SOFTWARE ) {
    rc = fd_tlsrec_sock_ktls_attach( sock, fd );
    if( FD_UNLIKELY( rc ) ) return rc;
    if( fd_tlsrec_conn_is_ready( conn ) ) {
      rc = fd_tlsrec_sock_flush( sock, fd );
      if( FD_UNLIKELY( rc<0 ) ) return rc;
      if( sock->backend==FD_TLSREC_SOCK_BACKEND_KTLS_ACTIVE )
        return fd_tlsrec_sock_ktls_rx( sock, fd, opt_rx_sz );
      return 0; /* The userspace Finished is still parked. */
    }
  }

  ulong tx_free = sizeof(sock->tx_buf) - sock->tx_sz;
  if( FD_UNLIKELY( fd_tlsrec_sock_rx_avail( sock ) || tx_free<FD_TLSREC_SOCK_TX_RESERVE ) ) return 0;
  if( FD_UNLIKELY( conn->rx_closed ) ) return FD_TLSREC_SOCK_ERR_EOF;

  uchar tcp_rx_buf[ FD_TLSREC_SOCK_RX_MTU ];
  ulong tcp_rx_max = sizeof(tcp_rx_buf);
  if( sock->backend==FD_TLSREC_SOCK_BACKEND_KTLS )
    tcp_rx_max = fd_tlsrec_sock_handshake_rx_max( conn );

  long tcp_rx_sz;
  do {
    tcp_rx_sz = recv( fd, tcp_rx_buf, tcp_rx_max, MSG_NOSIGNAL|MSG_DONTWAIT );
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

  /* Send before reporting a TLS error so an alert reaches the peer. */
  if( tcp_tx_sz || (sock->backend==FD_TLSREC_SOCK_BACKEND_KTLS && fd_tlsrec_conn_is_ready( conn )) ) {
    int flush = fd_tlsrec_sock_flush( sock, fd );
    if( FD_UNLIKELY( flush<0 ) ) return flush;
  }
  if( FD_UNLIKELY( err ) ) return err;
  if( FD_UNLIKELY( conn->rx_closed && !app_rx_sz ) ) return FD_TLSREC_SOCK_ERR_EOF;

  if( opt_rx_sz ) *opt_rx_sz = (ulong)tcp_rx_sz;
  return 0;
}

int
fd_tlsrec_sock_close( fd_tlsrec_sock_t * sock,
                      fd_tlsrec_conn_t * conn,
                      int                fd ) {
  int rc = fd_tlsrec_sock_bind( sock, conn, fd );
  if( FD_UNLIKELY( rc ) ) return rc;
  if( sock->backend!=FD_TLSREC_SOCK_BACKEND_SOFTWARE ) {
    if( FD_UNLIKELY( !fd_tlsrec_conn_is_ready( conn ) || conn->tx_closed || sock->ktls_close ) )
      return FD_TLSREC_ERR_STATE;
    sock->ktls_close = 1U;
    return fd_tlsrec_sock_flush( sock, fd );
  }

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
  int rc = fd_tlsrec_sock_bind( sock, conn, fd );
  if( FD_UNLIKELY( rc ) ) return rc;

  if( sock->backend==FD_TLSREC_SOCK_BACKEND_KTLS ) {
    rc = fd_tlsrec_sock_ktls_attach( sock, fd );
    if( FD_UNLIKELY( rc ) ) return rc;
    rc = fd_tlsrec_sock_flush( sock, fd );
    if( FD_UNLIKELY( rc<0 ) ) return rc;
    if( sock->backend!=FD_TLSREC_SOCK_BACKEND_KTLS_ACTIVE ) return 0;
  }

  if( sock->backend==FD_TLSREC_SOCK_BACKEND_KTLS_ACTIVE ) {
    if( FD_UNLIKELY( !fd_tlsrec_conn_is_ready( conn ) || conn->tx_closed ) ) return FD_TLSREC_ERR_STATE;
    if( FD_UNLIKELY( sock->ktls_key_update || sock->ktls_close ) ) {
      rc = fd_tlsrec_sock_ktls_flush( sock, fd );
      if( FD_UNLIKELY( rc<0 ) ) return rc;
      if( rc ) return 0;
    }
    if( !app_sz ) return 0;

    if( FD_UNLIKELY( conn->write_seq>=FD_TLSREC_KEY_UPDATE_SEQ ) ) {
      sock->ktls_key_update = 1U;
      rc = fd_tlsrec_sock_ktls_flush( sock, fd );
      if( FD_UNLIKELY( rc<0 ) ) return rc;
      if( rc ) return 0;
    }

    ulong send_sz = fd_ulong_min( app_sz, FD_TLSREC_PLAINTEXT_MAX );
    long sent;
    do {
      sent = send( fd, app, send_sz, MSG_NOSIGNAL|MSG_DONTWAIT );
    } while( FD_UNLIKELY( sent<0L && errno==EINTR ) );
    if( FD_UNLIKELY( sent<0L ) ) {
      if( errno==EAGAIN || errno==EWOULDBLOCK ) return 0;
      return FD_TLSREC_SOCK_ERR_SEND;
    }
    if( sent>0L ) conn->write_seq++;
    if( opt_consumed ) *opt_consumed = (ulong)sent;
    return 0;
  }

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

int
fd_tlsrec_sock_key_update( fd_tlsrec_sock_t * sock,
                           fd_tlsrec_conn_t * conn,
                           int                fd,
                           int                request_peer_update ) {
  int rc = fd_tlsrec_sock_bind( sock, conn, fd );
  if( FD_UNLIKELY( rc ) ) return rc;
  if( FD_UNLIKELY( request_peer_update<0 || request_peer_update>1 ) ) return FD_TLSREC_ERR_PROTO;
  if( FD_UNLIKELY( sock->backend!=FD_TLSREC_SOCK_BACKEND_KTLS_ACTIVE ||
                   !fd_tlsrec_conn_is_ready( conn ) || conn->tx_closed || sock->ktls_close ) )
    return FD_TLSREC_ERR_STATE;
  sock->ktls_key_update = fd_uchar_max( sock->ktls_key_update, (uchar)(request_peer_update+1) );
  return fd_tlsrec_sock_ktls_flush( sock, fd );
}

char const *
fd_tlsrec_sock_strerror( int err ) {
  switch( err ) {
  case 0:                       return "success";
  case FD_TLSREC_SOCK_ERR_RECV: return "recv failed";
  case FD_TLSREC_SOCK_ERR_SEND: return "send failed";
  case FD_TLSREC_SOCK_ERR_EOF:  return "peer closed connection";
  case FD_TLSREC_SOCK_ERR_KTLS: return "kernel TLS failed";
  default:                      return err>0 ? fd_tlsrec_strerror( err ) : "unknown";
  }
}

#endif /* FD_HAS_HOSTED */
