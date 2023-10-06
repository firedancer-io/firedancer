#include "fd_ssl.h"
#include <sys/poll.h>

/*
 * The application wants to know a fd it can poll on to determine when the
 * SSL state machine needs to be pumped.
 */
static int
get_conn_fd( conn_t *conn ) {
  return (int) BIO_get_fd(conn->ssl_bio, NULL);
}

/*
 * These functions returns zero or more of:
 *
 *   POLLIN:    The SSL state machine is interested in socket readability events.
 *
 *   POLLOUT:   The SSL state machine is interested in socket writeability events.
 *
 *   POLLERR:   The SSL state machine is interested in socket error events.
 *
 * get_conn_pending_tx returns events which may cause SSL_write to make
 * progress and get_conn_pending_rx returns events which may cause SSL_read
 * to make progress.
 */
static int
get_conn_pending_tx( conn_t *conn ) {
  return (conn->tx_need_rx ? POLLIN : 0) | POLLOUT | POLLERR;
}

static int
get_conn_pending_rx( conn_t *conn ) {
  return (conn->rx_need_tx ? POLLOUT : 0) | POLLIN | POLLERR;
}

/*
 * Close the connection and free bookkeeping structures.
 */
static void
ssl_teardown( conn_t *conn ) {
  BIO_free_all( conn->ssl_bio );
  conn->ssl_bio = NULL;
}

/* Reinitialize the state machine. */
void
ssl_service_reinit( ssl_service_state_t * state ) {
  if( FD_LIKELY( state->conn.ssl_bio ) ) {
    ssl_teardown( &state->conn );
  }
  state->data_buf_capacity = state->data_buf_sz;
  state->tx_ptr = state->tx_msg;
  state->tx_len =  0;
  state->tx_done = 0;
  state->tx_tick = 0;
  state->rx_ptr = state->rx_msg;
  state->rx_len = SSL_SERVICE_RX_BUF_SZ;
  state->rx_done = 0;
  fd_memset( state->data_buf, 0, state->data_buf_sz );
  fd_memset( state->tx_msg,   0, state->tx_msg_sz );
}

/* Initialize the state machine. */
void
ssl_service_init( ssl_service_state_t * state,
                  char *                data_buf,
                  ulong                 data_buf_sz,
                  char *                tx_buf,
                  ulong                 tx_buf_sz ) {
  state->data_buf    = data_buf;
  state->data_buf_sz = data_buf_sz;
  state->tx_msg      = tx_buf;
  state->tx_msg_sz   = tx_buf_sz;
  ssl_service_reinit( state );
}

/* Format and setup staet machine to send the contents of state->data_buf to the server.
 * Requires subsequent calls to ssl_service */
void
fd_ssl_send_data( const char * server_port,
                  const char * user_pass,
                  const char * db,
                  SSL_CTX    * ctx,
                  ssl_service_state_t * state ) {

  if( FD_UNLIKELY( !ssl_conn_init( ctx, server_port, &state->conn ) ) ) {
    return;
  }

  int ret = snprintf( state->tx_msg, state->tx_msg_sz,
                      "POST /write?db=%s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Authorization: Basic %s\r\n"
                      "Content-Length: %zu\r\n"
                      "Connection: close\r\n"
                      "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                      "%s", db, server_port, user_pass, strlen(state->data_buf), state->data_buf );
  if( FD_UNLIKELY( ret<0 || ret>=(int)state->tx_msg_sz ) ) {
    FD_LOG_WARNING(( "snprintf error %d", ret ));
    return;
  }

  state->tx_len = (int)strlen( state->tx_msg );
}

/*
 * The application wants to create a new outgoing connection using a given
 * SSL_CTX.
 *
 * hostname is a string like "openssl.org:443" or "[::1]:443".
 */
int ssl_conn_init( SSL_CTX * ctx, const char * hostname, conn_t * conn ) {
  BIO * out = BIO_new_ssl_connect(ctx);
  if( FD_UNLIKELY( out == NULL ) ) {
    return 0;
  }

  SSL * ssl;
  if( FD_UNLIKELY( BIO_get_ssl( out, &ssl ) ) == 0 ) {
    BIO_free_all( out );
    return 0;
  }

  BIO * buf = BIO_new(BIO_f_buffer());
  if( FD_UNLIKELY( buf == NULL ) ) {
    BIO_free_all(out);
    return 0;
  }

  BIO_push(out, buf);

  if( FD_UNLIKELY( BIO_set_conn_hostname( out, hostname ) == 0 ) ) {
    BIO_free_all( out );
    return 0;
  }

  /* Tell the SSL object the hostname to check certificates against. */
  if( FD_UNLIKELY( SSL_set1_host( ssl, "metrics.solana.com" ) <= 0 ) ) {
    BIO_free_all( out );
    return 0;
  }

  /* Make the BIO nonblocking. */
  BIO_set_nbio( out, 1 );

  conn->ssl_bio = out;
  return 1;
}

/*
 * Non-blocking transmission.
 *
 * Returns -1 on error. Returns -2 if the function would block (corresponds to
 * EWOULDBLOCK).
 */
static int
tx( conn_t *conn, const void *buf, int buf_len ) {
  conn->tx_need_rx = 0;
  int l = BIO_write( conn->ssl_bio, buf, buf_len );
  if( FD_LIKELY( l <= 0 ) ) {
    if( FD_LIKELY( BIO_should_retry( conn->ssl_bio ) ) ) {
      conn->tx_need_rx = BIO_should_read( conn->ssl_bio );
      return -2;
    } else {
      int reason = BIO_get_retry_reason( BIO_get_retry_BIO( conn->ssl_bio, NULL ) );
      FD_LOG_NOTICE(( "tx failure reason %d", reason ));
      return -1;
    }
  }

  return l;
}

/*
 * Non-blocking reception.
 *
 * Returns -1 on error. Returns -2 if the function would block (corresponds to
 * EWOULDBLOCK).
 */
static int
rx( conn_t * conn, void * buf, int buf_len ) {
  int l;
  conn->rx_need_tx = 0;
  l = BIO_read( conn->ssl_bio, buf, buf_len );
  if( FD_LIKELY( l <= 0 ) ) {
    if( FD_LIKELY( BIO_should_retry( conn->ssl_bio ) ) ) {
      conn->rx_need_tx = BIO_should_write( conn->ssl_bio );
      return -2;
    } else {
      return -1;
    }
  }
  return l;
}

/* Log the HTTP response if the status code is not 204 */
static void
parse_http_status_code( const char * http_response ) {
  if( FD_LIKELY( strnlen( http_response, 12 ) == 12 && strncmp( http_response, "HTTP/1.1 ", 9 ) == 0 ) ) {
    int response_code = fd_cstr_to_int( &http_response[9] );
    if( FD_UNLIKELY( response_code != 204 ) ) {
      FD_LOG_WARNING(( "bad http response code %d %s", response_code, http_response ));
    }
  } else {
    FD_LOG_NOTICE(( "bad http response %s", http_response ));
  }
}

/* Pump the SSL state machine. This function requires a preceeding invocation of fd_ssl_send_data which connects to
 * the server and sets state->tx_msg and state->tx_len. It pumps the state machine until either the message is
 * successfully transmitted or an error occurs (l = -1). Either way, tx_done is set and then we attempt to read a
 * response. If the response is not an HTTP status code of 204 we log it.
 *
 * ssl_service DOES expect state to be initialized. */
void
ssl_service( ssl_service_state_t * state ) {
  /* TX */
  if( FD_UNLIKELY( !state->tx_done && state->tx_len != 0 ) ) {
    int l = tx( &state->conn, state->tx_ptr, (int)state->tx_len );
    if( FD_UNLIKELY( l > 0 ) ) {
      state->tx_ptr += l;
      state->tx_len -= l;
      if( FD_UNLIKELY( state->tx_len == 0 )) {
        state->tx_done = 1;
        state->tx_tick = fd_tickcount();
        FD_LOG_WARNING(( "tx capacity hit" ));
      }
    } else if( FD_UNLIKELY( l == -1 ) ) {
      FD_LOG_WARNING(( "tx error %d", state->tx_len ));
      state->tx_done = 1;
    } else if( FD_LIKELY( l == -2 ) ) {
      struct pollfd pfd = {0};
      pfd.fd = get_conn_fd( &state->conn );
      pfd.events = (short) get_conn_pending_tx( &state->conn );
      poll(&pfd, 1, 0 );
    }
  }

  /* RX */
  if( FD_LIKELY( state->tx_done ) ) {
    /* We do not check for a response until 150 milliseconds have passed because
     * the call to poll will block for about a microsecond even when given a timeout parameter of zero */
    long now = fd_tickcount();
    double delta_ns = (double)(now - state->tx_tick) / fd_tempo_tick_per_ns( NULL );
    if( FD_LIKELY( delta_ns < 150000000UL )) {
      return;
    }
    int l = rx( &state->conn, state->rx_ptr, (int)state->rx_len );
    if( FD_UNLIKELY( l > 0 ) ) {
      state->rx_ptr += l;
      state->rx_len -= l;
      if( FD_UNLIKELY( state->rx_len == 0 ) ) {
        state->rx_done = 1;
        parse_http_status_code( state->rx_msg );
        FD_LOG_WARNING(( "rx capacity hit" ));
      }
    } else if( FD_UNLIKELY( l == -1 ) ) {
      state->rx_done = 1;
      parse_http_status_code( state->rx_msg );
    } else if( FD_LIKELY( l == -2 ) ) {
      struct pollfd pfd = {0};
      pfd.fd = get_conn_fd( &state->conn );
      pfd.events = ( short ) get_conn_pending_rx( &state->conn );
      poll(&pfd, 1, 0 );
    }
  }
}
