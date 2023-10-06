#ifndef HEADER_fd_src_disco_metrics_fd_ssl_h
#define HEADER_fd_src_disco_metrics_fd_ssl_h

#include "../fd_disco_base.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

/* This struct contains state required by OpenSSL
 * See https://github.com/openssl/openssl/blob/master/doc/designs/ddd/ddd-02-conn-nonblocking.c */
typedef struct {
  SSL *ssl;
  BIO *ssl_bio;
  int rx_need_tx;
  int tx_need_rx;
} conn_t;

#define SSL_SERVICE_RX_BUF_SZ 8192
typedef struct {
  conn_t conn;
  char * data_buf;
  ulong  data_buf_sz;
  ulong  data_buf_capacity;

  char * tx_msg;
  ulong  tx_msg_sz;

  char * tx_ptr;
  int    tx_len;

  int    tx_done;
  long   tx_tick;

  char   rx_msg[ SSL_SERVICE_RX_BUF_SZ ];
  char * rx_ptr;
  int    rx_len;
  int    rx_done;
} ssl_service_state_t;

FD_PROTOTYPES_BEGIN

/*
 * The application wants to create a new outgoing connection using a given
 * SSL_CTX.
 *
 * hostname is a string like "openssl.org:443" or "[::1]:443".
 */
int ssl_conn_init( SSL_CTX * ctx, const char * hostname, conn_t * conn );

/* Format and setup staet machine to send the contents of state->data_buf to the server.
 * Requires subsequent calls to ssl_service */
void
fd_ssl_send_data( const char * server_port,
                  const char * user_pass,
                  const char * db,
                  SSL_CTX    * ctx,
                  ssl_service_state_t * state );

/* Initialize the state machine. */
void
ssl_service_init( ssl_service_state_t * state,
                  char *                data_buf,
                  ulong                 data_buf_sz,
                  char *                tx_buf,
                  ulong                 tx_buf_sz );

void
ssl_service_reinit( ssl_service_state_t * state );

/* Pump the SSL state machine. This function requires a preceeding invocation of fd_ssl_send_data which connects to
 * the server and sets state->tx_msg and state->tx_len. It pumps the state machine until either the message is
 * successfully transmitted or an error occurs (l = -1). Either way, tx_done is set and then we attempt to read a
 * response. If the response is not an HTTP status code of 204 we log it.
 *
 * ssl_service DOES expect state to be initialized. */
void ssl_service( ssl_service_state_t * state );

FD_PROTOTYPES_END

#endif
