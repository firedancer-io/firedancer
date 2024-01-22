#include "fd_quic_tls.h"
#include "../fd_quic_private.h"
#include "../../../util/fd_util.h"

#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <openssl/err.h>

/* internal callbacks */
int
fd_quic_ssl_add_handshake_data( SSL *                 ssl,
                                OSSL_ENCRYPTION_LEVEL enc_level,
                                uchar const *         data,
                                ulong                 data_sz );

int
fd_quic_ssl_flush_flight( SSL * ssl );

int
fd_quic_ssl_send_alert( SSL *                       ssl,
                        enum ssl_encryption_level_t level,
                        uchar                       alert );

int
fd_quic_ssl_client_hello( SSL *  ssl,
                          int *  alert,
                          void * arg );

int
fd_quic_tls_cb_alpn_select( SSL * ssl,
                            uchar const ** out,
                            uchar *        out_len,
                            uchar const *  in,
                            unsigned       in_len,
                            void *         arg );

int
fd_quic_ssl_set_encryption_secrets( SSL *                 ssl,
                                    OSSL_ENCRYPTION_LEVEL enc_level,
                                    uchar const *         read_secret,
                                    uchar const *         write_secret,
                                    ulong                 secret_len );

SSL_CTX *
fd_quic_create_context( fd_quic_tls_t * quic_tls,
                        X509 *          cert,
                        EVP_PKEY *      key );

/* fd_quic_tls_strerror returns a cstr describing the last OpenSSL
   error.  Error is read from OpenSSL's error stack.  The returned
   cstr is backed by a static buffer and is valid until next call. */

static char const *
fd_quic_tls_strerror( void ) {
  static char errbuf[ 512UL ];
  errbuf[ 0 ] = '\0';

  ulong err_id = ERR_get_error();
  ERR_error_string_n( err_id, errbuf, 2048UL );

  return errbuf;
}

ulong
fd_quic_tls_align( void ) {
  return alignof( fd_quic_tls_t );
}

/* fd_quic_tls_layout_t describes the memory layout on an fd_quic_tls_t */
struct fd_quic_tls_layout {
  ulong handshakes_off;
  ulong handshakes_used_off;
};
typedef struct fd_quic_tls_layout fd_quic_tls_layout_t;

ulong
fd_quic_tls_footprint_ext( ulong handshake_cnt,
                           fd_quic_tls_layout_t * layout ) {

  ulong off  = sizeof( fd_quic_tls_t );

        off  = fd_ulong_align_up( off, alignof( fd_quic_tls_hs_t ) );
  layout->handshakes_off = off;
        off += handshake_cnt * sizeof( fd_quic_tls_hs_t );

        /* no align required */
  layout->handshakes_used_off = off;
        off += handshake_cnt; /* used handshakes */

  return off;
}

ulong
fd_quic_tls_footprint( ulong handshake_cnt ) {
  fd_quic_tls_layout_t layout;
  return fd_quic_tls_footprint_ext( handshake_cnt, &layout );
}

fd_quic_tls_t *
fd_quic_tls_new( void *              mem,
                 fd_quic_tls_cfg_t * cfg ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !cfg ) ) {
    FD_LOG_WARNING(( "NULL cfg" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof( fd_quic_tls_t ) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong handshake_cnt = cfg->max_concur_handshakes;

  fd_quic_tls_layout_t layout = {0};
  ulong footprint = fd_quic_tls_footprint_ext( handshake_cnt, &layout );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for config" ));
    return NULL;
  }

  fd_quic_tls_t * self = (fd_quic_tls_t *)mem;

  self->client_hello_cb       = cfg->client_hello_cb;
  self->alert_cb              = cfg->alert_cb;
  self->secret_cb             = cfg->secret_cb;
  self->handshake_complete_cb = cfg->handshake_complete_cb;
  self->keylog_cb             = cfg->keylog_cb;
  self->keylog_fd             = cfg->keylog_fd;
  self->max_concur_handshakes = cfg->max_concur_handshakes;

  ulong handshakes_laddr = (ulong)mem + layout.handshakes_off;
  fd_quic_tls_hs_t * handshakes = (fd_quic_tls_hs_t *)(handshakes_laddr);
  self->handshakes = handshakes;

  /* FIXME use a bitmap instead of an array */
  ulong used_handshakes_laddr = (ulong)mem + layout.handshakes_used_off;
  uchar * used_handshakes = (uchar *)(used_handshakes_laddr);
  self->used_handshakes = used_handshakes;

  // set all to free
  fd_memset( used_handshakes, 0, (ulong)self->max_concur_handshakes );

  // create ssl context
  self->ssl_ctx = fd_quic_create_context( self, cfg->cert, cfg->cert_key );
  cfg->cert     = NULL;
  cfg->cert_key = NULL;
  if( FD_UNLIKELY( !self->ssl_ctx ) ) {
    FD_LOG_WARNING(( "fd_quic_create_context failed" ));
    return NULL;
  }

  /* keep pointer to ALPNs */
  self->alpns    = cfg->alpns;
  self->alpns_sz = cfg->alpns_sz;

  return self;
}

void *
fd_quic_tls_delete( fd_quic_tls_t * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL self" ));
    return NULL;
  }

  // free up all used handshakes
  ulong              hs_sz   = (ulong)self->max_concur_handshakes;
  fd_quic_tls_hs_t * hs      = self->handshakes;
  uchar *            hs_used = self->used_handshakes;
  for( ulong j = 0; j < hs_sz; ++j ) {
    if( hs_used[j] ) fd_quic_tls_hs_delete( hs + j );
  }

  if( self->ssl_ctx )
    SSL_CTX_free( self->ssl_ctx );

  return self;
}

fd_quic_tls_hs_t *
fd_quic_tls_hs_new( fd_quic_tls_t * quic_tls,
                    void *          context,
                    int             is_server,
                    char const *    hostname,
                    uchar const *   transport_params_raw,
                    ulong           transport_params_raw_sz ) {
  // find a free handshake
  ulong hs_idx = 0;
  ulong hs_sz  = (ulong)quic_tls->max_concur_handshakes;
  uchar * hs_used = quic_tls->used_handshakes;
  while( hs_idx < hs_sz && hs_used[hs_idx] ) hs_idx++;

  // no room
  if( hs_idx == hs_sz ) {
    FD_DEBUG( FD_LOG_DEBUG(( "tls_hs alloc fail" )) );
    return NULL;
  }

  FD_DEBUG( FD_LOG_DEBUG(( "tls_hs alloc %lu", hs_idx )) );

  // set the handshake to used
  hs_used[hs_idx] = 1;

  long int ssl_rc = 0;

  // self is the handshake at hs_idx
  fd_quic_tls_hs_t * self = quic_tls->handshakes + hs_idx;

  // clear the handshake bits
  fd_memset( self, 0, sizeof(fd_quic_tls_hs_t) );

  // set properties on self
  self->quic_tls  = quic_tls;
  self->is_server = is_server;
  self->is_flush  = 0;
  self->context   = context;
  self->state     = is_server ? FD_QUIC_TLS_HS_STATE_NEED_INPUT : FD_QUIC_TLS_HS_STATE_NEED_SERVICE;

  /* initialize handshake data */

  /* init free list */
  self->hs_data_free_idx = 0u; /* head points at first */
  for( ushort j = 0u; j < FD_QUIC_TLS_HS_DATA_CNT; ++j ) {
    if( j < FD_QUIC_TLS_HS_DATA_CNT-1u ) {
      self->hs_data[j].next_idx = (ushort)(j+1u); /* each point to next */
    } else {
      self->hs_data[j].next_idx = FD_QUIC_TLS_HS_DATA_UNUSED ;
    }
  }

  /* no data pending */
  for( unsigned j = 0; j < 4; ++j ) {
    self->hs_data_pend_idx[j]     = FD_QUIC_TLS_HS_DATA_UNUSED;
    self->hs_data_pend_end_idx[j] = FD_QUIC_TLS_HS_DATA_UNUSED;
  }

  /* set head and tail of used hs_data */
  self->hs_data_buf_head = 0;
  self->hs_data_buf_tail = 0;

  /* all handshake offsets start at zero */
  fd_memset( self->hs_data_offset, 0, sizeof( self->hs_data_offset ) );

  // set up ssl
  ERR_clear_error();
  SSL * ssl = SSL_new( quic_tls->ssl_ctx );
  if( FD_UNLIKELY( !ssl ) ) {
    FD_LOG_WARNING(( "SSL_new failed: %s", fd_quic_tls_strerror() ));
    goto fd_quic_tls_hs_new_error;
  }

  // add the user context to the ssl
  SSL_set_app_data( ssl, self );

  // set ssl on self to this new object
  self->ssl = ssl;

  /* solana actual: "solana-tpu" */
  ERR_clear_error();
  ssl_rc = SSL_set_alpn_protos( ssl, quic_tls->alpns, quic_tls->alpns_sz );
  if( FD_UNLIKELY( 0!=ssl_rc ) ) {
    FD_LOG_WARNING(( "SSL_set_alpn_protos failed: %s", fd_quic_tls_strerror() ));
    goto fd_quic_tls_hs_new_error;
  }

  /* set transport params on ssl */
  ERR_clear_error();
  if( FD_UNLIKELY( 1!=SSL_set_quic_transport_params( ssl, transport_params_raw, transport_params_raw_sz ) ) ) {
    FD_LOG_WARNING(( "SSL_set_quic_transport_params failed: %s", fd_quic_tls_strerror() ));
    goto fd_quic_tls_hs_new_error;
  }

  // returns void
  if( !is_server ) {
    SSL_set_connect_state( ssl );

    /* TODO determine whether hostname is required */
    if( hostname && hostname[0] != '\0' ) {
      ERR_clear_error();
      if( FD_UNLIKELY( 1!=SSL_set_tlsext_host_name( ssl, hostname ) ) ) {
        FD_LOG_WARNING(( "SSL_set_tlsext_host_name failed: %s", fd_quic_tls_strerror() ));
        goto fd_quic_tls_hs_new_error;
      }
    }
  } else {
    SSL_set_accept_state( ssl );
  }

  return self;

fd_quic_tls_hs_new_error:
  // free handshake
  FD_DEBUG( FD_LOG_DEBUG(( "tls_hs free inline %lu", hs_idx )) );
  quic_tls->used_handshakes[hs_idx] = 0;

  return NULL;
}

void
fd_quic_tls_hs_delete( fd_quic_tls_hs_t * self ) {
  if( !self ) return;

  self->state = FD_QUIC_TLS_HS_STATE_DEAD;

  fd_quic_tls_t * quic_tls = self->quic_tls;

  // find index into array
  ulong hs_idx = (ulong)( self - quic_tls->handshakes );
  FD_DEBUG( FD_LOG_DEBUG(( "tls_hs free %lu", hs_idx )) );
  if( quic_tls->used_handshakes[hs_idx] != 1 ) {
    return;
  }

  if( self->ssl ) SSL_free( self->ssl );

  self->ssl = NULL;

  // set used at the given index to zero to free
  quic_tls->used_handshakes[hs_idx] = 0;
}

int
fd_quic_tls_provide_data( fd_quic_tls_hs_t *    self,
                          OSSL_ENCRYPTION_LEVEL enc_level,
                          uchar const *         data,
                          ulong                 data_sz ) {
  switch( self->state ) {
    case FD_QUIC_TLS_HS_STATE_DEAD:
    case FD_QUIC_TLS_HS_STATE_COMPLETE:
      return FD_QUIC_TLS_SUCCESS;

    default:
      break;
  }

  if( FD_UNLIKELY( 1!=SSL_provide_quic_data( self->ssl, enc_level, data, data_sz ) ) ) {
    FD_LOG_WARNING(( "SSL_provide_quic_data failed: %s", fd_quic_tls_strerror() ));
    return FD_QUIC_TLS_FAILED;
  }

  /* needs a call to fd_quic_tls_process */
  self->state = FD_QUIC_TLS_HS_STATE_NEED_SERVICE;

  return FD_QUIC_TLS_SUCCESS;
}

int
fd_quic_tls_process( fd_quic_tls_hs_t * self ) {
  if( self->state != FD_QUIC_TLS_HS_STATE_NEED_SERVICE ) return FD_QUIC_TLS_SUCCESS;

  int   ssl_rc = 0;
  SSL * ssl    = self->ssl;
  if( !self->is_hs_complete ) {
    while(1) {
      ssl_rc = SSL_do_handshake( self->ssl );
      switch( ssl_rc ) {
        case 0: // failed
          // according to the API rc==0 means failure
          // but can this occur without any error?
          {
            int err = SSL_get_error( ssl, (int)ssl_rc );
            FD_LOG_WARNING(( "OpenSSL error: %d %s", err, fd_quic_tls_strerror() ));
            self->err_ssl_rc  = (int)ssl_rc;
            self->err_ssl_err = err;
            self->err_line    = __LINE__;
            self->state       = FD_QUIC_TLS_HS_STATE_DEAD;
            return FD_QUIC_TLS_FAILED;
          }
        case 1: // completed
          self->is_hs_complete = 1;
          self->quic_tls->handshake_complete_cb( self, self->context );
          self->state = FD_QUIC_TLS_HS_STATE_COMPLETE;
          /* free handshake data */
          return FD_QUIC_TLS_SUCCESS;
        default:
          {
            int err = SSL_get_error( ssl, (int)ssl_rc );
            /* WANT_READ and WANT_WRITE are expected conditions */
            if( FD_LIKELY( err == SSL_ERROR_WANT_READ ) ) {
              /* set state such that we don't do extra work until
                 provided with more data */
              self->state = FD_QUIC_TLS_HS_STATE_NEED_INPUT;
              return FD_QUIC_TLS_SUCCESS;
            }
            if( FD_LIKELY( err == SSL_ERROR_WANT_WRITE ) ) {
              break;
            }
            FD_LOG_WARNING(( "OpenSSL error: %d %s", err, fd_quic_tls_strerror() ));
            self->err_ssl_rc  = (int)ssl_rc;
            self->err_ssl_err = err;
            self->err_line    = __LINE__;
            self->state       = FD_QUIC_TLS_HS_STATE_DEAD;
            return FD_QUIC_TLS_FAILED;
          }
      }
    }
  } else {
    // handle post-handshake messages
    switch( SSL_process_quic_post_handshake( self->ssl ) ) {
      case 0: // failed
        {
          int err = SSL_get_error( ssl, (int)ssl_rc );
          if( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
            // WANT_READ and WANT_WRITE are expected conditions
            return FD_QUIC_TLS_SUCCESS;
          } else {
            self->err_ssl_rc  = (int)ssl_rc;
            self->err_ssl_err = err;
            self->err_line    = __LINE__;

            return FD_QUIC_TLS_FAILED;
          }
        }
      case 1: // success
        return FD_QUIC_TLS_SUCCESS;
      default:
        {
          // unexpected rc - treat as error
          int err = SSL_get_error( ssl, (int)ssl_rc );
          if( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
            // WANT_READ and WANT_WRITE are expected conditions
            return FD_QUIC_TLS_SUCCESS;
          } else {
            self->err_ssl_rc  = (int)ssl_rc;
            self->err_ssl_err = err;
            self->err_line    = __LINE__;

            return FD_QUIC_TLS_FAILED;
          }
        }
    }
  }
}

/* internal callbacks */
int
fd_quic_ssl_add_handshake_data( SSL *                 ssl,
                                OSSL_ENCRYPTION_LEVEL enc_level,
                                uchar const *         data,
                                ulong                 data_sz ) {
  uint buf_sz = FD_QUIC_TLS_HS_DATA_SZ;
  if( data_sz > buf_sz ) {
    return 0;
  }

  fd_quic_tls_hs_t * hs = SSL_get_app_data( ssl );

  /* add handshake data to handshake for retrieval by user */

  /* find free handshake data */
  ushort hs_data_idx = hs->hs_data_free_idx;
  if( hs_data_idx == FD_QUIC_TLS_HS_DATA_UNUSED ) {
    /* no free structures left. fail */
    return 0;
  }

  /* allocate enough space from hs data buffer */
  uint head       = hs->hs_data_buf_head;
  uint tail       = hs->hs_data_buf_tail;
  uint alloc_head = 0; /* to be determined */

#define POW2_ROUND_UP( x, a ) (((x)+((a)-1)) & (~((a)-1)))
  uint alloc_data_sz = POW2_ROUND_UP( data_sz, FD_QUIC_TLS_HS_DATA_ALIGN );
  uint free_data_sz  = alloc_data_sz; /* the number of bytes to free */

  /* we need contiguous bytes
     head >= buf_sz implies wrap around */
  if( head >= buf_sz ) {
    /* wrap around implies entire unused block is contiguous */
    if( head - tail < alloc_data_sz ) {
      /* not enough free */
      return 0;
    } else {
      alloc_head = head;
    }
  } else {
    /* available data split */
    if( buf_sz - head >= alloc_data_sz ) {
      alloc_head = head;
    } else {
      /* not enough at head, try front */
      if( tail < alloc_data_sz ) {
        /* not enough here either */
        return 0;
      }

      /* since we're skipping some free space at end of buffer,
         we need to free that also, upon pop */
      alloc_head   = 0;
      free_data_sz = alloc_data_sz + buf_sz - head;
    }
  }

  /* success */

  uint                    buf_mask = (uint)( buf_sz - 1u );
  fd_quic_tls_hs_data_t * hs_data = &hs->hs_data[hs_data_idx];
  uchar *                 buf     = &hs->hs_data_buf[alloc_head & buf_mask];

  /* update free list */
  hs->hs_data_free_idx = hs_data->next_idx;

  /* update buffer pointers */
  hs->hs_data_buf_head = alloc_head + alloc_data_sz;

  /* copy data into buffer, and update metadata in hs_data */
  fd_memcpy( buf, data, data_sz );
  hs_data->enc_level    = (OSSL_ENCRYPTION_LEVEL)enc_level;
  hs_data->data         = buf;
  hs_data->data_sz      = (uint)data_sz;
  hs_data->free_data_sz = free_data_sz;
  hs_data->offset       = hs->hs_data_offset[enc_level];

  /* offset adjusted ready for more data */
  hs->hs_data_offset[enc_level] += (uint)data_sz;

  /* add to end of pending list */
  hs_data->next_idx = FD_QUIC_TLS_HS_DATA_UNUSED;
  ulong pend_end_idx = hs->hs_data_pend_end_idx[enc_level];
  if( pend_end_idx == FD_QUIC_TLS_HS_DATA_UNUSED  ) {
    /* pending list is empty */
    hs->hs_data_pend_end_idx[enc_level] = hs->hs_data_pend_idx[enc_level] = hs_data_idx;
  } else {
    /* last element must point to next */
    hs->hs_data[pend_end_idx].next_idx  = hs_data_idx;
    hs->hs_data_pend_end_idx[enc_level] = hs_data_idx;
  }

  return 1;
}

int
fd_quic_ssl_flush_flight( SSL * ssl ) {
  fd_quic_tls_hs_t * hs = SSL_get_app_data( ssl );
  hs->is_flush = 1;
  return 1;
}

int
fd_quic_ssl_send_alert( SSL *                       ssl,
                        enum ssl_encryption_level_t level,
                        uchar                     alert ) {
  (void)level;
  fd_quic_tls_hs_t * hs = SSL_get_app_data( ssl );
  hs->alert = alert;
  hs->quic_tls->alert_cb( hs, hs->context, alert );
  return 0;
}

int
fd_quic_ssl_client_hello( SSL *  ssl,
                          int *  alert,
                          void * arg ) {
  (void)alert;
  (void)arg;

#if 1
  fd_quic_tls_hs_t * hs = SSL_get_app_data( ssl );

  /* TODO does the user need client hello? */
  /* user may use client hello to decline, in which case the
     user should be able to set the value of *alert */

  /* forward */
  int rc = hs->quic_tls->client_hello_cb( hs, hs->context );

  return rc == FD_QUIC_TLS_SUCCESS ? SSL_CLIENT_HELLO_SUCCESS : SSL_CLIENT_HELLO_ERROR;
#else
  (void)ssl;
  return 1;
#endif
}

typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);

/* fd_quic_ssl_keylog bounces an OpenSSL callback to a
   user-provided QUIC keylog callback and logs to a
   keyfile. */

static void
fd_quic_ssl_keylog( SSL const *  ssl,
                    char const * line ) {

  fd_quic_tls_hs_t * hs       = SSL_get_app_data( ssl );
  fd_quic_tls_t *    quic_tls = hs->quic_tls;

  int fd = quic_tls->keylog_fd;
  if( fd>0 ) {
    struct iovec iov[ 2 ] = {
      { .iov_base=(void *)line, .iov_len=strlen( line ) },
      { .iov_base=(void *)"\n", .iov_len=1UL            }
    };
    /* TODO blocking system call - consider using io_submit */
    if( FD_UNLIKELY( writev( fd, iov, 2 )==-1 ) )
      FD_LOG_WARNING(( "Keylog write failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fd_quic_tls_cb_keylog_t cb = quic_tls->keylog_cb;
  if( cb ) cb( hs, line );
}

/* suite ids

   0x03001301U - TLS_AES_128_GCM_SHA256
                 CXPLAT_AEAD_AES_128_GCM
                 CXPLAT_HASH_SHA256
                 AEAD_AES_128_ECB

   0x03001302U - TLS_AES_256_GCM_SHA384
                 CXPLAT_AEAD_AES_256_GCM
                 CXPLAT_HASH_SHA384
                 AEAD_AES_256_ECB

   0x03001303U - TLS_CHACHA20_POLY1305_SHA256
                 CXPLAT_AEAD_CHACHA20_POLY1305
                 CXPLAT_HASH_SHA256
                 AEAD_AES_128_ECB */

int
fd_quic_ssl_set_encryption_secrets( SSL *                 ssl,
                                    OSSL_ENCRYPTION_LEVEL enc_level,
                                    const uchar *       read_secret,
                                    const uchar *       write_secret,
                                    ulong                secret_len ) {
  fd_quic_tls_hs_t * hs = SSL_get_app_data( ssl );

  uint suite_id = SSL_CIPHER_get_id( SSL_get_current_cipher( ssl ) );

  fd_quic_tls_secret_t secret = {
    .enc_level    = enc_level,
    .read_secret  = read_secret,
    .write_secret = write_secret,
    .secret_len   = secret_len,
    .suite_id     = suite_id };

  hs->quic_tls->secret_cb( hs, hs->context, &secret );

  return 1;
}

SSL_QUIC_METHOD quic_method = {
  fd_quic_ssl_set_encryption_secrets,
  fd_quic_ssl_add_handshake_data,
  fd_quic_ssl_flush_flight,
  fd_quic_ssl_send_alert };

int
fd_quic_tls_cb_alpn_select( SSL * ssl,
                            uchar const ** out,
                            uchar       *  outlen,
                            uchar const *  in,
                            uint           inlen,
                            void *         arg ) {

  (void)ssl; (void)arg;

  /* sigh .. SSL_select_next_proto is clearly intended
     to be used from the application callback but the
     out value expected differs in constness.  According
     to https://grep.app/search?q=SSL_select_next_proto
     the whole world just casts the out array to a non-
     const, so we do it here too.  Not to mention the
     helper returns 1 on success and the callback
     returns 0.  */

  if( FD_UNLIKELY( SSL_select_next_proto( (uchar **)out, outlen, (uchar const *)"\xasolana-tpu", 11U, in, inlen )!=OPENSSL_NPN_NEGOTIATED ) ) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *
fd_quic_create_context( fd_quic_tls_t * quic_tls,
                        X509 *          cert,
                        EVP_PKEY *      pkey ) {

  if( FD_UNLIKELY( !cert ) ) {
    FD_LOG_WARNING(( "NULL cert" ));
    return NULL;
  }
  if( FD_UNLIKELY( !pkey ) ) {
    FD_LOG_WARNING(( "NULL pkey" ));
    return NULL;
  }

  SSL_METHOD const * method = TLS_method();

  ERR_clear_error();
  SSL_CTX * ctx = SSL_CTX_new( method );
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "SSL_CTX_new failed: %s", fd_quic_tls_strerror() ));
    return NULL;
  }

  ERR_clear_error();
  if( !SSL_CTX_set_min_proto_version( ctx, TLS1_3_VERSION ) ) {
    SSL_CTX_free( ctx );
    FD_LOG_WARNING(( "SSL_CTX_set_min_proto_version failed: %s", fd_quic_tls_strerror() ));
    return NULL;
  }

  ERR_clear_error();
  if( !SSL_CTX_set_max_proto_version( ctx, TLS1_3_VERSION ) ) {
    SSL_CTX_free( ctx );
    FD_LOG_WARNING(( "SSL_CTX_set_max_proto_version failed: %s", fd_quic_tls_strerror() ));
    return NULL;
  }

  ERR_clear_error();
  char const * ciphersuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
  if( !SSL_CTX_set_ciphersuites( ctx, ciphersuites ) ) {
    SSL_CTX_free( ctx );
    FD_LOG_WARNING(( "SSL_CTX_set_ciphersuites failed: %s", fd_quic_tls_strerror() ));
    return NULL;
  }

  ERR_clear_error();
  if( !SSL_CTX_set_quic_method( ctx, &quic_method ) ) {
    SSL_CTX_free( ctx );
    FD_LOG_WARNING(( "SSL_CTX_set_quic_method failed: %s", fd_quic_tls_strerror() ));
    return NULL;
  }

  /* Set the key and cert */
  if( FD_UNLIKELY( SSL_CTX_use_certificate( ctx, cert ) <= 0 ) ) {
    SSL_CTX_free( ctx );
    FD_LOG_WARNING(( "Failed to set SSL cert: %s", fd_quic_tls_strerror() ));
    return NULL;
  }
  X509_free( cert );
  if( FD_UNLIKELY( SSL_CTX_use_PrivateKey( ctx, pkey ) <= 0 ) ) {
    SSL_CTX_free( ctx );
    FD_LOG_WARNING(( "Failed to set SSL private key: %s", fd_quic_tls_strerror() ));
    return NULL;
  }
  EVP_PKEY_free( pkey );

  /* set verification */
  //SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, NULL );

  /* solana actual: "solana-tpu" */
  ERR_clear_error();
  if( SSL_CTX_set_alpn_protos( ctx, quic_tls->alpns, quic_tls->alpns_sz ) != 0 ) {
    SSL_CTX_free( ctx );
    FD_LOG_WARNING(( "SSL_set_alpn_protos failed" ));
    return NULL;
  }

  SSL_CTX_set_alpn_select_cb( ctx, fd_quic_tls_cb_alpn_select, NULL );

  //SSL_CTX_set_options(
  //    ctx,
  //    (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
  //    SSL_OP_SINGLE_ECDH_USE |
  //    SSL_OP_CIPHER_SERVER_PREFERENCE |
  //    SSL_OP_NO_ANTI_REPLAY);
  //SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
  //SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

  // TODO set cipher suites?
  // TODO set verify clients?

  // TODO support early data?
  SSL_CTX_set_max_early_data( ctx, 0 );

  // set callback for client hello
  SSL_CTX_set_client_hello_cb( ctx, fd_quic_ssl_client_hello, NULL );

  if( FD_UNLIKELY( quic_tls->keylog_cb || quic_tls->keylog_fd != 0 ) ) {
    SSL_CTX_set_keylog_callback( ctx, fd_quic_ssl_keylog );
  }

  return ctx;
}

fd_quic_tls_hs_data_t *
fd_quic_tls_get_hs_data( fd_quic_tls_hs_t * self, int enc_level ) {
  uint idx = self->hs_data_pend_idx[enc_level];
  if( idx == FD_QUIC_TLS_HS_DATA_UNUSED ) return NULL;

  return &self->hs_data[idx];
}

fd_quic_tls_hs_data_t *
fd_quic_tls_get_next_hs_data( fd_quic_tls_hs_t * self, fd_quic_tls_hs_data_t * hs ) {
  ushort idx = hs->next_idx;
  if( idx == (ushort)(~0u) ) return NULL;
  return self->hs_data + idx;
}

void
fd_quic_tls_pop_hs_data( fd_quic_tls_hs_t * self, int enc_level ) {
  ushort idx = self->hs_data_pend_idx[enc_level];
  if( idx == FD_QUIC_TLS_HS_DATA_UNUSED ) return;

  fd_quic_tls_hs_data_t * hs_data = &self->hs_data[idx];

  uint buf_sz       = FD_QUIC_TLS_HS_DATA_SZ;
  uint free_data_sz = hs_data->free_data_sz; /* amount of data to free */

  /* move tail pointer */
  uint head = self->hs_data_buf_head;
  uint tail = self->hs_data_buf_tail;

  tail += free_data_sz;
  if( tail > head ) {
    /* logic error - tried to free more than was allocated */
    FD_LOG_ERR(( "fd_quic_tls_pop_hs_data: tried to free more than was allocated" ));
    return;
  }

  /* adjust to maintain invariants */
  if( tail >= buf_sz ) {
    tail -= buf_sz;
    head -= buf_sz;
  }

  /* write back head and tail */
  self->hs_data_buf_head = head;
  self->hs_data_buf_tail = tail;

  /* pop from pending list */
  self->hs_data_pend_idx[enc_level] = hs_data->next_idx;

  /* if idx is the last, update last */
  if( hs_data->next_idx == FD_QUIC_TLS_HS_DATA_UNUSED ) {
    self->hs_data_pend_end_idx[enc_level] = FD_QUIC_TLS_HS_DATA_UNUSED;
  }

}

void
fd_quic_tls_get_peer_transport_params( fd_quic_tls_hs_t * self,
                                       uchar const **     transport_params,
                                       ulong *           transport_params_sz ) {
  SSL_get_peer_quic_transport_params( self->ssl, transport_params, transport_params_sz );
}
