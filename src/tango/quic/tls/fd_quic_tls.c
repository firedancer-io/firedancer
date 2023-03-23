/* TODO
   replace malloc with align/footprint/placement new */

#include "fd_quic_tls.h"
#include "../../../util/fd_util.h"

#include <stdlib.h>
#include <string.h>

// some prototypes

/* internal callbacks */
int
fd_quic_ssl_add_handshake_data( SSL *                 ssl,
                                OSSL_ENCRYPTION_LEVEL enc_level,
                                uchar const *       data,
                                ulong                data_sz );

int
fd_quic_ssl_flush_flight( SSL * ssl );

int
fd_quic_ssl_send_alert( SSL *                       ssl,
                        enum ssl_encryption_level_t level,
                        uchar                     alert );

int
fd_quic_ssl_client_hello( SSL *  ssl,
                          int *  alert,
                          void * arg );

int
fd_quic_alpn_select_cb( SSL * ssl,
                        uchar const ** out,
                        uchar *        out_len,
                        uchar const *  in,
                        unsigned       in_len,
                        void *         arg );

int
fd_quic_ssl_set_encryption_secrets( SSL *                 ssl,
                                    OSSL_ENCRYPTION_LEVEL enc_level,
                                    const uchar *       read_secret,
                                    const uchar *       write_secret,
                                    ulong                secret_len );

SSL_CTX *
fd_quic_create_context( fd_quic_tls_t * quic_tls,
                        char const *    cert_file,
                        char const *    key_file );

fd_quic_tls_t *
fd_quic_tls_new( fd_quic_tls_cfg_t * cfg ) {
  /* TODO eliminate malloc */
  fd_quic_tls_t * self = calloc( sizeof( fd_quic_tls_t ), 1 );
  if( !self ) {
    return NULL;
  }

  self->client_hello_cb       = cfg->client_hello_cb;
  self->alert_cb              = cfg->alert_cb;
  self->secret_cb             = cfg->secret_cb;
  self->handshake_complete_cb = cfg->handshake_complete_cb;

  self->max_concur_handshakes = cfg->max_concur_handshakes;

  // preallocate all handshake structures
  ulong bytes = (ulong)self->max_concur_handshakes * sizeof( fd_quic_tls_hs_t );
  fd_quic_tls_hs_t * handshakes = (fd_quic_tls_hs_t*)malloc( bytes );
  if( !handshakes ) {
    free( self );
    return NULL;
  }

  self->handshakes = handshakes;

  uchar * used_handshakes = (uchar*)malloc( (ulong)self->max_concur_handshakes );
  if( !used_handshakes ) {
    free( handshakes );
    free( self );
    return NULL;
  }

  self->used_handshakes = used_handshakes;

  // set all to free
  fd_memset( used_handshakes, 0, (ulong)self->max_concur_handshakes );

  // create ssl context
  self->ssl_ctx = fd_quic_create_context( self, cfg->cert_file, cfg->key_file );
  if( FD_UNLIKELY( !self->ssl_ctx ) ) {
    FD_LOG_WARNING(( "NULL fd_quic_create_context" ));
    free( handshakes );
    free( self );
    return NULL;
  }

  /* keep pointer to ALPNs */
  self->alpns    = cfg->alpns;
  self->alpns_sz = cfg->alpns_sz;

  return self;
}

void
fd_quic_tls_delete( fd_quic_tls_t * self ) {
  if( !self ) return;

  // free up all used handshakes
  ulong              hs_sz   = (ulong)self->max_concur_handshakes;
  fd_quic_tls_hs_t * hs      = self->handshakes;
  uchar *            hs_used = self->used_handshakes;
  for( ulong j = 0; j < hs_sz; ++j ) {
    if( hs_used[j] ) fd_quic_tls_hs_delete( hs + j );
  }

  // free up memory
  free( self->handshakes );
  free( self->used_handshakes );

  free( self );
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
  if( hs_idx == hs_sz ) return NULL;

  // set the handshake to used
  hs_used[hs_idx] = 1;

  long int ssl_rc = 0;

  // self is the handshake at hs_idx
  fd_quic_tls_hs_t * self = quic_tls->handshakes + hs_idx;

  // clear the handshake bits
  fd_memset( self, 0, sizeof( *self ) );

  // set properties on self
  self->quic_tls  = quic_tls;
  self->is_server = is_server;
  self->is_flush  = 0;
  self->context   = context;

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
  SSL * ssl = SSL_new( quic_tls->ssl_ctx );
  if( !ssl ) {
    quic_tls->err_ssl_rc  = 0;
    quic_tls->err_ssl_err = SSL_get_error( ssl, (int)ssl_rc );
    quic_tls->err_line    = __LINE__;

    goto fd_quic_tls_hs_new_error;
  }

  // add the user context to the ssl
  SSL_set_app_data( ssl, self );

  // set ssl on self to this new object
  self->ssl = ssl;

  /* solana actual: "solana-tpu" */
  ssl_rc = SSL_set_alpn_protos( ssl, quic_tls->alpns, quic_tls->alpns_sz );
  if( ssl_rc != 0 ) {
    quic_tls->err_ssl_rc  = (int)ssl_rc;
    quic_tls->err_ssl_err = SSL_get_error( ssl, (int)ssl_rc );
    quic_tls->err_line    = __LINE__;

    goto fd_quic_tls_hs_new_error;
  }

  /* set transport params on ssl */
  ssl_rc = SSL_set_quic_transport_params( ssl, transport_params_raw, transport_params_raw_sz );
  if( ssl_rc != 1 ) {
    quic_tls->err_ssl_rc  = (int)ssl_rc;
    quic_tls->err_ssl_err = SSL_get_error( ssl, (int)ssl_rc );
    quic_tls->err_line    = __LINE__;

    goto fd_quic_tls_hs_new_error;
  }

  // returns void
  if( !is_server ) {
    SSL_set_connect_state( ssl );

    /* TODO determine whether hostname is required */
    if( hostname && hostname[0] != '\0' ) {
      ssl_rc = SSL_set_tlsext_host_name( ssl, hostname );

      if( ssl_rc != 1 ) {
        quic_tls->err_ssl_rc  = (int)ssl_rc;
        quic_tls->err_ssl_err = SSL_get_error( ssl, (int)ssl_rc );
        quic_tls->err_line    = __LINE__;

        goto fd_quic_tls_hs_new_error;
      }
    }
  } else {
    SSL_set_accept_state( ssl );
  }

  return self;

fd_quic_tls_hs_new_error:
  // free handshake
  quic_tls->used_handshakes[hs_idx] = 0;

  return NULL;
}

void
fd_quic_tls_hs_delete( fd_quic_tls_hs_t * self ) {
  if( !self ) return;

  fd_quic_tls_t * quic_tls = self->quic_tls;

  // find index into array
  ulong hs_idx = (ulong)( self - quic_tls->handshakes );
  if( quic_tls->used_handshakes[hs_idx] != 1 ) {
    __asm__ __volatile__( "int $3" );
    return;
  }

  if( self->ssl ) SSL_free( self->ssl );

  // set used at the given index to zero to free
  quic_tls->used_handshakes[hs_idx] = 0;
}

int
fd_quic_tls_provide_data( fd_quic_tls_hs_t *    self,
                          OSSL_ENCRYPTION_LEVEL enc_level,
                          uchar const *         data,
                          ulong                data_sz ) {
  int ssl_rc = SSL_provide_quic_data( self->ssl, enc_level, data, data_sz );
  if( ssl_rc != 1 ) {
    self->err_ssl_rc  = (int)ssl_rc;
    self->err_ssl_err = SSL_get_error( self->ssl, (int)ssl_rc );
    self->err_line    = __LINE__;

    return FD_QUIC_TLS_FAILED;
  }

  return FD_QUIC_TLS_SUCCESS;
}

int
fd_quic_tls_process( fd_quic_tls_hs_t * self ) {
  int   ssl_rc = 0;
  SSL * ssl    = self->ssl;
  if( !self->is_hs_complete ) {
    ssl_rc = SSL_do_handshake( self->ssl );
    switch( ssl_rc ) {
      case 0: // failed
        // according to the API rc==0 means failure
        // but can this occur without any error?
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
      case 1: // completed
        self->is_hs_complete = 1;
        self->quic_tls->handshake_complete_cb( self, self->context );
        return FD_QUIC_TLS_SUCCESS;
      default:
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
    }
  } else {
    // handle post-handshake messages
    ssl_rc = SSL_process_quic_post_handshake( self->ssl );
    switch( ssl_rc ) {
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
                                uchar const *       data,
                                ulong                data_sz ) {
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
  hs_data->enc_level    = enc_level;
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

void
fd_quic_ssl_keylog_cb( SSL const * ssl, char const * line ) {
  fd_quic_tls_hs_t * hs = SSL_get_app_data( ssl );
  (void)hs;
  /* TODO this is debugging code... remove */
  printf( "KEYLOG: %s\n", line );
  fflush( stdout );
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


static int
alpn_select_cb( SSL * ssl,
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
fd_quic_create_context( fd_quic_tls_t * quic_tls, char const * cert_file, char const * key_file ) {
    const SSL_METHOD * method;
    SSL_CTX * ctx;

    method = TLS_method();

    ctx = SSL_CTX_new( method );
    if( !ctx ) {
      quic_tls->err_ssl_rc  = 0;
      quic_tls->err_ssl_err = 0;
      quic_tls->err_line    = __LINE__;
      FD_LOG_WARNING(( "SSL_CTX_new failed" ));

      return NULL;
    }

    if( !SSL_CTX_set_min_proto_version( ctx, TLS1_3_VERSION ) ) {
      quic_tls->err_ssl_rc  = 0;
      quic_tls->err_ssl_err = 0;
      quic_tls->err_line    = __LINE__;

      SSL_CTX_free( ctx );
      FD_LOG_WARNING(( "SSL_CTX_set_min_proto_version failed" ));

      return NULL;
    }


    if( !SSL_CTX_set_max_proto_version( ctx, TLS1_3_VERSION ) ) {
      quic_tls->err_ssl_rc  = 0;
      quic_tls->err_ssl_err = 0;
      quic_tls->err_line    = __LINE__;

      SSL_CTX_free( ctx );
      FD_LOG_WARNING(( "SSL_CTX_set_max_proto_version failed" ));

      return NULL;
    }

    if( !SSL_CTX_set_ciphersuites( ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256" ) ) {
      quic_tls->err_ssl_rc  = 0;
      quic_tls->err_ssl_err = 0;
      quic_tls->err_line    = __LINE__;

      SSL_CTX_free( ctx );
      FD_LOG_WARNING(( "SSL_CTX_set_ciphersuites failed" ));

      return NULL;
    }

    if( !SSL_CTX_set_quic_method( ctx, &quic_method ) ) {
      quic_tls->err_ssl_rc  = 0;
      quic_tls->err_ssl_err = 0;
      quic_tls->err_line    = __LINE__;

      SSL_CTX_free( ctx );
      FD_LOG_WARNING(( "SSL_CTX_set_quic_method failed" ));

      return NULL;
    }

    /* Set the key and cert */
    if( cert_file ) {
      if( SSL_CTX_use_certificate_file( ctx, cert_file, SSL_FILETYPE_PEM ) <= 0 ) {
        quic_tls->err_ssl_rc  = 0;
        quic_tls->err_ssl_err = 0;
        quic_tls->err_line    = __LINE__;

        SSL_CTX_free( ctx );
        FD_LOG_WARNING(( "Failed to load SSL cert" ));

        return NULL;
      }
    }

    if( key_file ) {
      if( SSL_CTX_use_PrivateKey_file( ctx, key_file, SSL_FILETYPE_PEM ) <= 0 ) {
        quic_tls->err_ssl_rc  = 0;
        quic_tls->err_ssl_err = 0;
        quic_tls->err_line    = __LINE__;

        SSL_CTX_free( ctx );
        FD_LOG_WARNING(( "Failed to load SSL key" ));

        return NULL;
      }
    }

    /* solana actual: "solana-tpu" */
    if( SSL_CTX_set_alpn_protos( ctx, quic_tls->alpns, quic_tls->alpns_sz ) != 0 ) {

      SSL_CTX_free( ctx );
      FD_LOG_WARNING(( "SSL_set_alpn_protos failed" ));

      return NULL;
    }

    SSL_CTX_set_alpn_select_cb( ctx, alpn_select_cb, NULL );

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
    // TODO alpn?
    //SSL_CTX_set_alpn_select_cb( ctx, fd_quic_alpn_select_cb, NULL);

    // TODO support early data?
    SSL_CTX_set_max_early_data( ctx, 0 );

    // set callback for client hello
    SSL_CTX_set_client_hello_cb( ctx, fd_quic_ssl_client_hello, NULL );

    SSL_CTX_set_keylog_callback( ctx, fd_quic_ssl_keylog_cb );

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


int
fd_quic_alpn_select_cb( SSL *          ssl,
                        uchar const ** out,
                        uchar *        out_len,
                        uchar const *  in,
                        unsigned       in_len,
                        void *         arg ) {
  (void)ssl;
  (void)out;
  (void)out_len;
  (void)in;
  (void)in_len;
  (void)arg;
  /* tells us what alpn was selected - but we probably either don't use alpn, or only have one */
  /* alpn: "solana-tpu" */
  return SSL_TLSEXT_ERR_OK;
}

