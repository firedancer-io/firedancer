/* fd_tls_proto.c stubs fd_tls parsers */

#include <assert.h>
#include <tango/tls/fd_tls_proto.h>

static long
generic_encode( void const * in,
                ulong        in_sz,
                void *       wire,
                ulong        wire_sz ) {
  __CPROVER_r_ok( in,   in_sz   );
  __CPROVER_w_ok( wire, wire_sz );

  __CPROVER_havoc_slice( wire, wire_sz );

  uchar ok; __CPROVER_assume( ok<=1 );
  long res; __CPROVER_assume( res>INT_MIN );
  if( ok ) {
    __CPROVER_assume( wire_sz<LONG_MAX );
    __CPROVER_assume( res>=0L && res<=(long)wire_sz );
  } else {
    __CPROVER_assume( res<0L );
  }

  return res;
}

long
fd_tls_encode_client_hello( fd_tls_client_hello_t const * in,
                            void *                        wire,
                            ulong                         wire_sz ) {
  return generic_encode( in, sizeof(fd_tls_client_hello_t), wire, wire_sz );
}

long
fd_tls_decode_client_hello( fd_tls_client_hello_t * out,
                            void const *            wire,
                            ulong                   wire_sz ) {
  __CPROVER_havoc_slice( out, sizeof(fd_tls_client_hello_t) );

  ulong actual_sz; __CPROVER_assume( actual_sz!=0UL );
  if( actual_sz > wire_sz ) return -1L;
  __CPROVER_r_ok( wire, actual_sz );
  __CPROVER_assume( out->server_name.host_name_len<=253UL );
  __CPROVER_assume( out->server_name.host_name_len==  0UL ||
                    out->server_name.host_name[ out->server_name.host_name_len-1UL ]=='\0' );
  __CPROVER_assume( (ulong)out->quic_tp.buf >= (ulong)wire &&
                    (ulong)out->quic_tp.buf <  (ulong)wire+wire_sz );
  return actual_sz;
}

long
fd_tls_encode_server_hello( fd_tls_server_hello_t const * in,
                            void *                        wire,
                            ulong                         wire_sz ) {
  return generic_encode( in, sizeof(fd_tls_server_hello_t), wire, wire_sz );
}

long
fd_tls_decode_server_hello( fd_tls_server_hello_t * out,
                            void const *            wire,
                            ulong                   wire_sz ) {
  __CPROVER_havoc_slice( out, sizeof(fd_tls_server_hello_t) );

  ulong actual_sz; __CPROVER_assume( actual_sz!=0UL );
  if( actual_sz > wire_sz ) return -1L;
  __CPROVER_r_ok( wire, actual_sz );
  return actual_sz;
}

long
fd_tls_encode_enc_ext( fd_tls_enc_ext_t const * in,
                       void *                   wire,
                       ulong                    wire_sz ) {
  return generic_encode( in, sizeof(fd_tls_enc_ext_t), wire, wire_sz );
}

long
fd_tls_decode_enc_ext( fd_tls_enc_ext_t * out,
                       void const *       wire,
                       ulong              wire_sz ) {
  __CPROVER_havoc_slice( out, sizeof(fd_tls_enc_ext_t) );

  ulong actual_sz; __CPROVER_assume( actual_sz!=0UL );
  if( actual_sz > wire_sz ) return -1L;
  __CPROVER_r_ok( wire, actual_sz );
  __CPROVER_assume( (ulong)out->quic_tp.buf >= (ulong)wire &&
                    (ulong)out->quic_tp.buf <  (ulong)wire+wire_sz );
  return actual_sz;
}

long
fd_tls_encode_raw_public_key( void const * ed25519_pubkey,
                              void *       wire,
                              ulong        wire_sz ) {
  ulong const encoded_sz = 57UL;

  if( wire_sz<encoded_sz ) return -1L;
  __CPROVER_r_ok( ed25519_pubkey, 32UL );
  __CPROVER_havoc_slice( wire, encoded_sz );
  return 57L;
}

long
fd_tls_decode_cert_verify( fd_tls_cert_verify_t * out,
                           void const *           wire,
                           ulong                  wire_sz ) {
  __CPROVER_havoc_slice( out, sizeof(fd_tls_cert_verify_t) );

  ulong actual_sz; __CPROVER_assume( actual_sz!=0UL );
  if( actual_sz > wire_sz ) return -1L;
  __CPROVER_r_ok( wire, actual_sz );
  out->sig_alg = FD_TLS_SIGNATURE_ED25519;
  return actual_sz;
}

fd_tls_extract_cert_pubkey_res_t
fd_tls_extract_cert_pubkey( uchar const * cert,
                            ulong         cert_sz,
                            uint          cert_type ) {
  assert( ( cert_type==FD_TLS_CERTTYPE_RAW_PUBKEY ) |
          ( cert_type==FD_TLS_CERTTYPE_X509       ) );

  fd_tls_extract_cert_pubkey_res_t res;  /* unconstrained */

  uchar ok = 0; __CPROVER_assume( ok<=1 );
        ok &= (cert_sz >= 32UL);
  if( ok ) {
    __CPROVER_assume( res.pubkey >= cert &&
                      res.pubkey <  cert+cert_sz-32UL );
    res.alert  = 0U;
    res.reason = 0U;
  } else {
    /* res.{alert,reason} arbitrary */
    res.pubkey = NULL;
  }

  return res;
}
