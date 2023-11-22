#include "fd_tls_base.h"
#include "fd_tls_proto.h"
#include "fd_tls_serde.h"
#include "fd_tls_asn1.h"
#include "../../ballet/x509/fd_x509_cert_parser.h"

typedef struct fd_tls_u24 tls_u24;  /* code generator helper */

#define FD_TLS_ENCODE_EXT_BEGIN( type )                         \
  do {                                                          \
    int valid = 1;                                              \
    FD_TLS_SERDE_LOCATE( ext_type, _, ushort, 1 );              \
    FD_TLS_SERDE_LOCATE( ext_sz,   _, ushort, 1 );              \
    FD_TLS_SERDE_CHECK                                          \
    ushort *    ext_type_ptr = (ushort *)_field_ext_type_laddr; \
    ushort *    ext_sz_ptr   = (ushort *)_field_ext_sz_laddr;   \
    ulong const ext_start    = wire_laddr;                      \
    *ext_type_ptr = fd_ushort_bswap( type );

#define FD_TLS_ENCODE_EXT_END                    \
    ulong ext_sz = wire_laddr - ext_start;       \
    if( FD_UNLIKELY( ext_sz > USHORT_MAX ) )     \
      return -(long)FD_TLS_ALERT_INTERNAL_ERROR; \
    *ext_sz_ptr = fd_ushort_bswap( ext_sz );     \
  } while(0)

long
fd_tls_decode_client_hello( fd_tls_client_hello_t * out,
                            uchar const * const      wire,
                            ulong                   wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Decode static sized part of client hello.
     (Assuming that session ID field is of a certain size) */

  ushort legacy_version;       /* ==FD_TLS_VERSION_TLS12 */
  uchar  legacy_session_id_sz; /* ==0 */

# define FIELDS( FIELD )                            \
    FIELD( 0, &legacy_version,       ushort, 1    ) \
    FIELD( 1, &out->random[0],       uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz, uchar,  1    )
    FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( FD_UNLIKELY( legacy_session_id_sz != 0 ) )
    return -(long)FD_TLS_ALERT_PROTOCOL_VERSION;

  /* Decode cipher suite list */

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(ushort) ) {
    ushort cipher_suite;
    FD_TLS_DECODE_FIELD( &cipher_suite, ushort );

    switch( cipher_suite ) {
    case FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
      out->cipher_suites.aes_128_gcm_sha256 = 1;
      break;
    default:
      /* Ignore unsupported cipher suites ... */
      break;
    }
  }
  FD_TLS_DECODE_LIST_END

  /* Decode next static sized part of client hello */

  uchar  legacy_compression_method_cnt;    /* == 1  */
  uchar  legacy_compression_methods[ 1 ];  /* =={0} */

# define FIELDS( FIELD )                                  \
    FIELD( 5, &legacy_compression_method_cnt, uchar,  1 ) \
    FIELD( 6, &legacy_compression_methods[0], uchar,  1 )
    FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( FD_UNLIKELY( ( legacy_compression_method_cnt != 1 )
                 | ( legacy_compression_methods[0] != 0 ) ) )
    return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;

  /* Read extensions */

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    /* Read extension type and length */
    ushort ext_type;
    ushort ext_sz;
#   define FIELDS( FIELD )             \
      FIELD( 0, &ext_type, ushort, 1 ) \
      FIELD( 1, &ext_sz,   ushort, 1 )
      FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#   undef FIELDS

    /* Bounds check extension data */
    if( FD_UNLIKELY( ext_sz > wire_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    /* Decode extension data */
    uchar const * ext_data = (uchar const *)wire_laddr;
    long ext_parse_res;
    switch( ext_type ) {
    case FD_TLS_EXT_SUPPORTED_VERSIONS:
      ext_parse_res = fd_tls_decode_ext_supported_versions( &out->supported_versions, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_SERVER_NAME:
      ext_parse_res = fd_tls_decode_ext_server_name( &out->server_name, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_SUPPORTED_GROUPS:
      ext_parse_res = fd_tls_decode_ext_supported_groups( &out->supported_groups, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_SIGNATURE_ALGORITHMS:
      ext_parse_res = fd_tls_decode_ext_signature_algorithms( &out->signature_algorithms, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_KEY_SHARE:
      ext_parse_res = fd_tls_decode_key_share_list( &out->key_share, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_SERVER_CERT_TYPE:
      ext_parse_res = fd_tls_decode_ext_cert_type_list( &out->server_cert_types, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_CLIENT_CERT_TYPE:
      ext_parse_res = fd_tls_decode_ext_cert_type_list( &out->client_cert_types, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_QUIC_TRANSPORT_PARAMS:
      ext_parse_res = fd_tls_decode_ext_quic_tp( &out->quic_tp, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_ALPN:
      ext_parse_res = fd_tls_decode_ext_alpn( &out->alpn, ext_data, ext_sz );
      break;
    default:
      ext_parse_res = (long)ext_sz;
      break;
    }
    if( FD_UNLIKELY( ext_parse_res<0L ) )
      return ext_parse_res;
    if( FD_UNLIKELY( ext_parse_res != (long)ext_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    /* Seek to next extension */
    wire_laddr += ext_sz;
    wire_sz    -= ext_sz;
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_client_hello( fd_tls_client_hello_t const * in,
                            uchar *                       wire,
                            ulong                         wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Encode static sized part of client hello */

  ushort legacy_version        = FD_TLS_VERSION_TLS12;
  uchar  legacy_session_id_sz  = 0;
  ushort cipher_suite_sz       = 1*sizeof(ushort);
  ushort cipher_suites[1]      = { FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 };
  uchar  legacy_comp_method_sz = 1;
  uchar  legacy_comp_method[1] = {0};

# define FIELDS( FIELD )                                 \
    FIELD( 0, &legacy_version,            ushort, 1    ) \
    FIELD( 1,  in->random,                uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz,      uchar,  1    ) \
    FIELD( 3, &cipher_suite_sz,           ushort, 1    ) \
    FIELD( 4,  cipher_suites,             ushort, 1    ) \
    FIELD( 5, &legacy_comp_method_sz,     uchar,  1    ) \
    FIELD( 6,  legacy_comp_method,        uchar,  1    )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Encode extensions */

  ushort * extension_tot_sz = FD_TLS_SKIP_FIELD( ushort );
  ulong    extension_start  = wire_laddr;

  ushort ext_supported_versions_ext_type = FD_TLS_EXT_SUPPORTED_VERSIONS;
  ushort ext_supported_versions_ext_sz   = 3;
  uchar  ext_supported_versions_sz       = 2;
  ushort ext_supported_versions[1]       = { FD_TLS_VERSION_TLS13 };

  ushort ext_key_share_ext_type = FD_TLS_EXT_KEY_SHARE;
  ushort ext_key_share_ext_sz   = 38;
  ushort ext_key_share_sz1      = 36;
  ushort ext_key_share_group    = FD_TLS_GROUP_X25519;
  ushort ext_key_share_sz       = 32;

  ushort ext_supported_groups_ext_type = FD_TLS_EXT_SUPPORTED_GROUPS;
  ushort ext_supported_groups_ext_sz   = 4;
  ushort ext_supported_groups_sz       = 2;
  ushort ext_supported_groups[1]       = { FD_TLS_GROUP_X25519 };

  ushort ext_sigalg_ext_type = FD_TLS_EXT_SIGNATURE_ALGORITHMS;
  ushort ext_sigalg_ext_sz   = 4;
  ushort ext_sigalg_sz       = 2;
  ushort ext_sigalg[1]       = { FD_TLS_SIGNATURE_ED25519 };

# define FIELDS( FIELD ) \
    FIELD( 0, &ext_supported_versions_ext_type,   ushort, 1    ) \
    FIELD( 1, &ext_supported_versions_ext_sz,     ushort, 1    ) \
    FIELD( 2, &ext_supported_versions_sz,         uchar,  1    ) \
    FIELD( 3,  ext_supported_versions,            ushort, 1    ) \
    FIELD( 4, &ext_key_share_ext_type,            ushort, 1    ) \
    FIELD( 5, &ext_key_share_ext_sz,              ushort, 1    ) \
    FIELD( 6, &ext_key_share_sz1,                 ushort, 1    ) \
    FIELD( 7, &ext_key_share_group,               ushort, 1    ) \
    FIELD( 8, &ext_key_share_sz,                  ushort, 1    ) \
    FIELD( 9, &in->key_share.x25519[0],           uchar,  32UL ) \
    FIELD(10, &ext_supported_groups_ext_type,     ushort, 1    ) \
    FIELD(11, &ext_supported_groups_ext_sz,       ushort, 1    ) \
    FIELD(12, &ext_supported_groups_sz,           ushort, 1    ) \
    FIELD(13,  ext_supported_groups,              ushort, 1    ) \
    FIELD(14, &ext_sigalg_ext_type,               ushort, 1    ) \
    FIELD(15, &ext_sigalg_ext_sz,                 ushort, 1    ) \
    FIELD(16, &ext_sigalg_sz,                     ushort, 1    ) \
    FIELD(17,  ext_sigalg,                        ushort, 1    )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Add ALPN */

  if( in->alpn.bufsz ) {
    fd_tls_ext_hdr_t ext_hdr = { .type = FD_TLS_EXT_ALPN,
                                 .sz   = (ushort)( in->alpn.bufsz+2 ) };
    FD_TLS_ENCODE_SUB( fd_tls_encode_ext_hdr,  &ext_hdr  );
    FD_TLS_ENCODE_SUB( fd_tls_encode_ext_alpn, &in->alpn );
  }

  /* Add QUIC transport params */

  if( in->quic_tp.buf ) {
    ushort  quic_tp_ext_type = FD_TLS_EXT_QUIC_TRANSPORT_PARAMS;
    ushort  quic_tp_ext_sz   = (ushort)in->quic_tp.bufsz;
#   define FIELDS( FIELD )                    \
    FIELD( 0, &quic_tp_ext_type, ushort, 1 ); \
    FIELD( 1, &quic_tp_ext_sz,   ushort, 1 ); \
    FIELD( 2, in->quic_tp.buf,   uchar,  in->quic_tp.bufsz );
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS
  }

  /* Add certificate types */

  uchar  cert_type_srv[2]            = { FD_TLS_CERTTYPE_RAW_PUBKEY, FD_TLS_CERTTYPE_X509 };
  ulong  cert_type_srv_cnt           = 1 + (!!in->server_cert_types.x509);
  ushort cert_type_srv_list_ext_type = FD_TLS_EXT_SERVER_CERT_TYPE;
  ushort cert_type_srv_list_ext_sz   = (ushort)(cert_type_srv_cnt+1UL);
  uchar  cert_type_srv_list_sz       = (uchar ) cert_type_srv_cnt;

  uchar  cert_type_cli[2]            = { FD_TLS_CERTTYPE_RAW_PUBKEY, FD_TLS_CERTTYPE_X509 };
  ulong  cert_type_cli_cnt           = 1 + (!!in->client_cert_types.x509);
  ushort cert_type_cli_list_ext_type = FD_TLS_EXT_CLIENT_CERT_TYPE;
  ushort cert_type_cli_list_ext_sz   = (ushort)(cert_type_cli_cnt+1UL);
  uchar  cert_type_cli_list_sz       = (uchar ) cert_type_cli_cnt;

# define FIELDS( FIELD ) \
  FIELD( 0, &cert_type_srv_list_ext_type, ushort, 1                 ); \
  FIELD( 1, &cert_type_srv_list_ext_sz,   ushort, 1                 ); \
  FIELD( 2, &cert_type_srv_list_sz,       uchar,  1                 ); \
  FIELD( 3,  cert_type_srv,               uchar,  cert_type_srv_cnt ); \
  FIELD( 4, &cert_type_cli_list_ext_type, ushort, 1                 ); \
  FIELD( 5, &cert_type_cli_list_ext_sz,   ushort, 1                 ); \
  FIELD( 6, &cert_type_cli_list_sz,       uchar,  1                 ); \
  FIELD( 7,  cert_type_cli,               uchar,  cert_type_cli_cnt );
  FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  *extension_tot_sz = fd_ushort_bswap( (ushort)( (ulong)wire_laddr - extension_start ) );
  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_server_hello( fd_tls_server_hello_t * out,
                            uchar const *           wire,
                            ulong                   wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Decode static sized part of server hello */

  ushort legacy_version;            /* ==FD_TLS_VERSION_TLS12 */
  uchar  legacy_session_id_sz;      /* ==0 */
  ushort cipher_suite;              /* ==FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 */
  uchar  legacy_compression_method; /* ==0 */

# define FIELDS( FIELD )                                 \
    FIELD( 0, &legacy_version,            ushort, 1    ) \
    FIELD( 1, &out->random[0],            uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz,      uchar,  1    ) \
    FIELD( 3, &cipher_suite,              ushort, 1    ) \
    FIELD( 4, &legacy_compression_method, uchar,  1    )
    FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( FD_UNLIKELY( ( legacy_version != FD_TLS_VERSION_TLS12 )
                 | ( legacy_session_id_sz      != 0         )
                 | ( legacy_compression_method != 0         ) ) )
    return -(long)FD_TLS_ALERT_PROTOCOL_VERSION;

  if( FD_UNLIKELY( cipher_suite != FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 ) )
    return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;

  /* Middlebox compatibility for HelloRetryRequest */

  static uchar const special_random[ 32 ] =
    { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
      0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
      0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };
  if( FD_UNLIKELY( 0==memcmp( out->random, special_random, 32 ) ) )
    return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;

  /* Read extensions */

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    /* Read extension type and length */
    ushort ext_type;
    ushort ext_sz;
#   define FIELDS( FIELD )             \
      FIELD( 0, &ext_type, ushort, 1 ) \
      FIELD( 1, &ext_sz,   ushort, 1 )
      FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#   undef FIELDS

    /* Bounds check extension data */
    if( FD_UNLIKELY( ext_sz > wire_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    ulong next_field = wire_laddr + ext_sz;
    ulong next_sz    = wire_sz    - ext_sz;

    /* Decode extension data */
    uchar const * ext_data = (uchar const *)wire_laddr;
    long ext_parse_res;
    switch( ext_type ) {
    case FD_TLS_EXT_SUPPORTED_VERSIONS: {
      ushort chosen_version;
      FD_TLS_DECODE_FIELD( &chosen_version, ushort );
      ext_parse_res = 2L;
      if( FD_UNLIKELY( chosen_version!=FD_TLS_VERSION_TLS13 ) )
        return -(long)FD_TLS_ALERT_PROTOCOL_VERSION;
      break;
    }
    case FD_TLS_EXT_KEY_SHARE:
      ext_parse_res = fd_tls_decode_key_share( &out->key_share, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_QUIC_TRANSPORT_PARAMS:
      /* Copy transport params as-is (TODO...) */
      ext_parse_res = (long)ext_sz;
      break;
    default:
      /* Reject unsolicited extensions */
      return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
    }

    if( FD_UNLIKELY( ext_parse_res<0L ) )
      return ext_parse_res;
    if( FD_UNLIKELY( ext_parse_res != (long)ext_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    wire_laddr = next_field;
    wire_sz    = next_sz;
  }
  FD_TLS_DECODE_LIST_END

  /* Check for required extensions */

  if( FD_UNLIKELY( !out->key_share.has_x25519 ) )
    return -(long)FD_TLS_ALERT_MISSING_EXTENSION;

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_server_hello( fd_tls_server_hello_t const * in,
                            uchar *                       wire,
                            ulong                         wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Encode static sized part of server hello.
     (Assuming that session ID field is of a certain size) */

  ushort legacy_version            = FD_TLS_VERSION_TLS12;
  uchar  legacy_session_id_sz      = 0;
  ushort cipher_suite              = FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
  uchar  legacy_compression_method = 0;

# define FIELDS( FIELD )                                 \
    FIELD( 0, &legacy_version,            ushort, 1    ) \
    FIELD( 1, &in->random[0],             uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz,      uchar,  1    ) \
    FIELD( 3, &cipher_suite,              ushort, 1    ) \
    FIELD( 4, &legacy_compression_method, uchar,  1    )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Encode extensions */

  ushort * extension_tot_sz = FD_TLS_SKIP_FIELD( ushort );
  ulong    extension_start  = wire_laddr;

  ushort ext_supported_versions_ext_type = FD_TLS_EXT_SUPPORTED_VERSIONS;
  ushort ext_supported_versions[1]       = { FD_TLS_VERSION_TLS13 };
  ushort ext_supported_versions_ext_sz   = sizeof(ext_supported_versions);

  ushort ext_key_share_ext_type = FD_TLS_EXT_KEY_SHARE;
  ushort ext_key_share_ext_sz   = sizeof(ushort) + sizeof(ushort) + 32UL;
  ushort ext_key_share_group    = FD_TLS_GROUP_X25519;
  ushort ext_key_share_sz       = 32UL;

# define FIELDS( FIELD )                                         \
    FIELD( 0, &ext_supported_versions_ext_type,   ushort, 1    ) \
    FIELD( 1, &ext_supported_versions_ext_sz,     ushort, 1    ) \
    FIELD( 2,  ext_supported_versions,            ushort, 1    ) \
    FIELD( 3, &ext_key_share_ext_type,            ushort, 1    ) \
    FIELD( 4, &ext_key_share_ext_sz,              ushort, 1    ) \
    FIELD( 5, &ext_key_share_group,               ushort, 1    ) \
    FIELD( 6, &ext_key_share_sz,                  ushort, 1    ) \
    FIELD( 7, &in->key_share.x25519[0],           uchar,  32UL )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  *extension_tot_sz = fd_ushort_bswap( (ushort)( (ulong)wire_laddr - extension_start ) );
  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_enc_ext( fd_tls_enc_ext_t * const out,
                       uchar const *      const wire,
                       ulong                    wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    ushort ext_type;
    ushort ext_sz;
#   define FIELDS( FIELD )             \
      FIELD( 0, &ext_type, ushort, 1 ) \
      FIELD( 1, &ext_sz,   ushort, 1 )
      FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#   undef FIELDS

    /* Bounds check extension data
       (list_stop declared by DECODE_LIST macro) */
    if( FD_UNLIKELY( wire_laddr + ext_sz > list_stop ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    switch( ext_type ) {
    case FD_TLS_EXT_ALPN: {
      long res = fd_tls_decode_ext_alpn( &out->alpn, (uchar const *)wire_laddr, ext_sz );
      if( FD_UNLIKELY( res<0L ) )
        return res;
      if( FD_UNLIKELY( res!=(long)ext_sz ) )
        return -(long)FD_TLS_ALERT_DECODE_ERROR;
      break;
    }
    case FD_TLS_EXT_QUIC_TRANSPORT_PARAMS:
      if( FD_UNLIKELY( ext_sz > FD_TLS_EXT_QUIC_PARAMS_SZ_MAX ) )
        return -(long)FD_TLS_ALERT_DECODE_ERROR;
      out->quic_tp.buf   = (void *)wire_laddr;
      out->quic_tp.bufsz = (ushort)ext_sz;
      break;
    case FD_TLS_EXT_SERVER_CERT_TYPE:
      if( FD_UNLIKELY( (ext_sz>wire_sz) | (ext_sz!=1) ) )
        return -(long)FD_TLS_ALERT_DECODE_ERROR;
      out->server_cert.cert_type = *(uchar const *)wire_laddr;
      break;
    case FD_TLS_EXT_CLIENT_CERT_TYPE:
      if( FD_UNLIKELY( (ext_sz>wire_sz) | (ext_sz!=1) ) )
        return -(long)FD_TLS_ALERT_DECODE_ERROR;
      out->client_cert.cert_type = *(uchar const *)wire_laddr;
      break;
    default:
      break;  /* TODO should we error on unknown extensions? */
    }

    wire_laddr += ext_sz;
    wire_sz    -= ext_sz;
  }
  FD_TLS_DECODE_LIST_END

  /* TODO Fail if trailing bytes detected? */

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_server_cert_x509( uchar const * x509,
                                ulong         x509_sz,
                                uchar *       wire,
                                ulong         wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* TLS Record Header */
  uchar msg_type = (uchar)FD_TLS_MSG_CERT;

  /* TLS Certificate Message header preceding X.509 data */

  /* All size prefixes known in advance */
  fd_tls_u24_t msg_sz       = fd_uint_to_tls_u24( (uint)( x509_sz + 9UL ) );
  fd_tls_u24_t cert_list_sz = fd_uint_to_tls_u24( (uint)( x509_sz + 5UL ) );
  fd_tls_u24_t cert_sz      = fd_uint_to_tls_u24( (uint)( x509_sz       ) );

  /* zero sz certificate_request_context
     (Server certificate never has a request context) */
  uchar certificate_request_context_sz = (uchar)0;

  /* No certificate extensions */
  ushort ext_sz = (ushort)0;

# define FIELDS( FIELD )                                            \
    FIELD( 0, &msg_type,                         uchar,   1       ) \
    FIELD( 1, &msg_sz,                           tls_u24, 1       ) \
      FIELD( 2, &certificate_request_context_sz, uchar,   1       ) \
      FIELD( 3, &cert_list_sz,                   tls_u24, 1       ) \
        FIELD( 4, &cert_sz,                      tls_u24, 1       ) \
        FIELD( 5, x509,                          uchar,   x509_sz ) \
        FIELD( 6, &ext_sz,                       ushort,  1       )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_enc_ext( fd_tls_enc_ext_t const * in,
                       uchar *                  wire,
                       ulong                    wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* ALPN */

  if( in->alpn.bufsz ) {
    fd_tls_ext_hdr_t ext_hdr = { .type = FD_TLS_EXT_ALPN,
                                 .sz   = (ushort)( in->alpn.bufsz+2 ) };
    FD_TLS_ENCODE_SUB( fd_tls_encode_ext_hdr,  &ext_hdr  );
    FD_TLS_ENCODE_SUB( fd_tls_encode_ext_alpn, &in->alpn );
  }

  /* QUIC transport params */

  if( in->quic_tp.buf ) {
    ushort ext_type = FD_TLS_EXT_QUIC_TRANSPORT_PARAMS;
    ushort ext_sz   = (ushort)in->quic_tp.bufsz;
#   define FIELDS( FIELD )             \
      FIELD( 0, &ext_type, ushort, 1 ) \
      FIELD( 1, &ext_sz,   ushort, 1 ) \
        FIELD( 2, in->quic_tp.buf, uchar, in->quic_tp.bufsz )
      FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
#   undef FIELDS
  }

  /* Server certificate type */

  if( in->server_cert.cert_type ) {
    ushort ext_type  = FD_TLS_EXT_SERVER_CERT_TYPE;
    ushort ext_sz    = 1;
    uchar  cert_type = (uchar)in->server_cert.cert_type;
#   define FIELDS( FIELD )                \
      FIELD( 0, &ext_type,    ushort, 1 ) \
      FIELD( 1, &ext_sz,      ushort, 1 ) \
        FIELD( 2, &cert_type, uchar,  1 )
      FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
#   undef FIELDS
  }

  /* Client certificate type */

  if( in->client_cert.cert_type ) {
    ushort ext_type  = FD_TLS_EXT_CLIENT_CERT_TYPE;
    ushort ext_sz    = 1;
    uchar  cert_type = (uchar)in->client_cert.cert_type;
#   define FIELDS( FIELD )                \
      FIELD( 0, &ext_type,    ushort, 1 ) \
      FIELD( 1, &ext_sz,      ushort, 1 ) \
        FIELD( 2, &cert_type, uchar,  1 )
      FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
#   undef FIELDS
  }

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_raw_public_key( uchar const * key,
                              uchar *       wire,
                              ulong         wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* TLS Record Header */
  uchar msg_type = (uchar)FD_TLS_MSG_CERT;

  /* TLS Certificate Message header preceding X.509 data */

  /* All size prefixes known in advance */
  uint         rpk_sz       = sizeof(fd_asn1_ed25519_pubkey_prefix)+32UL;
  fd_tls_u24_t msg_sz       = fd_uint_to_tls_u24( (uint)( rpk_sz + 9UL ) );
  fd_tls_u24_t cert_list_sz = fd_uint_to_tls_u24( (uint)( rpk_sz + 5UL ) );
  fd_tls_u24_t cert_sz      = fd_uint_to_tls_u24( (uint)( rpk_sz       ) );

  /* zero sz certificate_request_context
     (Server certificate never has a request context) */
  uchar certificate_request_context_sz = (uchar)0;

  /* No certificate extensions */
  ushort ext_sz = (ushort)0;

  /* TODO Should use fd_memcpy() instead of memcpy() */
# define FIELDS( FIELD )                                            \
    FIELD( 0, &msg_type,                         uchar,   1       ) \
    FIELD( 1, &msg_sz,                           tls_u24, 1       ) \
      FIELD( 2, &certificate_request_context_sz, uchar,   1       ) \
      FIELD( 3, &cert_list_sz,                   tls_u24, 1       ) \
        FIELD( 4, &cert_sz,                      tls_u24, 1       ) \
        FIELD( 5, fd_asn1_ed25519_pubkey_prefix, uchar,   sizeof(fd_asn1_ed25519_pubkey_prefix) ) \
        FIELD( 6, key,                           uchar,   32UL    ) \
        FIELD( 7, &ext_sz,                       ushort,  1       )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_cert_verify( fd_tls_cert_verify_t * out,
                           uchar const *          wire,
                           ulong                  wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  ushort sig_sz;
# define FIELDS( FIELD ) \
    FIELD( 0, &out->sig_alg, ushort,  1 ) \
    FIELD( 1, &sig_sz,       ushort,  1 ) \
    FIELD( 2,  out->sig,     uchar,  64 )
  FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( FD_UNLIKELY( ( out->sig_alg != FD_TLS_SIGNATURE_ED25519 )
                 | (      sig_sz  != 0x40UL                   ) ) )
    return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_cert_verify( fd_tls_cert_verify_t const * in,
                           uchar *                      wire,
                           ulong                        wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  ushort sig_sz = 0x40;
# define FIELDS( FIELD ) \
    FIELD( 0, &in->sig_alg, ushort,  1 ) \
    FIELD( 1, &sig_sz,      ushort,  1 ) \
    FIELD( 2,  in->sig,     uchar,  64 )
  FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_server_name( fd_tls_ext_server_name_t * out,
                               uchar const *              wire,
                               ulong                      wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* TLS v1.3 server name lists practically always have one element. */

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    /* Read type and length */
    uchar  name_type;
    ushort name_sz;
#   define FIELDS( FIELD )              \
      FIELD( 0, &name_type, uchar,  1 ) \
      FIELD( 1, &name_sz,   ushort, 1 )
      FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#   undef FIELDS

    /* Bounds check name */
    if( FD_UNLIKELY( wire_laddr + name_sz > list_stop ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    /* Decode name on first use */
    if( ( ( name_type == FD_TLS_SERVER_NAME_TYPE_DNS )
        & ( name_sz < 254                            )
        & ( out->host_name_len == 0                  ) ) ) {
      out->host_name_len = (uchar)name_sz;
      memcpy( out->host_name, (uchar const *)wire_laddr, name_sz );
      out->host_name[ name_sz ] = '\0';
    }

    /* Seek to next name */
    wire_laddr += name_sz;
    wire_sz    -= name_sz;
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_supported_groups( fd_tls_ext_supported_groups_t * out,
                                    uchar const *                   wire,
                                    ulong                           wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_GROUP_X25519:
      out->x25519 = 1;
      break;
    default:
      /* Ignore unsupported groups ... */
      break;
    }
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_supported_versions( fd_tls_ext_supported_versions_t * out,
                                      uchar const *                     wire,
                                      ulong                             wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( uchar, alignof(ushort) ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_VERSION_TLS13:
      out->tls13 = 1;
      break;
    default:
      /* Ignore unsupported TLS versions ... */
      break;
    }
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_signature_algorithms( fd_tls_ext_signature_algorithms_t * out,
                                        uchar const *                       wire,
                                        ulong                               wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(ushort) ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_SIGNATURE_ED25519:
      out->ed25519 = 1;
      break;
    default:
      /* Ignore unsupported signature algorithms ... */
      break;
    }
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_key_share( fd_tls_key_share_t * out,
                         uchar const *        wire,
                         ulong                wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Read type and length */
  ushort group;
  ushort kex_data_sz;
# define FIELDS( FIELD )                \
    FIELD( 0, &group,       ushort, 1 ) \
    FIELD( 1, &kex_data_sz, ushort, 1 )
    FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Bounds check */
  if( FD_UNLIKELY( kex_data_sz > wire_sz ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  switch( group ) {
  case FD_TLS_GROUP_X25519:
    if( FD_UNLIKELY( kex_data_sz != 32UL ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;
    out->has_x25519 = 1;
    memcpy( out->x25519, (uchar const *)wire_laddr, 32UL );
    break;
  default:
    /* Ignore unsupported key share groups ... */
    break;
  }

  /* Seek to next group */
  wire_laddr += kex_data_sz;
  wire_sz    -= kex_data_sz;

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_key_share_list( fd_tls_key_share_t * out,
                              uchar const *        wire,
                              ulong                wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    FD_TLS_DECODE_SUB( fd_tls_decode_key_share, out );
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_cert_type_list( fd_tls_ext_cert_type_list_t * out,
                                  uchar const *                 wire,
                                  ulong                         wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  out->present = 1;
  FD_TLS_DECODE_LIST_BEGIN( uchar, alignof(uchar) ) {
    uchar cert_type;
    FD_TLS_DECODE_FIELD( &cert_type, uchar );  /* is this really a uchar? */
    switch( cert_type ) {
    case FD_TLS_CERTTYPE_X509:       out->x509 = 1;       break;
    case FD_TLS_CERTTYPE_RAW_PUBKEY: out->raw_pubkey = 1; break;
    default:
      /* Ignore unsupported cert types ... */
      break;
    }
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_ext_cert_type_list( fd_tls_ext_cert_type_list_t in,
                                  uchar const *               wire,
                                  ulong                       wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Encode list size */
  uchar cnt = (uchar)fd_uchar_popcnt( in.uc );
  FD_TLS_ENCODE_FIELD( &cnt, uchar );

  /* Encode list */
  uchar * fields = FD_TLS_SKIP_FIELDS( uchar, cnt );
  if( in.x509       ) *fields++ = FD_TLS_CERTTYPE_X509;
  if( in.raw_pubkey ) *fields++ = FD_TLS_CERTTYPE_RAW_PUBKEY;

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_cert_type( fd_tls_ext_cert_type_t * out,
                              uchar const *           wire,
                              ulong                   wire_sz ) {
  ulong wire_laddr = (ulong)wire;
  FD_TLS_DECODE_FIELD( &out->cert_type, uchar );
  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_ext_cert_type( fd_tls_ext_cert_type_t in,
                             uchar const *          wire,
                             ulong                  wire_sz ) {
  ulong wire_laddr = (ulong)wire;
  FD_TLS_ENCODE_FIELD( &in.cert_type, uchar );
  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_opaque( fd_tls_ext_opaque_t * const out,
                          uchar const *         const wire,
                          ulong                       wire_sz ) {
  out->buf   = wire;
  out->bufsz = wire_sz;
  return (long)wire_sz;
}

long
fd_tls_decode_ext_alpn( fd_tls_ext_alpn_t * const out,
                        uchar const *       const wire,
                        ulong                     wire_sz ) {
  ulong wire_laddr = (ulong)wire;
  ushort alpn_sz;
  FD_TLS_DECODE_FIELD( &alpn_sz, ushort );
  if( FD_UNLIKELY( (ulong)alpn_sz != wire_sz ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;
  return 2L + (long)fd_tls_decode_ext_opaque( out, (uchar const *)wire_laddr, wire_sz );
}

long
fd_tls_encode_ext_alpn( fd_tls_ext_alpn_t const * in,
                        uchar *                   wire,
                        ulong                     wire_sz ) {
  ulong sz = 2UL + in->bufsz;
  if( FD_UNLIKELY( sz>wire_sz ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;
  wire[0] = (uchar)( (in->bufsz >> 8)&0xFF );
  wire[1] = (uchar)(  in->bufsz      &0xFF );
  fd_memcpy( wire+2UL, in->buf, in->bufsz );
  return (long)sz;
}

/* fd_tls_client_handle_x509 extracts the Ed25519 subject public key
   from the certificate.  Does not validate the signature found on the
   certificate (might be self-signed).  [cert,cert+cert_sz) points to
   an ASN.1 DER serialization of the certificate.  On success, copies
   public key bits to out_pubkey and returns 0U.  On failure, returns
   positive TLS alert error code. */

static uint
fd_tls_client_handle_x509( uchar const *  const cert,
                           ulong          const cert_sz,
                           uchar const ** const out_pubkey ) {

  cert_parsing_ctx parsed = {0};
  int err = parse_x509_cert( &parsed, cert, (uint)cert_sz );
  if( FD_UNLIKELY( err ) )
    return FD_TLS_ALERT_BAD_CERTIFICATE;

  if( FD_UNLIKELY( parsed.spki_alg != SPKI_ALG_ED25519 ) )
    return FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE;

  if( FD_UNLIKELY( parsed.spki_alg_params.ed25519.ed25519_raw_pub_len != 32 ) )
    return FD_TLS_ALERT_BAD_CERTIFICATE;

  *out_pubkey = cert + parsed.spki_alg_params.ed25519.ed25519_raw_pub_off;
  return 0L;
}

static long
fd_tls_extract_cert_pubkey_( fd_tls_extract_cert_pubkey_res_t * res,
                             uchar const * cert_chain,
                             ulong         cert_chain_sz,
                             uint          cert_type ) {

  fd_memset( res, 0, sizeof(fd_tls_extract_cert_pubkey_res_t) );

  ulong wire_laddr = (ulong)cert_chain;
  ulong wire_sz    = cert_chain_sz;

  /* Skip 'opaque certificate_request_context<0..2^8-1>' */
  uchar const * opaque_sz = FD_TLS_SKIP_FIELD( uchar );
  uchar const * opaque    = FD_TLS_SKIP_FIELDS( uchar, *opaque_sz );
  (void)opaque;

  /* Get first entry of certificate chain
     CertificateEntry certificate_list<0..2^24-1> */
  fd_tls_u24_t const * cert_list_sz_be = FD_TLS_SKIP_FIELD( fd_tls_u24_t );
  fd_tls_u24_t         cert_list_sz_   = fd_tls_u24_bswap( *cert_list_sz_be );
  uint                 cert_list_sz    = fd_tls_u24_to_uint( cert_list_sz_ );
  if( FD_UNLIKELY( cert_list_sz==0U ) ) {
    res->alert  = FD_TLS_ALERT_BAD_CERTIFICATE;
    res->reason = FD_TLS_REASON_CERT_CHAIN_EMPTY;
    return -1L;
  }

  /* Get certificate size */
  fd_tls_u24_t const * cert_sz_be = FD_TLS_SKIP_FIELD( fd_tls_u24_t );
  fd_tls_u24_t         cert_sz_   = fd_tls_u24_bswap( *cert_sz_be );
  uint                 cert_sz    = fd_tls_u24_to_uint( cert_sz_ );
  if( FD_UNLIKELY( cert_sz>wire_sz ) ) {
    res->alert = FD_TLS_ALERT_DECODE_ERROR;
    res->reason = FD_TLS_REASON_CERT_PARSE;
    return -1L;
  }

  void * cert = (void *)wire_laddr;

  switch( cert_type ) {

  case FD_TLS_CERTTYPE_X509: {

    /* DER-encoded X.509 certificate */

    uint x509_alert = fd_tls_client_handle_x509( cert, cert_sz, &res->pubkey );
    if( FD_UNLIKELY( x509_alert!=0U ) ) {
      res->pubkey = NULL;
      res->alert  = x509_alert;
      res->reason = FD_TLS_REASON_X509_PARSE;
      return -1L;
    }

    return 0L;
  }

  case FD_TLS_CERTTYPE_RAW_PUBKEY: {

    /* Interpret certificate entry as raw public key (RFC 7250)
       'opaque ASN1_subjectPublicKeyInfo<1..2^24-1>' */

    res->pubkey = fd_ed25519_public_key_from_asn1( cert, cert_sz );
    if( FD_UNLIKELY( !res->pubkey ) ) {
      res->reason = FD_TLS_REASON_SPKI_PARSE;
      res->alert  = FD_TLS_ALERT_BAD_CERTIFICATE;
      return -1L;
    }

    return 0L;
  }

  default:
    __builtin_unreachable();

  } /* end switch */
}

fd_tls_extract_cert_pubkey_res_t
fd_tls_extract_cert_pubkey( uchar const * cert_chain,
                            ulong         cert_chain_sz,
                            uint          cert_type ) {
  fd_tls_extract_cert_pubkey_res_t res;
  long ret = fd_tls_extract_cert_pubkey_( &res, cert_chain, cert_chain_sz, cert_type );
  (void)ret;
  return res;
}
