#include "fd_tls.h"
#include "fd_tls_proto.h"
#include "fd_tls_serde.h"
#include "../../ballet/x509/fd_x509.h"

typedef struct fd_tls_u24 tls_u24;  /* code generator helper */

/* RFC 8446 Section 4.1.3: "the server's value [random] will be set to the
   SHA-256 hash of 'HelloRetryRequest'" */
static uchar const hello_retry_magic[ 32 ] =
  { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };

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

/* Decode ClientHello (RFC 8446 Section 4.1.2) */
long
fd_tls_decode_client_hello( fd_tls_client_hello_t * out,
                            uchar const * const     wire,
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

  if( FD_UNLIKELY( ( legacy_session_id_sz > 32      ) |
                   ( wire_sz < legacy_session_id_sz ) ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  out->session_id.buf   = (void *)wire_laddr;
  out->session_id.bufsz = legacy_session_id_sz;
  wire_laddr += legacy_session_id_sz;
  wire_sz    -= legacy_session_id_sz;

  /* Decode cipher suite list */

  if( FD_UNLIKELY( wire_sz<2UL || !FD_LOAD( ushort, (void const *)wire_laddr ) ) )
    return -FD_TLS_ALERT_DECODE_ERROR;
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

  ulong seen = 0UL;
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

    /* RFC 8446 Section 4.2: at most one extension of each type */
    if( ext_type<64 ) {
      if( FD_UNLIKELY( seen & (1UL<<ext_type) ) ) return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
      seen |= 1UL<<ext_type;
    }

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
    case FD_TLS_EXT_SIGNATURE_ALGORITHMS_CERT:
      ext_parse_res = fd_tls_decode_ext_signature_algorithms( &out->signature_algorithms_cert, ext_data, ext_sz );
      break;
    case FD_TLS_EXT_KEY_SHARE:
      ext_parse_res = fd_tls_decode_key_share_list( &out->key_share, ext_data, ext_sz );
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
  uchar  legacy_session_id_sz  = (uchar)in->session_id.bufsz;
  ushort cipher_suite_sz       = 1*sizeof(ushort);
  ushort cipher_suites[1]      = { FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 };
  uchar  legacy_comp_method_sz = 1;
  uchar  legacy_comp_method[1] = {0};

# define FIELDS( FIELD )                                 \
    FIELD( 0, &legacy_version,            ushort, 1    ) \
    FIELD( 1,  in->random,                uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz,      uchar,  1    )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Encode session_id (0 for QUIC, 32 random bytes for TCP middlebox compat) */

  if( legacy_session_id_sz ) {
    if( FD_UNLIKELY( legacy_session_id_sz > 32 ) )
      return -(long)FD_TLS_ALERT_INTERNAL_ERROR;
    if( FD_UNLIKELY( (ulong)legacy_session_id_sz > wire_sz ) )
      return -(long)FD_TLS_ALERT_INTERNAL_ERROR;
    fd_memcpy( (void *)wire_laddr, in->session_id.buf, legacy_session_id_sz );
    wire_laddr += legacy_session_id_sz;
    wire_sz    -= legacy_session_id_sz;
  }

# define FIELDS( FIELD )                                 \
    FIELD( 0, &cipher_suite_sz,           ushort, 1    ) \
    FIELD( 1,  cipher_suites,             ushort, 1    ) \
    FIELD( 2, &legacy_comp_method_sz,     uchar,  1    ) \
    FIELD( 3,  legacy_comp_method,        uchar,  1    )
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

  /* Advertise the signature algorithms the caller opted into, in
     descending order of preference */

  ushort ext_sigalg[2];
  ulong  ext_sigalg_cnt = 0UL;
  if( in->signature_algorithms.ecdsa_secp256r1_sha256 )
    ext_sigalg[ ext_sigalg_cnt++ ] = FD_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
  if( in->signature_algorithms.ed25519 )
    ext_sigalg[ ext_sigalg_cnt++ ] = FD_TLS_SIGNATURE_ED25519;
  if( FD_UNLIKELY( !ext_sigalg_cnt ) ) return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  ushort ext_sigalg_ext_type = FD_TLS_EXT_SIGNATURE_ALGORITHMS;
  ushort ext_sigalg_sz       = (ushort)( 2UL*ext_sigalg_cnt );
  ushort ext_sigalg_ext_sz   = (ushort)( 2U+ext_sigalg_sz );

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
    FIELD(17,  ext_sigalg,                        ushort, ext_sigalg_cnt )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( in->signature_algorithms_cert.ed25519 ||
      in->signature_algorithms_cert.ecdsa_secp256r1_sha256 ||
      in->signature_algorithms_cert.ecdsa_secp384r1_sha384 ) {
    ushort schemes[3];
    ulong  cnt = 0UL;
    if( in->signature_algorithms_cert.ecdsa_secp256r1_sha256 ) schemes[cnt++] = FD_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
    if( in->signature_algorithms_cert.ecdsa_secp384r1_sha384 ) schemes[cnt++] = FD_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384;
    if( in->signature_algorithms_cert.ed25519                ) schemes[cnt++] = FD_TLS_SIGNATURE_ED25519;
    ushort type    = FD_TLS_EXT_SIGNATURE_ALGORITHMS_CERT;
    ushort list_sz = (ushort)(2UL*cnt);
    ushort ext_sz  = (ushort)(list_sz+2U);
#   define FIELDS( FIELD )                     \
      FIELD( 0, &type,    ushort, 1   )        \
      FIELD( 1, &ext_sz,  ushort, 1   )        \
      FIELD( 2, &list_sz, ushort, 1   )        \
      FIELD( 3, schemes,  ushort, cnt )
      FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
#   undef FIELDS
  }

  /* Add Server Name Indication (SNI) */

  if( in->server_name.host_name_len ) {
    ushort sni_name_len = in->server_name.host_name_len;
    ushort sni_list_len = (ushort)( 1 + 2 + sni_name_len );  /* name_type(1) + name_len(2) + name */
    ushort sni_ext_type = FD_TLS_EXT_SERVER_NAME;
    ushort sni_ext_sz   = (ushort)( 2 + sni_list_len );      /* list_len(2) + list */
    uchar  sni_name_type = FD_TLS_SERVER_NAME_TYPE_DNS;
#   define FIELDS( FIELD )                                    \
      FIELD( 0, &sni_ext_type,  ushort, 1 )                  \
      FIELD( 1, &sni_ext_sz,    ushort, 1 )                  \
      FIELD( 2, &sni_list_len,  ushort, 1 )                  \
      FIELD( 3, &sni_name_type, uchar,  1 )                  \
      FIELD( 4, &sni_name_len,  ushort, 1 )                  \
      FIELD( 5, in->server_name.host_name, uchar, sni_name_len )
      FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
#   undef FIELDS
  }

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

  FD_STORE( ushort, extension_tot_sz, fd_ushort_bswap( (ushort)( (ulong)wire_laddr - extension_start ) ) );
  return (long)( wire_laddr - (ulong)wire );
}

/* Decode ServerHello (RFC 8446 Section 4.1.3) */
long
fd_tls_decode_server_hello( fd_tls_server_hello_t * out,
                            uchar const *           wire,
                            ulong                   wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Decode static sized part of server hello */

  ushort legacy_version;            /* ==FD_TLS_VERSION_TLS12 */
  uchar  legacy_session_id_sz;      /* 0 for QUIC, 0-32 for TCP */
  ushort cipher_suite;              /* ==FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 */
  uchar  legacy_compression_method; /* ==0 */

# define FIELDS( FIELD )                                 \
    FIELD( 0, &legacy_version,            ushort, 1    ) \
    FIELD( 1, &out->random[0],            uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz,      uchar,  1    )
    FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Skip legacy_session_id (echoed back for TCP middlebox compat) */

  if( FD_UNLIKELY( legacy_session_id_sz > 32 ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;
  if( FD_UNLIKELY( (ulong)legacy_session_id_sz > wire_sz ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;
  out->session_id.buf   = (uchar const *)wire_laddr;
  out->session_id.bufsz = legacy_session_id_sz;
  wire_laddr += legacy_session_id_sz;
  wire_sz    -= legacy_session_id_sz;

# define FIELDS( FIELD )                                 \
    FIELD( 0, &cipher_suite,              ushort, 1    ) \
    FIELD( 1, &legacy_compression_method, uchar,  1    )
    FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( FD_UNLIKELY( ( legacy_version != FD_TLS_VERSION_TLS12 )
                 | ( legacy_compression_method != 0         ) ) )
    return -(long)FD_TLS_ALERT_PROTOCOL_VERSION;

  out->cipher_suite = cipher_suite;

  /* Reject HelloRetryRequest (we only support X25519) */

  if( FD_UNLIKELY( 0==memcmp( out->random, hello_retry_magic, 32 ) ) )
    return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;

  /* Read extensions */

  ulong seen = 0UL;
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

    /* RFC 8446 Section 4.2: at most one extension of each type */
    if( ext_type<64 ) {
      if( FD_UNLIKELY( seen & (1UL<<ext_type) ) ) return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
      seen |= 1UL<<ext_type;
    }

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
    default:
      /* RFC 8446 Section 4.2: a ServerHello may only carry responses
         to extensions the client offered */
      return -(long)FD_TLS_ALERT_UNSUPPORTED_EXTENSION;
    }

    if( FD_UNLIKELY( ext_parse_res<0L ) )
      return ext_parse_res;
    if( FD_UNLIKELY( ext_parse_res != (long)ext_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    wire_laddr = next_field;
    wire_sz    = next_sz;
  }
  FD_TLS_DECODE_LIST_END

  /* Check for required extensions.  Without supported_versions this
     is a TLS 1.2 ServerHello (RFC 8446 Section 4.1.3). */

  if( FD_UNLIKELY( !(seen & (1UL<<FD_TLS_EXT_SUPPORTED_VERSIONS)) ) )
    return -(long)FD_TLS_ALERT_PROTOCOL_VERSION;
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
  uchar  legacy_session_id_sz      = (uchar)in->session_id.bufsz;
  ushort cipher_suite              = FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
  uchar  legacy_compression_method = 0;

# define FIELDS( FIELD )                                 \
    FIELD( 0, &legacy_version,            ushort, 1    ) \
    FIELD( 1, &in->random[0],             uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz,      uchar,  1    ) \
    FIELD( 3,  in->session_id.buf,        uchar,  legacy_session_id_sz ) \
    FIELD( 4, &cipher_suite,              ushort, 1    ) \
    FIELD( 5, &legacy_compression_method, uchar,  1    )
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
fd_tls_encode_hello_retry_request( fd_tls_server_hello_t const * in,
                                   uchar *                       wire,
                                   ulong                         wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  ushort legacy_version            = FD_TLS_VERSION_TLS12;
  uchar  legacy_session_id_sz      = (uchar)in->session_id.bufsz;
  ushort cipher_suite              = FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
  uchar  legacy_compression_method = 0;

# define FIELDS( FIELD )                                 \
    FIELD( 0, &legacy_version,            ushort, 1    ) \
    FIELD( 1, hello_retry_magic,          uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz,      uchar,  1    ) \
    FIELD( 3,  in->session_id.buf,        uchar,  legacy_session_id_sz ) \
    FIELD( 4, &cipher_suite,              ushort, 1    ) \
    FIELD( 5, &legacy_compression_method, uchar,  1    )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Encode extensions */

  ushort * extension_tot_sz = FD_TLS_SKIP_FIELD( ushort );
  ulong    extension_start  = wire_laddr;

  ushort ext_supported_versions_ext_type = FD_TLS_EXT_SUPPORTED_VERSIONS;
  ushort ext_supported_versions[1]       = { FD_TLS_VERSION_TLS13 };
  ushort ext_supported_versions_ext_sz   = sizeof(ext_supported_versions);

  ushort ext_key_share_ext_type = FD_TLS_EXT_KEY_SHARE;
  ushort ext_key_share_ext_sz   = sizeof(ushort);
  ushort ext_key_share_group    = FD_TLS_GROUP_X25519;

# define FIELDS( FIELD )                                         \
    FIELD( 0, &ext_supported_versions_ext_type,   ushort, 1    ) \
    FIELD( 1, &ext_supported_versions_ext_sz,     ushort, 1    ) \
    FIELD( 2,  ext_supported_versions,            ushort, 1    ) \
    FIELD( 3, &ext_key_share_ext_type,            ushort, 1    ) \
    FIELD( 4, &ext_key_share_ext_sz,              ushort, 1    ) \
    FIELD( 5, &ext_key_share_group,               ushort, 1    )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  *extension_tot_sz = fd_ushort_bswap( (ushort)( (ulong)wire_laddr - extension_start ) );
  return (long)( wire_laddr - (ulong)wire );
}

/* Decode EncryptedExtensions (RFC 8446 Section 4.3.1) */
long
fd_tls_decode_enc_ext( fd_tls_enc_ext_t * const out,
                       uchar const *      const wire,
                       ulong                    wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  ulong seen = 0UL;
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

    /* RFC 8446 Section 4.2: at most one extension of each type */
    if( ext_type<64 ) {
      if( FD_UNLIKELY( seen & (1UL<<ext_type) ) ) return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
      seen |= 1UL<<ext_type;
    }

    switch( ext_type ) {
    case FD_TLS_EXT_SERVER_NAME:
      if( FD_UNLIKELY( ext_sz ) ) return -FD_TLS_ALERT_DECODE_ERROR;
      out->server_name = 1;
      break;
    case FD_TLS_EXT_SUPPORTED_GROUPS: {
      /* RFC 8446 Section 4.2.7 explicitly permits this in EE. */
      fd_tls_ext_supported_groups_t groups = {0};
      long res = fd_tls_decode_ext_supported_groups( &groups, (uchar const *)wire_laddr, ext_sz );
      if( FD_UNLIKELY( res<0L ) ) return res;
      if( FD_UNLIKELY( res!=(long)ext_sz ) ) return -FD_TLS_ALERT_DECODE_ERROR;
      break;
    }
    case FD_TLS_EXT_ALPN: {
      long res = fd_tls_decode_ext_alpn( &out->alpn, (uchar const *)wire_laddr, ext_sz );
      if( FD_UNLIKELY( res<0L ) )
        return res;
      if( FD_UNLIKELY( res!=(long)ext_sz ) )
        return -(long)FD_TLS_ALERT_DECODE_ERROR;
      if( FD_UNLIKELY( out->alpn.bufsz != 1UL+out->alpn.buf[0] ) )
        return -FD_TLS_ALERT_DECODE_ERROR;
      break;
    }
    case FD_TLS_EXT_QUIC_TRANSPORT_PARAMS:
      if( FD_UNLIKELY( ext_sz > FD_TLS_EXT_QUIC_PARAMS_SZ_MAX ) )
        return -(long)FD_TLS_ALERT_DECODE_ERROR;
      out->quic_tp.buf   = (void *)wire_laddr;
      out->quic_tp.bufsz = (ushort)ext_sz;
      break;
    default:
      return -(long)FD_TLS_ALERT_UNSUPPORTED_EXTENSION;
    }

    wire_laddr += ext_sz;
    wire_sz    -= ext_sz;
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

/* Decode CertificateRequest (RFC 8446 Section 4.3.2) */
long
fd_tls_decode_cert_req( fd_tls_ext_signature_algorithms_t * out,
                        uchar const *                       wire,
                        ulong                               wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* certificate_request_context is empty outside of post-handshake
     authentication, which is not supported */
  uchar ctx_sz;
  FD_TLS_DECODE_FIELD( &ctx_sz, uchar );
  if( FD_UNLIKELY( ctx_sz ) )
    return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;

  ulong seen = 0UL;
  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    ushort ext_type;
    ushort ext_sz;
#   define FIELDS( FIELD )             \
      FIELD( 0, &ext_type, ushort, 1 ) \
      FIELD( 1, &ext_sz,   ushort, 1 )
      FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#   undef FIELDS

    if( FD_UNLIKELY( ext_sz > wire_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    /* RFC 8446 Section 4.2: at most one extension of each type */
    if( ext_type<64 ) {
      if( FD_UNLIKELY( seen & (1UL<<ext_type) ) ) return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
      seen |= 1UL<<ext_type;
    }

    long ext_parse_res;
    switch( ext_type ) {
    case FD_TLS_EXT_SIGNATURE_ALGORITHMS:
      ext_parse_res = fd_tls_decode_ext_signature_algorithms( out, (uchar const *)wire_laddr, ext_sz );
      break;
    default:
      /* Ignore everything else.  certificate_authorities, oid_filters
         and signature_algorithms_cert do not change which certificate
         we send (we only have one), and extensions that RFC 8446
         Section 4.2 forbids here are tolerated rather than rejected
         with illegal_parameter. */
      ext_parse_res = (long)ext_sz;
      break;
    }
    if( FD_UNLIKELY( ext_parse_res<0L ) )
      return ext_parse_res;
    if( FD_UNLIKELY( ext_parse_res != (long)ext_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    wire_laddr += ext_sz;
    wire_sz    -= ext_sz;
  }
  FD_TLS_DECODE_LIST_END

  /* signature_algorithms MUST be specified */
  if( FD_UNLIKELY( !(seen & (1UL<<FD_TLS_EXT_SIGNATURE_ALGORITHMS)) ) )
    return -(long)FD_TLS_ALERT_MISSING_EXTENSION;

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_cert_x509( uchar const * x509,
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
                       uchar *                        wire,
                       ulong                          wire_sz ) {

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

  return (long)( wire_laddr - (ulong)wire );
}

/* Decode CertificateVerify (RFC 8446 Section 4.4.3) */
long
fd_tls_decode_cert_verify( fd_tls_cert_verify_t * out,
                           uchar const *          wire,
                           ulong                  wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  ushort sig_sz;
# define FIELDS( FIELD ) \
    FIELD( 0, &out->algorithm, ushort, 1 ) \
    FIELD( 1, &sig_sz,       ushort, 1 )
  FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Validate signature algorithm and length */

  switch( out->algorithm ) {
  case FD_TLS_SIGNATURE_ED25519:
    if( FD_UNLIKELY( sig_sz != 64U ) )
      return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
    break;
  case FD_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
    /* ECDSA DER-encoded signatures are variable length, max 73 */
    if( FD_UNLIKELY( sig_sz > 73U || sig_sz < 8U ) )
      return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
    break;
  default:
    return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
  }

  /* Read signature bytes */

  if( FD_UNLIKELY( sig_sz > wire_sz ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;
  fd_memcpy( out->signature, (void const *)wire_laddr, sig_sz );
  out->signature_len = sig_sz;
  wire_laddr += sig_sz;
  wire_sz    -= sig_sz;

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_cert_verify( fd_tls_cert_verify_t const * in,
                           uchar *                      wire,
                           ulong                        wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  ushort sig_sz = in->signature_len;
# define FIELDS( FIELD ) \
    FIELD( 0, &in->algorithm, ushort, 1 ) \
    FIELD( 1, &sig_sz,      ushort, 1 )
  FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( FD_UNLIKELY( sig_sz > wire_sz ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;
  fd_memcpy( (void *)wire_laddr, in->signature, sig_sz );
  wire_laddr += sig_sz;
  wire_sz    -= sig_sz;

  return (long)( wire_laddr - (ulong)wire );
}

/* Decode server_name extension (RFC 6066 Section 3) */
long
fd_tls_decode_ext_server_name( fd_tls_ext_server_name_t * out,
                               uchar const *              wire,
                               ulong                      wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* TLS v1.3 server name lists practically always have one element. */

  if( FD_UNLIKELY( wire_sz<2UL || !FD_LOAD( ushort, wire ) ) )
    return -FD_TLS_ALERT_DECODE_ERROR;
  uchar seen[ 32 ] = {0};
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
    if( FD_UNLIKELY( !name_sz || wire_laddr + name_sz > list_stop ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;
    uchar mask = (uchar)( 1U<<(name_type&7U) );
    if( FD_UNLIKELY( seen[ name_type>>3 ]&mask ) ) return -FD_TLS_ALERT_ILLEGAL_PARAMETER;
    seen[ name_type>>3 ] |= mask;

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

/* Decode supported_groups extension (RFC 8446 Section 4.2.7) */
long
fd_tls_decode_ext_supported_groups( fd_tls_ext_supported_groups_t * out,
                                    uchar const *                   wire,
                                    ulong                           wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  if( FD_UNLIKELY( wire_sz<2UL || !FD_LOAD( ushort, wire ) ) )
    return -FD_TLS_ALERT_DECODE_ERROR;
  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(ushort) ) {
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

/* Decode supported_versions extension (RFC 8446 Section 4.2.1) */
long
fd_tls_decode_ext_supported_versions( fd_tls_ext_supported_versions_t * out,
                                      uchar const *                     wire,
                                      ulong                             wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  if( FD_UNLIKELY( !wire_sz || !wire[0] ) ) return -FD_TLS_ALERT_DECODE_ERROR;
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

/* Decode signature_algorithms extension (RFC 8446 Section 4.2.3) */
long
fd_tls_decode_ext_signature_algorithms( fd_tls_ext_signature_algorithms_t * out,
                                        uchar const *                       wire,
                                        ulong                               wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  if( FD_UNLIKELY( wire_sz<2UL || !FD_LOAD( ushort, wire ) ) )
    return -FD_TLS_ALERT_DECODE_ERROR;
  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(ushort) ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_SIGNATURE_ED25519:
      out->ed25519 = 1;
      break;
    case FD_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
      out->ecdsa_secp256r1_sha256 = 1;
      break;
    case FD_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384:
      out->ecdsa_secp384r1_sha384 = 1;
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
  if( FD_UNLIKELY( !kex_data_sz || kex_data_sz > wire_sz ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  switch( group ) {
  case FD_TLS_GROUP_X25519:
    if( FD_UNLIKELY( kex_data_sz != 32UL ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;
    /* RFC 8446 Section 4.2.8: at most one KeyShareEntry per group */
    if( FD_UNLIKELY( out->has_x25519 ) )
      return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
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
  if( FD_UNLIKELY( alpn_sz<2U ) ) return -FD_TLS_ALERT_DECODE_ERROR;
  uchar const * list = (uchar const *)wire_laddr;
  for( ulong off=0UL; off<wire_sz; ) {
    ulong len = list[ off++ ];
    if( FD_UNLIKELY( !len || len>wire_sz-off ) ) return -FD_TLS_ALERT_DECODE_ERROR;
    off += len;
  }
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

static long
fd_tls_extract_cert_pubkey_( fd_tls_extract_cert_pubkey_res_t * res,
                             uchar const * cert_chain,
                             ulong         cert_chain_sz ) {

  fd_memset( res, 0, sizeof(fd_tls_extract_cert_pubkey_res_t) );

  ulong wire_laddr = (ulong)cert_chain;
  ulong wire_sz    = cert_chain_sz;

  /* Initial-handshake Certificate messages always have empty context. */
  uchar const * opaque_sz = FD_TLS_SKIP_FIELD( uchar );
  if( FD_UNLIKELY( *opaque_sz ) ) return -FD_TLS_ALERT_ILLEGAL_PARAMETER;

  /* Get first entry of certificate chain
     CertificateEntry certificate_list<0..2^24-1> */
  fd_tls_u24_t const * cert_list_sz_be = FD_TLS_SKIP_FIELD( fd_tls_u24_t );
  fd_tls_u24_t         cert_list_sz_   = fd_tls_u24_bswap( *cert_list_sz_be );
  uint                 cert_list_sz    = fd_tls_u24_to_uint( cert_list_sz_ );
  if( FD_UNLIKELY( cert_list_sz!=wire_sz ) ) return -FD_TLS_ALERT_DECODE_ERROR;
  if( FD_UNLIKELY( cert_list_sz==0U ) ) {
    res->alert  = FD_TLS_ALERT_BAD_CERTIFICATE;
    res->reason = FD_TLS_REASON_CERT_CHAIN_EMPTY;
    return -1L;
  }

  /* Validate every entry before extracting the leaf key, independently
     of whether the caller requests X.509 chain authentication. */
  uchar const * cert    = NULL;
  ulong         cert_sz = 0UL;
  while( wire_sz ) {
    fd_tls_u24_t const * sz_be = FD_TLS_SKIP_FIELD( fd_tls_u24_t );
    ulong sz = fd_tls_u24_to_uint( fd_tls_u24_bswap( *sz_be ) );
    if( FD_UNLIKELY( !sz || sz>wire_sz ) ) return -FD_TLS_ALERT_DECODE_ERROR;
    if( !cert ) {
      cert    = (uchar const *)wire_laddr;
      cert_sz = sz;
    }
    wire_laddr += sz;
    wire_sz    -= sz;
    /* We never solicit CertificateEntry extensions (RFC 8446 Section
       4.4.2), so the extensions vector must be empty */
    ushort const * ext_sz_be = FD_TLS_SKIP_FIELD( ushort );
    ulong          ext_sz    = fd_ushort_bswap( *ext_sz_be );
    if( FD_UNLIKELY( ext_sz > wire_sz ) ) return -(long)FD_TLS_ALERT_DECODE_ERROR;
    if( FD_UNLIKELY( ext_sz ) ) return -(long)FD_TLS_ALERT_UNSUPPORTED_EXTENSION;
  }

  if( FD_UNLIKELY( fd_x509_extract_pubkey( cert, cert_sz, &res->pubkey,
                                           &res->pubkey_len, &res->key_type ) ) ) {
    res->pubkey = NULL;
    res->alert  = FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE;
    res->reason = FD_TLS_REASON_X509_PARSE;
    return -1L;
  }

  return 0L;
}

fd_tls_extract_cert_pubkey_res_t
fd_tls_extract_cert_pubkey( uchar const * cert_chain,
                            ulong         cert_chain_sz ) {
  fd_tls_extract_cert_pubkey_res_t res;
  long ret = fd_tls_extract_cert_pubkey_( &res, cert_chain, cert_chain_sz );
  if( FD_UNLIKELY( ret<0L && !res.alert ) ) {
    res.alert  = (uint)(-ret);
    res.reason = FD_TLS_REASON_CERT_PARSE;
  }
  return res;
}
