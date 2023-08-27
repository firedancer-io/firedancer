#include "fd_tls_proto.h"
#include "fd_tls_serde.h"

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
                            void const * const      wire,
                            ulong                   wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Decode static sized part of client hello.
     (Assuming that session ID field is of a certain size) */

  ushort cipher_suites_sz;     /* size occupied by cipher suite list */
  ushort legacy_version;       /* ==FD_TLS_VERSION_TLS12 */
  uchar  legacy_session_id_sz; /* ==0 */

# define FIELDS( FIELD )                            \
    FIELD( 0, &legacy_version,       ushort, 1    ) \
    FIELD( 1, &out->random[0],       uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz, uchar,  1    ) \
    FIELD( 3, &cipher_suites_sz,     ushort, 1    )
    FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( FD_UNLIKELY( legacy_session_id_sz != 0 ) )
    return -(long)FD_TLS_ALERT_PROTOCOL_VERSION;

  /* Decode cipher suite list */

  if( FD_UNLIKELY( ( !fd_uint_is_aligned( cipher_suites_sz, 2U ) )
                 | ( cipher_suites_sz > wire_sz                  ) ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  while( cipher_suites_sz > 0 ) {
    ushort cipher_suite;
    FD_TLS_DECODE_FIELD( &cipher_suite, ushort );
    cipher_suites_sz = (ushort)( cipher_suites_sz - sizeof(ushort) );

    switch( cipher_suite ) {
    case FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
      out->cipher_suites.aes_128_gcm_sha256 = 1;
      break;
    /* Add more cipher suites here */
    }
  }

  /* Decode next static sized part of client hello */

  ushort extension_tot_sz;  /* size occupied by extensions */
  uchar  legacy_compression_method_cnt;    /* == 1  */
  uchar  legacy_compression_methods[ 1 ];  /* =={0} */

# define FIELDS( FIELD )                                  \
    FIELD( 5, &legacy_compression_method_cnt, uchar,  1 ) \
    FIELD( 6, &legacy_compression_methods[0], uchar,  1 ) \
    FIELD( 7, &extension_tot_sz,              ushort, 1 )
    FD_TLS_DECODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  if( FD_UNLIKELY( legacy_compression_method_cnt != 1 ) )
    return -(long)FD_TLS_ALERT_PROTOCOL_VERSION;

  /* Byte range occupied by extensions */

  if( FD_UNLIKELY( extension_tot_sz > wire_sz ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  ulong ext_start = wire_laddr;
  ulong ext_stop  = ext_start + extension_tot_sz;

  /* Read extensions */

  while( wire_laddr < ext_stop ) {
    /* Read extension type and length */
    ushort ext_type;
    ushort ext_sz;
#   define FIELDS( FIELD )             \
      FIELD( 0, &ext_type, ushort, 1 ) \
      FIELD( 1, &ext_sz,   ushort, 1 )
      FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#   undef FIELDS

    /* Bounds check extension data */
    if( FD_UNLIKELY( (ext_stop - wire_laddr) < ext_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    /* Decode extension data */
    void const * ext_data = (void const *)wire_laddr;
    long ext_parse_res;
    switch( ext_type ) {
    case FD_TLS_EXT_SUPPORTED_VERSIONS:
      ext_parse_res = fd_tls_decode_ext_supported_versions( &out->supported_versions, ext_data, wire_sz );
      break;
    case FD_TLS_EXT_TYPE_SERVER_NAME:
      ext_parse_res = fd_tls_decode_ext_server_name( &out->server_name, ext_data, wire_sz );
      break;
    case FD_TLS_EXT_TYPE_SUPPORTED_GROUPS:
      ext_parse_res = fd_tls_decode_ext_supported_groups( &out->supported_groups, ext_data, wire_sz );
      break;
    case FD_TLS_EXT_SIGNATURE_ALGORITHMS:
      ext_parse_res = fd_tls_decode_ext_signature_algorithms( &out->signature_algorithms, ext_data, wire_sz );
      break;
    case FD_TLS_EXT_KEY_SHARE:
      ext_parse_res = fd_tls_decode_key_share_list( &out->key_share, ext_data, wire_sz );
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

  /* Assert: wire_laddr == ext_stop */

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_client_hello( fd_tls_client_hello_t * in,
                            void *                  wire,
                            ulong                   wire_sz ) {

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

  ushort ext_supported_groups_ext_type = FD_TLS_EXT_TYPE_SUPPORTED_GROUPS;
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

  *extension_tot_sz = fd_ushort_bswap( (ushort)( (ulong)wire_laddr - extension_start ) );
  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_server_hello( fd_tls_server_hello_t * out,
                            void const *            wire,
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

  fd_tls_ext_supported_versions_t versions = {0};

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
    void const * ext_data = (void const *)wire_laddr;
    long ext_parse_res;
    switch( ext_type ) {
    case FD_TLS_EXT_SUPPORTED_VERSIONS:
      ext_parse_res = fd_tls_decode_ext_supported_versions( &versions, ext_data, wire_sz );
      break;
    case FD_TLS_EXT_KEY_SHARE:
      ext_parse_res = fd_tls_decode_key_share( &out->key_share, ext_data, wire_sz );
      break;
    default:
      /* Reject unsolicited extensions */
      return -(long)FD_TLS_ALERT_ILLEGAL_PARAMETER;
    }

    if( FD_UNLIKELY( ext_parse_res<0L ) )
      return ext_parse_res;
    if( FD_UNLIKELY( ext_parse_res != (long)ext_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;
  }
  FD_TLS_DECODE_LIST_END

  /* Check for required extensions */

  if( FD_UNLIKELY( !versions.tls13 ) )
    return -(long)FD_TLS_ALERT_PROTOCOL_VERSION;
  if( FD_UNLIKELY( !out->key_share.has_x25519 ) )
    return -(long)FD_TLS_ALERT_MISSING_EXTENSION;

  return 0L;
}

long
fd_tls_encode_server_hello( fd_tls_server_hello_t * out,
                            void *                  wire,
                            ulong                   wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Encode static sized part of server hello.
     (Assuming that session ID field is of a certain size) */

  ushort legacy_version            = FD_TLS_VERSION_TLS12;
  uchar  legacy_session_id_sz      = 0;
  ushort cipher_suite              = FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
  uchar  legacy_compression_method = 0;

# define FIELDS( FIELD )                                 \
    FIELD( 0, &legacy_version,            ushort, 1    ) \
    FIELD( 1, &out->random[0],            uchar,  32UL ) \
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
    FIELD( 7, &out->key_share.x25519[0],          uchar,  32UL )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  *extension_tot_sz = fd_ushort_bswap( (ushort)( (ulong)wire_laddr - extension_start ) );
  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_server_cert_x509( void const * x509,
                                ulong        x509_sz,
                                void *       wire,
                                ulong        wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* TLS Record Header */
  uchar record_type = (uchar)FD_TLS_RECORD_CERT;

  /* TLS Certificate Message header preceding X.509 data */

  /* All size prefixes known in advance */
  fd_tls_u24_t record_sz    = fd_uint_to_tls_u24( (uint)( x509_sz + 9UL ) );
  fd_tls_u24_t cert_list_sz = fd_uint_to_tls_u24( (uint)( x509_sz + 5UL ) );
  fd_tls_u24_t cert_sz      = fd_uint_to_tls_u24( (uint)( x509_sz       ) );

  /* zero sz certificate_request_context
     (Server certificate never has a request context) */
  uchar certificate_request_context_sz = (uchar)0;

  /* TODO Ugly: Type cast required to make macro happy, though no
          actual writes take place. */
  uchar * _x509 = (uchar *)x509;

  /* No certificate extensions */
  ushort ext_sz = (ushort)0;

  /* TODO Should use fd_memcpy() instead of memcpy() _x509 */
# define FIELDS( FIELD )                                            \
    FIELD( 0, &record_type,                      uchar,   1       ) \
    FIELD( 1, &record_sz,                        tls_u24, 1       ) \
      FIELD( 2, &certificate_request_context_sz, uchar,   1       ) \
      FIELD( 3, &cert_list_sz,                   tls_u24, 1       ) \
        FIELD( 4, &cert_sz,                      tls_u24, 1       ) \
        FIELD( 5, _x509,                         uchar,   x509_sz ) \
        FIELD( 6, &ext_sz,                       ushort,  1       )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_server_name( fd_tls_ext_server_name_t * out,
                               void const *               wire,
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
    if( FD_UNLIKELY( list_stop - wire_laddr < name_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    /* Decode name on first use */
    if( ( ( name_type == FD_TLS_SERVER_NAME_TYPE_DNS )
        & ( name_sz < 254                            )
        & ( out->host_name_len == 0                  ) ) ) {
      out->host_name_len = (uchar)name_sz;
      memcpy( out->host_name, (void const *)wire_laddr, name_sz );
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
                                    void const *                    wire,
                                    ulong                           wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_GROUP_X25519:
      out->x25519 = 1;
      break;
    /* Add more groups here */
    }
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_supported_versions( fd_tls_ext_supported_versions_t * out,
                                      void const *                      wire,
                                      ulong                             wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( uchar, alignof(ushort) ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_VERSION_TLS13:
      out->tls13 = 1;
      break;
    /* Add more versions here */
    }
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_signature_algorithms( fd_tls_ext_signature_algorithms_t * out,
                                        void const *                        wire,
                                        ulong                               wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(ushort) ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_SIGNATURE_ED25519:
      out->ed25519 = 1;
      break;
    /* Add more groups here */
    }
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_key_share( fd_tls_key_share_t * out,
                               void const *             wire,
                               ulong                    wire_sz ) {

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
    memcpy( out->x25519, (void const *)wire_laddr, 32UL );
    break;
  /* Add more groups here */
  }

  /* Seek to next group */
  wire_laddr += kex_data_sz;
  wire_sz    -= kex_data_sz;

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_key_share_list( fd_tls_key_share_t * out,
                                    void const *             wire,
                                    ulong                    wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    FD_TLS_DECODE_SUB( fd_tls_decode_key_share, out );
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_decode_ext_cert_type_list( fd_tls_ext_cert_type_list_t * out,
                                  void const *                  wire,
                                  ulong                         wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( uchar, alignof(uchar) ) {
    uchar cert_type;
    FD_TLS_DECODE_FIELD( &cert_type, uchar );  /* is this really a uchar? */
    switch( cert_type ) {
    case FD_TLS_CERTTYPE_X509:       out->x509 = 1;       break;
    case FD_TLS_CERTTYPE_RAW_PUBKEY: out->raw_pubkey = 1; break;
    /* Add more cert types here */
    }
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_ext_cert_type_list( fd_tls_ext_cert_type_list_t in,
                                  void const *                wire,
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
                              void const *            wire,
                              ulong                   wire_sz ) {
  ulong wire_laddr = (ulong)wire;
  FD_TLS_DECODE_FIELD( &out->cert_type, uchar );
  return (long)( wire_laddr - (ulong)wire );
}

long
fd_tls_encode_ext_cert_type( fd_tls_ext_cert_type_t in,
                             void const *           wire,
                             ulong                  wire_sz ) {
  ulong wire_laddr = (ulong)wire;
  FD_TLS_ENCODE_FIELD( &in.cert_type, uchar );
  return (long)( wire_laddr - (ulong)wire );
}
