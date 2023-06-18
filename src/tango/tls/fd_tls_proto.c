#include "fd_tls_proto.h"
#include "fd_tls_serde.h"

long
fd_tls_decode_record_hdr( fd_tls_record_hdr_t * out,
                          void const *          wire,
                          ulong                 wire_sz ) {

  if( FD_UNLIKELY( wire_sz<4UL ) )
    return -(long)FD_TLS_ALERT_DECODE_ERROR;

  uchar raw[ 4 ]; memcpy( raw, wire, 4UL );
  out->type = raw[0];
  out->sz   = 0xFFFFFFU &
            ( ( ((uint)raw[1])<<16 )
            + ( ((uint)raw[2])<< 8 )
            + (  (uint)raw[3]      ) );
  return 4L;
}

long
fd_tls_encode_record_hdr( fd_tls_record_hdr_t const * in,
                          void *                      wire,
                          ulong                       wire_sz ) {

  if( FD_UNLIKELY( wire_sz<4UL ) )
    return -(long)FD_TLS_ALERT_INTERNAL_ERROR;

  uchar raw[ 4 ] = { in->type,
                     (uchar)( in->sz >> 16 ),
                     (uchar)( in->sz >>  8 ),
                     (uchar)( in->sz       ) };
  memcpy( wire, raw, 4UL );
  return 4L;
}

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
      ext_parse_res = fd_tls_decode_ext_key_share_client( &out->key_share, ext_data, wire_sz );
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
fd_tls_encode_server_hello( fd_tls_server_hello_t * out,
                            void *                  wire,
                            ulong                   wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  /* Encode static sized part of server hello.
     (Assuming that session ID field is of a certain size) */

  ushort legacy_version       = FD_TLS_VERSION_TLS12;
  uchar  legacy_session_id_sz = 0;
  ushort cipher_suites_sz     = sizeof(ushort);
  ushort cipher_suites[1]     = { FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 };

# define FIELDS( FIELD )                            \
    FIELD( 0, &legacy_version,       ushort, 1    ) \
    FIELD( 1, &out->random[0],       uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz, uchar,  1    ) \
    FIELD( 3, &cipher_suites_sz,     ushort, 1    ) \
    FIELD( 4, cipher_suites,         ushort, 1    )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

  /* Encode extensions */

  ushort * extension_tot_sz = FD_TLS_SKIP_FIELD( ushort );
  ulong    extension_start  = wire_laddr;

# define FIELDS( FIELD )                            \
    FIELD( 0, &legacy_version,       ushort, 1    ) \
    FIELD( 1, &out->random[0],       uchar,  32UL ) \
    FIELD( 2, &legacy_session_id_sz, uchar,  1    ) \
    FIELD( 3, &cipher_suites_sz,     ushort, 1    ) \
    FIELD( 4, cipher_suites,         ushort, 1    )
    FD_TLS_ENCODE_STATIC_BATCH( FIELDS )
# undef FIELDS

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
    FIELD( 2, ext_supported_versions,             ushort, 1    ) \
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
    /* Add more groups here */
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

static long
fd_tls_decode_key_share_entry( fd_tls_ext_key_share_t * out,
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
fd_tls_decode_ext_key_share_client( fd_tls_ext_key_share_t * out,
                                    void const *             wire,
                                    ulong                    wire_sz ) {

  ulong wire_laddr = (ulong)wire;

  FD_TLS_DECODE_LIST_BEGIN( ushort, alignof(uchar) ) {
    long res = fd_tls_decode_key_share_entry( out, (void const *)wire_laddr, wire_sz );
    if( FD_UNLIKELY( res<0L ) )
      return res;
    wire_laddr += (ulong)res;
    wire_sz    -= (ulong)res;
  }
  FD_TLS_DECODE_LIST_END

  return (long)( wire_laddr - (ulong)wire );
}

