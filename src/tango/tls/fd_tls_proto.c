#include "fd_tls_proto.h"
#include "fd_tls_serde.h"

long
fd_tls_decode_client_hello( fd_tls_client_hello_t * out,
                            void const *            wire,
                            ulong                   wire_sz ) {

  void const * const wire_start = wire;

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

  void const * const ext_start = wire;
  void const * const ext_stop  = (void const *)( (ulong)ext_start + extension_tot_sz );

  /* Read extensions */

  while( wire < ext_stop ) {
    /* Read extension type and length */
    ushort ext_type;
    ushort ext_sz;
#   define FIELDS( FIELD )             \
      FIELD( 0, &ext_type, ushort, 1 ) \
      FIELD( 6, &ext_sz,   ushort, 1 )
      FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#   undef FIELDS

    /* Bounds check extension data */
    if( FD_UNLIKELY( ((ulong)ext_stop - (ulong)wire) < ext_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    /* Decode extension data */
    long ext_parse_res;
    switch( ext_type ) {
    case FD_TLS_EXT_SUPPORTED_VERSIONS:
      ext_parse_res = fd_tls_decode_ext_supported_versions( &out->supported_versions, wire, wire_sz );
      break;
    case FD_TLS_EXT_TYPE_SERVER_NAME:
      ext_parse_res = fd_tls_decode_ext_server_name( &out->server_name, wire, wire_sz );
      break;
    case FD_TLS_EXT_TYPE_SUPPORTED_GROUPS:
      ext_parse_res = fd_tls_decode_ext_supported_groups( &out->supported_groups, wire, wire_sz );
      break;
    case FD_TLS_EXT_SIGNATURE_ALGORITHMS:
      ext_parse_res = fd_tls_decode_ext_signature_algorithms( &out->signature_algorithms, wire, wire_sz );
      break;
    case FD_TLS_EXT_KEY_SHARE:
      ext_parse_res = fd_tls_decode_ext_key_share( &out->key_share, wire, wire_sz );
      break;
    default:
      ext_parse_res = (long)ext_sz;
      break;
    }
    if( FD_UNLIKELY( ext_parse_res<0L ) )
      return ext_parse_res;
    if( FD_UNLIKELY( ext_parse_res != (long)ext_sz ) )
      return FD_TLS_ALERT_DECODE_ERROR;

    /* Seek to next extension */
    wire    = (void const *)( (ulong)wire + ext_sz );
    wire_sz = wire_sz - ext_sz;
  }

  /* Assert: wire == ext_stop */

  return (long)( (ulong)wire - (ulong)wire_start );
}

long
fd_tls_decode_ext_server_name( fd_tls_ext_server_name_t * out,
                               void const *               wire,
                               ulong                      wire_sz ) {

  void const * const wire_start = wire;

  /* Get size of server names list.
     TLS v1.3 server name lists practically always have one element. */

  ushort server_name_list_sz;
  FD_TLS_DECODE_FIELD( &server_name_list_sz, ushort );

  void const * const list_start = wire;
  void const * const list_stop  = (void const *)( (ulong)list_start + server_name_list_sz );

  while( wire < list_stop ) {
    /* Read type and length */
    uchar  name_type;
    ushort name_sz;
#   define FIELDS( FIELD )              \
      FIELD( 0, &name_type, uchar,  1 ) \
      FIELD( 1, &name_sz,   ushort, 1 )
      FD_TLS_DECODE_STATIC_BATCH( FIELDS )
#   undef FIELDS

    /* Bounds check name */
    if( FD_UNLIKELY( ( (ulong)list_stop - (ulong)wire ) < name_sz ) )
      return -(long)FD_TLS_ALERT_DECODE_ERROR;

    /* Decode name on first use */
    if( ( ( name_type == FD_TLS_SERVER_NAME_TYPE_DNS )
        & ( name_sz < 254                            )
        & ( out->host_name_len == 0                  ) ) ) {
      out->host_name_len = (uchar)name_sz;
      memcpy( out->host_name, wire, name_sz );
      out->host_name[ name_sz ] = '\0';
    }

    /* Seek to next name */
    wire    = (void const *)( (ulong)wire + name_sz );
    wire_sz = wire_sz - name_sz;
  }

  /* Assert: wire == list_stop */

  return (long)( (ulong)wire - (ulong)wire_start );
}

long
fd_tls_decode_ext_supported_groups( fd_tls_ext_supported_groups_t * out,
                                    void const *                    wire,
                                    ulong                           wire_sz ) {

  void const * const wire_start = wire;

  ushort list_sz;
  FD_TLS_DECODE_FIELD( &list_sz, ushort );

  void const * const list_start = wire;
  void const * const list_stop  = (void const *)( (ulong)list_start + list_sz );

  if( FD_UNLIKELY( ( list_sz > wire_sz )
                 | ( !fd_uint_is_aligned( list_sz, 2U ) ) ) )
    return FD_TLS_ALERT_DECODE_ERROR;

  while( wire < list_stop ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_GROUP_X25519:
      out->x25519 = 1;
      break;
    /* Add more groups here */
    }
  }

  /* Assert: wire == list_stop */

  return (long)( (ulong)wire - (ulong)wire_start );
}

long
fd_tls_decode_ext_supported_versions( fd_tls_ext_supported_versions_t * out,
                                      void const *                      wire,
                                      ulong                             wire_sz ) {

  void const * const wire_start = wire;

  uchar list_sz;
  FD_TLS_DECODE_FIELD( &list_sz, uchar );

  void const * const list_start = wire;
  void const * const list_stop  = (void const *)( (ulong)list_start + list_sz );

  if( FD_UNLIKELY( ( list_sz > wire_sz )
                 | ( !fd_uint_is_aligned( list_sz, 2U ) ) ) )
    return FD_TLS_ALERT_DECODE_ERROR;

  while( wire < list_stop ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_VERSION_TLS13:
      out->tls13 = 1;
      break;
    /* Add more groups here */
    }
  }

  /* Assert: wire == list_stop */

  return (long)( (ulong)wire - (ulong)wire_start );
}

long
fd_tls_decode_ext_signature_algorithms( fd_tls_ext_signature_algorithms_t * out,
                                        void const *                        wire,
                                        ulong                               wire_sz ) {

  void const * const wire_start = wire;

  ushort list_sz;
  FD_TLS_DECODE_FIELD( &list_sz, ushort );

  void const * const list_start = wire;
  void const * const list_stop  = (void const *)( (ulong)list_start + list_sz );

  if( FD_UNLIKELY( ( list_sz > wire_sz )
                 | ( !fd_uint_is_aligned( list_sz, 2U ) ) ) )
    return FD_TLS_ALERT_DECODE_ERROR;

  while( wire < list_stop ) {
    ushort group;
    FD_TLS_DECODE_FIELD( &group, ushort );
    switch( group ) {
    case FD_TLS_SIGNATURE_ED25519:
      out->ed25519 = 1;
      break;
    /* Add more groups here */
    }
  }

  /* Assert: wire == list_stop */

  return (long)( (ulong)wire - (ulong)wire_start );
}

static long
fd_tls_decode_ext_key_share_entry( fd_tls_ext_key_share_t * out,
                                   void const *             wire,
                                   ulong                    wire_sz ) {

  void const * const wire_start = wire;

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
    memcpy( out->x25519, wire, 32UL );
    break;
  /* Add more groups here */
  }

  /* Seek to next group */
  wire     = (void const *)( (ulong)wire + kex_data_sz );
  wire_sz -= kex_data_sz;

  return (long)( (ulong)wire - (ulong)wire_start );
}

long
fd_tls_decode_ext_key_share( fd_tls_ext_key_share_t * out,
                             void const *             wire,
                             ulong                    wire_sz ) {

  void const * const wire_start = wire;

  ushort list_sz;
  FD_TLS_DECODE_FIELD( &list_sz, ushort );

  void const * const list_start = wire;
  void const * const list_stop  = (void const *)( (ulong)list_start + list_sz );

  if( FD_UNLIKELY( ( list_sz > wire_sz )
                 | ( !fd_uint_is_aligned( list_sz, 2U ) ) ) )
    return FD_TLS_ALERT_DECODE_ERROR;

  while( wire < list_stop ) {
    long res = fd_tls_decode_ext_key_share_entry( out, wire, wire_sz );
    if( FD_UNLIKELY( res<0L ) )
      return res;
    wire     = (void const *)( (ulong)wire + (ulong)res );
    wire_sz -= (ulong)res;
  }

  /* Assert: wire == list_stop */

  return (long)( (ulong)wire - (ulong)wire_start );
}

