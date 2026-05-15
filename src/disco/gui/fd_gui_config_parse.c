#include "fd_gui_config_parse.h"

#include "../../ballet/utf8/fd_utf8.h"

int
fd_gui_config_parse_validator_info_check( uchar const * data,
                                          ulong         sz,
                                          yyjson_doc ** out_json,
                                          fd_pubkey_t * out_pubkey,
                                          void *        scratch,
                                          ulong         scratch_max ) {
  /*
    pub struct ConfigKeys {
        #[cfg_attr(feature = "serde", serde(with = "short_vec"))]
        pub keys: Vec<(Pubkey, bool)>,
    }

    The memory layout of a ConfigProgram account is a bincode serialized
    ConfigKeys followed immediately by a stringified json object
    containing the desired info.

    The short_vec serialization format is a 1-3 bytes size field (where
    the highest bit in a given byte is a continuation bit) followed by
    serialized elements in the vector (in this case, each element is a
    32byte pubkey followed by a 1byte bool. For our simple parser, we
    only need to consider vectors smaller than 128 elements.

    The JSON schema for a validator info object is the following

    {
      "name": "<validator name>",
      "website": "<website url>",
      "details": "<validator details>",
      "iconUrl": "<icon url>"
    }

    Since validator info JSON strings are bounded by
    FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_MAX_SZ, we can parse with a small
    caller-provided yyjson bump allocator.
*/
  ulong i = 0UL;

#define CHECK( cond )  do { \
    if( FD_UNLIKELY( !(cond) ) ) { \
      return 0; \
    } \
  } while( 0 )

  /* CHECK that it is safe to read at least n more bytes assuming i is
     the current location. n is untrusted and could trigger overflow, so
     don't do i+n<=payload_sz */
#define CHECK_LEFT( n ) CHECK( (n)<=(sz-i) )

  CHECK_LEFT( 1UL ); uchar ck_sz = FD_LOAD( uchar, data+i ); i++;
  if( FD_UNLIKELY( ck_sz!=2 ) ) return 0;

  struct __attribute__((packed, aligned(1))) config_keys {
    fd_pubkey_t pubkey;
    uchar       is_signer;
  };

  struct config_keys * data_config_keys = (struct config_keys *)(data + i);
  CHECK_LEFT( (sizeof(fd_pubkey_t) + 1UL)*ck_sz ); i += (sizeof(fd_pubkey_t) + 1UL)*ck_sz;
  CHECK_LEFT( FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_MAX_SZ );

  /* First entry should be Va1idator1nfo111111111111111111111111111111 */
  uchar expected[ 32UL ] = { 0x07, 0x51, 0x97, 0x01, 0x74, 0x48, 0xf2, 0xac, 0x5d, 0xc2, 0x3c, 0x9e, 0xbc, 0x7a, 0xc7, 0x8c, 0x0a, 0x27, 0x25, 0x7a, 0xc6, 0x14, 0x45, 0x8d, 0xe0, 0xa4, 0xf1, 0x6f, 0x80, 0x00, 0x00, 0x00 };
  if( FD_UNLIKELY( memcmp( data_config_keys[0].pubkey.uc, expected, sizeof(fd_pubkey_t) ) || data_config_keys[0].is_signer ) ) return 0;

  CHECK_LEFT( sizeof(ulong) ); ulong json_str_sz = FD_LOAD( ulong, data+i ); i += sizeof(ulong);

  CHECK_LEFT( json_str_sz );
  yyjson_alc alloc[1];
  CHECK( yyjson_alc_pool_init( alloc, scratch, scratch_max ) );

  yyjson_doc * json = yyjson_read_opts( (char *)(data+i), json_str_sz, YYJSON_READ_NOFLAG, alloc, NULL );
  if( FD_UNLIKELY( !json ) ) return 0;

#undef CHECK
#undef CHECK_LEFT

  *out_json = json;
  fd_memcpy( out_pubkey->uc, data_config_keys[1].pubkey.uc, sizeof(fd_pubkey_t) );
  return 1;
}

static void
fd_gui_config_parse_validator_info_str( yyjson_val const * obj,
                                        char const *       key,
                                        char *             out,
                                        ulong              out_max ) {
  yyjson_val const * val = yyjson_obj_get( obj, key );
  char const * str = yyjson_get_str( val );
  ulong str_len = yyjson_get_len( val );

  int missing = !str
             || str_len>out_max
             || memchr( str, '\0', str_len )
             || !fd_utf8_verify( str, str_len );
  if( FD_UNLIKELY( missing ) ) {
    out[ 0 ] = '\0';
    return;
  }

  if( FD_LIKELY( str_len ) ) fd_memcpy( out, str, str_len );
  out[ str_len ] = '\0';
}

void
fd_gui_config_parse_validator_info( yyjson_doc * json, fd_gui_config_parse_info_t * node_info ) {
  yyjson_val const * root = yyjson_doc_get_root( json );

  fd_gui_config_parse_validator_info_str( root, "name",            node_info->name,             FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_NAME_SZ             );
  fd_gui_config_parse_validator_info_str( root, "website",         node_info->website,          FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_WEBSITE_SZ          );
  fd_gui_config_parse_validator_info_str( root, "details",         node_info->details,          FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_DETAILS_SZ          );
  fd_gui_config_parse_validator_info_str( root, "iconUrl",         node_info->icon_uri,         FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_ICON_URI_SZ         );
  fd_gui_config_parse_validator_info_str( root, "keybaseUsername", node_info->keybase_username, FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_KEYBASE_USERNAME_SZ );
}
