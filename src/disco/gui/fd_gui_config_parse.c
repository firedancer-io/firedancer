#include "fd_gui_config_parse.h"

#include "../../ballet/utf8/fd_utf8.h"

int
fd_gui_config_parse_validator_info_check( uchar const * data,
                                          ulong         sz,
                                          cJSON **      out_json,
                                          fd_pubkey_t * out_pubkey ) {
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

    Since accounts are at most 10MB, we should be safely within cJSON's
    allocator limits.
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

  CHECK_LEFT( json_str_sz+1UL ); /* cJSON_ParseWithLengthOpts requires having byte after the JSON payload */
  cJSON * json = cJSON_ParseWithLengthOpts( (char *)(data+i), json_str_sz, NULL, 0 );
  if( FD_UNLIKELY( !json ) ) return 0;

#undef CHECK
#undef CHECK_LEFT

  *out_json = json;
  fd_memcpy( out_pubkey->uc, data_config_keys[1].pubkey.uc, sizeof(fd_pubkey_t) );
  return 1;
}

void
fd_gui_config_parse_validator_info( cJSON * json, fd_gui_config_parse_info_t * node_info ) {
  const cJSON * name = cJSON_GetObjectItemCaseSensitive( json, "name" );
  /* cJSON guarantees name->valuestring is NULL terminated */
  int missing_name = !cJSON_IsString( name )
                  || strlen(name->valuestring)>FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_NAME_SZ
                  || !fd_cstr_printf_check( node_info->name, strlen(name->valuestring)+1UL, NULL, "%s", name->valuestring )
                  || !fd_utf8_verify( node_info->name, strlen(node_info->name) );
  if( FD_UNLIKELY( missing_name ) ) node_info->name[ 0 ] = '\0';

  const cJSON * website = cJSON_GetObjectItemCaseSensitive( json, "website" );
  int missing_website = !cJSON_IsString( website )
                     || strlen(website->valuestring)>FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_WEBSITE_SZ
                     || !fd_cstr_printf_check( node_info->website, strlen(website->valuestring)+1UL, NULL, "%s", website->valuestring )
                     || !fd_utf8_verify( node_info->website, strlen(node_info->website) );
  if( FD_UNLIKELY( missing_website ) ) node_info->website[ 0 ] = '\0';

  const cJSON * details = cJSON_GetObjectItemCaseSensitive( json, "details" );
  int missing_details = !cJSON_IsString( details )
                     || strlen(details->valuestring)>FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_DETAILS_SZ
                     || !fd_cstr_printf_check( node_info->details, strlen(details->valuestring)+1UL, NULL, "%s", details->valuestring )
                     || !fd_utf8_verify( node_info->details, strlen(node_info->details) );
  if( FD_UNLIKELY( missing_details ) ) node_info->details[ 0 ] = '\0';

  const cJSON * icon_uri = cJSON_GetObjectItemCaseSensitive( json, "iconUrl" );
  int missing_icon_uri = !cJSON_IsString( icon_uri )
                      || strlen(icon_uri->valuestring)>FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_ICON_URI_SZ
                      || !fd_cstr_printf_check( node_info->icon_uri, strlen(icon_uri->valuestring)+1UL, NULL, "%s", icon_uri->valuestring )
                      || !fd_utf8_verify( node_info->icon_uri, strlen(node_info->icon_uri) );
  if( FD_UNLIKELY( missing_icon_uri ) ) node_info->icon_uri[ 0 ] = '\0';

  const cJSON * keybase_username = cJSON_GetObjectItemCaseSensitive( json, "keybaseUsername" );
  int missing_keybase_username = !cJSON_IsString( keybase_username )
                      || strlen(keybase_username->valuestring)>FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_KEYBASE_USERNAME_SZ
                      || !fd_cstr_printf_check( node_info->keybase_username, strlen(keybase_username->valuestring)+1UL, NULL, "%s", keybase_username->valuestring )
                      || !fd_utf8_verify( node_info->keybase_username, strlen(node_info->keybase_username) );
  if( FD_UNLIKELY( missing_keybase_username ) ) node_info->keybase_username[ 0 ] = '\0';

  cJSON_Delete( json );
}
