#include "fd_gui_config_parse.h"

#include "../../ballet/json/fd_jtok.h"

/* parse_field consumes the pending string value of j into out (out_sz
   bytes).  A value that is not a string, or a string whose decoded
   form does not fit, leaves out empty and does not error j. */

static void
parse_field( fd_jtok_t * j,
             char *      out,
             ulong       out_sz ) {
  out[ 0 ] = '\0';
  if( FD_UNLIKELY( fd_jtok_peek( j )!=FD_JTOK_STR ) ) return;

  char const * raw = NULL; ulong raw_sz = 0UL;
  fd_jtok_raw( j, &raw, &raw_sz );
  if( FD_UNLIKELY( !raw ) ) return;

  fd_jtok_t s[1]; fd_jtok_init( s, raw, raw_sz );
  fd_jtok_cstr( s, out, out_sz );
  if( FD_UNLIKELY( fd_jtok_fini( s ) ) ) out[ 0 ] = '\0';
}

int
fd_gui_config_parse_validator_info( uchar const *                data,
                                    ulong                        sz,
                                    fd_gui_config_parse_info_t * info ) {
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

  /* The config program only requires signatures from keys flagged
     is_signer, so an unsigned identity key could be anyone's */
  if( FD_UNLIKELY( data_config_keys[1].is_signer!=1 ) ) return 0;

  CHECK_LEFT( sizeof(ulong) ); ulong json_str_sz = FD_LOAD( ulong, data+i ); i += sizeof(ulong);

  CHECK_LEFT( json_str_sz );

#undef CHECK
#undef CHECK_LEFT

  info->name            [ 0 ] = '\0';
  info->website         [ 0 ] = '\0';
  info->details         [ 0 ] = '\0';
  info->icon_uri        [ 0 ] = '\0';
  info->keybase_username[ 0 ] = '\0';

  fd_jtok_t j[1]; fd_jtok_init( j, data+i, json_str_sz );
  fd_jtok_str_t key;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    if(      fd_jtok_str_eq( &key, "name"            ) ) parse_field( j, info->name,             sizeof(info->name)             );
    else if( fd_jtok_str_eq( &key, "website"         ) ) parse_field( j, info->website,          sizeof(info->website)          );
    else if( fd_jtok_str_eq( &key, "details"         ) ) parse_field( j, info->details,          sizeof(info->details)          );
    else if( fd_jtok_str_eq( &key, "iconUrl"         ) ) parse_field( j, info->icon_uri,         sizeof(info->icon_uri)         );
    else if( fd_jtok_str_eq( &key, "keybaseUsername" ) ) parse_field( j, info->keybase_username, sizeof(info->keybase_username) );
  }
  if( FD_UNLIKELY( fd_jtok_fini( j ) ) ) return 0;

  fd_memcpy( info->pubkey.uc, data_config_keys[1].pubkey.uc, sizeof(fd_pubkey_t) );
  return 1;
}
