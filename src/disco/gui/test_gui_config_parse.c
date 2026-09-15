#include "fd_gui_config_parse.h"

#include "../../util/fd_util.h"

/* Builds a ConfigProgram account: ConfigKeys of length 2 with the
   Va1idator1nfo key first and the identity second, then the bincode
   length-prefixed JSON.  Returns the account size. */

static ulong
build_account( uchar *      out,
               ulong        out_sz,
               uchar        identity_is_signer,
               char const * json ) {
  static uchar const validator_info_key[ 32UL ] = { 0x07, 0x51, 0x97, 0x01, 0x74, 0x48, 0xf2, 0xac, 0x5d, 0xc2, 0x3c, 0x9e, 0xbc, 0x7a, 0xc7, 0x8c, 0x0a, 0x27, 0x25, 0x7a, 0xc6, 0x14, 0x45, 0x8d, 0xe0, 0xa4, 0xf1, 0x6f, 0x80, 0x00, 0x00, 0x00 };
  ulong json_sz = strlen( json );
  memset( out, 0, out_sz );
  ulong i = 0UL;
  out[ i++ ] = 2;
  memcpy( out+i, validator_info_key, 32UL ); i += 32UL; out[ i++ ] = 0;
  memset( out+i, 0x42, 32UL );              i += 32UL; out[ i++ ] = identity_is_signer;
  FD_STORE( ulong, out+i, json_sz );        i += sizeof(ulong);
  memcpy( out+i, json, json_sz );           i += json_sz;
  FD_TEST( i<=out_sz );
  return out_sz;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar account[ 1024UL ];
  cJSON * json;
  fd_pubkey_t pubkey;
  fd_gui_config_parse_info_t info[1];

  /* signed identity: accepted */
  ulong sz = build_account( account, sizeof(account), 1, "{\"name\":\"alice\",\"website\":\"https://example.com\"}" );
  FD_TEST( fd_gui_config_parse_validator_info_check( account, sz, &json, &pubkey ) );
  FD_TEST( pubkey.uc[ 0 ]==0x42 && pubkey.uc[ 31 ]==0x42 );
  fd_gui_config_parse_validator_info( json, info );
  FD_TEST( !strcmp( info->name, "alice" ) );
  FD_TEST( !strcmp( info->website, "https://example.com" ) );
  FD_TEST( !info->details[ 0 ] );

  /* unsigned identity: anyone could have written it, rejected */
  sz = build_account( account, sizeof(account), 0, "{\"name\":\"spoof\"}" );
  FD_TEST( !fd_gui_config_parse_validator_info_check( account, sz, &json, &pubkey ) );

  /* malformed bool */
  sz = build_account( account, sizeof(account), 2, "{\"name\":\"spoof\"}" );
  FD_TEST( !fd_gui_config_parse_validator_info_check( account, sz, &json, &pubkey ) );

  /* malformed JSON */
  sz = build_account( account, sizeof(account), 1, "{\"name\":" );
  FD_TEST( !fd_gui_config_parse_validator_info_check( account, sz, &json, &pubkey ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
