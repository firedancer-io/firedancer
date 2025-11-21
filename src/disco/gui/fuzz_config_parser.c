#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_gui_config_parse.h"

#include "../../ballet/utf8/fd_utf8.h"
#include "../../util/fd_util.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  putenv( "FD_LOG_PATH=" );
  fd_boot( argc, argv );
  fd_log_level_core_set(0); /* crash on debug log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  cJSON * json;
  fd_gui_config_parse_info_t validator_info[1];
  fd_pubkey_t pubkey;
  int valid = fd_gui_config_parse_validator_info_check( data, size, &json, &pubkey );

  if( valid ) {
    fd_gui_config_parse_validator_info( json, validator_info );

    assert( fd_utf8_verify( validator_info->name,             strlen( validator_info->name )             ) );
    assert( fd_utf8_verify( validator_info->website,          strlen( validator_info->website )          ) );
    assert( fd_utf8_verify( validator_info->details,          strlen( validator_info->details )          ) );
    assert( fd_utf8_verify( validator_info->icon_uri,         strlen( validator_info->icon_uri )         ) );
    assert( fd_utf8_verify( validator_info->keybase_username, strlen( validator_info->keybase_username ) ) );
  }
  return 0;
}
