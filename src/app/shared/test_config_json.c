#include "fd_config_json.h"

#include <string.h>

FD_IMPORT_CSTR( default_config, "src/app/firedancer/config/default.toml" );

/* the fail-closed classification must cover every string key the
   extractor accepts, a superset of the default.toml vocabulary; both
   directions are swept from source below */

FD_IMPORT_CSTR( config_parse_src, "src/app/shared/fd_config_parse.c" );
FD_IMPORT_CSTR( config_json_src,  "src/app/shared/fd_config_json.c"  );

/* extractor_cstr_keys scans src for CFG_POP*( cstr, <toml path>, ... )
   and collects the paths */

static ulong
extractor_cstr_keys( char const * src,
                     char         out[][ 64 ],
                     int *        arr,
                     ulong        max ) {
  ulong cnt = 0UL;
  for( char const * p=strstr( src, "CFG_POP" ); p; p=strstr( p+1UL, "CFG_POP" ) ) {
    char const * q = p+7UL;
    int is_arr = 0;
    while( ( *q>='A' && *q<='Z' ) || ( *q>='0' && *q<='9' ) || *q=='_' ) { is_arr |= !strncmp( q, "_ARRAY", 6UL ); q++; }
    while( *q==' ' ) q++;
    if( *q!='(' ) continue;
    q++;
    while( *q==' ' ) q++;
    /* boolau values are strings in toml ("auto"/"true"/"false") */
    if(      !strncmp( q, "cstr,",   5UL ) || !strncmp( q, "cstr ",   5UL ) ) q += 4UL;
    else if( !strncmp( q, "boolau,", 7UL ) || !strncmp( q, "boolau ", 7UL ) ) q += 6UL;
    else continue;
    while( *q==' ' || *q==',' ) q++;
    ulong len = 0UL;
    while( q[ len ]!=',' && q[ len ]!=' ' && q[ len ]!=')' ) len++;
    FD_TEST( cnt<max && len<64UL );
    ulong dup = 0UL;
    for( ; dup<cnt; dup++ ) if( strlen( out[ dup ] )==len && !strncmp( out[ dup ], q, len ) ) break;
    if( dup<cnt ) continue;
    fd_memcpy( out[ cnt ], q, len );
    out[ cnt ][ len ] = '\0';
    arr[ cnt ] = is_arr;
    cnt++;
  }
  FD_TEST( cnt );
  return cnt;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static fd_config_t config[1];
  fd_config_load( 1, 0, default_config, strlen( default_config ), NULL, NULL, 0UL, NULL, 0UL, NULL, config, 0 );

  /* default config checks */
  FD_TEST( config->firedancer.snapshots.sources.max_local_full_effective_age>config->firedancer.snapshots.full_snapshot_interval_slots );

  strcpy( config->tiles.bundle.url, "https://user:hunter2@mainnet.example.com:443/v1/txns?api-key=SECRET#frag" );
  strcpy( config->tiles.event.url,  "https://events.example.com/submit" );

  static char json[ 262144 ];
  ulong len = fd_config_to_json( config, json, sizeof(json) );
  FD_TEST( len && len==strlen( json ) );

  /* balanced braces/brackets outside strings */
  long depth = 0L; int in_str = 0, esc = 0;
  for( ulong i=0UL; i<len; i++ ) {
    char c = json[ i ];
    if( esc ) { esc = 0; continue; }
    if( in_str ) {
      if( c=='\\' ) esc = 1;
      if( c=='"'  ) in_str = 0;
      continue;
    }
    if( c=='"' ) in_str = 1;
    if( c=='{' || c=='[' ) depth++;
    if( c=='}' || c==']' ) depth--;
    FD_TEST( depth>=0L );
  }
  FD_TEST( !depth && !in_str );

  /* host identity and paths are redacted, settings are present */
  FD_TEST( !strstr( json, config->hostname ) );
  FD_TEST( !strstr( json, config->paths.base ) );
  FD_TEST(  strstr( json, "\"tick_per_ns_mu\"" ) );
  FD_TEST(  strstr( json, "\"max_live_slots\"" ) );
  FD_TEST(  strstr( json, "\"shred_listen_port\"" ) );

  /* external service urls are fully redacted */
  FD_TEST( !strstr( json, "SECRET" ) );
  FD_TEST( !strstr( json, "hunter2" ) );
  FD_TEST( !strstr( json, "example.com" ) );

  /* user override toml renders with keyword redaction */
  static char const user_toml[] =
    "name = \"fd1\"\n"
    "[tiles.bundle]\n"
    "  url = \"https://mainnet.example.com/?api-key=SECRET\"\n"
    "[gossip]\n"
    "  entrypoints = [\"entrypoint.mainnet-beta.solana.com:8001\"]\n"
    "  port = 8001\n"
    "[paths]\n"
    "  accounts = \"/data/accounts\"\n"
    "[tiles.pack]\n"
    "  account_blocklist = []\n";
  strcpy( config->user_config, user_toml );
  config->user_config_len = strlen( user_toml );

  static char user_json[ 65536 ];
  ulong user_len = fd_config_user_toml_to_json( config, user_json, sizeof(user_json) );
  FD_TEST( user_len && user_len==strlen( user_json ) );
  FD_TEST( !strstr( user_json, "SECRET" ) );
  FD_TEST( !strstr( user_json, "/data/accounts" ) );
  FD_TEST(  strstr( user_json, "\"port\":8001" ) );
  FD_TEST( !strstr( user_json, "entrypoint.mainnet-beta.solana.com" ) );
  FD_TEST(  strstr( user_json, "\"name\":\"fd1\"" ) );
  FD_TEST(  strstr( user_json, "\"account_blocklist\":[]" ) );
  FD_LOG_NOTICE(( "user config json %s", user_json ));

  /* the full default.toml vocabulary must classify: an unlisted string
     key aborts here rather than on an operator's boot */
  FD_TEST( strlen( default_config )<sizeof(config->user_config) );
  strcpy( config->user_config, default_config );
  config->user_config_len = strlen( default_config );
  FD_TEST( fd_config_user_toml_to_json( config, user_json, sizeof(user_json) ) );

  /* every string key the extractor accepts for firedancer must also
     classify, since the extractor vocabulary is wider than default.toml
     (e.g. the capture keys); a synthetic toml exercises all of them */
  static char keys[ 128 ][ 64 ]; static int is_arr[ 128 ];
  char const * podf = strstr( config_parse_src, "fd_config_extract_podf" );
  FD_TEST( podf );
  ulong key_cnt = extractor_cstr_keys( podf, keys, is_arr, 128UL );
  ulong off = 0UL;
  for( ulong i=0UL; i<key_cnt; i++ ) {
    ulong n;
    FD_TEST( fd_cstr_printf_check( config->user_config+off, sizeof(config->user_config)-off, &n, is_arr[ i ] ? "%s = [\"x\"]\n" : "%s = \"x\"\n", keys[ i ] ) );
    off += n;
  }
  config->user_config_len = off;
  FD_TEST( fd_config_user_toml_to_json( config, user_json, sizeof(user_json) ) );
  FD_LOG_NOTICE(( "extractor vocabulary swept: %lu cstr keys", key_cnt ));

  /* and the reverse: every classified key must exist in the extractor
     vocabulary, catching dead list entries */
  static char all_keys[ 160 ][ 64 ]; static int all_arr[ 160 ];
  ulong all_cnt = extractor_cstr_keys( config_parse_src, all_keys, all_arr, 160UL );
  for( int list=0; list<2; list++ ) {
    char const * p = strstr( config_json_src, list ? "jw_reported_keys[] = {" : "jw_redacted_keys[] = {" );
    FD_TEST( p );
    char const * end = strstr( p, "};" );
    FD_TEST( end );
    while( 1 ) {
      p = strchr( p+1UL, '"' );
      if( !p || p>=end ) break;
      char const * q = strchr( p+1UL, '"' );
      FD_TEST( q && q<end );
      ulong len = (ulong)( q-p )-1UL;
      ulong i = 0UL;
      for( ; i<all_cnt; i++ ) if( strlen( all_keys[ i ] )==len && !strncmp( all_keys[ i ], p+1UL, len ) ) break;
      if( FD_UNLIKELY( i==all_cnt ) ) FD_LOG_ERR(( "classified key %.*s is not popped by the config extractor; remove the dead entry from fd_config_json.c", (int)len, p+1UL ));
      p = q;
    }
  }

  FD_LOG_NOTICE(( "rendered %lu bytes", len ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
